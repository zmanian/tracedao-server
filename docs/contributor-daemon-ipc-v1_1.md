# Contributor daemon IPC — `trace_commons.daemon.v1_1`

Status: **stable, additive, with one deliberate exception**. This is the
contract the native menu-bar and window applications are built against, on
three separate teams, from this document alone. `v1_1` is additive over
`v1`: every `v1` method keeps its `v1` request and response shape, so a
`v1` client that ignores methods and fields it does not recognize keeps
working against a `v1_1` daemon without modification. New methods and
fields are additions, not replacements.

**The exception, stated rather than buried:** `set_settings` now *refuses* a
key it does not recognize, where `v1` silently ignored it. A `v1` caller
that sent an unrecognized key alongside a recognized one used to get a
partial success and now gets `bad_params`. This is a deliberate break of the
compatibility rule above, made because the old behaviour meant a mistyped
key left the daemon quietly running on the old value with the caller
believing otherwise -- and one of those keys decides which directories get
scanned for the contributor's transcripts. No shipped client relies on the
old behaviour, because no application has shipped against `v1` yet. See
[`set_settings`](#set_settings) for the full rules.

**New in this revision (additive, no existing field or shape changed):**

- `set_settings` now accepts `max_uploads_per_day` and `max_bytes_per_day`,
  each validated against a fixed ceiling rather than left open (see
  [`set_settings`](#set_settings)). Before this, the only way to raise either
  cap was to stop the daemon and hand-edit `daemon-settings.json`.
- `project_id` — an opaque, daemon-issued handle for a project. It appears
  on every queue entry (`list_pending`, the `snapshot` event) and on every
  `list_projects` row, and `set_project_mode` accepts it in place of
  `project_key`. Before this, a socket client could not call
  `set_project_mode` at all: paths never cross this socket, so a client held
  only `project_label`, and a label is not an admissible `project_key`.
  Arming and ignoring a project were unreachable from every GUI. See
  ["Naming a project"](#naming-a-project-ids-keys-and-labels).
- `set_public_profile`, `clear_public_profile`, and `get_public_profile` --
  the public roster handle. A shell could show the `public_attribution`
  consent scope but had no way to claim the handle that scope is about, so
  the "Go public" flow and the settings profile panel were unreachable from
  every application. See ["The public profile"](#the-public-profile).
- `status.routing` — whether the IronWire proxy overlay is declared and
  whether it is producing anything, in three states rather than two. Before
  this, a contributor who declared a proxy that never produced a row saw the
  same nothing as one who never declared it, and a declaration change did
  not take effect until the daemon was restarted. It now applies on the
  `set_settings` call. See ["`routing`"](#routing).
- `list_projects` now reports **discovered** projects as well as configured
  ones, each with the mode actually in force and a `configured` boolean. An
  onboarding screen that asks a contributor to exclude a repository has to
  be able to list a repository nobody has ruled on yet.
- `preview_turns` — an index of turn boundaries **into the body
  `preview_body` already returns**. The transcript surface wants
  `— user — turn 1 —` separators and a `144 more turns` footer, and had
  nothing to place them from. This is strictly an overlay: `preview_body`'s
  request and response shapes are untouched, its bytes are unchanged, and
  every offset indexes that same string. The daemon deliberately does not
  re-render the events as turns -- that would drop `structured_payload`,
  `token_counts`, `latency_ms`, `cost_usd` and `failure_modes`, showing a
  contributor less than the artifact under a tab titled "exactly what would
  be sent". See ["`preview_turns`"](#preview_turns).
- `preview_request`, `preview_visible`, `preview_cancel`, and the
  `preview_ready` event — the **bounded** preview path. `preview` builds on
  the connection's time, which meant a shell drawing a list of N cards
  started N full read-parse-redact-serialize passes at once; on one
  contributor's machine (about 500 queued sessions, 11.7 GB across 4,097
  files, the largest 367.5 MB) that reached 1.7 cores sustained, 1.34 GB
  resident, and a load average of 649 inside three minutes. The daemon now
  owns a two-worker preview pool with deduplication, visible-first
  priority, cancellation, a size admission cap, and a result cache.
  `preview` itself is **unchanged** in request shape, response shape, and
  behaviour -- the CLI and the C ABI still use it. See
  ["Scheduled previews"](#scheduled-previews).
- `history_rollup` now carries an optional `community` object: this
  contributor's own line on the public roster, polled from the server's
  public snapshot on the daemon's own interval. Both desktop clients already
  draw a History community section and neither could populate it, because
  nothing on this contract carried the standing. Additive in the strict
  sense -- no existing `history_rollup` field changed shape, and a client
  that ignores the object is unaffected. See
  ["`history_rollup`"](#history_rollup).

`crates/trace-commons-contributor/tests/daemon_ipc_contract.rs` is the
executable half of this document. `hello` reports its own method list and a
test asserts that list matches `METHODS` in `src/daemon/ipc.rs`, so this file
and the implementation cannot drift silently.

## Transport

Two transports carrying an identical protocol. The framing, the method set,
and the error taxonomy do not vary by platform; only the listening and
connecting ends do. `ipc::serve_connection` is generic over the stream, so
both share one implementation of everything above the transport.

**Unix**: a domain socket at `$TRACE_COMMONS_CONTRIBUTOR_DIR/daemon.sock`
(default `~/.config/trace-commons/daemon.sock`). Access control is the
containing directory: the daemon refuses to serve unless it is 0700, and a
0700 directory belonging to another user is not writable, so no one else can
place a socket there either.

**Windows**: a named pipe at `\\.\pipe\trace-commons-daemon-<16 hex>`, where
the hex is a SHA-256 prefix over the state directory path — never the path
itself, which under the default layout carries the OS username, and which a
pipe name would expose to every process on the machine.

The Windows access control is entirely different in kind, and the difference
matters. A named pipe does not live in the state directory; it lives in the
machine-wide pipe namespace, where any local process may attempt to open it
by name. **Its DACL is the only thing protecting it.** The daemon builds one
granting the creating user's SID alone (`D:P(A;;GA;;;<sid>)`, protected so
no inherited entry can widen it) and refuses to serve if it cannot — there is
no fallback to a default-ACL pipe, because that fallback is the
vulnerability. The first instance is created with `first_pipe_instance` so a
squatter cannot pre-create the name under a weaker descriptor and be served
on.

One behavioural difference on the client side: the Windows one-shot client
opens the pipe as a file handle, which has no equivalent of
`set_read_timeout`, so the 60-second request timeout is not applied there.

> **The Windows DACL is verified by CI, and that job has not yet run.**
> Type-checking for `x86_64-pc-windows-gnu` establishes the FFI signatures
> and the control flow and nothing about whether the descriptor actually
> excludes another user — a runtime property no cross-compile can observe.
> The observation is the `windows-pipe-acl` CI job
> (`scripts/windows/verify-pipe-acl.ps1`, driving
> `src/bin/win-pipe-acl-probe.rs`): on `windows-latest` it creates a second,
> non-administrator local account, has it attempt to open the pipe, and
> requires ERROR_ACCESS_DENIED, with a control confirming the owning user is
> still admitted. The account is deliberately not an administrator — one can
> take ownership of any object and would reach the pipe regardless, so that
> test would look like evidence while proving nothing.
>
> **That job has run and passed** (PR #247, run 31307072159): `DENIED 5` from
> the second user — ERROR_ACCESS_DENIED, refused by the access check
> specifically rather than by pipe-busy or file-not-found, which the script
> rejects so a coincidental refusal cannot pass as evidence — and `CONNECTED`
> from the owner. The claim holds only while that job keeps running; weaken
> or remove it and the verification lapses with it.

`windows-sys` is approved (2026-08-08) for exactly this and scoped to
`[target.'cfg(windows)'.dependencies]`; macOS and Linux dependency trees do
not contain it.
See `docs/superpowers/specs/2026-08-08-contributor-shell-windows-design.md`.

## Framing

JSON, one message per line, UTF-8.

- **Request**: `{"id": <u64>, "method": "<name>", "params": {...}}`. `params`
  may be omitted.
- **Response**: `{"id": <same u64>, "result": {...}}` or
  `{"id": <same u64>, "error": {"code": "...", "message": "..."}}`.
- **Event** (server-pushed): `{"event": "<name>", "data": {...}}`. Events
  never carry an `id`; that is how a client distinguishes them from responses
  on the shared connection.

Rules:

- Every response echoes its request's `id`. Clients may pipeline; the server
  may answer out of order.
- Maximum line length is 1 MiB. A longer or unparseable line gets one
  `bad_params` response and the connection closes.
- `error.message` is always a fixed label, never a server response body,
  a path, or a token.

## Authorization

The 0700 state directory is the access control. The daemon refuses to serve
from a directory that is not 0700; a 0700 directory belonging to someone else
is not writable by this process, so a socket cannot be created there.

**There is no longer a terminal-only carve-out.** Through `v1`, two
operations -- arming a project for `set_project_mode: "auto_upload"` and
bulk-approving the whole queue with `approve: {"all": true}` -- were refused
over the socket (`not_authorized` / `tty-required`) and a client was expected
to tell the contributor to run a CLI command instead. `v1_1` removes that
restriction. Both calls now work over the socket exactly like every other
method, with no TTY requirement. **Applications must stop special-casing
these two calls or telling users to open a terminal for them.**

This is an accepted-risk change, recorded deliberately, not an oversight.
The `v1` rationale was that the socket would let same-user code arm the
contributor's own daemon to exfiltrate a project continuously. That reasoning
does not survive scrutiny: malware with same-user code execution can already
read the contributor's session files (e.g. `~/.claude/projects`) directly and
send them anywhere, and can install its own persistent watcher process to do
so continuously -- the daemon confers it neither the read access nor the
persistence it would need. Routing exfiltration through the daemon instead
would in fact be strictly worse for such an attacker: it is rate-limited,
capped, redacted, PII-filtered, and delivered to a server the attacker
cannot read back from. Holding the device key already lets an attacker
upload once; these two calls do not meaningfully extend what that key
already grants.

What replaces the restriction is **visibility, not gatekeeping**:

- Every autonomy change (`set_project_mode: "auto_upload"`) and every bulk
  approval -- `approve: {"all": true}` and `approve: {"project_id": ...}`
  alike -- appends a local, hash-only audit entry, readable via
  `list_audit`. A project-wide approval that matched nothing appends no
  entry, because nothing was approved. So do `set_consent_scopes` and
  `acknowledge_near_ai_notice`, and so does `cancel: {"project_id": ...}`
  -- undoing a batch approval is the same class of act as making one.
- The action and its audit entry are **one fail-closed unit**. If the entry
  cannot be persisted -- disk full, permissions, a corrupt log -- the action
  is rolled back and the call returns `audit-write-failed`. It does not
  succeed with a warning: an unrecorded change is exactly what removing the
  terminal-only restriction was not supposed to make possible.
- The durable log is capped and rotates oldest-first, so it cannot grow
  until appending to it starts failing. Capping `list_audit`'s output alone
  would not have bounded the file.
- Applications are expected to show armed (`auto_upload`) projects
  persistently in their UI, never collapsed away, so a contributor always
  knows what is armed.

**The audit log is a visibility feature for the contributor's own benefit.
It is not a security control, and this document does not claim it is one.**
It does not prevent anything; it only lets a contributor later see that
something happened. Do not build a security argument, a permission gate, or
any enforcement logic on top of `list_audit` -- it is a record, not a guard.

## Naming a project: ids, keys, and labels

A project has three names on this contract, and they are not
interchangeable.

| Name | Who mints it | Crosses the socket | What it is for |
|---|---|---|---|
| `project_id` | the daemon | yes | naming a project back to the daemon |
| `project_label` | the daemon | yes | showing a project to a human |
| `project_key` | the caller | **no** | naming a project from a terminal |

### `project_id`

`project_id` is an opaque handle the daemon derives from the project key:
`"proj_"` followed by 16 hex characters of `sha256(project_key)`. It is a
hash, not an encoding, so it carries no path component and cannot be turned
back into one. It is derived rather than stored, so it is the same across a
daemon restart and across a policy file rebuilt from scratch, and there is
nothing to migrate.

It appears on every queue entry and every `list_projects` row: a client that
can see a project can name it. `set_project_mode` accepts it in place of
`project_key`, and it is the identifier **every socket client should use**.
`project_id` wins if both are sent.

An id resolves only against projects the daemon already knows — one already
in the policy, one sitting in the queue, or the `unknown-project` sentinel.
An id that resolves to none of those is refused with the fixed label
`project-id-unrecognized`, and nothing is recorded.

Knowing an id confers nothing. It is an identifier, not a capability: the
same call was always available to anyone who could name the directory, and
resolution is still limited to projects the daemon discovered on its own.

### `project_key`, and why it is still accepted

`project_key` is an absolute local path. It does not cross the socket in any
response, and no GUI should ever hold one. It remains an accepted
*parameter* for exactly one caller: a human in a terminal running
`daemon project <path> --mode ignore` **before that project's first
session** — the flow that excludes a repository pre-emptively. The daemon
cannot mint an id for a project it has never discovered, so an id cannot
serve that flow, and the two coexist deliberately rather than one replacing
the other.

Sending neither is `bad_params` with `project_id-or-project_key-required`.

### `project_label`

`project_label` is **always derived by the daemon** from `project_key`. A
client cannot choose one. `set_project_mode` still accepts a `label`
parameter for compatibility with older clients, and ignores it: a
caller-supplied string used to be stored verbatim and then returned by
`list_projects` and written into `daemon-audit.jsonl`, which made both of
those -- the two surfaces the label-only rule exists to protect -- writable
by any socket client with an arbitrary path, token, or transcript fragment.

`project_key` itself is validated. It must be one of:

- the locked unknown-cwd sentinel (`unknown-project`), which can never be
  armed;
- a key the daemon already knows -- discovered on a queued session, or
  already present in the project policy;
- an absolute path that exists on this machine as a directory and
  canonicalizes to itself.

Anything else is refused with the fixed label `project-key-unrecognized`
and nothing is recorded. An unrecognized `project_id` is refused the same
way, with `project-id-unrecognized`. This keeps the label the daemon derives anchored to
something it can corroborate, rather than to a string a client invented.

## Privacy rules binding on clients

- Queue entries on the wire carry `project_label` and `project_id`, never
  `project_key` or `path`. Both of those are local filesystem paths and never
  cross the socket. Do not display or log a path. Render the label; send the
  id back.
- History records carry no path at all.
- `get_settings` reports five booleans -- `near_ai_configured`,
  `near_ai_inference_configured`, `near_ai_session_retained`,
  `claude_root_configured`, `codex_root_configured` -- and never the
  underlying values. The first three are credentials and are **different
  credentials for different services**, which their near-identical names do
  not convey: `near_ai_configured` is the privacy-filter API key,
  `near_ai_inference_configured` is the NEAR AI inference key this daemon
  mints for a contributor, and `near_ai_session_retained` is the NEAR AI
  session kept alongside that key so the account balance can be read. The
  session is the **widest** of the three -- a refresh token can mint further
  API keys and read organization and workspace state, where the inference key
  buys inference and nothing else -- and it is the one that most obviously
  must never cross this socket. The last two are local filesystem paths. All
  five are configured-or-not facts an app may render as a checkmark, never as
  text containing the actual value.
- `preview` returns a **summary** over the socket -- counts, labels, and
  sizes. The full redacted event body is a separate call, `preview_body`,
  because it does not fit one frame and has to be paged. Both carry trace
  content under the one carve-out below; nothing else on this surface does.
  An earlier revision of this document said the body was deliberately
  in-process only, reachable through the crate's C ABI, on the reasoning
  that any process could compute a preview for itself. That reasoning does
  not survive the deployment we recommend: the C ABI's entry point needs the
  daemon's shared state, which only the process holding the daemon lock has,
  and under a systemd-managed daemon with the window as a socket client that
  is never the window. Loading a second copy of the daemon's state is not a
  substitute -- it rewrites the queue file and sweeps the pinned envelopes
  the running daemon is still holding. So the body is served over the
  socket, paged.

### The preview exemption

`preview` is the **one** interface that deliberately carries trace content,
and this is a decision, not a contradiction left lying around. The socket's
`opening_prompt`, the socket's `preview_body` chunks, and the C ABI's
`tc_preview_body` are all trace content. A contributor cannot consent to
sending something they cannot see; an approval given against a byte count
and a project name is not an informed one. So the rule has exactly one
carve-out, and it is bounded:

- **Post-redaction only.** What preview carries is what the real redaction
  pipeline produced. Raw session text never crosses either boundary.
- **Only for an entry the caller already holds.** Content is reachable only
  by naming an `entry_id` already in the queue. There is no bulk read, no
  ambient read, and no way to ask for a session the daemon has not offered.
  An id that is not in the queue -- unknown, already swept, or never
  offered -- is refused by both `preview` and `preview_body` with the same
  fixed label, `bad_params` / `unknown-entry-id`, so the two cases are not
  distinguishable from outside.
- **Never onward.** It never appears in a log line, an audit entry, a
  history record, notification text, or a receipt. Not truncated, not
  summarized, not hashed-with-a-sample. Nothing copies it into any of those.

`preview_turns` is **not** part of the exemption and does not need to be: it
carries event-type labels, tool names the envelope already records as
metadata, and byte offsets, never redacted text. It is still served only for
an entry the caller already holds, under the same `unknown-entry-id` rule,
because the shape of a contributor's transcript is itself something they
have not offered anyone.

The exemption also covers **the previewed envelope at rest**. A successful
`preview` writes the redacted envelope it built to the contributor's own
0700 state directory (`daemon-approved-envelope-{entry_id}.json`, 0600,
atomic), and the upload sends exactly those bytes rather than building a
second envelope. That is what makes preview and upload agree under a
privacy filter that does not reproduce its own output: with
`pii_filter = "near-ai"` an LLM-backed filter returns different spans for
identical text, and any design that rebuilt-and-compared refused every
previewed entry forever. The stored bytes are held to the same bounds as
the rest of the exemption, plus three of their own:

- **Bounded in bytes.** One file per pinned entry, each at most the 16 MB
  envelope ceiling, and live entries are capped by `max_queue_entries` --
  but that pair alone would allow 7.8 GB of redacted trace content on a
  contributor's disk, which is not a bound anyone would choose. The store
  is held under a ceiling of its own (256 MB) by releasing the oldest
  pending previews.
- **Kept only while somebody is waiting on it.** The exemption is for an
  entry the contributor asked about, so a `pending` entry's stored envelope
  is released once it is three days old and the contributor has not acted
  on it; opening the entry again rebuilds and re-pins it. An `approved` or
  `uploading` entry is never released this way: its bytes are the bytes the
  upload will send.
- **Deleted when the entry resolves.** Uploading, refusing, failing,
  expiring, superseding, or revoking an approval all drop the file, and
  `logout` removes any that remain. If the bytes are missing or unreadable
  when the upload comes to read them, the approval is revoked and the entry
  re-offered -- never silently rebuilt.

They never cross the socket or the C ABI. `preview` reports the
`envelope_digest` that identifies them; it does not serve them.

Everywhere else the rule remains absolute: no path, token, invite code,
claim, device key, or trace content in any log line, error string, receipt,
history record, audit entry, notification text, or IPC response.

## Native onboarding state and bootstrap trust

`get_settings.admission_evidence_required` is an additive boolean derived from
configured witness admission policy. It is not proof of eligibility or a grant.
The separate `ironwire_attested_bodies` consent remains authoritative. If that
consent is off while admission is required, explicit witness review refuses with
`admission_receipt_unavailable` before transmitting a session. Clients must reread
`get_settings` after a failed settings write rather than display an assumed value.

The native wallet view carries `flow_id`, `state` (`Unsupported`, `Idle`,
`Checking`, `Ready`, `WaitingForWallet`, `Refused`, `Complete`), `busy`,
`can_check`, `can_start`, `can_edit`, `can_cancel`, `wait`, `message`, `tone`,
`glyph`, and optional `browser_url`. Shells render core copy and state, open the
browser handoff once, and request `wait` while requested by the view. Core owns
the two-second cadence and discards late replies after cancellation. Closing a
sheet sends `cancel`, including while start is pending. `Refused` uses the
returned refusal tone and glyph. Unsupported methods retain the invite flow.

`prepare_admission_session.view` adds `{ready, state, message, tone, glyph}` to
its existing result. Core requires both the expected status and a future expiry;
shells use `view.ready` rather than repeat readiness or clock rules.

Capability discovery bootstraps trust from allowlisted HTTPS at the ingest origin
chosen by the user (trust on first use). The advertised witness/issuer pins are
not independently authenticated merely because TLS succeeds. Operators must
provide an authenticated service origin; subsequent exchanges enforce the stored
pins. No account token, device key or PKCE verifier is returned to native views.

## Methods

| Method | Params | Result | Notes |
|---|---|---|---|
| `hello` | — | `schema_version`, `supported_versions[]`, `methods[]`, `events[]`, `max_line_bytes` | |
| `status` | — | see below | |
| `list_pending` | — | `pending[]` of queue entries | |
| `preview` | `entry_id` | see below | summary only; the body is `preview_body` |
| `preview_body` | `entry_id`, `offset` (optional), `limit` (optional), `body_digest` (required when `offset > 0`) | `chunk`, `next_offset`, `total_bytes`, `body_digest`, `envelope_digest`, `enrolled`, `max_chunk_bytes` | the redacted body, paged; see "`preview_body`" below |
| `preview_turns` | `entry_id`, `body_digest` (**required**) | `entry_id`, `body_digest`, `envelope_digest`, `turn_count`, `turns[]` | an index of turn boundaries **into the body `preview_body` returns**; the body itself is unchanged. See "`preview_turns`" below |
| `prepare_admission_session` | `entry_id`, `backend`, `confirmed: true` | `status: "ready_for_next_inference"`, `expires_at`, `view` | consent-gated challenge registration for the next inference; no funding or routing changes |
| `native_wallet_flow` | `action: open/check/start/wait/cancel`; `flow_id` after open; `ingest_url` for check/start; `account_id` for start | shared wallet view (see below) | owns capability checks, origin validation, polling cadence and cancellation; no new C ABI |
| `near_account_capabilities` | `ingest_url` | validated `ready`, issuer, audience and witness settings; on `ready: false` a `reason` of `address_refused`, `unreachable` or `unsupported` | checks allowlisted HTTPS service; no signup or funding. With `TRACE_COMMONS_ALLOWED_HOSTS` unset the allowlist is derived from `ingest_url` plus the issuer and witness hosts that origin publishes |
| `near_account_start` | `ingest_url`, `account_id` | `attempt_id`, `browser_url`, `status` | explicit wallet ceremony; keys and PKCE stay in daemon |
| `near_account_status` | `attempt_id` | `attempt_id`, `status` | no account token or signing material |
| `near_account_cancel` | `attempt_id` | cancellation state | cancels the matching local attempt |
| `near_ai_credential_start` | `provider` (optional, default `github`) | `attempt_id`, `browser_url`, `status` | asynchronous only; opens a sign-in whose result is an inference key kept on this machine. The browser URL is returned **once** and no poll re-serves it |
| `near_ai_credential_status` | `attempt_id` (optional) | `state`, plus `attempt_id` and `attempt_status` for a caller that named the current attempt | never errors on a missing or stale `attempt_id`: `state` is a fact about the machine. See "The credential state" below |
| `near_ai_credential_cancel` | `attempt_id` (**required**) | `attempt_id`, `status` | stops this machine waiting on the browser; `near_ai_credential_unknown` if the id is not the current attempt |
| `near_ai_credential_forget` | — | `removed`, `revoked: false` | removes the key from **this machine only**; `revoked` is always false and is not a placeholder. See "The credential state" below |
| `witness_preview_request` | `entry_id`, `raw_session_confirmed: true`; optional `outcome`, `correction` | `status: "ready"`, `summary` | awaits explicit remote review; saves and pins certified bytes without approval or upload |
| `preview_request` | `entry_id` | `entry_id`, `state`, and the fields that state carries | enqueues and returns immediately; the result arrives as a `preview_ready` event. See "Scheduled previews" below |
| `preview_visible` | `entry_ids[]` | `visible: <count>` | replaces the on-screen set wholesale; decides preview **order**, never membership |
| `preview_cancel` | `entry_id` | `entry_id`, `dropped` | drops a queued preview, or discards a running one's result; `dropped: false` is a no-op, not an error |
| `approve` | `entry_id`, `all: true`, or `project_id`; `outcome` (optional); `correction` (optional, `entry_id` + `partly`/`failed` only) | `approved: <count>`, `hold_secs`, `hold_until`, `flagged`, `redactions`, `skipped[]` | `all: true` no longer requires a terminal; `project_id` approves that project's `Pending` entries and no others, matched by the id `entry_value` publishes (never `project_label`, which is display text and unstable), and is refused with `project-id-unrecognized` if the daemon does not know that project; the three are mutually exclusive and `all` wins over `project_id` wins over `entry_id` when more than one is sent; see "The approval hold", "What `approve` reports" and "The `outcome` verdict" below |
| `dismiss` | `entry_id` | `ok: true` | declines the **session**, not just this entry: the daemon never offers that session file again, however much it grows afterwards. See "`dismiss` is permanent" below |
| `cancel` | `entry_id` **or** `project_id` | `ok: true` (`entry_id`) or `canceled: <count>` (`project_id`) | returns matching `approved` entries to `pending` and clears their pin, so the next `approve` rebuilds; guaranteed to succeed for the whole hold; `project_id` undoes that project's `approved` entries and no others -- `pending` entries are left alone, matched by the id `entry_value` publishes (never `project_label`) -- and is refused with `project-id-unrecognized` if the daemon does not know that project; the two selectors are mutually exclusive and `project_id` wins if both are sent; a known project with nothing `approved` succeeds with `canceled: 0`; the single-`entry_id` form errors if that entry is not currently `approved`; see "The approval hold" below |
| `pause` | `until` (optional RFC 3339 timestamp) | `paused: true`, `paused_until` | see "Pause semantics" below |
| `resume` | — | `paused: false` | |
| `list_projects` | — | `projects[]` of `{project_id, project_label, mode, added_at, configured, is_unresolved_bucket}` | configured **and** discovered projects; see "`list_projects`" below |
| `set_project_mode` | `project_id` **or** `project_key`, `mode` (`label` accepted and ignored) | `ok: true`, `purged: <count>` | socket clients send `project_id`; `auto_upload` no longer requires a terminal; see "Naming a project" above and "`set_project_mode` and the ignore purge" below |
| `list_history` | `limit` (optional, default 50, max 1000) | `history[]` | |
| `history_rollup` | — | see below | |
| `refresh_history` | — | `requested: true` | |
| `list_audit` | `limit` (optional, default 50, max 1000) | `entries[]`, newest first | see "Audit log" below |
| `queue_outcome_counts` | — | `reasons: {label: count}` | see "queue_outcome_counts" below; does **not** cover sessions never queued |
| `probe_routing` | `port` (required), `token_dir` (optional absolute directory) | `outcome`, plus `token_path` or `port` | asks a declared IronWire proxy whether it is there; performs real loopback I/O and **never returns the token**; see "`probe_routing`" below |
| `discover_routing` | — | `found`, plus `port` and optionally `token_path` when found | reads the pointer a running IronWire published, so the declaring flow can pre-fill instead of asking; no network I/O and **never returns the token**; see "`discover_routing`" below |
| `harness_list` | — | `catalog_present`, `harnesses[]`, `activity`, `spend`, `destination_port` | which coding tools this machine has and whether each sends its calls here; reads the filesystem on every call, never a cache; see "The harness list" below |
| `harness_plan` | `id` (required), `action` (`connect` \| `disconnect`) | `id`, `action`, `outcome`, `plan_id`, `path`, `changes[]`, `occupied[]` | works out an edit and **writes nothing**; see "The harness list" below |
| `harness_commit` | `plan_id` (required) | `id`, `action`, `committed: true`, `path`, `backup_path` | makes an edit that was already shown; takes a plan id and **nothing else**, so a shell cannot ask for a write it did not preview |
| `quiesce` | `timeout_secs` (optional, default 60, max 300) | `quiesced: true`, `waited_ms` | parks uploads for an update swap; `busy` / `quiesce-timeout` if in-flight work does not finish in time |
| `get_settings` | — | settings; credential presence as booleans, source declarations as `*_source_mode` (`unset`/`off`/`watch`), never local paths | |
| `set_settings` | any of `quiescence_secs`, `digest_interval_secs`, `approval_hold_secs`, `local_notifications`, `claude_root`, `codex_root`, `claude_source`, `codex_source`, `gemini_source`, `cline_source`, `opencode_source`, `ironwire`, `ironwire_attested_bodies`, `token_distributions_contribution`, `token_capture_enabled`, `private_inference`, `private_inference_offer_seen`, `max_uploads_per_day`, `max_bytes_per_day` | updated settings | see "`set_settings`" below |
| `consent_options` | — | `scopes[]` of `{name, description, always_on, grants_data_use}` | |
| `set_consent_scopes` | `scopes[]` (wire-name strings; omitted means floor scope only) | `consent_scopes[]` | requires an existing enrollment |
| `enroll` | `grant` xor `invite`, `scopes[]` (optional) | `enrolled: bool`, and on success `tenant_id`, `device_key_id`, `consent_scopes[]` | performs real network I/O |
| `acknowledge_near_ai_notice` | — | `acknowledged: true` | clears the `near-ai-notice-not-acknowledged` health label |
| `near_ai_balance` | — | `state`, `currency`, `scale`, `remaining_nanos`, `spend_limit_nanos`, `total_spent_nanos`, `total_requests`, `total_tokens`, `observed_at` | performs real network I/O; **always succeeds** and reports every way of not knowing as a named `state`; see "`near_ai_balance`" below |
| `set_public_profile` | `handle` (required), `bio` (required, string **or** `null`) | the profile, plus `handle_persisted` | performs real network I/O; replaces the whole profile; see "The public profile" below |
| `clear_public_profile` | — | the profile (now empty), plus `withdrawn: true` and `handle_persisted` | performs real network I/O; see "The public profile" below |
| `get_public_profile` | — | `on_roster`, `handle`, `bio`, `public_since`, `public_url` | a LOCAL cache, not a server read-back; `public_url` is always `null` |
| `subscribe` | — | `subscribed: true`, then a `snapshot` event | |
| `shutdown` | — | `stopping: true` | |
| `withdraw` | `submission_id` | `withdrawn: true`, `distribution_reach` | performs real network I/O; see "Withdrawal" below |
| `withdraw_bulk` | `status` (`submitted` \| `quarantined` \| `accepted`) | `withdrawn: <count>`, `failed: <count>` | performs real network I/O; see "Withdrawal" below |

### `status`

```json
{
  "schema_version": "trace_commons.daemon.v1_1",
  "logged_in": false,
  "tenant_id": null,
  "consent_scopes": [],
  "paused": false,
  "queue_depth": 0,
  "next_digest_at": null,
  "health": { "last_error_label": null, "since": null },
  "daily_budget": {
    "bytes_today": 204659969,
    "max_bytes_per_day": 209715200,
    "bytes_remaining": 5055231,
    "uploads_today": 12,
    "max_uploads_per_day": 50,
    "uploads_remaining": 38,
    "resets_at": "2026-08-22T00:00:00Z",
    "blocked": true,
    "blocked_entries": 14,
    "blocked_bytes": 137283584
  },
  "routing": { "state": "not_declared", "last_refresh_at": null }
}
```

`health.last_error_label` is the field a tray renders when something is
wrong. It is one of the labels in "Health precedence" below, or `null` when
healthy.

#### `daily_budget`

Added in `trace_commons.daemon.v1_1` as an additive field. It reports the
daily volume caps and, crucially, how much already-approved work they are
holding back.

It is deliberately **not** routed through `health`. The daemon does set
`daily-cap-reached` when a cap refuses an upload, but that label sits at the
bottom of the precedence order, so any other condition — a full queue, in
the case this field was added for — occupies the single
`health.last_error_label` slot and the cap becomes invisible. A client that
only reads `health` therefore cannot tell a spent budget from a broken
daemon. Read `daily_budget` independently of `health`.

| field | meaning |
| --- | --- |
| `bytes_today` / `uploads_today` | consumed so far in the current UTC day |
| `max_bytes_per_day` / `max_uploads_per_day` | the caps in force |
| `bytes_remaining` / `uploads_remaining` | what is left, saturating at zero |
| `resets_at` | the next UTC midnight, when the counters zero. Derived from the daemon's own day bucket, so a client may state it |
| `blocked` | whether at least one approved entry cannot be uploaded before `resets_at` |
| `blocked_entries` / `blocked_bytes` | how many, and their combined on-disk size |

`blocked_entries` counts every approved entry that will not go out today,
not only the ones that individually overflow the budget: the upload pass
stops at the first entry that does not fit rather than skipping past it, so
a small entry queued behind a large one waits as well.

`blocked` is false when the budget is spent but nothing is approved and
waiting — there is no one to tell in that case.

Counts and timestamps only. No entry id, hash, or path appears here.

Approved entries are not listed by `list_pending`, which returns `pending`
entries only, so this is the only place the condition is reported; there is
no per-entry equivalent.

#### `routing`

Additive, and the protocol version is unchanged: `trace_commons.daemon.v1_1`
stays as it is. Every shell ignores keys it does not know — the Swift models
decode declared keys only, the GTK models carry no `deny_unknown_fields`, and
the Windows deserializer is left at its default — so an older shell against a
newer daemon behaves exactly as it did before, which is the rule this
document's "additive" status already states.

Whether the effective IronWire metadata overlay is enabled and whether it is
producing anything. Four ordinary states distinguish configuration from data;
`unknown` reports unavailable internal state without blaming a credential.

An explicit `ironwire: {"mode":"off"}` always disables this overlay. An
explicit Watch declaration keeps its exact port and token directory, including
while private-inference hosting starts or stops. With no explicit declaration,
a successfully persisted `private_inference: true` may derive metadata routing
from the proxy this daemon actually owns: its bound port and canonical home.
Discovery, an existing foreign instance, an unpersisted request, and a failed or
stopping proxy cannot supply that endpoint. Turning hosting off withdraws the
derived reader in the accepted settings transaction; cleanup need not finish
first. Terminal daemon cleanup also withdraws only the derived reader.

This derived declaration is not written to settings. `ironwire: null` removes
an explicit declaration, so automatic metadata can resume while owned hosting
is enabled; use explicit Off to refuse it. Derivation never grants body
collection: `ironwire_attested_bodies` still requires its separate opt-in and an
explicit Watch declaration. No agent configuration or tool endpoint is changed.
Unrelated settings writes retain a warm metadata reader when its effective
endpoint is unchanged. Derived refresh first reconciles owned lifecycle state, so
an already-observed proxy exit withdraws its reader before the next request.
This does not authenticate a later listener or cancel an already in-flight request.

| `state` | meaning |
| --- | --- |
| `not_declared` | no effective metadata declaration; the daemon holds no ledger and reads nothing |
| `awaiting_rows` | declared, and the daemon holds a ledger, but no row has arrived yet |
| `rows_seen` | declared, and the last refresh window had rows |
| `token_unreadable` | declared, and no ledger could be built: `control.token` could not be read |
| `unknown` | internal routing state is unavailable; no configuration or token diagnosis is implied |

Every routing snapshot includes `derived: true|false`. True identifies automatic
metadata routing from this daemon's owned proxy; false identifies an explicit or
absent declaration. With `state: "unknown"`, false is only a conservative default,
not evidence that metadata is disabled. Shells use the effective status and its
origin alongside the independent explicit declaration controls. The shared routing
copy payload includes `derived_origin` for that explanation and `state_unknown`
for unavailable nonempty labels. The origin is descriptive and never turns the
explicit routing switch on or enables body reading. Older snapshots without
`derived` omit that explanation; they do not synthesize it from a hosting flag.

`token_unreadable` is what a declared proxy that is not running looks like,
and it is the one state a contributor has to act on. It was reported as
`not_declared` before it existed, which made a shell print "off" under a
switch the contributor could see was on. It is not `awaiting_rows` either:
that state says a reader exists and has seen nothing, and this one says no
reader exists. `last_refresh_at` is always `null` under it — nothing was
built, so nothing was ever checked.

`awaiting_rows` is **not an error** and a client must not render it as one.
A machine whose proxy was installed this morning reports it, and so does one
whose declaration changed a second ago: `set_settings` rebuilds the ledger in
place — no restart — and a rebuilt ledger starts cold by construction. Say
"nothing seen yet", not "broken".

The distinction `not_declared` carries cannot be recovered from row counts:
a daemon holding no ledger and a daemon holding a ledger that has read
nothing both have zero rows, and reporting them the same way tells a
contributor whose declaration never took that everything is fine.

`last_refresh_at` is when a refresh last **reached** the proxy and came back
readable — RFC 3339, or `null` when none ever has. It is not stamped on a
failed attempt, which is what makes it useful: rows say data exists, not that
the proxy answers now, and a proxy that died an hour ago still has rows. With
`awaiting_rows`, a non-null `last_refresh_at` means the proxy answered and
this window genuinely had nothing in it; a null one means nothing has
answered yet.

No port, token, or row content appears here.

### `preview`

```json
{
  "entry": { "...": "queue entry, see list_pending" },
  "would_send_bytes": 4160,
  "raw_session_bytes": 1615,
  "event_count": 3,
  "opening_prompt": "…",
  "redactions": { "aws_secret_key": 1 },
  "pii_labels_present": ["email"],
  "consent_scopes": ["debugging_evaluation"],
  "residual_risk": "pattern-based",
  "envelope_digest": "sha256:…",
  "input_fingerprint": "sha256:…",
  "enrolled": true,
  "subagent_count": 3,
  "subagents_dropped": 0
}
```

`subagent_count` and `subagents_dropped` also appear on every queue entry
(`list_pending`, the `snapshot` event), as do `eligibility` and
`eligibility_reason` -- see "Contribution eligibility" below -- and
`attestation` and `attestation_reason`, see "The attestation mark" below,
and `holds_certificate`, see "The certificate a queue entry holds" below.
`attestation` and `holds_certificate` are on EVERY entry; `eligibility` is
not. All are
additive; the schema version
stays `trace_commons.daemon.v1_1`, and a client that ignores them behaves
exactly as before.

A Claude Code conversation is not one file: each delegated subagent's turns
are written beside the session under `<session-uuid>/subagents/`, and one
conversation on a probed machine had 114 of them. The daemon offers the whole
conversation as a single entry, so `subagent_count` is how many delegated
transcripts that entry covers. A client should say so on the card -- what is
being consented to is the whole conversation, and its extent is part of the
description rather than decoration.

`subagents_dropped` is non-zero only when the conversation exceeded the
source's raw byte budget and the largest delegated transcripts were left out
to keep the envelope under its cap. A client **must** surface a non-zero
value: the difference between a trace the contributor knows was trimmed and
one that silently arrives partial is the whole point of showing it. The drop
is decided when the transcript is loaded, so the preview and the upload
describe the same bytes.

No ordinal is exposed -- there is no "1 of 3" -- because nothing in the
transcript format supplies one. Ordering delegated transcripts against each
other would be a claim this daemon cannot verify.

`opening_prompt` is redacted trace content -- see "The preview exemption"
above for why this one field is allowed to be, and what that permission does
not extend to.

`envelope_digest` identifies the redacted envelope this summary describes;
`input_fingerprint` identifies the configuration that produced it. Both are
hashes, never content. Issuing `preview` **pins the entry** to that envelope
and stores the envelope itself: an `approve` that follows is an approval of
exactly those bytes, and the upload sends them verbatim rather than
redacting a second time. The upload still refuses and re-offers the entry if
an envelope-determining input has moved since (`approval-inputs-changed`),
if the session file has changed, or if the stored bytes are gone
(`approved-envelope-unavailable`). An app can hold these two values to
confirm that the entry it later approves is the one it actually displayed.

Previewing the same entry twice re-pins it to the second preview, which is
the one the upload will send. Previewing an entry that is no longer
`pending` reports the summary but changes no pin: an entry already approved
stays bound to the artifact it was approved as.

`would_send_bytes` is the size of the **redacted envelope**, not the raw
session file -- the same envelope `submit` would actually send, computed by
running the real redaction pipeline. It is normally **larger** than
`raw_session_bytes`, not smaller. Intuition runs the other way, because
redaction removes content, but a redacted envelope also carries schema,
consent, and privacy metadata that the raw session file does not, and that
overhead usually outweighs whatever redaction shortened. Measured example: a
1615-byte raw session produced a 4160-byte envelope. Do not build a UI that
assumes `would_send_bytes < raw_session_bytes`; assert nothing about the
direction, only that `would_send_bytes` is the number that governs consent.

`preview` requires an entry currently in the queue (`bad_params` /
`unknown-entry-id` otherwise) and a working privacy filter (`unavailable` /
`preview-failed` on failure). Neither `redactions` nor `pii_labels_present`
in the response ever contains the actual matched text, only counts and
category labels.

**`preview` does not require an enrollment.** It performs no network I/O and
needs neither the daemon's file lock nor its running loop, so an app can
show a contributor what would be sent *before* they decide to enrol -- which
is when the question matters most. Through `v1_1`'s first releases this
refused with `unavailable` / `not-logged-in` unless a `contributor.json`
existed, which forced app harnesses to fabricate an enrollment purely to
preview a local file; that requirement was incidental and is gone.

`enrolled` says which kind of preview you got:

- `true` — the ordinary case. Built from the real enrolled identity through
  the configured privacy filter, and (as described above) **pinned**: the
  envelope is stored and a later `approve` covers exactly those bytes.
- `false` — no enrollment on this device. The envelope is built from the
  same placeholder identity the CLI's unenrolled `--dry-run` uses, with a
  preview submission id disjoint from any real one, and through the
  **deterministic-only** redactor: any configured external privacy filter is
  ignored, so pre-enrollment trace text is never sent anywhere to be
  classified. Nothing is pinned, and `envelope_digest` /
  `input_fingerprint` describe that placeholder build -- neither is bindable
  to a later approval, since enrolling changes the identity the envelope
  carries. Render such a preview as an illustration, and re-preview after
  enrolling before asking for an approval.

`would_send_bytes`, `redactions`, `pii_labels_present` and `opening_prompt`
are real in both cases; an unenrolled preview understates nothing about
redaction except what an external filter would additionally have removed.

### Explicit witnessed review

The daemon exposes `witness_preview_request` through authenticated local IPC.
Clients must not offer it unless the daemon advertises that method. Existing `preview`, `preview_request`, card summaries, and background
refresh never invoke this builder. A configured witness still refuses ordinary
preview with `witness_claim_unavailable`, rather than building a local substitute.

The handler enforces these conditions:

1. Require an authenticated local IPC caller, an enrolled device, a pending entry
   the caller already holds, and explicit confirmation to send this session to
   the configured remote witness before redaction. Body-export consent remains
   separate: read `ironwire_attested_bodies` from current daemon settings, never
   from a caller's inferred proxy/scanner state. No confirmation means no work.
2. Snapshot the selected entry's source hash and current configuration, including
   consent and witness pins. Call `preview::build_witnessed_preview` with
   `WitnessPreviewOptions { raw_session_confirmed, expected_session_hash,
   include_inference_bodies, verdict, correction }`. A missing/stale device,
   changed source, unpinned witness, failed claim, or unverified certificate
   refuses. There is no local-redaction fallback.
3. This is an ordinary authenticated upload-claim request, not an admission or
   credit action. Its explicitly echoed grant must be fresh and no wider than
   requested permissions. The granted scopes/uses are included in the bytes the
   witness certifies. The helper never uploads a contribution or persists a token.
4. On completion, take the queue lock and recheck that the entry is still pending
   and its source/configuration/consent match the snapshot. Persist via
   `approved_envelope::save_witnessed`, then pin `summary.envelope_digest` and save
   the queue. A failed save must not allow approval without a persisted artifact.
   Never route this result through the local-envelope `save` function.
5. `witness-sha256:` pins identify the full versioned record: exact wire bytes,
   certificate/signature, source hash, configuration fingerprint, and approval
   answers. Read through `load_witnessed`; check its digest and `validate` against
   current context, then use `envelope()` for existing body/turn/summary rendering.
   Missing, corrupt, partial, unknown-version, or legacy local records are refused.
6. The witnessed artifact is immutable. Corrections/verdicts must be supplied
   before that explicit review, and approval must match those answers exactly.
   A changed answer requires another explicit review; neither ordinary `approve`
   nor background upload may re-witness on the contributor's behalf. Keep local
   envelope approval semantics unchanged.
7. Upload obtains fresh authorization. All certified scopes/uses must match; a
   compatible 401/403 re-mint may resend the **same bytes and certificate**, while
   a changed grant re-offers the entry for review. No restamping, second redaction,
   or new raw witness request occurs. Existing source/fingerprint/residual-secret
   checks remain enforced. Record cleanup uses the existing pin lifetime/sweep.

The record stores only redacted artifact content and hash-only bindings; attached
inference bodies, bearer claims, and plaintext correction inputs are excluded.
Exact envelope bytes are base64-encoded only inside the atomic local record;
ingest receives the original bytes. The envelope remains bounded by the existing
size limit; the record including encoding/certificate overhead is limited to twice
that size, under the existing aggregate approved-artifact storage ceiling.

This enables a local implementation seam, not a deployed capability claim.
Live acceptance still requires configured trusted witness deployment, usable
provider receipt retrieval, and an invited end-to-end artifact check.

### Scheduled previews

`preview` is synchronous: the connection is held for the whole
read-parse-redact-serialize pass. That is correct for a caller that wants
one preview and is willing to wait for it, and it is what the CLI and the C
ABI still use. It is wrong for a shell drawing a list, because the natural
implementation -- one request per card -- starts one full pipeline pass per
queued entry, and nothing bounded how many ran at once. See the "New in this
revision" note for what that measured out to on a real machine.

`preview_request` is the same preview, scheduled. The daemon runs at most
**two** at a time, deduplicates, serves repeats from a cache, builds
on-screen entries first, and refuses sessions too large to be worth parsing
for a card.

**`preview_request`** — params `{entry_id}`. Returns immediately, always,
with an object whose `state` is one of:

| `state` | Also carries | Meaning |
|---|---|---|
| `queued` | — | accepted; a `preview_ready` event will follow |
| `running` | — | already building from an earlier request; a `preview_ready` event will follow |
| `ready` | `summary` | answered from cache; **no event follows**, because no work was done |
| `too_large` | `raw_session_bytes`, `limit_bytes` | refused by admission control; nothing was parsed |
| `failed` | `code`, `label` | the pipeline refused; same fixed labels `preview` uses |

`summary` carries exactly the fields `preview` returns -- `would_send_bytes`,
`raw_session_bytes`, `event_count`, `opening_prompt`, `redactions`,
`pii_labels_present`, `consent_scopes`, `residual_risk`, `envelope_digest`,
`input_fingerprint`, `enrolled` -- with one deliberate omission: it does
**not** carry `entry`. The summary is cached and a queue entry's state
changes underneath it, so embedding one would let a cached preview assert a
stale state. Clients already hold entries from `list_pending` and
`snapshot`.

Calling this repeatedly for the same entry is free and is the intended
usage: a cached result comes straight back, and an entry already queued or
building is not enqueued twice.

**`preview_visible`** — params `{entry_ids: [...]}`. Replaces the daemon's
idea of what is on screen, wholesale. Send it after each scroll settles; it
takes one lock and moves no work. Visibility decides the **order** previews
are built in, never whether they are built: an entry that scrolls away keeps
its place in the queue. An unparseable id is `bad_params` /
`entry-ids-invalid`; an empty array is valid and means nothing is on screen.

**`preview_cancel`** — params `{entry_id}`. Returns `{entry_id, dropped}`.
`dropped: false` means there was nothing to drop -- already finished, never
requested, already cancelled -- and is not an error, because a client that
cancels on every card leaving the list will hit it constantly.

> **What cancel cannot do.** A preview that has already started cannot be
> interrupted. The pipeline has no cancellation point in it, and its
> expensive stretch is a single parse the daemon does not get control back
> from. Cancelling a running entry costs exactly the CPU that job had left
> to spend; what it buys is that no `preview_ready` event is published and
> nothing is cached. The bound on that waste is two jobs, which is why the
> two-worker bound rather than cancellation is what protects the machine. Do
> not build a client on the assumption that cancelling is immediate.

`dismiss` cancels an entry's scheduled preview implicitly. `approve` does
not -- it needs the envelope it would be cancelling.

### `dismiss` is permanent

A queue entry is identified by the hash of its content, so a dismissal
recorded on the entry alone was a decision about a byte range: the moment
the contributor typed the next message into the same conversation it hashed
to something else, and the watcher offered it again as a brand-new
`pending` card. In a project set to `auto_upload` the re-offer arrived
already `approved`, so a declined conversation uploaded unattended.

`dismiss` therefore declines the **session**, addressed the way the daemon
addresses every session -- by its path. Once dismissed, the watcher skips
that session for good: no new `pending` card, no `approved` one, and no
re-read (the skip sits in front of the load, so a declined conversation
someone keeps working in costs nothing per poll). Arming a project does not
override it -- `auto_upload` is a standing yes to sessions the contributor
has not ruled on, not to one they have.

There is no un-dismiss. The record is the dismissed entry itself, which
lives in the queue file with reason `dismissed-by-contributor` and is never
compacted, so dismissals made by older daemons are honoured with no
migration. A `refused` entry carrying any *other* reason is the daemon's
verdict on some bytes rather than the contributor's on the conversation,
and does not suppress anything.

**Too large.** A session over the admission cap is refused rather than
previewed, and the refusal carries **no size estimate of any kind**:
`raw_session_bytes` is a `stat` of the file, `limit_bytes` is the cap, and
there is no `would_send_bytes` and no `summary`. A would-send number is a
claim about an envelope that was never built, and the preview card is a
consent surface. Render "too large to preview" and the raw size; do not
synthesize a would-send figure from the raw bytes. This is a *preview*
policy only -- it does not decide whether such a session can be contributed,
and `approve` still builds and pins one.

**Caching and staleness.** A result is cached against the session file's
path, size, and mtime, the entry's whole-group size, and a fingerprint of
the local configuration. Any of those changing rebuilds. The cache lives in
the daemon process and does not survive a daemon restart.

### `set_project_mode` and the ignore purge

Setting a project to `ignore` also clears whatever it has waiting: every
`pending` entry for that project moves to `refused` with
`reason_label = "project-ignored"`. The response carries `purged`, the
number of entries that moved.

`approved` and `uploading` entries are deliberately untouched. An approval
is a decision already made about specific bytes under specific consent
scopes, and a project-level preference set afterwards does not retract it --
so a project with three waiting and one approved loses three and still
uploads one. A client MUST say so rather than let a contributor discover it.

`"project-ignored"` is not `"dismissed-by-contributor"`. A dismissal is
permanent and suppresses that conversation at its path forever; this is a
verdict on whatever was queued at the moment the mode changed, so setting
the project back to `notify_only` or `auto_upload` lets those sessions be
offered again -- including sessions that are finished and will never be
written to again. Leaving `ignore` drops that project's `"project-ignored"`
entries outright, which is what lets the watcher re-offer them; `dismissed`
and pipeline refusals in the same project are untouched. The re-offer
arrives on a later poll, not in this response, and is still subject to the
queue cap.

A client MUST NOT present the purge as irreversible, and MUST NOT rely on
the entries reappearing within any particular time.

### `preview_body`

The redacted body `preview` describes: the envelope's redacted events,
pretty-printed JSON, exactly the bytes the upload will send. This is what a
"Search" tab searches and what an "Exactly what would be sent" tab renders.

Request:

```json
{ "entry_id": "…", "offset": 0, "limit": 131072, "body_digest": "sha256:…" }
```

Response:

```json
{
  "entry_id": "…",
  "total_bytes": 432118,
  "offset": 0,
  "chunk": "[\n  {\n    \"event_type\": \"user_message\", …",
  "next_offset": 131072,
  "body_digest": "sha256:…",
  "envelope_digest": "sha256:…",
  "enrolled": true,
  "max_chunk_bytes": 131072
}
```

**It is paged, and you must page it.** A redacted envelope can approach the
1.5 MB envelope ceiling; a socket line is capped at `max_line_bytes` (1 MiB).
A single frame therefore cannot be promised, so there is none: read from
`offset: 0`, append `chunk`, and follow `next_offset` until it is `null`.
Nothing is ever silently truncated -- `total_bytes` is the length of the
whole body, and a client that has not received `[0, total_bytes)` has not
read the trace.

**Continuation pages must be anchored.** Every response carries
`body_digest`, a SHA-256 over the complete body. Send it back on every
request with `offset > 0`. Omitting it is `bad_params` /
`body-digest-required`; sending one that does not match the body the daemon
resolved is `unavailable` / `preview-body-changed`, and the correct
response to that is to restart from `offset: 0`, not to splice. This is not
ceremony: a rebuilt envelope is a different artifact (event ids are minted
per build, and an LLM-backed privacy filter does not reproduce its own
spans), so two pages of two builds concatenated would be a transcript that
never existed.

`offset` is a byte offset into a UTF-8 string and is only ever a value the
daemon handed you: pages break on character boundaries, so `next_offset` is
not always `offset + limit`. An `offset` that is out of range or not on a
character boundary is `bad_params` / `offset-invalid`. `limit` above
`max_chunk_bytes` is capped rather than refused; `limit: 0` is
`bad_params` / `limit-invalid`.

**Search happens in the client.** The daemon ships the body and does not
match against it. A daemon-side search would have to reproduce whatever the
client means by a match -- case folding, word boundaries, how a hit that
spans two events is presented -- and would still have to ship surrounding
text for the client to render, leaving the client holding the body anyway
plus a second matcher to keep in step. One body, one text, one search: what
the contributor searched is the text in front of them.

The property that outranks both of those decisions: **never report a trace
clean that you could not actually read.** A "0 matches" is only honest after
`[0, total_bytes)` has been received and searched. If any page errors, if
`preview-body-changed` interrupts you, or if you stopped early, say so --
"could not read the whole trace" -- and do not render an all-clear.

Where the body comes from, and why it is stable:

- An entry already previewed (and so pinned) has its envelope stored on
  disk, and that is what is read -- byte-identical across pages, across
  calls, and identical to the C ABI's `tc_preview_body` for the same entry.
- An entry with no stored envelope runs the redaction pipeline, exactly as
  `preview` does, and is pinned by the same rules (an unenrolled build is
  never pinned, and `enrolled: false` says so). A first call may therefore
  take as long as `preview`.
- An entry that is pinned but whose stored bytes are missing or unusable is
  refused with `unavailable` / `approved-envelope-unavailable`. It is not
  rebuilt: a rebuild is not the artifact the contributor approved, and
  presenting it as "what would be sent" would be false.

`envelope_digest` is the same value `preview` reports, so an app can confirm
the body it is showing belongs to the summary it displayed.

### `preview_turns`

Where the turns begin inside the body `preview_body` returns, so a client
can draw `— user — turn 1 —` separators and a `144 more turns` footer over a
transcript it is rendering verbatim.

**This adds nothing to the body and changes nothing about it.** It is an
overlay: `preview_body`'s bytes are still the whole artifact, still
pretty-printed JSON, still exactly what the upload sends, and every offset
here indexes that same string. The daemon does **not** re-render the events
as chat turns, and a client must not either. A prose re-render drops every
field that has no prose form -- `structured_payload`, `token_counts`,
`latency_ms`, `cost_usd`, `failure_modes` -- and would therefore show a
contributor *less* than what would be sent, under a tab titled "exactly what
would be sent". Flat monospace with separators drawn at these offsets is the
design, and this method is what makes it possible without a second
rendering path.

Request:

```json
{ "entry_id": "…", "body_digest": "sha256:…" }
```

Response:

```json
{
  "entry_id": "…",
  "body_digest": "sha256:…",
  "envelope_digest": "sha256:…",
  "turn_count": 3,
  "turns": [
    { "index": 0, "role": "user_message", "byte_offset": 2, "byte_len": 412 },
    { "index": 1, "role": "assistant_message", "byte_offset": 416, "byte_len": 690 },
    { "index": 2, "role": "tool_call", "tool_name": "bash", "byte_offset": 1108, "byte_len": 1244 }
  ]
}
```

`index` is 0-based and dense, so it indexes the array directly; a client
showing "turn 1" for the first separator renders `index + 1`. `role` is the
`event_type` wire name of the event that opens the turn -- the same string
that appears in the bytes at `byte_offset`, so there are not two
vocabularies to reconcile. `tool_name` is present only when the opening
event names a tool. `byte_offset` and `byte_len` are a half-open range of
**UTF-8 byte** offsets into the body, on character and element boundaries.

**Grouping: a tool call and its result are one turn.** A `tool_call`
followed immediately by the `tool_result` carrying the same `tool_call_id`
is indexed as a single turn spanning both events, so the separator reads
`— tool: bash — turn 3 —` once rather than putting a boundary between a
command and its output. The pairing must be explicit and adjacent:
an unmatched call, a result whose call is missing, a pair reordered by the
source, and a pair with no `tool_call_id` to correlate on are all one turn
per event. Guessing a pair would mean labelling a span that covers two
unrelated events, which is the one error this index must not make.

**`body_digest` is required, on every call.** This is the anchoring rule
`preview_body`'s continuation pages use, applied from the first request,
because an index is a set of offsets into one specific string: against any
other string it is not stale, it is wrong, and wrong invisibly -- a
separator drawn over the wrong text still looks like a transcript. Omitting
it is `bad_params` / `body-digest-required`; a non-string is `bad_params` /
`body-digest-invalid`; a digest that does not match the body the daemon
resolved is `unavailable` / `preview-body-changed`. The correct response to
that last one is the same as for a page: re-read the body from `offset: 0`
and index the body you actually hold.

Where the body comes from, when an unpinned entry is built and pinned, and
which failures are refused rather than rebuilt are all exactly as described
for `preview_body` -- the two methods resolve the same envelope through the
same path, so the index and the body can never come from two different
builds. An entry that resolves but whose body cannot be indexed is
`unavailable` / `preview-turn-index-failed`: fail-closed, because an index
that is not certainly exact is worse than none.

The result is not paged, and does not need to be: a turn serializes to well
under 100 bytes while one pretty-printed event costs upwards of 170, and an
envelope is capped at 1.5 MB, so the index stays a fraction of the 1 MiB
line cap even for an envelope at the ceiling. It is never truncated -- a
truncated index is a transcript with turns silently missing from the end --
so `turn_count` always equals `turns.length`. A client that wants a
`144 more turns` footer computes it from `turn_count` and what it chose to
render, not from anything the daemon left out.

### `list_projects`

```json
{
  "projects": [
    {
      "project_id": "proj_9f2c1ab30d4e5f60",
      "project_label": "my-proj",
      "mode": "notify_only",
      "added_at": null,
      "configured": false,
      "is_unresolved_bucket": false,
      "pending_count": 7,
      "contributable_count": 3
    }
  ]
}
```

`pending_count` is how many `Pending` entries this project holds.
`contributable_count` is how many of those a group-level `approve` would act
on -- what a shell needs to draw "send the 3 of 7 that can be sent" without
enumerating rows and classifying them itself.

**`contributable_count` is ABSENT when eligibility does not apply**, on the
same rule as an entry's `eligibility` field: an invited contributor has no
"3 of 7" to be told about, and `pending_count` alone is their answer. Test
for the key; it is never null.

Both numbers, never one. "Submit all (7)" quietly becoming "Submit all (3)"
is worse than either: the contributor sees a smaller number with no
explanation and cannot tell whether four sessions vanished or were never
counted. A control that counts the sendable ones needs the total beside it,
and `pending_count - contributable_count` is what
`tc_contribution_withheld_line` turns into the sentence that closes the gap.

**Absent, never zero.** A client that read a zero where the question does not
apply would draw "Submit all (0)" and offer nothing to an invited contributor
whose sessions are all perfectly sendable. When the key is missing, count the
button off `pending_count` and render no withheld line.

**`contributable_count: 0` means the group's submit control is not offered.**
A header offering "Submit all" where nothing is eligible is a press with no
visible consequence -- the row-level rule ("shown, not offered") one level up.
The group still renders, with its rows and their sentences; only the control
goes. Decide it through `tc_contribution_group_control(pending,
contributable)`, passing **any negative value** for an absent
`contributable_count`, so the absent-versus-zero distinction is made once
rather than in three shells.

It is a count and not a promise. Entries can move between this call and the
approve, and the expensive checks still run at submit -- see "Contribution
eligibility" below.

Every project the daemon knows about, in two kinds:

- **configured** (`configured: true`, `added_at` set) — the contributor has
  ruled on it with `set_project_mode`.
- **discovered** (`configured: false`, `added_at: null`) — the daemon has
  seen a session for it and nobody has ruled on it. `mode` is the effective
  mode, which for an unruled project is the `notify_only` default.

#### `is_unresolved_bucket`

True for exactly one row: the bucket holding sessions whose working directory
had no usable final segment. Sessions in it can never be armed for automatic
upload — `Policy` refuses `auto_upload` for that key independently of any
client — so a shell showing the row with a permanent note is **reporting**
enforcement, not performing it. `Ignore` still applies: the bucket can be
silenced even though it cannot be armed.

The flag is sent rather than left for clients to derive, because the daemon is
the only side that knows it for free. Deriving it means re-implementing the
`project_id_for` hash to compare ids, which is a copy of the rule per client
with nothing keeping the copies in step.

**Clients MUST NOT recognise this row by `project_label`.** The raw label is a
slug no contributor should read, so every shell replaces it with its own
wording; a client keyed on the displayed string loses the row's explanation
the moment that wording improves, and does it silently.

Discovered rows are reported because the onboarding "which of these should
never be uploaded" screen has to list precisely the projects nobody has
decided about yet. A project becomes configured only by being ruled on, so a
configured-only list is a list of decisions already made — it can never
contain the repository the contributor is being asked to exclude. Nothing
new crosses the socket: a discovered row carries the same two
daemon-derived fields (`project_id`, `project_label`) that the queue entry
for that project already carries.

`mode` is always the mode in force, not the stored value: the
`unknown-project` bucket reports `notify_only` even if a hand-edited policy
file says `auto_upload`, because the daemon refuses to act on that.

### The `outcome` verdict

`approve` accepts an optional `outcome` parameter: the contributor's own
verdict on how the session went. It is optional; the accepted values are
`worked`, `partly`, or `failed`. Absent means `TaskSuccess::Unknown`, and the
approval proceeds normally -- no verdict is not an error. Any other value is
refused with `bad_params` (`outcome-invalid`) and approves nothing. A value
supplied alongside `all` or `project_id` applies to every entry that
approval covers, not just one.

### The `correction` parameter

`approve` also accepts an optional `correction`: what the contributor wrote
about what the run got wrong, stored **as they typed it**.

- **String, optional.** Blank or whitespace-only is treated as absent, and
  the approval proceeds exactly as an uncorrected one. Anything but a string
  is refused with `bad_params` (`correction-invalid`).
- **Only with `partly` or `failed`.** A correction sent with `worked`, or
  with no `outcome` at all, is refused with `correction-needs-outcome` and
  approves nothing. You cannot correct a run you have just called
  successful; the gate is a guard as much as it is semantics.
- **Only with `entry_id`.** Sent with `all` or `project_id` it is refused
  with `correction-needs-entry-id`: a correction is written about one
  session, and applying one string to a batch would attach an explanation to
  sessions it does not describe.
- **Capped** at 2000 characters (`envelope::MAX_CORRECTION_CHARS`); longer is
  refused with `correction-too-long`. Clients should cap at the keyboard so
  the refusal lands where the person can shorten what they wrote.

A correction is folded into the envelope **before redaction runs**, not
stamped on afterwards like `outcome`. That is what puts it in front of
credential detection and what makes `consent.correction_included` describe
the envelope. Consequently an entry carrying a correction is **rebuilt and
re-pinned** by this call even if it was already previewed: the pinned
artifact was built before the contributor had written anything.

A correction is **not scrubbed** -- neither the deterministic semantic passes
nor the prose-PII filter runs over it, because redaction would destroy the
explanation it exists to give. Credential detection still runs and still
blocks: a High or Critical match refuses that entry with the skip
`reason_label` `correction-credential-detected`, approves nothing for it, and
leaves it `Pending`. Clients must surface that refusal distinctly from other
skips -- the contributor needs to remove the credential *and* rotate it --
and must never echo the correction text or the detected value.

### What `approve` reports

`approve` returns:

```json
{
  "approved": 1,
  "hold_secs": 10,
  "hold_until": "2026-08-08T12:00:10Z",
  "flagged": 1,
  "redactions": { "private_email": 2, "secret:openai_api_key": 1 },
  "skipped": [ { "entry_id": "…", "reason_label": "not-enrolled" } ],
  "excluded_ineligible": 4
}
```

**A group-level `approve` means "all eligible", never "all".** Both group
selectors -- `project_id` and `all` -- act only on entries whose
`eligibility` is `eligible`. The alternative either fails partway or succeeds
at sending exactly what the surface just finished saying could not be sent,
and no shell can close it: a per-project approve has no row to check, so the
per-row gate cannot reach it.

`excluded_ineligible` is how many pending entries the selector left out for
this reason, so a client can say what became of the rest rather than infer it
from a count smaller than the one it drew a button for. Excluded entries do
**not** appear in `skipped`: they were never selected, and `skipped` is the
account of what this call was asked to act on.

`excluded_ineligible` is **absent** when no filter ran -- an invited
contributor, or a single `entry_id`. Absent, never zero: zero would read as
"nothing was left out", which is a claim about a filter that did not run.

Render it through `tc_contribution_withheld_line`, which turns the count into
a sentence and answers the **empty string** for zero. A button reading
"Submit all (2)" above a folder showing five rows, with nothing explaining the
gap, is the same small dishonesty the rest of this surface removes. The
sentence says how many and **not why**: the reason a particular session cannot
be sent is that row's own sentence, one level in, and a summary here would
stand for up to fourteen different reasons and say nothing true about any of
them.

**One reply, one deadline.** A group `approve` does not fan out. It takes one
approval instant for the whole call, so every entry it approves shares one
hold and the single `hold_until` it reports is true of all of them. A client
must not fan a group submit out into per-entry calls and keep the first
reply's hold: an undo bar has to outlast every entry it offers to undo, and
the first reply's deadline retires Undo while something it covers is still
recoverable. Ask for the group and use the group's deadline.

An entry with no recorded eligibility renders `unknown`. `unknown` IS offered
the control and IS included by a group selector: it is a session whose
attestation could not be decided at discovery -- every Responses-API call,
which is every Codex session, because a hosted and a brokered call come back
under the same identifier shape -- and the receipt fetch at submission is the
only thing that can decide it. Nothing is claimed; the state sentence still
says it has not been worked out. The two `ineligible_*` states are the ones
that offer nothing and are excluded.

**A single `entry_id` is never filtered.** Naming one entry is an explicit act
about a session the contributor is looking at, the shell's per-row gate
already covers it, and the server decides admission either way. The daemon
reports eligibility on a row; it enforces it only where a shell cannot.

This is the whole signal a one-click submit needs: a client that never calls
`preview` can still show "Sent -- scrubbing removed 3 things, 1 flagged.
[Undo]" off this response alone, with `hold_until` driving the undo window
(see below).

- **`redactions`** sums the redaction category counts from
  `preview`'s `redactions` (same shape: category name to count) across every
  entry this call built a preview for. An entry that was already previewed
  before this call -- and so was already pinned -- contributes nothing here;
  its own `preview` response already reported those counts once, and this
  call does not rebuild it. **This means an already-previewed entry and a
  freshly-built one with nothing to redact look identical in this
  response**: both report `redactions: {}`, `flagged: 0`. A client that
  calls `preview` before `approve` should render its toast from the
  `preview` response's own counts, not assume `approve`'s zero means
  nothing was found. Counts and category names only, exactly as in
  `preview`: never the redacted text itself. Keys are real category names
  the deterministic redactor and the (optional) remote privacy filter emit
  -- e.g. `private_email`, `local_path`, `secret:openai_api_key`,
  `secret:github_token`, or a `privacy_filter:<label>` from the remote pass
  -- not the two placeholder names shown above; see
  `PreviewSummary::redactions` for the full set.
- **`flagged`** counts how many of the entries this call built a preview for
  came back with a non-empty `pii_labels_present` (the same field `preview`
  reports). It is a count of entries, not a count of labels. Same
  already-previewed caveat as `redactions` above.
- **`skipped`** lists, for every id `approve` was asked to act on that it
  did not approve, an `entry_id` plus a fixed `reason_label`:

  | `reason_label` | Meaning | Retry |
  |---|---|---|
  | `not-enrolled` | No config was readable when the build ran | Retry after enrolling |
  | `session-file-vanished` | The session file behind the entry is gone | Will not succeed for this entry |
  | `preview-failed` | The redaction pipeline itself failed | May be transient |
  | `envelope-too-large` | The built envelope exceeds the size the daemon will store, even though the build succeeded. The entry is moved to `refused` with this same string as its `reason_label`, so it stops being offered | **Never** succeeds for this entry -- do not offer retry |
  | `not-pinned` | The pin did not stick even though the build succeeded, and the entry is still `pending` (a concurrent write, or the entry vanished from the queue mid-call) | Transient -- retry is expected to work |
  | `correction-credential-detected` | The `correction` sent with this call contains something credential-shaped. Nothing was built, pinned or sent; the entry stays `pending` | Retry succeeds once the credential is out of the text. Surface this distinctly and tell the contributor to rotate it -- never echo the correction or the match |
  | `not-pending` | The entry was not `pending` when this call reached it -- already `approved` by an earlier `approve`, or dismissed, expired or superseded meanwhile | Refresh queue state rather than retry blindly; a retry alone can never succeed |

  Only `envelope-too-large` changes the entry's state; every other label
  above leaves the entry exactly where it stood. A refusal that no retry
  can ever get past is not a state a queue should keep calling `pending`,
  and leaving it there re-offered the same unapprovable card on every poll.
  The refusal binds to the entry, not to the session's path: a dismissal
  (`dismissed-by-contributor`) silences a conversation permanently, but
  this is a verdict on one envelope built under one set of consent scopes,
  so a session that grows or is rebuilt under narrower scopes is offered
  again. Note that `list_pending` returns `pending` entries only, so a
  client's own toast is the only place the contributor sees this: render
  the skip rather than dropping it.

  Nothing here is free text, a path, or trace content. **`approved` plus
  the length of `skipped` always equals the number of entries `approve` was
  asked to act on** -- for `entry_id` that is 1, for `all`/`project_id` it
  is however many matched at selection time. An id absent from both would
  be a silent loss of an approval decision; the response is built so that
  cannot happen. An `entry_id` naming no entry at all is refused before any
  of this runs -- see below.
- **An unrecognized `entry_id`** is refused the same way `preview` refuses
  the same input: `bad_params` / `unknown-entry-id`, not a `skipped` entry.
  This applies only to the single-`entry_id` form. `all` and `project_id`
  cannot produce this case: their ids are read from the queue itself at
  selection time, so every id they act on already names a real entry.
- **An unrecognized `project_id`** is refused the same way
  `set_project_mode` refuses it: `bad_params` / `project-id-unrecognized`.
  A handle the daemon cannot resolve is a client bug, and answering it
  `approved: 0` would be indistinguishable from "that project had nothing
  pending" -- a client holding a typo'd or stale id would render "Sent 0
  sessions" and never learn otherwise. A project the daemon **does** know
  with nothing pending -- everything already approved, dismissed or swept
  -- is not an error: it succeeds with `approved: 0` and an empty
  `skipped`. Recognition is by the project appearing in the daemon's policy
  or on any queue entry in any state, so a project whose entries were all
  just approved stays recognized.
- `approve` builds and pins an envelope for any entry that was not already
  previewed -- the same build `preview` runs, just triggered by `approve`
  instead. This is what makes `redactions` and `flagged` available even when
  a client skips `preview` entirely: a client that never calls `preview`
  still produces a pinned envelope the uploader accepts, and still gets the
  counts to render its toast from. An entry that was already pinned by an
  earlier `preview` is approved without rebuilding, so it is counted in
  `approved` but does not contribute to `redactions` or `flagged` (see the
  caveat above).

### The approval hold (the undo window)

`hold_until` is the instant the daemon will first consider the entry for
upload. Until then the uploader skips it, so an "Undo" offered during that
window is real: `cancel` cannot answer `not-cancelable` while the hold runs,
because nothing can have claimed the entry.

Rules an application can rely on:

- **Count down against `hold_until`, never against your own duration.** A
  client running its own five-second timer while the daemon holds for some
  other interval is the same bug as having no hold at all -- the countdown
  and the daemon disagree about when the decision stops being reversible.
  `hold_until` is read from the entry the daemon just wrote and is the exact
  value its upload pass compares against.
- **The entry uploads at `hold_until`, not after some later poll.** The
  comparison is `now < hold_until`, so waiting out exactly the reported
  instant is waiting out exactly the hold. (The upload itself still happens
  on the daemon's ordinary poll, so the send occurs at or after that
  instant, never before it.)
- **`approve: {"all": true}` holds every entry it approved**, all to the one
  reported deadline. The response's `hold_until` is true of the whole batch.
- **`hold_until` is `null`** when nothing was approved, or when
  `approval_hold_secs` is `0`. A client must then offer no undo rather than
  invent one.
- **`cancel` during the hold returns the entry to `pending`** and clears the
  approval outright: the scopes, the envelope-determining fingerprint, the
  hold itself, and the pin binding the approval to the exact bytes it
  covered. A subsequent `approve` therefore rebuilds the envelope from the
  session as it then stands -- reporting its own `redactions` and `flagged`
  counts, like any other approval of an entry with no preview behind it --
  and starts a fresh window. An undone approval leaves nothing on disk: the
  stored envelope is swept once the pin naming it is gone. `cancel:
  {"project_id": ...}` applies exactly this to every `approved` entry in
  that project in one call, so an Undo offered on a batch `approve` is one
  call with the same `project_id` argument rather than a shell deriving
  "the ids I saw pending minus the ones reported skipped" and racing the
  queue to cancel them individually.
- **A standing `auto_upload` opt-in is not held.** Those entries are
  approved in advance, are separately audited, and no client is counting
  down for them; they upload on the next pass exactly as before. Only an
  `approve` call creates a hold.

`hold_secs` is the configured window (`approval_hold_secs`, default **10
seconds**). Ten rather than five: the designed undo is five seconds, and
five is therefore the floor, not the target -- the client's countdown starts
after the approval was stamped, and the `cancel` that ends it still has to
travel back over the socket. The extra margin also absorbs clock skew
between an application counting in its own process and a daemon deciding in
another. It costs nothing that matters: uploading is unattended background
work on a 60-second poll.

The hold is a property of the entry (the approval instant it carries plus
the configured window), not of the daemon's poll timing. Tuning
`poll_interval_secs`, or the uploader getting faster, cannot shorten it.

### `pause` semantics

`until` is optional. Passed, it is parsed as an RFC 3339 timestamp:

- A timestamp in the past is rejected with `bad_params` /
  `until-in-the-past` rather than accepted and immediately treated as
  resumed -- a pause that is already a lie the instant it is acknowledged is
  worse than an explicit error.
- A malformed timestamp is rejected with `bad_params` / `until-invalid`.
- A valid future timestamp is persisted (it survives a daemon or app
  restart) and, once it lapses, the daemon clears the pause on its own and
  publishes a `status_changed` event. A client should treat `status_changed`
  as the authoritative signal that a timed pause ended, rather than running
  its own timer against the `paused_until` it was given.
- Omitting `until` pauses indefinitely, exactly as in `v1`.

### `list_audit`

```json
{
  "entries": [
    { "at": "2026-08-08T12:00:00Z", "action": "armed-auto-upload", "project_label": "myproj", "detail": null }
  ]
}
```

A `bulk-approved` entry carries the number of entries selected in `detail`,
and, for the `project_id` form, that project's derived label in
`project_label` -- `null` for `approve: {"all": true}`, which names no one
project. The label is derived from the key the daemon holds, never from the
caller's string.

A `bulk-canceled` entry is `cancel: {"project_id": ...}`'s counterpart: same
shape, `detail` carries the number of `approved` entries in that project
that were undone, and `project_label` is that project's derived label. It is
written before anything is canceled, under the same rollback-cannot-record
guarantee as `bulk-approved`, and only when the selector matched at least
one entry -- a `cancel` against a project with nothing `approved` appends
nothing. The single-`entry_id` form of `cancel` stays unaudited, the same
as the single-`entry_id` form of `approve`.

`limit` is optional, defaults to 50, and is capped at 1000 even if a larger
value is requested. Entries are returned newest first, matching
`list_history`'s convention. `action` and `detail` are always fixed labels --
never free text, a path, or a token. See "Authorization" above for what this
log is (and is not) for.

### `queue_outcome_counts`

```json
{ "reasons": { "dismissed-by-contributor": 2, "expired-without-decision": 1 } }
```

A count, by `reason_label`, across every entry currently on the queue in any
state. This method is **not** named `eligibility_reasons`, and does not
explain sessions that were never offered at all. Every `reason_label` this
method can report belongs to an entry that already exists in the queue (in
practice: dismissed, refused, expired, and superseded entries). It cannot
answer "I finished a session, why is nothing pending?" for a session the
watcher discarded *before* a queue entry was ever created -- for example a
non-eligible verdict or an `Ignore`-mode project. Do not present this
method's output as covering that case; a future method may be added for it,
and this name was deliberately chosen to leave room for that without another
contract break.

### `quiesce`

```json
{ "quiesced": true, "waited_ms": 412 }
```

Parks the upload queue and waits for anything already in flight to finish, so
an update can replace the binary without abandoning a half-uploaded trace.
Used by `trace-commons-contributor update`.

The park is in-memory and dies with the daemon process. It is deliberately not
`pause`: pause is the contributor's own persisted setting, and an update must
not rewrite it. There is no `unquiesce` verb for the same reason -- the process
that was quiesced is the process the swap replaces.

On timeout the daemon answers `busy` / `quiesce-timeout` and un-parks itself.
The caller leaves the update staged and retries later. There is no forced
path.

### `probe_routing`

```json
{ "outcome": "reachable" }
{ "outcome": "token_unreadable", "token_path": "/Users/x/.ironwire/control.token" }
{ "outcome": "unreachable", "port": 8463 }
```

Asks the IronWire proxy a contributor is about to declare whether it is
actually there, so that declaring can answer instead of failing silently.

The routing *reader* deliberately treats absence and failure as the same
state: a proxy that vanished must never cost anyone a trace, so nothing on
the submission path reports an error. That is right for reading and wrong
for declaring. Without this method a contributor can name a wrong port or an
unreachable token, see no error and no indicator, and have every trace carry
no routing data. This method runs only when a human asks; it touches no
daemon state and cannot affect a submission.

`token_dir` is resolved exactly as the reader resolves it -- the declared
directory, then the `token_path` in IronWire's discovery pointer, then
`IRONWIRE_HOME`, then `~/.ironwire` -- through the same function, so the
path reported is the file that would actually be read.

The three outcomes:

- **`reachable`** -- the proxy answered and the token was accepted.
- **`token_unreadable`** -- carries `token_path`, the absolute path that was
  tried. Covers no readable `control.token` there and a proxy that answered
  and refused the one that was. A GUI-launched daemon never sees
  `IRONWIRE_HOME`, so it reads `~/.ironwire/control.token` whatever the
  contributor set in a shell; that produces a missing file on one machine
  and a stale token on another, and naming the directory fixes both.
  `token_path` is absent only when nothing resolves at all -- no declared
  directory, no `IRONWIRE_HOME`, no discoverable home.
- **`unreachable`** -- carries `port`, the port that was tried. Also the
  answer when something answered but did not serve the ledger (a 404, a
  500): the usual cause is a number naming some other local service, so the
  port is still the actionable fact.

**No outcome ever carries the token.** It is a credential for an API that
can rewrite the contributor's agent configuration, and this answer crosses a
socket to a shell. The token *directory* is not the token, and the path is
the whole point.

Refusals are `bad_params` / `port-invalid` (missing, non-integer, `0`, or
above 65535) and `bad_params` / `token-dir-invalid` (present but not a
non-empty string -- refused rather than treated as absent, which would
answer about a path the caller did not ask about).

### `discover_routing`

```json
{ "found": true, "port": 8463, "token_path": "/Users/x/.ironwire/control.token" }
{ "found": false }
```

Reads `~/.ironwire/endpoint.json`, the pointer IronWire writes when its
daemon binds and removes on a clean stop, and reports what it says. The
point is that a contributor should not be asked for two things the machine
already knows.

Takes no parameters and performs no network I/O -- it reads one small local
file. `probe_routing` is the other half: this method reports a proxy that
published itself, the probe checks a proxy the contributor named.

`found` is a boolean and not a vocabulary of outcome names on purpose. There
is one distinction to draw -- a pointer was read, or it was not -- and every
reason it was not (IronWire not installed, not running, a version that does
not publish a pointer, a file this reader will not act on) is the same fact
to the caller and the same next step for the contributor: type the port. A
set of outcome strings would invite matching on one, and a name that is a
prefix of another is how a shell comes to treat `unreachable` as
`reachable`.

`token_path` is absent when the pointer named none, or named a relative one.
Its presence is informational -- something to show beside the port. A caller
does **not** need to pass it back: the daemon resolves the same pointer
itself whenever it opens a token, so a declaration that names no `token_dir`
finds it anyway.

**The answer never carries the token**, for the same reason `probe_routing`
does not: it is a credential for an API that can rewrite the contributor's
agent configuration, and this answer crosses a socket to a shell. The
pointer itself never contains a token either -- it names a path.

The pointer's **port is advisory**. It is offered here, to a flow where a
human confirms it, and it is deliberately not used to override a port
already declared in settings: IronWire removes the pointer on a clean stop,
so a crash leaves one behind, and a stale port silently overriding a correct
declaration would make every trace carry either nothing or another local
service's data while the settings file and the probe both still agreed on
the declared port. A missing or stale pointer costs at most one refused
connection, which is what a daemon that never ran would cost.

### The harness list

Three methods, and there is deliberately **no fourth** that plans and commits
in one call.

These edit configuration files this application does not own -- Claude Code's
`settings.json`, Codex's `config.toml`. That is acceptable only because of
three rules, which come from `ironwire_agents` and which this surface carries
end to end rather than reimplementing:

- **Never rewrite a file we cannot parse.** A contributor's own syntax error
  must not come back looking like ours.
- **Fill an empty slot; leave a full one alone.** A value already in the key is
  another destination or a deliberate choice. It is **reported, never
  overwritten**.
- **Remove only what we put there.** A disconnect leaves neighbouring keys
  alone and needs no saved original.

#### `harness_list`

```json
{
  "catalog_present": false,
  "destination_port": 8463,
  "harnesses": [
    {
      "id": "claude",
      "name": "Claude Code",
      "installed": true,
      "connected": true,
      "config_path": "/Users/x/.claude/settings.json",
      "connect_command": "ironwire connect claude",
      "family": "anthropic",
      "state": "answering",
      "last_call_at": "2026-09-07T18:04:11+00:00",
      "can_connect": false,
      "can_disconnect": true
    }
  ],
  "activity": {
    "readable": true,
    "window_hours": 24,
    "last_call_at": "2026-09-07T18:04:11+00:00",
    "families": [{ "family": "anthropic", "last_call_at": "...", "calls": 12 }]
  },
  "spend": {
    "known": true,
    "micros": 1230000
  }
}
```

`installed` and `connected` are read from the filesystem on **every** call,
never cached: a tool that rewrites its own config underneath us is a real
thing, and a list read fresh corrects itself where a cached one lies.

`config_path` is present always, not on demand. A tool nobody expected to be
configured is a question about *which file*, every time. It is `null` only
where this build could not work out where the tool keeps its config.

`connect_command` is a command string, not prose. Show it verbatim, as the
fallback for a contributor who would rather do it themselves; do not parse it
and do not paraphrase it.

`catalog_present` is a fact about **this build**, not about the machine. When
it is `false` the list is the two tools IronWire ships knowing about, and a
surface must say that the list is what this machine knows about rather than
implying only two coding tools exist. A harness that is not installed is
listed with `installed: false`, not omitted: hiding it makes the absence of a
tool indistinguishable from the app never having heard of it.

`spend` is what the calls answered **on this computer** have cost since the
most recent local midnight, in millionths of a dollar. It comes from the
proxy's own status object, which is why it is metered-only: the ledger rows
this daemon already reads price *every* exchange, including work a monthly
plan has already paid for, and summing those would produce a figure for a day
on which nothing was billed.

`known` is `false` -- and `micros` `null` -- for **every way of not knowing**:
no declared, readable proxy; a refresh that has not landed; an answer that did
not come back or would not parse; and a figure the proxy itself declined to
measure.

**`known: false` IS NOT ZERO, and a surface must not render it as one.** A day
on which nothing was spent is `known: true, micros: 0`, and it says so in
words. A day nobody could measure draws no line at all. The amount is
assembled by `tc_harness_spend_line`, whose absence convention is an
out-of-range integer -- pass a negative value for `known: false` -- so no
shell formats money, rounds it, or decides for itself what an unmeasured
figure looks like. The sentence saying what the figure leaves out is the copy
payload's `harnesses_spend_scope`, drawn beside the amount and only when the
amount is drawn.

A daemon older than the release that reports this sends no `spend` block at
all, which is one of the ways of not knowing -- not a zero.

`destination_port` is the port a connect would write into a config file -- the
hosted listener's port when it is up, else the port declared for a proxy the
contributor runs themselves. It is `null` when nothing on this machine is
answering model calls, and in that state `harness_plan` refuses a connect with
`harness-no-destination` rather than writing a guess.

#### `state`, and why there are five values and not two

`connected` proves a config file has the right value in it. It does **not**
prove a single call was ever answered. `state` is the three-valued answer the
design asks for, plus two honest unknowns:

| `state` | meaning |
|---|---|
| `not_connected` | its config does not send calls here |
| `connected_no_calls` | config is right; no call has arrived yet |
| `answering` | a call arrived, and only this tool could have made it. `last_call_at` says when |
| `activity_shared` | a call arrived in this tool's protocol family, and another connected tool speaks that family too, so it cannot be attributed to either |
| `unknown` | connected, and nothing here can say whether a call arrived -- no readable ledger, or a tool whose family this build does not know |

**Attribution is approximate and must be described as such.** The proxy's
ledger records a *facade* -- `anthropic`, `openai` -- not a tool id. Claude
Code speaks Anthropic and Codex speaks OpenAI, so today a call separates them;
two connected tools of the same family do not separate at all. `family` on a
row is what makes attribution possible, and it is `null` for a
catalog-described tool, whose facade nothing here knows.

`last_call_at` on a **row** is present only for `answering` -- the case where
the tool is nameable. The `activity` block is the same evidence with **no tool
named**: `last_call_at` there answers "did a call arrive at all", and
`families[]` answers it per protocol family. A surface that needs to say a
call arrived without naming a tool reads that block. `readable: false` means
no ledger answered, which is not evidence of no calls and must never be
rendered as "nothing has arrived yet".

Making this exact needs an upstream change -- a per-tool path chosen at connect
time, which `plan_connect(id, port, catalog)` does not expose.

#### `harness_plan`

```json
{
  "id": "claude",
  "action": "connect",
  "outcome": "changes",
  "plan_id": "6f1c...",
  "path": "/Users/x/.claude/settings.json",
  "changes": ["set env.ANTHROPIC_BASE_URL"],
  "occupied": [{ "slot": "env.ANTHROPIC_BASE_URL", "current": "https://their-proxy.example" }]
}
```

Writes nothing. `outcome` is one of:

| `outcome` | meaning |
|---|---|
| `changes` | there is an edit to make; `changes[]` describes it and `plan_id` is minted |
| `noop` | nothing to do. Say so rather than showing an empty confirmation |
| `unparseable` | the file could not be parsed, so it was **refused rather than rewritten**. Distinct from `noop`: nothing was decided and the file needs a human. Name the file -- `path` carries it |
| `not_installed` | the tool is not on this machine, so there is nothing to connect |
| `entry_unusable` | the catalog entry describing this tool did not survive validation |
| `no_config_path` | this build could not work out where the tool keeps its config |

`plan_id` is minted for `changes` and for nothing else, so "there is a plan id"
and "the outcome is committable" are one question answered once.

**`occupied` is not an outcome.** A plan can carry changes *and* occupied slots
at once -- the empty slots are filled and the full one is reported in the same
pass -- so it rides alongside whatever `outcome` says, and must be rendered
whatever `outcome` says. Each entry names the slot and shows the value already
in it. Show the value, say it was left alone, and **do not offer to take it
over**.

Refusals that are call errors rather than facts about the machine come back as
errors, not outcomes: `harness-unknown` for an id nothing knows,
`harness-no-destination` for a connect while nothing is answering model calls,
`action-invalid`, `id-required`.

Parse-failure *detail* never crosses the socket. The underlying error quotes
the offending line of the contributor's own file; only the label and the path
are reported.

#### `harness_commit`

```json
{
  "id": "claude",
  "action": "connect",
  "committed": true,
  "path": "/Users/x/.claude/settings.json",
  "backup_path": "/Users/x/.claude/settings.json.ironwire-backup"
}
```

Takes `plan_id` and **nothing else**. There is no argument here that could name
a different tool, a different action or a different file from the one
previewed, which is what makes the preview binding rather than advisory. The
plan itself never crosses the socket -- the daemon holds it between the two
calls -- so a shell cannot reconstruct one it was not given.

A plan id is **single use** and expires after ten minutes. Refusals:

| label | meaning |
|---|---|
| `harness-plan-unknown` | expired, already committed, or never minted. Plan again and show the contributor the result |
| `harness-config-changed` | the file moved between the plan and the commit -- the tool rewrote its own config while the preview was on screen. The write is refused rather than reverting whatever the tool just wrote |
| `harness-commit-failed` | the write itself failed |
| `plan-id-invalid` | not a plan id at all |

`backup_path` is where the file as it was before this edit was kept, when one
was written. Only the **first** backup of a file is kept -- it is the only copy
holding the file as it was before any of our edits -- so this is `null` on a
second edit to the same file, and on a file that did not exist before.

### `set_settings`

Takes a JSON object of settings to change. Every top-level key must be one
of `quiescence_secs`, `digest_interval_secs`, `approval_hold_secs`,
`local_notifications`, `claude_root`, `codex_root`, `claude_source`,
`codex_source`, `gemini_source`, `cline_source`, `opencode_source`, `ironwire`,
`ironwire_attested_bodies`, `private_inference`,
`private_inference_offer_seen`, `max_uploads_per_day`,
`max_bytes_per_day` --
a key this method does
not recognize is
refused outright (`bad_params` / `settings-unknown-field`), not silently
ignored, so a caller that mistypes a key gets a definite signal rather than
a daemon that quietly kept the old value. A recognized key holding the
wrong JSON type is refused the same way (`bad_params` /
`settings-invalid-value`). An object with no keys at all is refused
(`bad_params` / `no-known-setting-supplied`).

`opencode_source` takes `{"mode":"watch","path":"/chosen/export-directory"}`,
`{"mode":"off"}`, or `null`. Absent/null and Off construct no adapter, including
when loading older settings. Watch reads direct `.json` children exported with
`opencode export SESSION_ID`; it does not scan OpenCode's database. Export
version support and routing limits are recorded in
[the qualification report](superpowers/reports/2026-09-07-opencode-export-qualification.md).
This source declaration does not enable body capture or remote submission.

`approval_hold_secs` takes a non-negative integer: how long an approval is
held before the uploader will touch it, i.e. how long the contributor's undo
really lasts. Default 10; `0` disables the hold, and `approve` then reports
`hold_until: null` so a client knows to offer no undo. It is read at each
upload pass, so a change applies to approvals already sitting in the queue,
and a shortened hold can release an entry a client is still counting down
for -- treat the `hold_until` from `approve` as authoritative for the
approval it accompanied, and do not change this setting mid-countdown.

`claude_root` and `codex_root` each take a JSON string (a filesystem path)
or `null` (clear the override, falling back to the conventional per-user
location). Setting either here only takes effect from the daemon's *next*
supervisor tick onward -- the tick already scheduled or in flight when this
call returns has already read the old value. A caller that needs the
watcher to scan a non-default location from the very first tick -- most
importantly a native host embedding the daemon via the C ABI, or a test
harness that must never scan the real `~/.claude`/`~/.codex` -- cannot get
that through `set_settings`, since it only works on an already-running
daemon and the first tick fires immediately on start. That is what the C
ABI's `tc_daemon_start_with_settings` is for: it applies the same object
this method validates, but before starting the daemon, so the first tick
already observes the override. See `include/trace_commons.h`.

`ironwire_attested_bodies` takes a boolean, and it is a **second, separate
answer from `ironwire`** rather than a detail of it. `ironwire` declares a
local inference proxy whose ledger the daemon may read: metadata about model
calls -- how many, what they cost, which backend served them. This key says
that the final call's verbatim request and response bodies -- the
contributor's own prompt, in the clear -- may additionally be carried to a
configured redaction witness, which verifies an inference receipt against
them inside its enclave, strips them, and certifies what is left. Declaring
the proxy therefore never switches this on: cost attribution is not consent
to send a prompt, and a client that sets `ironwire` alone gets routing
telemetry and no bodies.

Default `false`, and a settings file written before this key existed loads
with it off. Turning it on moves the approval fingerprint, so approvals
already given are re-asked rather than honoured under the new terms. The
directory read is not configurable and is not this key: it is
`bodies/` inside whichever proxy home the control token resolved in, so the
body store and the ledger always belong to the same proxy. With no proxy
declared, with the proxy declared off, or with no witness configured,
setting this changes nothing that leaves the machine.

`private_inference` takes a boolean and asks this daemon to host the proxy.
An explicit `ironwire` declaration still controls metadata precedence; without
one, accepted hosting opt-in supplies metadata from the owned proxy, as described
under `routing`. Body collection stays separate. With hosting enabled, the daemon starts IronWire in its own process,
using `$IRONWIRE_HOME`, else `~/.ironwire`, as its home, so the `ironwire`
CLI and the existing ledger reader see the same ledger, token and pointer
they always did.

Default `false`, and a settings file written before this key existed loads
with it off. Nothing turns it on by discovery: a pointer on disk means
someone else is running IronWire, which is a different fact from the
contributor asking this daemon to. Turning it on repoints no agent -- which
tools route through IronWire stays a per-tool declaration -- and turning it
off stops only the instance this daemon started.

**What turning it on exposes.** Until this key, a running daemon bound one
thing: its own IPC socket or named pipe, guarded by the 0700 state directory
on unix and by the pipe DACL on Windows. With the switch on it also binds
IronWire's loopback listener, and that listener is not the same shape of
thing. IronWire's *control* API is token-gated -- a caller needs the token
file out of the proxy home -- but the *inference* path is not: any process
running as any user who can reach `127.0.0.1` on that port can send
inference requests through it, and they are billed and authenticated with
whatever upstream credentials the proxy home is configured with. On a
single-user desktop that is the contributor's own software; on a shared or
multi-user machine it is anyone with a local shell. Enabling it also starts
IronWire's own background work, including catalogue discovery, which makes
network calls the daemon did not previously make.

This is why the default is off and why nothing turns it on by discovery. A
client offering the switch should say plainly what it turns on, rather than
presenting it as a performance or privacy toggle alone.

What actually happened is reported separately, as `private_inference_state`
on `get_settings`, `set_settings` and `status`. It is an object,
`{"state": <label>, "port": <number or null>}`, with these labels:

| `state` | meaning | `port` |
|---|---|---|
| `off` | the switch is off, this daemon owns no proxy and nothing is bound | `null` |
| `stopping` | retained shutdown is awaiting outstanding startup, calls or cleanup; the requested switch may already be off | last owned port, or `null` before binding |
| `running` | this daemon's proxy is serving and has a backend registered | the bound port |
| `running_no_backends` | this daemon's proxy is serving but no backend is configured, so nothing will route through it | the bound port |
| `running_elsewhere` | a loopback discovery pointer responds, or the exclusive home lock is held; nothing was bound or stopped, and readiness is not established | the published port, or requested port when the lock owner has not published one |
| `port_in_use` | something that is not this daemon's proxy holds the port | `null` |
| `start_failed` | the proxy refused to start for any other reason | `null` |
| `crashed` | startup, serving, or cleanup failed; release of owned resources may be unconfirmed | `null` |

Turning hosting off persists the request before stopping the owned proxy. The
reply may report `stopping` while requests drain; it does not mean the listener,
pointer, or home lock has been released. A new on request waits for that cleanup
before another listener can start. Daemon termination prevents any later restart
and waits up to five seconds for cleanup, including waiting for a startup already
in progress. On expiry the retained cleanup continues while the runtime lives;
process exit or runtime destruction can interrupt remaining streams. Closing or
dropping the embedded daemon requests cleanup without blocking synchronously.
Drop-based cleanup requires unwinding; a `panic=abort` build terminates the
process instead and cannot finish in-flight requests.

Existing-instance discovery reads at most 64 KiB from an opened regular pointer
file and probes only the fixed IPv4 loopback health path. Accepted hosts are
`127.0.0.1` and `localhost`; an IPv6-only pointer is not discovered through an
unrelated IPv4 port. URL-shape restrictions are defense in depth because the
request URL is constructed from the validated port, not used verbatim. On supported Unix targets,
the opened object must match the checked device/inode and effective-user owner,
remain unwritable by others, and is opened with no-follow/nonblocking flags so a
replacement symlink or FIFO cannot bypass the check or block the open. Windows
checks regular-file/reparse shape on the opened handle; this is not a DACL or
Unix ownership guarantee. Advisory discovery fails closed on Unix targets other
than shipped macOS and Linux x86_64/aarch64. The probe sends no token,
ignores environment proxies, and never follows redirects. A successful health
response is advisory: it conservatively avoids takeover but does not authenticate
the endpoint. The exclusive home lock remains authoritative when starting.

`running_no_backends` is deliberately not `running`: the proxy answers its
health endpoint and no inference can pass through it, so a client that
rendered it as running would show a green light over a proxy that cannot
work. `crashed` is sticky until the switch is turned off and on again,
rather than restarting every poll tick, so a proxy that cannot stay up is
visible instead of flickering. If startup or shutdown lost its completion
signal, Off does not claim cleanup succeeded. A newly accepted off/on cycle may
retry through IronWire's exclusive home lock; only a successful start clears
that uncertainty. If the prior owner still holds the lock, the failure remains
visible and no second proxy is started.

The shells distinguish an absent or empty status from a nonempty state label
this build does not recognize. The former says the daemon does not report
model-call status (including older daemons); the latter says the state is
unavailable. Neither proves `off`. `stopping` uses the Held tone until the
retained-shutdown producer confirms cleanup; a port alone is metadata, not
proof that calls can be answered.

The companion C ABI copy payload (`tc_private_inference_copy`, not a daemon
settings key) supplies the fixed string fields for the destination, the proxy
state, the harness rows and the credential row:

- `destination`, `subtitle`;
- `offer_title`, `offer_what`, `offer_exposure`, `offer_no_repoint`,
  `offer_accept`, `offer_decline`, `offer_asked_once`;
- `settings_title`, `settings_toggle`, `settings_applies_at_once`;
- `state_off`, `state_unreported`, `state_unknown`, `state_stopping`,
  `state_running`, `state_running_no_backends`,
  `state_running_answered_elsewhere`, `state_running_destination_unknown`,
  `state_running_elsewhere`,
  `state_port_in_use`, `state_start_failed`, `state_crashed`;
- `quit_also_stops`, `write_unconfirmed`;
- `settings_moved`, `tray_turn_off`, `tray_open_to_turn_on`;
- `harnesses_title`, `harnesses_what`, `harnesses_spend_scope`,
  `harnesses_none_found`;
- `harness_not_connected`, `harness_connected_nothing_seen`,
  `harness_answering`;
- `harness_connect`, `harness_disconnect`;
- `harness_preview_title`, `harness_preview_confirm`,
  `harness_preview_cancel`;
- `harness_slot_taken`, `harness_needs_restart`,
  `harness_unreadable_config`;
- `harness_not_installed`;
- `harness_plan_nothing_to_change`, `harness_plan_entry_unusable`,
  `harness_plan_no_config_path`;
- `credential_title`, `credential_what`, `credential_cost`;
- `credential_obtain`, `credential_cancel`, `credential_forget`,
  `credential_forget_explains`;
- `credential_absent`, `credential_obtaining`, `credential_failed`,
  `credential_cancelled`, `credential_present`, `credential_unknown`,
  `credential_unreported`.

**Those are the fields for those rows, and not the whole payload.** The
payload also carries a sentence for every state of every per-state family --
the queue entry's `eligibility_*` and `attestation_*` sentences among them --
and each family is written down in the section for the field it describes
rather than repeated here. It grows a set whenever a family is added, and
the list above is not extended when that happens. So do not read that list as
an inventory of the payload: a key's absence from it is not evidence the key
does not exist. The place that settles the question is `private_inference_copy`
in `trace-commons-contributor`, whose `every_sentence_arrives_finished` pins
the payload's field count and is what a shell's decoder is checked against.
This document deliberately does not repeat that number: a count copied into
prose goes stale in silence, and the test does not.

### Contribution eligibility

Queue entries carry two additive fields. They appear on **every** surface that
hands a client an entry object -- `list_pending`, the `snapshot` event, and
the `entry` object both `preview` responses carry (the async-dispatch one and
the built card) -- and on no other, because `entry_value` is the only thing
that serialises a queue entry and those are all of its callers. `approve` and
the `preview_ready` event do not carry an entry object at all; they carry an
`entry_id`. A client MUST NOT reconstruct eligibility from an entry it cached
from some other path.

| Field | Meaning |
|---|---|
| `eligibility` | `eligible` \| `ineligible_permanent` \| `ineligible_configuration` \| `unknown` |
| `eligibility_reason` | a stable label naming why, or absent |

**`eligibility` is ABSENT -- not `unknown`, not null -- whenever the
contributor is admitted on an invite** rather than on evidence, i.e. whenever
`admission_evidence_required` is false or could not be read. An invited
contributor has no eligibility question: everything in their queue is
contributable, which is why this whole surface stayed invisible for so long.
A field answering a question they do not have would put three shells to work
rendering a caveat on work that carries none. A client MUST test for the key,
never read a missing key as a state.

Show every session. Offer only the eligible ones. Hiding a contributor's own
work is its own dishonesty and makes the app look as though it had not
noticed files the contributor knows it can see. An ineligible row is present,
not offered, and carries its reason.

| `eligibility` | Means | Sentence | Control a shell may offer |
|---|---|---|---|
| `eligible` | the cheap checks pass and the marked call is here | `eligibility_eligible` | contribute |
| `ineligible_permanent` | nothing the contributor changes will alter this | `eligibility_ineligible_permanent` | **none** |
| `ineligible_configuration` | this session stays ineligible; a setting decides future ones | `eligibility_ineligible_configuration` | **none** |
| `unknown` | not evaluated | `eligibility_unknown` | **none** |
| anything else | the state could not be read | `eligibility_unknown` | **none** |

The sentence, the tone and the control come from the shared Rust tables --
`tc_contribution_eligibility_line`, `tc_contribution_eligibility_tone` and
`tc_contribution_eligibility_control` -- never from shell-authored branching
on a variant name, and a shell must not recover any of the three by reading
another. `TC_CONTRIBUTION_CONTROL_NONE` (50) and
`TC_CONTRIBUTION_CONTROL_CONTRIBUTE` (51) are the control values.

**An unrecognised state must not borrow an ineligibility sentence.** A state
this build cannot read is not evidence about a contributor's session, and
saying it is would stop them offering work that is fine. Every shell carries
a test for this.

A shell does not have to apply this rule to a group control itself. Ask for
the project and the daemon returns the honest subset; `list_projects` carries
`contributable_count` so the button can name it before the press. See "What
`approve` reports".

`eligible` is a well-founded expectation and not a guarantee. The cheap
checks -- the ones a list may run -- are answered here; the expensive ones,
which need every captured body read back and hashed, still run at submit. The
server decides admission either way, and if this answer and the server's
decision disagree, **the server is right**. When a submission is refused for
an admission reason the daemon writes the refusal back into the row, so a row
that was `eligible` stops saying so. A list that changes while it is being
read is the cost of that, and it is also just what happened.

`eligibility_reason` is absent on an `eligible` entry -- there is nothing to
explain -- and is one of these otherwise. Render each through
`tc_contribution_eligibility_reason_line`, which answers the **empty string**
for a label this build does not know; render nothing for an empty string
rather than guessing.

The two unknown-handling rules are deliberately different, and the difference
is not an inconsistency. An unrecognised **state** degrades to a sentence
because the row still has to say something -- it is on screen, a contributor
is reading it, and silence there would leave them to infer a state from an
empty space. An unrecognised **reason** has nothing honest to say: the state
sentence beside it has already carried the fact, and a sentence invented for a
label this build does not know would add a detail nobody established. Silence
beats a guess exactly where something true has already been said.

| `eligibility_reason` | Sentence | Usually seen with |
|---|---|---|
| `no_inference_call` | `eligibility_reason_no_call` | `ineligible_permanent` |
| `capture_off` | `eligibility_reason_capture_off` | `ineligible_configuration` |
| `digest_absent` | `eligibility_reason_digest_absent` | `ineligible_permanent` |
| `upstream_id_absent` | `eligibility_reason_upstream_id_absent` | `ineligible_permanent` |
| `digest_mismatch` | `eligibility_reason_digest_mismatch` | `ineligible_permanent` |
| `reference_malformed` | `eligibility_reason_reference_malformed` | `ineligible_permanent` |
| `bodies_unreadable` | `eligibility_reason_bodies_unreadable` | `ineligible_permanent` |
| `body_not_utf8` | `eligibility_reason_body_not_utf8` | `ineligible_permanent` |
| `body_too_large` | `eligibility_reason_body_too_large` | `ineligible_permanent` |
| `evidence_capture_off` | `eligibility_reason_evidence_capture_off` | `ineligible_configuration` |
| `marker_absent` | `eligibility_reason_marker_absent` | `ineligible_permanent` |
| `request_malformed` | `eligibility_reason_request_malformed` | `ineligible_permanent` |
| `receipt_unavailable` | `eligibility_reason_receipt_unavailable` | `unknown` |
| `receipt_not_issued` | `eligibility_reason_receipt_not_issued` | `ineligible_permanent` |

Only `ineligible_configuration` names a setting, and it is the only state
painted `TC_PRIVATE_INFERENCE_TONE_ATTENTION`. `no_inference_call` has no
actionable answer for the session the row is about, and advice about the
*next* session is guidance rather than status -- rows stay about their own
session. A permanent ineligibility is `_NEUTRAL` and never `_REFUSED`:
nothing was refused and nothing went wrong.

Both fields are additive; the schema version stays
`trace_commons.daemon.v1_1`, and a client that ignores them behaves exactly
as before.

The seventeen sentences named above are fields of the `private_inference_copy`
payload (`tc_private_inference_copy`), which now carries **97** fields.

### The attestation mark

`eligibility` above answers *may I send this?* -- a permission question, and
one an invited contributor does not have. Underneath it is a second question
every contributor has, all of the time:

> Does this session carry a checkable copy of the model call that produced it?

That is a fact about the trace rather than about anyone's permission, and it
is about to stop being provenance metadata: the credit scoring function is
expected to weight attestations. A contributor who cannot see which of their
sessions carry one cannot act on it, and an app that showed the same
classification to one class of user under a different name would be
withholding a fact that affects what their work is worth.

| Field | Values |
|---|---|
| `attestation` | `attested` \| `unattested_permanent` \| `unattested_configuration` \| `unknown` |
| `attestation_reason` | a stable label naming why not, or absent |

**`attestation` is ALWAYS PRESENT, on every entry, for every contributor.**
The exact opposite of the `eligibility` rule above, and deliberately: there
is no contributor for whom the question does not apply, so the only thing an
absent field could mean is a build too old to answer it. An entry written
before the field existed reports `unknown`, never an unattested mark.

| `attestation` | Means | Sentence | Tone |
|---|---|---|---|
| `attested` | the session carries a checkable copy of its last model call | `attestation_attested` | `_CLEAR` |
| `unattested_permanent` | it does not, and nothing the contributor changes will add one | `attestation_unattested_permanent` | `_NEUTRAL` |
| `unattested_configuration` | it does not; a setting decides whether future ones will | `attestation_unattested_configuration` | `_ATTENTION` |
| `unknown` | not worked out | `attestation_unknown` | `_NEUTRAL` |
| anything else | the mark could not be read | `attestation_unknown` | `_NEUTRAL` |

Sentence and tone come from `tc_contribution_attestation_line` and
`tc_contribution_attestation_tone` -- never from shell-authored branching on
the label.

### The certificate a queue entry holds

| Field | Values |
|---|---|
| `holds_certificate` | `true` \| `false` |

True when a witness certificate is held for the bytes this entry was pinned
to. Both witness routes produce one: `POST /v1/witness` returns a
certificate, and `POST /v1/witness/admission` returns a certificate AND
admission evidence. The daemon stores either as a single
`trace_commons.witness_review.v1` artifact under a single pin, so "did the
contributor complete step 1 or step 2" is not two questions.

**`holds_certificate` is ALWAYS PRESENT, on every entry, for every
contributor** -- the `attestation` rule, not the `eligibility` one, and for
a reason of its own. This is one fact with two readings:

| Contributor | Reads `true` as |
|---|---|
| without an invite | this session is a candidate for submission |
| with an invite | this session is cryptographically attested |

The fact does not differ between them; only the wording does. The shell
picks the wording from the invite status it already holds for the
eligibility surface, and MUST NOT ask the daemon a second question to get
it. Emitting the field only under the signup flag would put the second
reading out of reach of exactly the contributors it is written for.

**This is not `attestation`, and the two must not be conflated.**
`attestation` answers whether the session carries a checkable copy of the
model call that produced it. `holds_certificate` answers whether a witness
certificate is held over the reviewed bytes. A session can have either
without the other, and *holds a certificate*, *is attestable* and *was
attested* are three different facts. A shell deciding what to put in a
certificate-held list MUST read `holds_certificate` and never the mark.

Derived from the pin rather than stored, so it cannot drift from it: the
artifact is written and the pin recorded under one queue lock. An entry
re-offered because its bytes moved loses the pin and therefore the claim --
the certificate covered the old bytes.

**There is no control accessor, and that is the contract.** The mark
describes the trace; it offers nothing to press. A shell that drew a button
from it would be inventing an action out of a description. Whether a row may
be sent is `eligibility`'s question and `tc_contribution_eligibility_control`
answers it.

**The positive case is the one that matters here**, unlike `eligibility`,
whose surface only ever spoke up to explain a refusal. A session that IS
attested says so. A surface that only names what is missing teaches a
contributor that the mark means bad news.

**An unrecognised mark must not read as "no copy".** A mark this build
cannot read is not evidence about a contributor's session, and telling them
an attested session carries nothing is the one wrong answer this table can
give.

**A permanently unattested session is `_NEUTRAL` and never `_REFUSED`.**
Nothing was refused and nothing went wrong: most of a contributor's history
was recorded before anything was keeping copies.

`attestation_reason` takes the **same fourteen labels** as
`eligibility_reason` -- a reason names a fact about the session, not an answer
to either question -- and is rendered through
`tc_contribution_attestation_reason_line`, which answers the **empty string**
for an unfamiliar or absent label. It is absent on an `attested` entry.

**`unknown` may arrive with or without a reason, and a shell MUST branch on
the key rather than on the mark.** Two different things produce that mark. A
row the daemon never evaluated has no reason -- nobody worked anything out.
A row whose send was turned away because the receipt could not be fetched is
`unknown` **with** `receipt_unavailable`, and that reason is the only thing
telling the contributor it may work later. Every other mark is
shape-predictable: `attested` never carries a reason, and the two unattested
marks always do.

**The sentences are NOT the same, and a shell must not substitute one call
for the other.** Five of the eligibility sentences say the session cannot be
sent, which is true for an evidence-admitted contributor and false for an
invited one, whose session sends perfectly well and merely arrives without a
copy of its call.

| `attestation_reason` | Sentence | Usually seen with |
|---|---|---|
| `no_inference_call` | `attestation_reason_no_call` | `unattested_permanent` |
| `capture_off` | `attestation_reason_capture_off` | `unattested_configuration` |
| `digest_absent` | `attestation_reason_digest_absent` | `unattested_permanent` |
| `upstream_id_absent` | `attestation_reason_upstream_id_absent` | `unattested_permanent` |
| `digest_mismatch` | `attestation_reason_digest_mismatch` | `unattested_permanent` |
| `reference_malformed` | `attestation_reason_reference_malformed` | `unattested_permanent` |
| `bodies_unreadable` | `attestation_reason_bodies_unreadable` | `unattested_permanent` |
| `body_not_utf8` | `attestation_reason_body_not_utf8` | `unattested_permanent` |
| `body_too_large` | `attestation_reason_body_too_large` | `unattested_permanent` |
| `evidence_capture_off` | `attestation_reason_evidence_capture_off` | `unattested_configuration` |
| `marker_absent` | `attestation_reason_marker_absent` | `unattested_permanent` |
| `request_malformed` | `attestation_reason_request_malformed` | `unattested_permanent` |
| `receipt_unavailable` | `attestation_reason_receipt_unavailable` | `unknown` |
| `receipt_not_issued` | `attestation_reason_receipt_not_issued` | `unattested_permanent` |

A submission turned away for an admission reason writes back here exactly as
it does to `eligibility`: a row still claiming its session carries proof,
after a send of that session was refused for want of that proof, is the
defect this surface removes reproduced one layer up.

Both fields are additive; the schema version stays
`trace_commons.daemon.v1_1`, and a client that ignores them behaves exactly
as before.

### The attested-inference record

The attestation mark above is computed at discovery, before any receipt is
fetched and before any witness is contacted. What happened *after* that --
whether the witness that certified this entry's review was actually handed a
receipt with the bodies -- was recorded nowhere: the certificate carries no
such field, the receipt is discarded after the witness call, and ingest
stores nothing about it. This field is the daemon's own record of that fact.

| Field | Shape |
|---|---|
| `attested_inference` | `{"state": "certified"}` or `{"state": "uncertified", "reason": <label>}` |

| `state` | Means |
|---|---|
| `certified` | a receipt was offered with the bodies and the witness issued a certificate over them |
| `uncertified` | the review was certified without attested inference; `reason` says why |

| `reason` | Means |
|---|---|
| `no_attested_call` | the session joined no inference hop, or the hop recorded no verbatim bodies |
| `bodies_withheld` | the session carried an attested call and the review was requested without inference bodies |
| `receipt_unavailable` | the session carried an attested call and no receipt could be obtained for it; the trace was certified without it |

**`attested_inference` is PRESENT only while a witnessed review is pinned to
the entry**, and then it is exactly what the stored review records. It is
ABSENT -- not `unknown`, not null -- for an entry with no witnessed review, an
entry whose review predates the record, and an entry whose pin is a local
preview. Absent means *not known*, and a shell MUST render it as nothing: an
older review may have carried a verified receipt, and nothing says either
way. Flattening absence into `uncertified` tells a contributor their work is
worth less than it may be; flattening it into `certified` is the lie this
field exists to stop.

**Written from the fact, not the intention.** `certified` is set only when a
receipt was among what the witness was handed *and* the witness answered
with a certificate. A session whose queue row says `attestation: attested`
and whose receipt fetch then fails is `uncertified` with
`receipt_unavailable` -- the mark describes what the session carries, this
record describes what the witness was given. The two disagreeing is the
case that matters, not a defect.

What it does not say: whether the receipt's *signer* was one the witness
pins. That is the witness's configuration, invisible to the client; a
certificate from a pinning witness and one from a dormant witness read the
same here.

The record lives and dies with the pin: an undone approval, a released
preview or a re-preview without a witness clears it, so a row can never
inherit an answer from a review that is no longer the one it would send.

### The credential state

`near_ai_credential_status` answers ONE label, and it is the only thing a
shell branches on:

| `state` | Means | Sentence | Action a shell may offer |
|---|---|---|---|
| `absent` | no key is kept on this machine | `credential_absent` | obtain |
| `obtaining` | a ceremony is in flight here | `credential_obtaining` | cancel |
| `failed` | the last attempt ended without a key | `credential_failed` | obtain |
| `cancelled` | the last attempt was stopped by the contributor | `credential_cancelled` | obtain |
| `present` | a key is kept on this machine | `credential_present` | forget |
| absent/empty field | this daemon does not answer the question | `credential_unreported` | **none** |
| anything else | the state could not be read | `credential_unknown` | **none** |

The sentence, the tone and the action are chosen by the shared Rust tables --
`tc_near_ai_credential_state_line`, `tc_near_ai_credential_state_tone` and
`tc_near_ai_credential_action` -- never by shell-authored branching, and a
shell must not recover any of the three by reading another.

**Neither unread case may render as `absent`.** "No key is kept here" in
front of somebody who has one invites a second sign-in, at a third party,
that their own account will list and nothing on this screen will ever mention
again. That is why the unread states also answer *no action*: the action in
question mints the second key.

The precedence is the daemon's, not a shell's. A ceremony in flight outranks
a key already stored, because somebody with a browser tab open is waiting on
that and not on what they had before; a stored key outranks the ending of an
older attempt; `absent` is the answer only when there is nothing else to say.

`attempt_id` and `attempt_status` are echoed only to a caller that already
named the current attempt. A caller that names none, or names a stale one,
still gets `state` -- the resting state is not a secret -- but learns nothing
that would let it cancel somebody else's ceremony, and the browser URL is
never re-served.

`credential_cost` is the sentence that has to sit in front of the obtain
action, and it is the counterpart of `offer_exposure`: getting a key opens a
browser, signs the contributor in to a company that is not this app, and
mints a key this app then keeps. `credential_forget_explains` is its
counterpart at the other end -- forgetting is LOCAL, the key stays valid at
the service until the contributor removes it there, and this app cannot do it
for them, which is why `near_ai_credential_forget` answers `revoked: false`
rather than leaving "removed" to be read as "revoked".

No sentence on this surface renders a key, a key prefix, an id or an account
name, and none of them carries a hole a shell could fill with one.

The three per-harness states are not two. `harness_connected_nothing_seen`
says a tool's own settings send its calls here; `harness_answering` says a
call actually arrived, and it is the only one of the three that means the
tool works. `harness_slot_taken` reports a slot left exactly as the
contributor had it and must never be rendered as a fault or paired with an
action that takes it over.

`harness_not_installed` is what a row whose tool is not on this computer
shows INSTEAD of any state sentence. Such a tool is listed and disabled
rather than hidden -- a tool left out cannot be told apart from one the app
was never taught about -- and it must not also carry
`harness_not_connected`, which claims a tool's own settings still send its
calls wherever they went before.

`harnesses_spend_scope` is the sentence that has to accompany the amount
`tc_harness_spend_line` assembles: only calls answered on **this** computer
are in the figure, and work a monthly plan has already paid for is not. A
contributor signed in to the same account on a second machine, or in a
browser, has spent more than the figure says, and the number without this
sentence is a lie of omission. It is drawn beside the amount and only when
the amount is drawn -- a scope line on its own qualifies a figure that is not
on screen. Neither this sentence nor the amount may say anything about a
balance: the amount is what went out, and nothing here is an account total.

The four `harness_plan_*` sentences plus `harness_unreadable_config` are the
answers of `tc_harness_outcome_line`, one per non-committable `harness_plan`
outcome. `changes` answers the empty string, because a plan with changes in
it shows them. Every other outcome writes nothing, and without a sentence its
preview is a title, a path and a way out.

State sentences, outcome sentences and tones are chosen by the shared Rust
table rather than by shell-authored branching. Copy-field inventory parity is checked separately
from successful decoding of required fields.

The shared `tc_private_inference_write_confirmed` decision accepts optional
requested-on, echoed-offer-seen, and echoed-on booleans (`-1` absent, `0` false,
`1` true). Decline requests no switch and requires only a true marker echo;
a settings switch requires both the marker and a present matching switch.
Invalid inputs refuse confirmation. Shells keep their previous confirmed
state and display `write_unconfirmed` on failures, including ambiguous
transport failures that may have followed persistence. A daemon predating
`private_inference_offer_seen` cannot acknowledge an answer: the offer remains
until a supporting daemon confirms it. Missing values are not explicit off.
The GTK switch starts disabled with the shared unavailable explanation until
settings arrive. macOS serializes offer and settings writes through one
pending guard; its toggle stays bound to the last confirmed settings.

`private_inference_offer_seen` takes a boolean, and it is **not a fourth
answer**: it records that the question was put, never what the answer was.
A client that offers the switch on first start writes `true` here on
*either* button, so declining is remembered exactly as accepting is and the
contributor is not asked again on the next launch. Nothing in the daemon
reads it except a client deciding whether to ask; setting it starts nothing,
stops nothing, and changes no other value.

It lives here rather than in each application's own state file because the
fact belongs to the machine and not to a window. On Linux the daemon
outlives the GTK shell and a second shell would otherwise re-ask; on macOS
and Windows the app is the daemon, and this file is the thing that survives
a reinstall of neither more nor less than the settings do.

Default `false`, and a settings file written before this key existed loads
with it false. That default is what makes an offer appear on the first start
after an upgrade as well as on a fresh install: an installed build's
settings file has no such key, so the first build that knows the key reads
it as unanswered and asks once.

`max_uploads_per_day` and `max_bytes_per_day` each take a positive integer,
validated against a fixed ceiling (1,000 uploads; 5 GiB) rather than
accepted as an open field. The cap exists to bound a runaway client -- an
app that decided to upload everything should not be able to -- so making it
freely settable to any value would give up exactly the protection it was
added for. A value below the built-in default (50 uploads; 200 MiB) is
accepted with no floor beyond non-zero: a contributor throttling their own
uploads is legitimate and is not what the ceiling guards against. Zero is
refused (`bad_params` / `settings-invalid-value`) rather than treated as
"stop uploading" -- that state already exists and is spelled `pause`, which
is visibly temporary in a way a cap of zero would not be. A value above
either ceiling is refused the same way. Like the other numeric knobs, the
new setting is read at each upload pass, so a change reaches an
already-running daemon -- including one that reached its old cap with
approved traces still waiting -- without a restart, and it is written to
the persisted settings file in the same call, so the raised value survives
one.

### `history_rollup`

```json
{
  "week":     {"submitted": 0, "accepted": 0, "quarantined": 0, "other": 0},
  "month":    {"submitted": 0, "accepted": 0, "quarantined": 0, "other": 0},
  "all_time": {"submitted": 0, "accepted": 0, "quarantined": 0, "other": 0},
  "credit_pending": 0.0,
  "credit_final": 0.0,
  "quarantined": 0,
  "last_refreshed_at": null
}
```

`quarantined` is reported separately and must be rendered separately.
Quarantine means **held for operator privacy review**, not rejected. A
contributor who sees it grouped with failures reads it as rejection.

`last_refreshed_at` is `null` when history has never been refreshed from the
server; show staleness rather than presenting a stale cache as current.

The `submitted` bucket means **uploaded, no verdict back yet**. It is a real
and ordinary state, and it now appears promptly: an upload pass writes its
receipts into the history cache immediately, without calling the server, so
a trace that has just gone out is counted as `submitted` within seconds
rather than at the next `history_poll_secs` boundary. Those rows carry
`last_refreshed_at: null`, because nothing has been read back for them yet.

The daemon then asks the server for verdicts about ninety seconds after an
upload pass, rather than waiting out the full `history_poll_secs` interval
(1800 by default). A burst of uploads produces one such read-back, not one
per upload, and no two read-backs are ever less than two minutes apart. A
verdict, a quarantine, or a withdrawal moves the row out of `submitted` on
the next refresh; the count can go down as well as up.

Render `submitted` in the contributor's words — sent, waiting to hear back —
and never as an error.

The answer additionally carries a `community` object when, and only when,
this contributor has a standing on the public roster:

```json
{
  "community": {
    "rank": 14,
    "novelty_credit": 1240.0,
    "accepted_in_window": 12,
    "accept_rate": 0.75,
    "window_label": "7d",
    "public_since": "2026-07-09T10:30:00Z",
    "snapshot_at": "2026-08-17T12:00:00Z",
    "analytics_withheld": true
  }
}
```

This is additive: every field above is new, no existing field of
`history_rollup` changed shape, and a client that ignores `community`
behaves exactly as it did before. The protocol version is unchanged.

The figures are this contributor's own row on the roster the server serves
publicly at `GET /v1/community/leaderboard`, reduced to what a client draws.
The names differ from the server's, deliberately: `novelty_credit` is the
server's `score` (named for the snapshot's metric, which is
`novelty_credit`); `accepted_in_window` is its `accepted_count`, whose window
is `window_label`; `snapshot_at` is its `computed_at`. `accept_rate` is a
decimal in `0..=1`, not a percentage. `analytics_withheld` says whether the
corpus-wide aggregates were withheld -- when it is `true`, say so in words
rather than drawing an empty chart.

**Absent means no standing, and absent is not `null`.** The object is omitted
entirely -- rather than sent with null or zeroed fields -- in every one of
these cases, which a client renders identically by drawing no community
section at all:

- The contributor has published no handle.
- No snapshot is being served. The server answers `503` when the snapshot is
  withheld or has not been computed yet; that is a normal state of the
  community surface, not an error, and it must not surface to a contributor
  as one.
- The handle is not on the roster.
- `accepted_in_window` cannot be represented -- the snapshot reported a
  negative or out-of-range count. It is a bare number on the wire with no
  absent form, so rather than being rounded into a definite "0 accepted" it
  withholds the whole object.

`rank` and `accept_rate` may themselves be `null` inside an otherwise present
object; render a dash rather than `#0` or `0%`.

The daemon fetches the roster on its own interval (15 minutes, matching the
server's snapshot cadence and its published 15-minute withdrawal bound) and
`history_rollup` serves that cache. **The handler makes no network call**, and
there is no method to force a fetch. A cached standing older than twice the
withdrawal bound is dropped rather than served, so a daemon whose poll has
been failing goes quiet instead of publishing a stale public figure.

No `profile_url` is sent: nothing on the contributor's machine is configured
with the community site's address. A client draws no link rather than a
guessed one.

### `consent_options`

```json
{
  "scopes": [
    { "name": "debugging_evaluation", "description": "…", "always_on": true, "grants_data_use": true },
    { "name": "public_attribution", "description": "…", "always_on": false, "grants_data_use": false }
  ]
}
```

`always_on` is `true` for exactly one scope, the floor scope every
contributor implicitly grants. `grants_data_use` is `false` for scopes (such
as `public_attribution`) that carry no data-use grant of their own -- do not
present those beside real data-use scopes with equal visual weight.

### `set_consent_scopes`

Takes an optional `scopes` array of wire-name strings (omitted means the
floor scope only) and replaces the enrolled config's consent scopes.
Requires an existing enrollment (`unavailable` / `not-logged-in` otherwise).
Appends a `consent-scopes-changed` audit entry.

### `enroll`

Performs real network I/O against the issuer -- registering this device,
exactly as the CLI's `login` does for a terminal caller. Takes `grant` xor
`invite` (both present is `bad_params` / `grant-and-invite-mutually-exclusive`)
plus the optional `scopes` array described above. Does **not** accept an
`allowed_hosts` override from the caller (unlike the CLI's `--allowed-hosts`
flag); a caller-supplied allowlist can degrade to permissive, and a socket
caller is not trusted with that. On success, the underlying error is never
echoed back over the socket -- it can carry an issuer response body or a URL
-- so failures are reported only as `unavailable` / `enroll-failed`.

### `acknowledge_near_ai_notice`

Records that the NEAR AI first-use privacy disclosure was shown to the
contributor in a UI, and clears the `near-ai-notice-not-acknowledged` health
label so the daemon will start using that filter. This is the only way an
app-only contributor (one who never touches the CLI, which shows the same
notice on stdout) can get past that gate. Because this asserts, on the
caller's unverified word, that a disclosure was actually shown to someone,
it is audited (`near-ai-notice-acknowledged`) -- an application must not
call it without actually having shown the notice text first.

### `near_ai_balance`

What the contributor's NEAR AI account has left, read with the session the
credential ceremony retained. A `state` and a set of numbers:

```json
{
  "state": "known",
  "currency": "USD",
  "scale": 9,
  "remaining_nanos": 8500000000,
  "spend_limit_nanos": 10000000000,
  "total_spent_nanos": 1500000000,
  "total_requests": 12,
  "total_tokens": 3456,
  "observed_at": "2026-09-08T09:17:15Z"
}
```

`state` is one of:

| `state` | What it means | What a client should say |
|---|---|---|
| `known` | The service answered. | The figures, with their age. |
| `no_session` | Nothing is stored. The account was never connected, or was forgotten. | Offer the credential ceremony. |
| `session_expired` | The stored session was refused. | Offer the ceremony again. It does **not** require forgetting first: the ceremony overwrites both records. |
| `no_organization` | The account has no active organization, which is a real state -- the service creates one on signup **best effort**. | Point at the contributor's NEAR AI account page. |
| `unavailable` | The service did not answer, or answered something this daemon cannot read. | Say nothing about the balance. |

Three rules bind a client here, and they are the reason the shape is this
shape rather than a bare number:

- **Every numeric key is present and `null` in every state but `known`.** An
  absent key would be ambiguous between "this daemon is too old to know" and
  "this daemon knows it does not know"; a `null` is only ever the second.
  **A `null` must never be rendered as `0`.** Zero is a real balance and
  means the contributor is out of credit.
- **`remaining_nanos` and `spend_limit_nanos` can be `null` even when `state`
  is `known`.** They are nullable in the service's own schema: an
  organization with no credit ceiling configured genuinely has no remaining
  balance to report. Same rule -- not zero.
- **`observed_at` is when this daemon asked**, not the service's own
  `updated_at`. It is there so a client can say how old the figure is.
  A stale balance presented as current is worse than no balance; the daemon
  will not serve a cached figure older than a minute, and returns a failure
  state rather than the last good number when a read fails.

The units are the service's own: fixed scale 9 (nano-dollars) and USD,
carried on the wire rather than assumed, and not rounded by the daemon.

The call performs network I/O -- it may exchange the stored refresh token
for an access token before making two management reads -- so it is on the
async dispatch path and a client should not call it on a paint loop.

#### A shell does not write these sentences, or this arithmetic

Every word and every figure on this row is assembled in
`trace-commons-contributor`'s `private_inference_copy` and reachable across
the C ABI. A shell reads `state` and the numbers off this wire and passes
them straight back; it does not branch on the state string to pick a
sentence, and it does not divide by `10^scale` itself.

| Call | What it takes | What it gives |
|---|---|---|
| `tc_near_ai_balance_state_line` | `state` | The sentence. `known` gives `""`; a state this build cannot read gets its own sentence and borrows nobody's. |
| `tc_near_ai_balance_state_tone` | `state` | `TC_PRIVATE_INFERENCE_TONE_*`. `known` is the only `_CLEAR`, and it means the READ succeeded -- nothing judges the amount. |
| `tc_near_ai_balance_action` | `state` | `TC_CREDENTIAL_ACTION_*`. `OBTAIN` for `no_session` and `session_expired`, `NONE` for everything else. |
| `tc_near_ai_balance_amount` | `present`, `nanos`, `scale` | The bare amount, e.g. `$8.50`. |
| `tc_near_ai_balance_remaining_line` | `present`, `nanos`, `scale` | `Left to spend: $8.50.`, or the no-limit sentence when `present == 0`. |
| `tc_near_ai_balance_limit_line` | `present`, `nanos`, `scale` | The ceiling, or `""`. |
| `tc_near_ai_balance_spent_line` | `present`, `nanos`, `scale` | What the account has spent, or `""`. |
| `tc_near_ai_balance_observed_line` | `seconds_ago` | How long ago **this daemon** asked. Negative gives `""`. |

`present` is `0` for a `null` on the wire and non-zero otherwise. It is a
separate argument rather than the out-of-range-integer convention the other
money exports use, because these amounts are **signed**: an overdrawn account
is a negative figure, and folding `null` onto `negative` would render a real
debt as no figure at all.

The rounding is **down**, toward minus infinity, so a printed figure is never
larger than the one that arrived; a nonzero amount under a cent is
`less than $0.01` and not `$0.00`.

#### Three neighbouring fields, three different meanings for a missing key

Read this before writing a client that touches more than one of them. They
share a wire and nothing else: each is an answer to its own question, and
knowing one tells you nothing about the next.

- **`attestation_reason`: branch on the key's presence, not on the mark.**
  This is the one that catches people, because the mark does not determine
  the shape. `attested` never carries a reason and both unattested marks
  always do -- but `unknown` has two sources, and they differ: a row written
  before the field existed has **no** reason, while a send refused with
  `admission_receipt_unavailable` carries `receipt_unavailable`. The second
  is a retraction rather than a refusal -- the receipt comes from a service
  that can be down -- and that reason is the only thing telling the
  contributor it may work later. Do not "simplify" it to always-absent.
- **`eligibility`: an absent key means the question does not apply.** A
  present `unknown` means the question applies and was not answered.
- **`near_ai_balance`: every numeric key is present and `null`**, and the
  `null` is load-bearing -- it means "this daemon knows it does not know". An
  **absent** key here means only "this daemon is too old to answer", and a
  client that treats it as a `null` is asserting a state the daemon never
  reported. **A `null` must never be rendered as `0`.**

Each of these answers its own question and they happen to share a wire.
There is no convention here to generalise from: read the contract for the
field you are touching, and do not carry a habit across from another one.
A field added later is a fourth answer to a fourth question, not a fourth
instance of a pattern.

### The public profile

Three methods, one shape. `set_public_profile` and `clear_public_profile`
call the server's `PUT` and `DELETE` on `/v1/community/profile`;
`get_public_profile` reads a local cache and makes no network call at all.

```json
{
  "on_roster": true,
  "handle": "manian",
  "bio": "Ships billing systems by day.",
  "public_since": "2026-05-12T09:31:00Z",
  "public_url": null
}
```

`set_public_profile` adds `handle_persisted`; `clear_public_profile` adds
`withdrawn: true` and `handle_persisted`. Both are otherwise this shape, so
a client parses one profile whichever call it made.

**"Go public" is TWO calls, not one.** `set_consent_scopes` with
`public_attribution` added to the scope list, and then
`set_public_profile`. Neither implies the other: the scope records what the
contributor agreed to, and the second call is what actually puts a row on
the roster. A dialog that only sets the scope leaves the contributor
believing they are listed when nothing was published.

**The server authorizes against the claim's grant ceiling, not the local
scope list**, and the daemon deliberately does not pre-check
`consent_scopes` before calling. These calls mint an empty-scope claim,
which the issuer resolves to the caller's full grant ceiling, so the local
set can be *narrower* than what the credential actually carries -- refusing
locally would refuse contributors the server would have allowed. If the
server refuses, the contributor's remedy is to enrol again with
`public_attribution` in `scopes`, not to change anything locally.

**`bio` is required, and `null` is how you publish none.** The server
upserts with `bio = excluded.bio`, so the `PUT` replaces the *whole*
profile: there is no "leave the bio alone", and a call that omitted `bio`
would silently erase a published one on a handle rename. Omitting the key
is `bad_params` / `bio-required-or-null`. Send `"bio": null` to publish no
bio and `"bio": "…"` to publish one. (The CLI refuses the same ambiguity
with its `--bio` / `--no-bio` pair.)

**`get_public_profile` is a local cache, and a client must present it as
one.** There is no `GET /v1/community/profile` -- the server derives the
principal from the authenticated request and offers a contributor no
read-back of their own row -- so this reports what *this device* last
published: the handle, bio, and roster date the server returned on the last
successful `set_public_profile`, cleared by a successful
`clear_public_profile`. It is not a live read, and a profile claimed from
another device does not appear here. `on_roster` is simply whether a handle
is cached.

**`public_url` is always `null`.** The daemon knows the ingest origin it
uploads to, not the origin the community website serves profiles from.
Inventing one would give a "View public profile" link that does not
resolve, so the field is reported as `null` and a client that wants that
link must get the origin elsewhere.

**`handle_persisted` is not whether the call worked.** The response is a
success either way: the server already accepted the change, and the profile
is public (or withdrawn) regardless of what happened on this disk.
`handle_persisted: false` means only that the local cache write failed, so
`get_public_profile` will not report this profile until the next successful
`set_public_profile`. Do not render it as a failed save.

Errors, all fixed labels under the taxonomy at the bottom of this document:

| Code | Label | When |
|---|---|---|
| `bad_params` | `handle-required` | no `handle` |
| `bad_params` | `handle-too-short`, `handle-too-long`, `handle-invalid-character`, `handle-invalid-boundary`, `handle-consecutive-separators`, `handle-reserved` | the shared handle rules refused it |
| `bad_params` | `bio-required-or-null` | `bio` omitted (see above) |
| `bad_params` | `bio-invalid` | `bio` present but neither a string nor `null` |
| `bad_params` | `bio-too-long`, `bio-invalid-character` | the shared bio rules refused it |
| `unavailable` | `not-logged-in` | no enrollment on this device |
| `unavailable` | `profile-update-failed` / `profile-withdraw-failed` | the server call failed; the underlying error is never echoed, since it can carry a response body or a URL |

The handle and bio rules are `trace_commons_protocol::community_handle`'s,
the same code the server validates with, rather than a second copy in the
daemon: 3--32 characters of ASCII `[a-zA-Z0-9_-]`, alphanumeric at both
ends, no doubled separator, not a reserved name, and a bio of at most 280
UTF-8 bytes with no control characters except newline. Surrounding
whitespace on the handle is trimmed before validating, and the trimmed form
is what gets published. A client may pre-validate to give live feedback,
but the daemon's refusal is the authority.

The handle and the bio are the one thing on this surface that may appear in
a response, because publishing them is the entire point of the call. They
are still never written to a log line or an audit entry.

### Withdrawal

`withdraw` and `withdraw_bulk` call the server's
`POST /v1/account/traces/{submission_id}/withdraw` (see
`docs/superpowers/specs/2026-08-08-trace-withdrawal-design.md` for the full
design and the three response tiers). A successful `withdraw` reports
`distribution_reach`, one of:

- `not_distributed` -- the trace was `submitted` or `quarantined` and never
  entered the commons. Its content is simply deleted.
- `commons_not_distributed` -- the trace was `accepted` but not yet used in
  any published export or benchmark. Its content is deleted and it is
  excluded going forward.
- `commons_distributed` -- the trace was `accepted` and already included in a
  published export or benchmark. Its content is deleted and it is excluded
  going forward, but copies already distributed cannot be recalled.

**These are the server's names, and two of them were wrong in this document
until 2026-08-10.** It previously said `in_commons` and `distributed`. A client
built from the old text deserialises `not_distributed` correctly and fails on
the other two -- which are exactly the tiers whose message a contributor most
needs to be true. `wire_names_match_the_server` in
`crates/trace-commons-contributor/src/withdraw.rs` pins them; if that test
fails, this table is what to fix.

#### Canonical confirmation copy

Three applications are built from this document, and withdrawal is the one
place where a plausible-sounding phrase becomes a false promise about erasure.
Do not paraphrase per platform. Use these, adapted only for sentence case and
platform punctuation conventions.

**The tier is not knowable before the call, and that shapes everything below.**
The server computes `distribution_reach` during the withdrawal, from live
export membership. A client holds only the local `status`. So:

- local status `submitted` or `quarantined` maps to `not_distributed`
  reliably -- that is the server's own rule, and its copy can be shown before
  the action.
- local status `accepted` may resolve to EITHER `commons_not_distributed` or
  `commons_distributed`, and the client cannot tell which. It must show
  **both** bodies before the action, with the `commons_distributed` one given
  the greater weight, and must say plainly that the outcome is decided on the
  server. Showing only the gentler one would be a promise the client is not in
  a position to make.
- an unrecognised status shows the `commons_distributed` body alone, on the
  grounds that the furthest reach cannot be ruled out.

After the call, report the tier the server actually applied, using that tier's
body. Never a generic "withdrawn".

A contributor deciding whether to withdraw needs to know what it will achieve
while they can still change their mind -- which here means knowing the range
of what it might achieve, honestly, rather than a single confident sentence
the client cannot support.

| tier | confirmation body |
|---|---|
| `not_distributed` | "This trace never entered the commons. Withdrawing deletes it. Nothing was distributed and nothing needs recalling." |
| `commons_not_distributed` | "This trace is in the commons but has not been included in any published export or benchmark yet. Withdrawing deletes it and excludes it from everything published from here on." |
| `commons_distributed` | "This trace has already been included in a published export or benchmark. Withdrawing deletes our copy and excludes it from everything published from here on, **but copies that have already been distributed cannot be recalled.** Withdrawing does not undo that." |

Rules that bind every application:

1. **Never a generic "withdrawn".** The tier determines what actually
   happened, and collapsing three outcomes into one word is the specific
   failure this table exists to prevent.
2. **Never claim more erasure than the tier achieved.** In particular
   `commons_distributed` must not be phrased so a contributor could come away
   believing distributed copies were retrieved.
3. **Withdrawal does not reverse settled credit.** Do not state or imply that
   it does. (Revocation used to claw credit back; that is being removed.)
4. **`not_found` must not disclose which.** The server deliberately answers
   the same way whether a submission belongs to someone else or does not exist
   at all, so that account enumeration is impossible. An application must
   therefore say something like "no trace with that id under your account",
   and must NOT say "that trace belongs to someone else" or "that trace does
   not exist" -- either phrasing leaks precisely what the server refuses to.
5. **`confirmation_prompt` in the Rust client takes a `reach` the caller does
   not have pre-action.** It is usable for the after-the-fact message, or with
   a deliberately chosen worst case; it is not a pre-action lookup. Do not
   build a flow that assumes the tier is known before the request.
6. **Bulk withdrawal spans tiers.** `withdraw_bulk` reports only counts, so a
   bulk confirmation cannot promise a per-tier outcome. It must say that the
   selected traces may fall into different tiers and that some may already
   have been distributed. If an application cannot say that clearly, it should
   not offer bulk withdrawal.

`withdraw_bulk` withdraws every submission currently at `status` in the
local history cache (one of `submitted`, `quarantined`, or `accepted`; not
`withdrawn` itself, and not the `other` bucket `history_rollup` reports,
which covers statuses this client has no stable name for). It reports
`withdrawn` and `failed` counts rather than per-submission detail -- a
partial failure does not fail the whole call, and a contributor can retry
individual traces with `withdraw` if some did not go through.

Both update the local history cache immediately (the record's `status`
becomes `withdrawn`) so a contributor sees the effect without needing a
`refresh_history` round trip first.

**Both methods answer `unavailable` / `account-session-required` today,
always**, before ever attempting the call. Withdrawal is authenticated by an
account session -- deliberately not the device key that authenticates every
other call in this contract, so withdrawal survives losing the device that
submitted the trace -- and this daemon does not yet acquire or store one; it
only ever holds a device key. `account-session-required` is a distinct,
documented error rather than a generic failure so a calling shell can route
the contributor to account sign-in instead of showing a dead end, once
account sign-in exists to route to. Acquiring an account session is separate
work, tracked outside this document; nothing in this contract should be
read as that flow already existing.

## Events

| Event | When | Data |
|---|---|---|
| `snapshot` | immediately after `subscribe` | `{pending[], status}` |
| `queue_changed` | queue contents changed | `{}` |
| `status_changed` | pause/resume, a lapsed timed pause, or health changed | `{}` |
| `digest_due` | batching interval elapsed with pending work | `{pending, text}` |
| `resync_required` | this client fell behind the event buffer | `{}` |
| `preview_ready` | a scheduled preview finished and was delivered | the same object `preview_request` returns for a cache hit -- see "Scheduled previews" |

`subscribe` sends a full `snapshot` before any delta, so a client never has to
race `list_pending` against the stream at startup. On `resync_required`, call
`list_pending` and `status` again.

## Queue states

`pending`, `approved`, `uploading`, `uploaded`, `refused`, `failed`,
`expired`, `superseded`.

- `expired` — aged out after the TTL (14 days) without a decision. The clock
  is **suspended** while the daemon is unhealthy, so an outage does not
  silently discard traces.
- `superseded` — the session changed after it was offered. The daemon re-hashes
  before uploading; on a mismatch it sends nothing and creates a fresh
  `pending` entry for the new content. An approval covers content, not a
  filename.
- An approval also covers the **terms** it was given under: the consent
  scopes, the configuration that determines the envelope, and -- if the
  entry was previewed -- the exact redacted envelope that was shown. If any
  of those move before the upload, the approval is revoked and the entry
  returns to `pending` with `consent-scopes-changed-after-approval`,
  `approval-inputs-changed`, or `envelope-changed-after-approval`. Nothing
  is sent. An app should treat these the same as a superseded entry: offer
  it again, previewing afresh.
- `approved` entries can be returned to `pending` with `cancel`, which
  clears the pin along with the rest of the approval, so a re-offered entry
  is previewed or rebuilt afresh rather than carrying the withdrawn
  approval's artifact. An entry approved through `approve` stays untouched
  for its hold window first (see "The approval hold" above), so `cancel` is
  guaranteed to succeed for that whole window. After it, `cancel` still works right up until the upload
  pass claims the entry (`uploading`), at which point it is refused.

## `reason_label` and health taxonomy

| Label | Meaning | Suspends expiry |
|---|---|---|
| `not-logged-in` | no config or no device key | yes |
| `pii-filter-unavailable` | filter configured but unreachable | yes |
| `claim-mint-failed` | issuer refused or failed | yes |
| `ingest-unreachable` | upload failed after retries | yes |
| `daily-cap-reached` | volume cap in force until the day rolls | yes |
| `near-ai-notice-not-acknowledged` | first-use notice not delivered interactively | yes |
| `privacy-filter-canary-failed` | canary self-test failed | yes |
| `queue-full` | queue at its configured maximum | no |
| `session-too-large` | at least one session on disk is past the byte budget its source will read, so it is not being offered | no |
| `dismissed-by-contributor` | declined by hand | n/a |
| `expired-without-decision` | aged out | n/a |
| `session-changed-after-offer` | superseded | n/a |
| `consent-scopes-changed-after-approval` | approval revoked, entry re-offered | n/a |
| `approval-inputs-changed` | an envelope-determining input moved after approval; entry re-offered | n/a |
| `envelope-changed-after-approval` | the envelope that would be sent is not the one previewed; entry re-offered | n/a |

### Health precedence

`status.health.last_error_label` carries a single label at a time, even
though several conditions can be true simultaneously. When more than one
applies, the daemon shows the one with the **highest precedence** below,
listed highest first:

1. `not-logged-in`
2. `near-ai-notice-not-acknowledged`
3. `privacy-filter-canary-failed`
4. `pii-filter-unavailable`
5. `claim-mint-failed`
6. `ingest-unreachable`
7. `queue-full`
8. `daily-cap-reached`
9. `session-too-large`

`session-too-large` sits last on purpose: every label above it describes the
daemon, and this one describes a single file on disk. It must never mask an
outage. It is raised by the poll pass when a source declines to read a
session at all, and retracted by the next full pass that reads everything --
a scoped pass over a handful of changed paths may raise it and never clears
it, since one readable session says nothing about the rest of the corpus.
A read that merely *failed* -- a file deleted mid-pass, a momentary
permission or IO error -- does not raise it: that is expected to succeed on
the next poll, and a flag a blip pins on a healthy daemon is one nobody will
trust.

Because `daily-cap-reached` is last, it is the label most often masked by
another condition. That is why the daily caps are also reported in full on
`status.daily_budget`, outside the precedence order — see above. A client
should render the budget condition from `daily_budget`, not by waiting for
`daily-cap-reached` to reach the health slot.

Rationale: states the contributor can act on outrank states they can only
wait out. An application should not attempt to infer or reconstruct this
order itself; treat `status.health.last_error_label` as the one label to
render, and use `queue_outcome_counts` / `list_audit` for supplementary
detail, not for picking a different label to show instead.

## Error codes

`unknown_method`, `bad_params`, `not_authorized`, `busy`, `unavailable`.

`error.message` is always a fixed label. The ones `preview_body` adds are
`unknown-entry-id`, `offset-invalid`, `limit-invalid`,
`body-digest-invalid`, `body-digest-required` (all `bad_params`), and
`preview-body-changed`, `preview-failed`, `approved-envelope-unavailable`
(all `unavailable`).

`preview_turns` reuses that set -- `unknown-entry-id`, `body-digest-invalid`
and `body-digest-required` (`bad_params`), `preview-body-changed`,
`preview-failed` and `approved-envelope-unavailable` (`unavailable`) -- and
adds one of its own, `preview-turn-index-failed` (`unavailable`), for a body
that resolved but could not be indexed exactly.

The harness methods add `id-required`, `action-invalid`, `harness-unknown`,
`harness-no-destination` and `plan-id-invalid` (all `bad_params`), and
`harness-plan-unknown`, `harness-config-changed` and `harness-commit-failed`
(all `unavailable`). A refusal that is a fact about the machine rather than
about the call -- an unparseable config, a tool that is not installed -- is
**not** an error: it is a `harness_plan` `outcome`. See "The harness list".

`not_authorized` is retained in the error taxonomy for forward
compatibility but is no longer returned by any method in this version --
the `v1` terminal-only gate that used it was removed (see "Authorization"
above).

### Token distribution contribution

`token_distributions_contribution` is a boolean, default `false`. It grants
permission to include token probabilities and alternatives in explicit witness
reviews. It does not enable Ironwire capture. Capture must be configured for an
exact supported backend/model pair, and `ironwire_attested_bodies` must also be
allowed before raw evidence goes to the configured, pinned witness.

When enabled, review requires an exact capture digest match, a bounded snapshot
lease, a verified provider receipt, and an ingest endpoint advertising the
restricted bundle policy. Missing support is a refusal, never a transcript-only
fallback. Changing this setting invalidates incompatible queued approvals.

The certified manifest and payload are pinned locally before approval. Upload
reuses those exact bytes and resumes missing objects. Only a destination-bound
durable receipt authorizes successful-submission cleanup. A separate three-day unapproved (seven-day approved)
review expiry abandons old local payloads and releases their own leases; it does
not imply successful submission. Logout deletes local token review state. Agent
session files are never deleted by this mechanism.

### Local token storage

`token_capture_enabled` is an optional boolean override for the hosted Ironwire
proxy. `false` stops future token captures; `true` requires explicitly configured
backend/model targets. An absent override honors the proxy configuration. This
setting does not authorize contribution or sending raw bodies to the witness.
Changing it cycles the hosted proxy. External proxies keep their own settings.

| Method | Parameters | Result |
| --- | --- | --- |
| `token_storage_status` | none | Content-free local byte counts, pending releases, review counts and lease renewal status |
| `remove_token_local_copies` | none | Updated status after removing submitted local payloads |
| `discard_token_reviews` | `confirmed: true` | Updated status after discarding unsubmitted token reviews; approved/uploading reviews require undoing approval first |

The CLI exposes these through `daemon token-storage`, `--cleanup`, and
`--discard --confirm`. Capture intent can be set with
`daemon settings --set token_capture_enabled=true` after configuring qualified
targets. Lease expiry is reported only when confirmed by the capture store.
Failed renewals and releases remain durable and retry with bounded backoff.
Server withdrawal is a separate action; local cleanup never deletes original
agent session files or another destination's capture lease.

Single-submission `withdraw` also returns an optional `token_deletion_note` from
shared Rust copy. It distinguishes pending deletion, a retention hold, completed
server-managed deletion and an unknown result. This does not claim deletion from
backups or previously distributed copies. Older servers omit the field.
