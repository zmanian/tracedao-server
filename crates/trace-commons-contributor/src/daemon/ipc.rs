//! The IPC contract: `trace_commons.daemon.v1_1` (v1 clients remain
//! supported; see `SUPPORTED_VERSIONS`).
//!
//! This is the surface the native menu-bar and window applications are built
//! against, so it is versioned and frozen rather than allowed to drift. It
//! serves both surfaces: the tray needs `status`, `list_pending`, `approve`,
//! `pause`/`resume` and the event stream; the window additionally needs
//! `preview`, `list_history`, `history_rollup`, `list_projects` and settings.
//!
//! Framing is JSON, one message per line, over a unix domain socket. Every
//! request carries an `id` and every response echoes it, because responses and
//! pushed events share the connection and a client with two calls in flight
//! must be able to tell which answer is which. Pushed events carry `event` and
//! never an `id`.
//!
//! # Authorization
//!
//! Filesystem ownership: the 0700 state directory is the sole access control
//! on the socket, since `UnixListener::bind` does not portably set the
//! socket's own mode; the daemon refuses to serve from a directory that is
//! not 0700.
//!
//! Two operations -- arming a project for `auto_upload` and bulk-approving
//! the whole queue -- used to be refused over the socket and required a
//! terminal. That restriction is gone: the reasoning behind it does not
//! survive scrutiny. Same-user code execution that can reach this socket can
//! already read `~/.claude/projects` directly and send it anywhere, and can
//! install its own persistent watcher -- the daemon confers neither the read
//! nor the persistence a real attacker needs. Routing exfiltration through it
//! would in fact be strictly worse for an attacker: rate-limited, capped,
//! redacted, PII-filtered, and delivered to a server they cannot read from.
//!
//! What replaces the restriction is visibility, not gatekeeping: both
//! operations append a local, hash-only audit entry (`daemon::audit`) that a
//! contributor can read to see when autonomy was granted and when a bulk
//! approval happened. This is user-facing visibility, not a security
//! control, and is not claimed to be one -- but it is written fail-closed:
//! an audited action whose entry cannot be persisted is rolled back and the
//! call returns `audit-write-failed`, because a change that stands with no
//! record of it is exactly what removing the restriction was not supposed
//! to make possible. See `daemon::audit`.
//!
//! # What crosses this socket
//!
//! No path, token, invite code, claim, device key, or trace content
//! appears in any response, error string, or pushed event. `error.message`
//! is a fixed label. Queue entries carry `project_label` and, for display
//! only, `project_path` -- never `project_key` or `path`. The path is on
//! this socket and nowhere else: see `display_path` for the bound, and
//! `no_sink_carries_a_project_path` for what enforces it. Project labels
//! are derived by the daemon from
//! the key and are never a string a caller supplied.
//!
//! **The preview exemption.** `"preview"`'s `opening_prompt`,
//! `"preview_body"`'s `chunk`, and the redacted body `open_preview` returns
//! to the C ABI, *are* trace content, deliberately. A contributor cannot
//! consent to sending something they cannot see, so preview is the one
//! interface allowed to carry it -- bounded to post-redaction content, only
//! for an `entry_id` the caller already holds, and never onward into a log
//! line, an audit entry, a history record, notification text, or a receipt.
//! Everywhere else in this module the rule is absolute.
//!
//! `"preview_body"` is the *same* carve-out reaching the same body over the
//! socket, not a second one. It exists because the body used to be
//! reachable only through `open_preview`, which takes `&DaemonShared` and so
//! can only be called by the process holding the daemon lock. On the
//! recommended Linux arrangement -- a systemd-managed daemon with the window
//! as a socket client -- that is never the window, so "search this trace for
//! my client's name" and "show me exactly what would be sent" were not slow
//! or awkward there, they were impossible. Loading a second `DaemonShared`
//! is not the workaround it looks like: it rewrites the queue file and
//! sweeps the pinned envelopes the running daemon is still holding.
//!
//! # Sync vs. async dispatch
//!
//! Most of this surface needs no `.await` and is answered by the synchronous
//! `handle_request`. A few methods do real async work -- `"preview"` runs the
//! redaction pipeline to report actual bytes and redactions, `"enroll"`
//! registers this device with an issuer over the network -- and
//! `handle_request` cannot run either of those to completion; its arms for
//! them (where present) return an honest partial or deferred answer rather
//! than a wrong one.
//!
//! `handle_request_async` is the complete dispatcher: it answers the async
//! methods for real and delegates everything else, unchanged, to
//! `handle_request`. There are exactly two real entry points, and both go
//! through it:
//!
//! - The socket connection loop (`serve_connection`), already async, calls
//!   `handle_request_async` directly.
//! - `handle_local` (the in-process CLI path, wired in
//!   `src/bin/trace-commons-contributor.rs`) is itself synchronous, so it
//!   runs `handle_request_async` to completion via `block_on_ipc`, a
//!   scoped-OS-thread blocking wrapper. It does this for *every* method, not
//!   only the async ones -- a per-method special case here was tried once
//!   already and is exactly how a socket caller and a CLI caller ended up
//!   able to get different answers to the same request. Routing every method
//!   through the one real dispatcher removes that failure mode by
//!   construction: a method added to `handle_request_async` is automatically
//!   answered identically by both callers, with nothing to remember to update
//!   here.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{Notify, broadcast};
use uuid::Uuid;

use super::audit::{self, AuditEntry};
use super::enroll;
use super::health::HealthState;
use super::history::{HistoryCache, rollup};
use super::policy::{
    ERR_PROJECT_ID_UNRECOGNIZED, ERR_PROJECT_KEY_UNRECOGNIZED, ProjectMode, ProjectPolicy,
    UNKNOWN_PROJECT_KEY, disambiguated_label, known_keys, project_id_for, project_key_for_id,
    project_key_is_admissible,
};
use super::preview_scheduler::{PreviewKey, PreviewScheduler, RequestState};
use super::queue::{Queue, QueueEntry, QueueState};
use super::settings::DaemonSettings;
use super::state::DaemonState;
use crate::config::ConfigStore;
#[cfg(unix)]
use crate::config::DAEMON_SOCK_FILE;

pub const IPC_SCHEMA: &str = "trace_commons.daemon.v1_1";
/// Every schema version a client may declare compatibility with. `hello`
/// reports this so a v1 client (built before the seven methods below existed
/// and before the terminal-only gate was dropped) can keep talking to this
/// daemon: every v1 method keeps its v1 request and response shape, so a v1
/// client that ignores unfamiliar methods and fields works unmodified.
pub const SUPPORTED_VERSIONS: [&str; 2] = ["trace_commons.daemon.v1", "trace_commons.daemon.v1_1"];
/// Longest accepted request line. Anything larger is a malformed client, not a
/// real request.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// The largest slice of a redacted preview body `preview_body` will put in
/// one frame, and the cap it silently applies to a larger `limit`.
///
/// Sized against [`MAX_LINE_BYTES`], not against the body. A redacted
/// envelope may approach `MAX_ENVELOPE_BYTES` (1.5 MB), so a whole body does
/// not reliably fit one 1 MiB line and `preview_body` pages. The chunk still
/// has to survive JSON string escaping on the way out: `serde_json` passes
/// non-ASCII UTF-8 through unescaped but expands a control byte to `\u00XX`,
/// six bytes for one, so a pathological 128 KiB chunk serializes to at most
/// 768 KiB and the frame stays comfortably inside the line cap with the
/// response's own fields on top.
pub const MAX_PREVIEW_BODY_CHUNK_BYTES: usize = 128 * 1024;

pub const ERR_UNKNOWN_METHOD: &str = "unknown_method";
pub const ERR_BAD_PARAMS: &str = "bad_params";
pub const ERR_NOT_AUTHORIZED: &str = "not_authorized";
pub const ERR_BUSY: &str = "busy";
pub const ERR_UNAVAILABLE: &str = "unavailable";

/// `preview_body` refused because the body it resolved is not the one the
/// caller has been reading: the `body_digest` from the caller's first page
/// does not match. Splicing two pages of two different bodies together
/// would produce a transcript nobody ever redacted, and a search over it
/// would be answering about text that does not exist. Restart from
/// `offset: 0`.
pub const ERR_PREVIEW_BODY_CHANGED: &str = "preview-body-changed";
/// A continuation page (`offset > 0`) arrived without the `body_digest` the
/// first page returned. Required, not optional: without it the daemon
/// cannot tell a continuation of the body the caller holds from a page of a
/// different one, and paging is the whole reason this method exists.
pub const ERR_BODY_DIGEST_REQUIRED: &str = "body-digest-required";
/// The fixed label every `preview_body` refusal for an entry the caller
/// does not hold -- unknown id, or an id that is not in the queue -- comes
/// back under. Identical to `preview`'s, deliberately: the two must not be
/// distinguishable.
pub const ERR_UNKNOWN_ENTRY_ID: &str = "unknown-entry-id";
/// `approve`'s `outcome` named something other than `worked`, `partly` or
/// `failed`. Refused, not coerced to `Unknown`, so a typo does not silently
/// discard the contributor's answer -- the same rule the `--outcome` flag
/// applies.
pub const ERR_BAD_VERDICT: &str = "outcome-invalid";
/// `approve`'s `correction` was not a string.
pub const ERR_BAD_CORRECTION: &str = "correction-invalid";
/// `approve` carried a correction without a `partly` or `failed` outcome.
///
/// The shells only show the field for those two verdicts, and the same rule
/// is enforced here rather than trusted to them. A run the contributor has
/// just called successful has nothing to correct, and refusing the
/// combination halves the surface for correction-shaped credit farming --
/// see the S5 design note.
pub const ERR_CORRECTION_NEEDS_VERDICT: &str = "correction-needs-outcome";
/// `approve` carried a correction longer than
/// `envelope::MAX_CORRECTION_CHARS`.
pub const ERR_CORRECTION_TOO_LONG: &str = "correction-too-long";
/// `approve` carried a correction with `all` or `project_id`.
///
/// A correction is written about one session. Applying one string to a whole
/// batch would attach an explanation to sessions it was not written about,
/// and every one of them would carry it into the corpus as the
/// contributor's own words.
pub const ERR_CORRECTION_NEEDS_ENTRY: &str = "correction-needs-entry-id";
/// The label an entry is skipped under when credential detection fired on
/// the correction the contributor wrote for it.
///
/// Nothing is approved and nothing is sent. The contributor is told to
/// remove the credential and, because it has already been typed, to rotate
/// it -- masking it and sending it on would leave a live credential
/// transmitted and its owner unaware. The label names the condition and
/// never the text or the match.
pub const REASON_CORRECTION_CREDENTIAL: &str = crate::envelope::REASON_CORRECTION_CREDENTIAL;

/// `quiesce` gave up waiting for in-flight uploads to finish. The caller
/// leaves the update staged and tries again later; the swap never forces its
/// way past active work, because a half-uploaded trace is not an acceptable
/// cost for an update.
pub const ERR_QUIESCE_TIMEOUT: &str = "quiesce-timeout";

/// How long `quiesce` waits for in-flight uploads by default.
pub const DEFAULT_QUIESCE_TIMEOUT_SECS: u64 = 60;
/// The longest a caller may ask `quiesce` to park uploads for.
pub const MAX_QUIESCE_TIMEOUT_SECS: u64 = 300;
/// How often the drain is re-checked while waiting.
const QUIESCE_POLL_MS: u64 = 200;

/// Every method this version answers. `hello` reports this list.
///
/// **The membership rule is the union of the two dispatchers.** A method is
/// a member if `handle_request` or `handle_request_async` has an arm for it;
/// the async one falls through to the sync one, so a caller on the socket
/// can reach either. `every_advertised_method_is_dispatched_and_the_reverse`
/// checks that in both directions against this file's own source, and it is
/// the reason a name cannot quietly go missing here again -- `near_ai_balance`
/// was dispatched and unadvertised for the life of the credential surface
/// (#777), which made `hello` deny a call the daemon demonstrably answers.
///
/// **Nothing on this list is deliberately unadvertised, and nothing
/// dispatched is deliberately left off.** If that ever changes, name the
/// method here and say why, because a reader who finds a dispatched method
/// missing from this array has no way to tell an omission from a decision.
///
/// Advertised is not the same as reachable on the synchronous entry point:
/// `ASYNC_ONLY_METHODS` names the ones that refuse there with a label saying
/// so, and `approve`, `search_original` and `near_ai_balance` answer
/// `unknown_method` there instead, because all three are dispatched only on
/// the async path and none of them is on that list. Advertising them here is
/// still right -- the socket reaches the async dispatcher -- but the sync
/// refusal they give is "no such method" rather than "wrong entry point".
/// That is a defect in `ASYNC_ONLY_METHODS`, not in this array, and it is
/// deliberately not fixed here: it would change the wire answer for two
/// methods that have shipped that way.
///
/// A slice rather than a fixed-size array: `serde` implements `Serialize`
/// for arrays only up to 32 elements, and `hello` serializes this list
/// directly.
///
/// The contract document (`docs/contributor-daemon-ipc-v1_1.md`) is NOT
/// checked against this array by any test, despite what this comment said
/// until #777. Four members (`arming_suggestion`, `decline_arming`,
/// `probe_routed_tools`, `search_original`) appear nowhere in it.
pub const METHODS: &[&str] = &[
    "acknowledge_near_ai_notice",
    "approve",
    "cancel",
    "clear_public_profile",
    "consent_options",
    "discover_routing",
    "dismiss",
    "arming_suggestion",
    "decline_arming",
    "enroll",
    "prepare_admission_session",
    "near_account_capabilities",
    "native_wallet_flow",
    "near_account_start",
    "near_ai_account_enroll",
    "near_account_status",
    "near_account_cancel",
    "near_ai_credential_start",
    "near_ai_credential_status",
    "near_ai_credential_cancel",
    "near_ai_credential_forget",
    "near_ai_balance",
    "near_ai_funding",
    "get_public_profile",
    "get_settings",
    "token_storage_status",
    "remove_token_local_copies",
    "discard_token_reviews",
    "harness_commit",
    "harness_list",
    "harness_plan",
    "hello",
    "history_rollup",
    "list_audit",
    "list_history",
    "list_pending",
    "list_projects",
    "pause",
    "preview",
    "preview_body",
    "preview_cancel",
    "preview_request",
    "witness_preview_request",
    "preview_turns",
    "preview_visible",
    "probe_routed_tools",
    "probe_routing",
    "queue_outcome_counts",
    "quiesce",
    "refresh_history",
    "resume",
    "search_original",
    "set_consent_scopes",
    "set_project_mode",
    "set_public_profile",
    "set_settings",
    "shutdown",
    "status",
    "subscribe",
    "withdraw",
    "withdraw_bulk",
];

pub const EVENT_SNAPSHOT: &str = "snapshot";
pub const EVENT_QUEUE_CHANGED: &str = "queue_changed";
pub const EVENT_STATUS_CHANGED: &str = "status_changed";
pub const EVENT_DIGEST_DUE: &str = "digest_due";
pub const EVENT_RESYNC_REQUIRED: &str = "resync_required";
/// One entry's scheduled preview finished. Carries the same object
/// `preview_request` returns for a cache hit: `entry_id`, `state`, and
/// whichever of `summary` / `raw_session_bytes` / `code` that state has.
///
/// Published for every job the scheduler completes and delivers, including
/// refusals -- a shell that showed a spinner needs to be told the answer is
/// "too large" just as much as it needs to be told the summary. It is *not*
/// published for a job that was cancelled while it ran; see
/// `preview_scheduler::PreviewScheduler::cancel`.
pub const EVENT_PREVIEW_READY: &str = "preview_ready";

#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    pub code: String,
    /// A fixed label, never a message body or server response text.
    pub message: String,
}

/// `Deserialize` as well as `Serialize`: `daemon::client` parses a running
/// daemon's reply back into this exact type, so the CLI's view of a
/// response and the socket's wire shape are the same definition rather
/// than two that can drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

impl Response {
    /// `pub`, not `pub(crate)`: `trace-commons-contributor-ffi` builds
    /// error frames for failures it must synthesize itself (a malformed
    /// `params_json`, a null pointer) rather than ones `handle_local`
    /// produces, and needs the exact wire shape a real dispatcher response
    /// serializes to -- constructing it this way, rather than hand-rolling
    /// an equivalent `serde_json::json!`, is what keeps the two from
    /// drifting apart.
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    /// See `ok`'s doc comment on why this is `pub`.
    pub fn err(id: u64, code: &str, message: &str) -> Self {
        Self {
            id,
            result: None,
            error: Some(IpcError {
                code: code.to_string(),
                message: message.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub event: String,
    pub data: serde_json::Value,
}

struct RoutingSnapshot {
    declaration: Option<super::settings::IronWireDeclaration>,
    ledger: Option<Arc<crate::routing::ironwire::IronWireLedger>>,
    derived: bool,
}

/// Everything the daemon's loops and its IPC server share.
pub struct DaemonShared {
    pub store: ConfigStore,
    pub queue: Mutex<Queue>,
    pub policy: Mutex<ProjectPolicy>,
    pub state: Mutex<DaemonState>,
    pub settings: Arc<Mutex<DaemonSettings>>,
    pub health: Mutex<HealthState>,
    pub paused: AtomicBool,
    /// Uploads are parked for an update swap.
    ///
    /// Deliberately *not* `paused`. Pause is the contributor's own setting
    /// and is persisted in `daemon-state.json`; an update that set it would
    /// be rewriting their preference, and a crash between quiescing and
    /// swapping would leave the daemon paused forever with nothing to say
    /// why. This flag is in-memory only and dies with the process, which is
    /// exactly the lifetime an update swap needs: after the swap there is a
    /// new process and nothing left to un-quiesce.
    pub quiesced: AtomicBool,
    pub shutdown: AtomicBool,
    /// Wakes the supervisor immediately on a shutdown request. Without it the
    /// daemon would not notice until its next poll, which is a minute away --
    /// long enough for a logout to give up waiting and leave it running.
    ///
    /// Notified with `notify_one`, which stores a permit when nobody is
    /// waiting yet. `notify_waiters` would drop the request on the floor if it
    /// arrived while the supervisor was mid-scan, which is exactly when a
    /// long poll makes it most likely to arrive.
    pub shutdown_signal: Arc<Notify>,
    pub events: broadcast::Sender<Event>,
    /// The daemon-wide bound on concurrent preview work.
    ///
    /// `Arc` rather than a plain field because the worker pool outlives any
    /// one request and is spawned from `daemon::start_embedded` with only
    /// this handle -- the pool must not hold an `Arc<DaemonShared>` through
    /// the scheduler, or the two would keep each other alive forever.
    pub previews: Arc<PreviewScheduler>,
    /// The routing overlay's one long-lived instance, built from the
    /// declaration in settings and refreshed on the poll tick.
    ///
    /// `None` is the majority case -- no proxy declared. Settings keep
    /// describing the *declaration* (`DaemonSettings::source_roots` stays
    /// bare); this is the single place the *instance* lives, because a
    /// ledger built per call would hand every caller a cold, empty snapshot
    /// -- see [`Self::source_roots_with_routing`].
    ///
    /// Behind an `RwLock` because the declaration can change while the
    /// daemon runs: `set_settings` rebuilds this in place (see
    /// [`Self::rebuild_effective_routing`]). Telling a contributor to restart the
    /// daemon because they typed a port number is the friction that makes a
    /// feature feel broken. Readers take the lock only long enough to clone
    /// the `Arc` out -- nothing holds it across an await, and nothing holds
    /// it while doing I/O.
    routing: RwLock<RoutingSnapshot>,
    private_inference_endpoint: Mutex<Option<super::private_inference::OwnedEndpoint>>,
    /// Whether the last state this daemon reported for `routing` was
    /// "has rows". Compared against on every refresh so a transition is
    /// reported once, not on every poll -- see [`Self::routing_transition`].
    routing_had_rows: AtomicBool,
    /// The one IronWire this daemon may host, when a home could be resolved
    /// for it at all.
    ///
    /// A `tokio` mutex rather than a `std` one because starting and stopping
    /// a proxy are both awaits, and the guard is therefore held across them.
    /// `None` is the machine where neither `$IRONWIRE_HOME` nor a home
    /// directory resolves -- private inference cannot be offered there, and
    /// asking for it is a refusal rather than a panic.
    private_inference: Arc<tokio::sync::Mutex<Option<super::private_inference::PrivateInference>>>,
    private_inference_terminating: AtomicBool,
    private_inference_generation: std::sync::atomic::AtomicU64,
    token_review_generation: std::sync::atomic::AtomicU64,
    /// The credential-change count this daemon has already absorbed.
    ///
    /// See [`super::nearai_credential::ceremony::change_count`] for what the
    /// other side of this is and why it has to be a count on a static rather
    /// than a message: the ceremony's last leg holds no handle to this
    /// struct. Starts at zero and is compared, never cleared, so a second
    /// ceremony completing before the first has been absorbed is not lost.
    near_ai_credential_changes: std::sync::atomic::AtomicU64,
    private_inference_stop_confirmed: Arc<AtomicBool>,
    pub(crate) private_inference_changed: tokio::sync::Notify,
    private_inference_stop_task: Mutex<Option<tokio::task::JoinHandle<bool>>>,
    /// The runtime a hosted proxy's tasks must be spawned onto.
    ///
    /// `embed::start` spawns the axum server and IronWire's housekeeping
    /// with plain `tokio::spawn`, so whichever runtime is in context when it
    /// runs owns the proxy for its whole life. On the poll tick that is the
    /// daemon runtime and this changes nothing -- but `handle_local`, the
    /// path `tc_call` and the in-process CLI use, answers by running the
    /// dispatcher on a throwaway current-thread runtime inside a scoped
    /// thread. That runtime is dropped the instant the scope returns, and a
    /// proxy started on it dies there while the response says `running` with
    /// a port on it.
    ///
    /// So the daemon's own runtime is recorded here, by `adopt_runtime`,
    /// which `start_embedded` calls while it is standing on it. A
    /// `DaemonShared` built by a test or a one-shot CLI command that never
    /// started a daemon has none, and falls back to the ambient runtime --
    /// which for those callers is the only one there is.
    proxy_runtime: std::sync::OnceLock<tokio::runtime::Handle>,
    /// The last state the instance above reported.
    ///
    /// Kept beside it, under a `std` mutex, because `get_settings` and
    /// `status` are synchronous: they must answer without awaiting, and
    /// without racing a start that is halfway through. Reconciliation and
    /// the retained terminal cleanup task publish observed transitions here.
    private_inference_state: Arc<Mutex<super::private_inference::PrivateInferenceState>>,
    /// Config edits that have been worked out and shown, and not yet made.
    ///
    /// Lives on the daemon rather than crossing the socket because
    /// `ironwire_agents::Planned` keeps the file contents it would write in
    /// private fields: a plan cannot be reconstructed from what a shell was
    /// shown, which is exactly what stops a shell asking for a write it did
    /// not preview. See `daemon::harness`.
    pub(crate) harness_plans: super::harness::PlanStore,
}

/// `status.routing.state`: the contributor never declared a proxy.
///
/// The state `IronWireLedger::has_rows` cannot express. A daemon holding no
/// ledger and a daemon holding a ledger that has read nothing both report
/// "no rows", and collapsing them tells a contributor who declared a proxy
/// that everything is fine when the declaration never took.
pub const ROUTING_NOT_DECLARED: &str = "not_declared";

/// `status.routing.state`: a proxy is declared and the daemon holds a
/// ledger, but no row has arrived yet.
///
/// **Not an error.** A proxy installed this morning reports this, and so
/// does one whose declaration was changed a second ago -- a rebuilt ledger
/// starts cold by construction. A shell that renders this as a fault will
/// be wrong on both. `routing.last_refresh_at` is what separates "the proxy
/// answered and had nothing" from "nothing has answered yet".
pub const ROUTING_AWAITING_ROWS: &str = "awaiting_rows";

/// `status.routing.state`: a proxy is declared and rows have been read.
pub const ROUTING_ROWS_SEEN: &str = "rows_seen";

/// `status.routing.state`: a proxy is declared, and no reader could be
/// built for it.
///
/// The fourth situation, and the one that used to be reported as
/// [`ROUTING_NOT_DECLARED`]. `settings::ironwire_ledger_for` answers `None`
/// whenever `control.token` cannot be read -- the ordinary case where the
/// proxy is not running, or keeps its record somewhere this daemon was not
/// told about -- and that is indistinguishable, from the held ledger alone,
/// from a contributor who declared nothing. Collapsing them printed "Off"
/// on a card whose switch was on.
///
/// **Not `awaiting_rows` either.** That state says a reader exists and has
/// seen nothing yet, which is normal and needs no action. This one says no
/// reader exists, and it will stay that way until somebody changes
/// something on this machine.
pub const ROUTING_TOKEN_UNREADABLE: &str = "token_unreadable";
/// Internal routing state could not be read; no token diagnosis is available.
pub const ROUTING_UNKNOWN: &str = "unknown";

impl DaemonShared {
    pub fn load(store: ConfigStore) -> Result<Self> {
        let mut queue = Queue::load(&store)?;
        // `Uploading` is a transient, in-pass claim. A daemon that died
        // mid-upload leaves entries in it, and nothing else would ever move
        // them out: never uploaded, never offered again. Re-sending is safe
        // -- the receipts file dedups by session hash, so a session that
        // did reach the server comes back `AlreadySubmitted`.
        if queue.release_in_flight() {
            queue.save(&store)?;
        }
        // One-time upgrade: retire entries that stand for a single subagent
        // transcript.
        //
        // Those entries were minted when each `<uuid>/subagents/*.jsonl`
        // file was discovered as a session in its own right. Discovery no
        // longer yields those paths, so `find_session` cannot resolve them:
        // an approved one would fail with `session-file-vanished` and a
        // pending one would sit in the queue until it aged out. Both are
        // safe and both are confusing, and leaving them would keep offering
        // a fragment whose opening prompt was written by the parent agent
        // rather than by the contributor. Superseding says what actually
        // happened -- the conversation each belongs to is offered whole
        // instead -- and releases the stored preview envelope on the next
        // sweep.
        if regroup_subagent_entries(&mut queue) {
            queue.save(&store)?;
        }
        // Release the pins on stored previews nobody is waiting on before
        // sweeping, so a store left over from an earlier version of the
        // daemon -- previews written for entries the contributor never
        // asked about, all of them still pending -- drains on the first
        // start rather than waiting for a tick.
        if !super::approved_envelope::release_stale_pins(&store, &mut queue).is_empty() {
            queue.save(&store)?;
        }
        // Sweep stored preview envelopes on the way up. A daemon that died
        // between resolving an entry and sweeping, or one whose queue file
        // was replaced underneath it, would otherwise leave redacted trace
        // content on disk with no entry that needs it.
        let _ = super::approved_envelope::sweep(&store, &queue.pinned_entry_ids());
        let policy = ProjectPolicy::load(&store)?;
        let state = DaemonState::load(&store)?;
        let settings = DaemonSettings::load_with_cloud_credentials(&store).or_else(|_| {
            let mut settings = DaemonSettings::load(&store)?;
            settings.near_ai_inference = None;
            settings.near_ai_session = None;
            settings.cloud_storage_unavailable = true;
            Ok::<_, anyhow::Error>(settings)
        })?;
        // Built here from the declaration this settings file carries at
        // startup. A later edit does not wait for a restart:
        // `set_settings` rebuilds the instance in place.
        let routing = RwLock::new(RoutingSnapshot {
            declaration: settings.ironwire.clone(),
            ledger: super::settings::ironwire_ledger_for(settings.ironwire.as_ref()),
            derived: false,
        });
        let (events, _) = broadcast::channel(256);
        let paused = state.paused;
        Ok(Self {
            store,
            queue: Mutex::new(queue),
            policy: Mutex::new(policy),
            state: Mutex::new(state),
            settings: Arc::new(Mutex::new(settings)),
            health: Mutex::new(HealthState::default()),
            paused: AtomicBool::new(paused),
            quiesced: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            shutdown_signal: Arc::new(Notify::new()),
            events,
            previews: Arc::new(PreviewScheduler::default()),
            routing,
            private_inference_endpoint: Mutex::new(None),
            routing_had_rows: AtomicBool::new(false),
            // Constructed, never started. Nothing binds until the reconcile
            // pass reads `private_inference` out of settings and finds it
            // on -- a daemon that has never been asked hosts nothing.
            private_inference: Arc::new(tokio::sync::Mutex::new(
                super::private_inference::ironwire_home()
                    .map(super::private_inference::PrivateInference::new),
            )),
            private_inference_terminating: AtomicBool::new(false),
            private_inference_generation: std::sync::atomic::AtomicU64::new(0),
            token_review_generation: std::sync::atomic::AtomicU64::new(0),
            near_ai_credential_changes: std::sync::atomic::AtomicU64::new(0),
            private_inference_stop_confirmed: Arc::new(AtomicBool::new(false)),
            private_inference_changed: tokio::sync::Notify::new(),
            private_inference_stop_task: Mutex::new(None),
            proxy_runtime: std::sync::OnceLock::new(),
            private_inference_state: Arc::new(Mutex::new(
                super::private_inference::PrivateInferenceState::Off,
            )),
            harness_plans: super::harness::PlanStore::default(),
        })
    }

    /// Bring the hosted IronWire in line with the `private_inference`
    /// setting, and notice a proxy that ended on its own.
    ///
    /// Idempotent, and safe to call on every poll tick: with the switch off
    /// and nothing held it does no work, and with a proxy running it only
    /// asks whether the task has finished.
    ///
    /// A proxy that will not start is a reported state, never an error out
    /// of here: private inference failing must not stop the watch, the
    /// upload pass, or the daemon.
    /// Record the runtime this daemon is running on, so a proxy started
    /// from any path lives on it.
    ///
    /// Called from `start_embedded`, which is `async` and therefore always
    /// executing on the real daemon runtime in both entry points -- the
    /// standalone binary and the embedded one. Idempotent: a second call is
    /// a no-op, because the first runtime to claim this is the one that
    /// outlives every request.
    pub(crate) fn adopt_runtime(&self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = self.proxy_runtime.set(handle);
        }
    }

    /// Whether a runtime has been claimed for hosted proxies.
    #[cfg(test)]
    pub(crate) fn has_adopted_runtime(&self) -> bool {
        self.proxy_runtime.get().is_some()
    }

    /// Take on a credential a ceremony wrote while this daemon was running,
    /// and treat it as a change to what the proxy is.
    ///
    /// The gap this closes: the ceremony writes the settings document from a
    /// detached task and cannot reach this struct, so the daemon's in-memory
    /// copy still says the contributor has no key. Reading the count first
    /// keeps the ordinary pass off the disk entirely -- it is zero against
    /// zero for every daemon whose contributor ran no ceremony.
    ///
    /// Both Cloud credentials are taken from the document that comes back.
    /// The rest of the in-memory copy is authoritative and must stay so: the
    /// ceremony's read-modify-write started from whatever was on disk when it
    /// happened to run, and adopting all of it would let a mint quietly
    /// revert a setting the contributor changed while the browser was open.
    ///
    /// The observed count is stored only once the change has been applied. A
    /// settings document that will not load leaves it where it was, so the
    /// next pass tries again rather than dropping the credential forever.
    async fn absorb_near_ai_credential_change(&self) {
        let observed = super::nearai_credential::ceremony::change_count(self.store.dir());
        if observed == self.near_ai_credential_changes.load(Ordering::Acquire) {
            return;
        }
        let store = self.store.clone();
        let Ok(Ok(stored)) = tokio::task::spawn_blocking(move || {
            DaemonSettings::load_with_cloud_credentials(&store)
        })
        .await
        else {
            return;
        };
        let Ok(locks) = crate::daemon::nearai_credential::session::coordination(self.store.dir())
        else {
            return;
        };
        let Ok(_commit) = locks.commit.lock() else {
            return;
        };
        let Ok(disk) = super::settings::DaemonSettings::load(&self.store) else {
            return;
        };
        if crate::daemon::cloud_credential_lifecycle::ensure_current(&disk, &stored).is_err() {
            return;
        }
        let mut settings = self.settings.lock().expect("settings lock");
        if settings.near_ai_inference != stored.near_ai_inference {
            settings.near_ai_inference = stored.near_ai_inference;
            // Same bump, and for the same reason, as a changed proxy
            // declaration in `handle_set_settings`: IronWire resolves its
            // credentials once, while building the registry, so a key that
            // is merely handed to the host reaches nothing. Advancing the
            // generation is what makes the reconcile below stop the proxy
            // and start it again on the key. Taken while the settings lock
            // is held, as there, so the value a pass reads and the switch it
            // read belong to the same document.
            self.private_inference_generation
                .fetch_add(1, Ordering::Release);
        }
        settings.near_ai_session = stored.near_ai_session;
        settings.cloud_credentials = stored.cloud_credentials;
        settings.cloud_storage_unavailable = false;
        drop(settings);
        self.near_ai_credential_changes
            .store(observed, Ordering::Release);
    }

    pub(crate) async fn reconcile_private_inference(&self) {
        if self.private_inference_terminating.load(Ordering::Acquire) {
            return;
        }
        // OS reads may wait for an unlock prompt. They must not hold proxy
        // ownership while Forget or shutdown needs to withdraw a live key.
        // Absorption rechecks disk authority under the credential commit lock.
        self.absorb_near_ai_credential_change().await;
        let mut held = self.private_inference.lock().await;
        // Read after acquiring lifecycle ownership: a queued reconciliation
        // must not replay a setting superseded while it waited for that lock.
        let (on, generation, credential, capture_enabled) = {
            let settings = self.settings.lock().expect("settings lock");
            (
                !self.private_inference_terminating.load(Ordering::Acquire)
                    && settings.private_inference,
                self.private_inference_generation.load(Ordering::Acquire),
                // Read here, under the same lock as the switch, so a key
                // obtained while the daemon runs is picked up on the next
                // pass. Cloned out rather than borrowed: the settings lock
                // must not be held across the proxy start.
                settings
                    .near_ai_inference
                    .as_ref()
                    .map(|c| ironwire_proxy::embed::HostSecret::from(c.key.clone())),
                settings.token_capture_enabled,
            )
        };
        let Some(host) = held.as_mut() else {
            // No home resolves on this machine, so there is nowhere to put
            // a ledger, a token, or a pointer. Saying so is better than
            // reporting `Off` beside a switch the contributor turned on.
            let reported = if on {
                super::private_inference::PrivateInferenceState::Failed {
                    label: super::private_inference::LABEL_START_FAILED,
                }
            } else {
                super::private_inference::PrivateInferenceState::Off
            };
            *self
                .private_inference_state
                .lock()
                .expect("private inference state lock") = reported;
            return;
        };
        host.set_runtime(self.proxy_runtime.get().cloned());
        host.set_credential(credential);
        host.set_token_capture(capture_enabled);
        if host.accept_generation(generation) {
            if on {
                // A cycle, not a stop: `apply(false)` alone leaves the start
                // below looking at a shutdown still in flight, which it
                // declines, so the proxy stays dark until some later pass.
                // Tolerable while the only reason to be here with the switch
                // still on was a changed port; not tolerable for a
                // credential, where coming back up a minute later is the
                // same dead end as never coming back. `cycle` drains only
                // when draining is bounded -- see its doc.
                host.cycle().await;
            } else {
                host.apply(false).await;
            }
        }
        host.apply(on).await;
        loop {
            // Settings commit and state publication share this ordering. A
            // completed start cannot publish Running for superseded consent.
            let published = {
                let settings = self.settings.lock().expect("settings lock");
                let mut state = self
                    .private_inference_state
                    .lock()
                    .expect("proxy state lock");
                let stale = self.private_inference_terminating.load(Ordering::Acquire)
                    || self.private_inference_generation.load(Ordering::Acquire) != generation
                    || !settings.private_inference;
                if stale && matches!(host.state(),
                    super::private_inference::PrivateInferenceState::Running { .. }
                    | super::private_inference::PrivateInferenceState::RunningWithoutBackends { .. }) {
                    None
                } else {
                    *self.private_inference_endpoint.lock().expect("proxy endpoint lock") = host.owned_endpoint();
                    self.rebuild_effective_routing(&settings);
                    let reported = host.state();
                    let changed = *state != reported;
                    *state = reported;
                    Some(changed)
                }
            };
            if let Some(changed) = published {
                drop(held);
                if changed {
                    self.private_inference_changed.notify_one();
                    self.publish(EVENT_STATUS_CHANGED, serde_json::json!({}));
                }
                return;
            }
            host.apply(false).await;
        }
    }

    /// Begin terminal cleanup on the daemon runtime, retaining only proxy state.
    /// The cleanup task cannot restart hosting or keep contributor queues alive.
    pub(crate) fn request_private_inference_stop(&self) {
        let mut task = self
            .private_inference_stop_task
            .lock()
            .expect("proxy stop task lock");
        if task.is_some() {
            return;
        }
        {
            let _state = self
                .private_inference_state
                .lock()
                .expect("proxy state lock");
            self.private_inference_terminating
                .store(true, Ordering::Release);
        }
        *self
            .private_inference_endpoint
            .lock()
            .expect("proxy endpoint lock") = None;
        self.withdraw_derived_routing();
        let Some(runtime) = self
            .proxy_runtime
            .get()
            .cloned()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
        else {
            return;
        };
        if self.private_inference.try_lock().is_ok_and(|held| {
            held.as_ref()
                .is_none_or(|host| !host.has_pending_ownership())
        }) {
            *self
                .private_inference_state
                .lock()
                .expect("proxy state lock") = super::private_inference::PrivateInferenceState::Off;
            self.private_inference_stop_confirmed
                .store(true, Ordering::Release);
            return;
        }
        {
            let mut state = self
                .private_inference_state
                .lock()
                .expect("proxy state lock");
            let port = match &*state {
                super::private_inference::PrivateInferenceState::Running { port }
                | super::private_inference::PrivateInferenceState::RunningWithoutBackends {
                    port,
                } => Some(*port),
                super::private_inference::PrivateInferenceState::Stopping { port } => *port,
                _ => None,
            };
            if !matches!(
                *state,
                super::private_inference::PrivateInferenceState::Failed { .. }
            ) {
                *state = super::private_inference::PrivateInferenceState::Stopping { port };
            }
        }
        let held = Arc::clone(&self.private_inference);
        let state = Arc::clone(&self.private_inference_state);
        let events = self.events.clone();
        let confirmed = Arc::clone(&self.private_inference_stop_confirmed);
        *task = Some(runtime.spawn(async move {
            let mut held = held.lock().await;
            let Some(host) = held.as_mut() else {
                *state.lock().expect("proxy state lock") =
                    super::private_inference::PrivateInferenceState::Off;
                confirmed.store(true, Ordering::Release);
                return true;
            };
            host.apply(false).await;
            *state.lock().expect("proxy state lock") = host.state();
            let _ = events.send(Event {
                event: EVENT_STATUS_CHANGED.to_string(),
                data: serde_json::json!({}),
            });
            let stopped = host.finish_stop().await;
            *state.lock().expect("proxy state lock") = host.state();
            let _ = events.send(Event {
                event: EVENT_STATUS_CHANGED.to_string(),
                data: serde_json::json!({}),
            });
            confirmed.store(stopped, Ordering::Release);
            stopped
        }));
    }

    /// Bound the host's cleanup wait, including waiting for an in-progress start.
    /// A deadline does not abort the retained cleanup task or report Off.
    pub(crate) async fn stop_private_inference(&self) {
        const STOP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
        if !self.finish_private_inference_stop(STOP_BUDGET).await {
            tracing::warn!(
                reason = "private-inference-drain-pending",
                "proxy cleanup is still pending"
            );
        }
    }

    async fn finish_private_inference_stop(&self, budget: std::time::Duration) -> bool {
        self.request_private_inference_stop();
        if self
            .private_inference_stop_confirmed
            .load(Ordering::Acquire)
        {
            return true;
        }
        let completed = tokio::time::timeout(budget, async {
            loop {
                let finished = self
                    .private_inference_stop_task
                    .lock()
                    .expect("proxy stop task lock")
                    .as_ref()
                    .is_some_and(|task| task.is_finished());
                if finished {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        completed
            && self
                .private_inference_stop_confirmed
                .load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn private_inference_stop_confirmation_for_test(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.private_inference_stop_confirmed)
    }

    pub(crate) fn private_inference_is_stopping(&self) -> bool {
        matches!(
            *self
                .private_inference_state
                .lock()
                .expect("proxy state lock"),
            super::private_inference::PrivateInferenceState::Stopping { .. }
        )
    }

    /// Replace the held private-inference instance with one rooted at
    /// `home` on an ephemeral port.
    ///
    /// Test-only, and the reason it exists: the production instance is
    /// rooted at `$IRONWIRE_HOME` or the real home directory, on whatever
    /// port IronWire's own configuration names. A test that exercised that
    /// instance would bind a developer's actual IronWire port and collide
    /// with a parallel test doing the same. Mutating `$IRONWIRE_HOME`
    /// instead would be process-global and race every other test in the
    /// binary.
    #[cfg(test)]
    pub(crate) fn install_private_inference_for_test(&self, home: std::path::PathBuf, port: u16) {
        *self
            .private_inference
            .try_lock()
            .expect("uncontended test proxy") = Some(
            super::private_inference::PrivateInference::with_port(home, port),
        );
    }

    /// The `private_inference_state` object `get_settings` and `status`
    /// both report: a lowercase label, and the port when there is one.
    ///
    /// Reported separately from the `private_inference` boolean beside it
    /// because the two are different facts. The boolean is what the
    /// contributor asked for; this is what actually happened, and a shell
    /// that renders the boolean alone would show a proxy as on while it was
    /// refusing to start.
    fn private_inference_value(&self) -> serde_json::Value {
        let state = self
            .private_inference_state
            .lock()
            .expect("private inference state lock")
            .clone();
        // The label, not `state.label()`: while the proxy is running, which
        // account answers is part of what a shell has to say, and the honest
        // answer includes "not known". The ledger is absent whenever this
        // daemon is not running a proxy it owns, and `nearai_authenticated`
        // is `None` until a status read succeeds -- both reach the unknown
        // label rather than the plain running one, which is the direction
        // this has to fail in.
        let destination = self
            .routing_ledger()
            .and_then(|ledger| ledger.nearai_authenticated());
        serde_json::json!({
            "state": state.label_for(destination),
            "port": state.port(),
        })
    }

    /// The port a tool's config would be pointed at, or `None`.
    ///
    /// Two sources, in this order, and the order is the point:
    ///
    /// 1. the port this daemon's own hosted listener actually bound, when it
    ///    is up. What is running beats what was asked for -- a config naming
    ///    a port nothing bound sends a tool's calls into a closed socket.
    /// 2. the port the contributor declared for a proxy they run themselves,
    ///    which is the machine where this daemon hosts nothing and the answer
    ///    still exists.
    ///
    /// `None` on a machine where nothing is answering and nothing was
    /// declared. That is not a failure to report: it is the state where a
    /// connect has no destination to write, and `harness_plan` refuses it by
    /// name rather than writing a guess into somebody's config file.
    pub(crate) fn destination_port(&self) -> Option<u16> {
        if let Some(port) = self
            .private_inference_state
            .lock()
            .expect("private inference state lock")
            .port()
        {
            return Some(port);
        }
        self.settings
            .lock()
            .expect("settings lock")
            .ironwire
            .as_ref()
            .and_then(super::settings::IronWireDeclaration::port)
    }

    /// Whether the destination a connect would name can answer anything.
    ///
    /// Presence of the inference credential, never the key: the boolean is all
    /// that leaves this function, the same treatment `redacted_settings` gives
    /// the same record.
    ///
    /// Only asked of a destination this daemon hosts. A proxy the contributor
    /// declared and runs themselves answers from an account whose credential
    /// was never handed to us, so demanding ours would refuse a connect that
    /// is perfectly good and leave no way to make it work. `destination_port`
    /// prefers the hosted listener in exactly the same order, so the two
    /// agree about which destination is being described.
    ///
    /// True when nothing is hosted and nothing is declared. That case is
    /// already refused as having no destination at all, and answering it
    /// "uncredentialed" would put the wrong name on it.
    pub(crate) fn destination_credentialed(&self) -> bool {
        if self
            .private_inference_state
            .lock()
            .expect("private inference state lock")
            .port()
            .is_none()
        {
            return true;
        }
        self.settings
            .lock()
            .expect("settings lock")
            .near_ai_inference
            .is_some()
    }

    /// Whether this contributor is admitted on evidence rather than on an
    /// invite -- `WitnessSettings::admission_evidence`.
    ///
    /// `None` when the config could not be read, which is a different fact
    /// from "off" and is kept apart from it here so callers do not have to
    /// guess. `add_admission_setting` reports the same three-way answer on
    /// the wire.
    pub(crate) fn admission_evidence(&self) -> Option<bool> {
        let cfg = self.store.load_config().ok()?;
        Some(super::contribution_eligibility::evidence_flag(cfg.as_ref()))
    }

    /// Source roots with the daemon's live routing ledger attached.
    ///
    /// Settings describe the declaration; the daemon owns the instance.
    /// Building a ledger per call would hand every caller its own cold
    /// snapshot, which is the defect this helper exists to prevent -- see
    /// `DaemonSettings::source_roots`, which stays bare on purpose.
    pub(crate) fn source_roots_with_routing(&self) -> crate::source::SourceRoots {
        let (roots, bodies, ledger) = {
            let s = self.settings.lock().expect("settings lock");
            (
                s.source_roots(&self.store),
                // The second, separate switch. Read from the same settings
                // snapshot as the declaration it derives its path from, so
                // a `set_settings` landing mid-call cannot produce a
                // directory from one declaration and a decision from
                // another.
                super::settings::attested_bodies_dir_for(
                    s.ironwire.as_ref(),
                    s.ironwire_attested_bodies,
                ),
                self.routing_ledger()
                    .map(|l| l as Arc<dyn crate::routing::RoutingLedger>),
            )
        };
        // Never without a ledger. `all_sources` already builds no overlay in
        // that case, so this is belt and braces -- and it is the belt worth
        // having: it states, at the one place the daemon decides, that a
        // body store is only ever read for a proxy this daemon is actually
        // reading rows from.
        let bodies = bodies.filter(|_| ledger.is_some());
        roots.with_routing(ledger).with_attested_bodies(bodies)
    }

    /// The routing ledger the daemon currently holds, if any.
    ///
    /// Every reader goes through here rather than touching the lock, so the
    /// guard is never held for longer than the clone -- in particular never
    /// across the await in [`Self::refresh_routing`], where holding it would
    /// block `set_settings` for the length of a network call.
    /// A poisoned lock reads as no ledger, and never as a panic. Before the
    /// hot-swap this was a plain `Option` that could not fail, and the
    /// promise made of the submission path -- which reaches here through
    /// `source_roots_with_routing` -- was that it cannot. Absence is
    /// already the state every caller handles, and it is the state a
    /// vanished proxy produces, so the one answer costs a trace nothing.
    pub(crate) fn routing_ledger(&self) -> Option<Arc<crate::routing::ironwire::IronWireLedger>> {
        self.routing
            .read()
            .ok()
            .and_then(|held| held.ledger.as_ref().map(Arc::clone))
    }

    /// Rebuild only when the effective endpoint changes, preserving warm rows.
    /// Caller holds settings; lock order is settings -> endpoint -> routing.
    pub(crate) fn rebuild_effective_routing(&self, settings: &DaemonSettings) {
        let owned = self
            .private_inference_endpoint
            .lock()
            .expect("proxy endpoint lock");
        let declaration = super::private_inference::effective_metadata_declaration(
            settings.ironwire.as_ref(),
            settings.private_inference
                && !self.private_inference_terminating.load(Ordering::Acquire),
            owned.as_ref(),
        );
        let derived = settings.ironwire.is_none() && declaration.is_some();
        let mut held = self.routing.write().expect("routing lock");
        if held.declaration == declaration {
            held.derived = derived;
            return;
        }
        let ledger = super::settings::ironwire_ledger_for(declaration.as_ref());
        *held = RoutingSnapshot {
            declaration,
            ledger,
            derived,
        };
        self.routing_had_rows.store(false, Ordering::Relaxed);
    }

    fn withdraw_derived_routing(&self) {
        let mut held = self.routing.write().expect("routing lock");
        if held.derived {
            *held = RoutingSnapshot {
                declaration: None,
                ledger: None,
                derived: false,
            };
            self.routing_had_rows.store(false, Ordering::Relaxed);
        }
    }

    /// Refresh the routing ledger, if the contributor declared one, and
    /// report a data-state transition.
    ///
    /// Infallible by construction: `IronWireLedger::refresh` never returns
    /// an error and carries its own short timeout, so awaiting it here
    /// cannot fail or stall the poll tick that calls this.
    pub(crate) async fn refresh_routing(&self) {
        let derived = self.routing.read().is_ok_and(|held| held.derived);
        if derived {
            // The periodic pass previously refreshed before noticing proxy
            // exit. Withdraw an observed-dead owner's reader before any new
            // metadata request can present its token on the former port.
            self.reconcile_private_inference().await;
        }
        let Some(ledger) = self.routing_ledger() else {
            return;
        };
        ledger.refresh().await;
        if let Some(has_rows) = self.routing_transition(ledger.has_rows()) {
            // Hash-only by construction: `has_rows` is a bool, and nothing
            // else about the ledger -- port, token, row contents -- appears
            // here. A machine whose proxy was installed today legitimately
            // logs `has_rows=false` once; that is not an error.
            tracing::info!(has_rows, "routing ledger data state changed");
        }
    }

    /// Whether `has_rows` differs from the state last reported for the
    /// routing ledger, updating the reported state either way.
    ///
    /// Returns the new state only on an actual change, so a caller logs
    /// once per transition rather than once per poll -- the same shape as
    /// `HealthState::fail`/`resolve`, but for a condition that is not an
    /// error and must never be treated as one.
    fn routing_transition(&self, has_rows: bool) -> Option<bool> {
        let previous = self.routing_had_rows.swap(has_rows, Ordering::Relaxed);
        (previous != has_rows).then_some(has_rows)
    }

    pub fn publish(&self, event: &str, data: serde_json::Value) {
        // A send with no subscribers is not an error: the daemon runs happily
        // with no application attached.
        let _ = self.events.send(Event {
            event: event.to_string(),
            data,
        });
    }

    fn logged_in(&self) -> bool {
        super::uploader::enrollment_is_live(&self.store)
    }

    /// Whether the daemon is currently paused, accounting for a timed pause
    /// that has lapsed.
    ///
    /// An elapsed timed pause auto-clears here (and persists the clear)
    /// rather than leaving the daemon paused until an explicit `resume`: an
    /// app-side timer would die with the app and silently fail to un-pause
    /// it otherwise.
    pub fn is_paused(&self, now: chrono::DateTime<Utc>) -> bool {
        if !self.paused.load(Ordering::Relaxed) {
            return false;
        }
        let mut state = self.state.lock().expect("state lock");
        if let Some(until) = state.paused_until {
            if now >= until {
                state.paused_until = None;
                state.paused = false;
                let _ = state.save(&self.store);
                drop(state);
                self.paused.store(false, Ordering::Relaxed);
                self.publish(EVENT_STATUS_CHANGED, serde_json::json!({}));
                return false;
            }
        }
        // Read `state.paused` rather than returning `true` unconditionally:
        // two concurrent readers both pass the atomic check above, but only
        // one of them actually clears the lapsed pause (it wins the `state`
        // lock first); the other must not report a pause that its sibling
        // call just resolved.
        state.paused
    }

    /// Today's volume budget, and how much approved work it is holding.
    ///
    /// Read-only: `budget_snapshot` rolls the day on a copy, so polling
    /// `status` cannot move the daemon's own counters.
    ///
    /// Approved entries never appear on `list_pending` -- that method
    /// returns `Pending` only -- so a shell has no row it could annotate.
    /// A count and a byte total on `status` are the only place the
    /// condition can be told, which is why it lands here rather than on a
    /// queue entry.
    pub fn daily_budget(&self, now: chrono::DateTime<Utc>) -> super::uploader::DailyBudget {
        let approved: Vec<super::queue::QueueEntry> = {
            let queue = self.queue.lock().expect("queue lock");
            queue
                .all()
                .iter()
                .filter(|e| e.state == super::queue::QueueState::Approved)
                .cloned()
                .collect()
        };
        let state = self.state.lock().expect("state lock");
        let settings = self.settings.lock().expect("settings lock");
        super::uploader::budget_snapshot(&approved, &state, &settings, now)
    }

    /// The tray's whole world in one object.
    pub fn status_value(&self) -> serde_json::Value {
        let now = Utc::now();
        // Taken before the queue lock below, and released with it, because
        // `daily_budget` takes the queue, state, and settings locks itself.
        let budget = self.daily_budget(now);
        // Taken before the locks below for the same reason as `budget`:
        // this reads the routing lock, and taking locks in one order
        // everywhere is what keeps that safe.
        let routing = self.routing_value();
        // Taken before the locks below for the same reason as `routing`:
        // one lock order everywhere.
        let private_inference = self.private_inference_value();
        let queue = self.queue.lock().expect("queue lock");
        let health = self.health.lock().expect("health lock");
        let cfg = self.store.load_config().ok().flatten();
        serde_json::json!({
            "schema_version": IPC_SCHEMA,
            "logged_in": self.logged_in(),
            "tenant_id": cfg.as_ref().map(|c| c.tenant_id.clone()),
            "consent_scopes": cfg.as_ref().map(|c| c.consent_scopes.clone()).unwrap_or_default(),
            "paused": self.is_paused(now),
            "queue_depth": queue.pending().len(),
            "next_digest_at": self.next_digest_at(),
            "health": {
                "last_error_label": health.last_error_label,
                "since": health.since,
            },
            // Additive. The daily cap is enforced whatever else is wrong,
            // and `health` can only carry one label at a time, so this is
            // reported independently of it -- see `DailyBudget`.
            "daily_budget": {
                "bytes_today": budget.bytes_today,
                "max_bytes_per_day": budget.max_bytes_per_day,
                "bytes_remaining": budget.bytes_remaining,
                "uploads_today": budget.uploads_today,
                "max_uploads_per_day": budget.max_uploads_per_day,
                "uploads_remaining": budget.uploads_remaining,
                "resets_at": budget.resets_at,
                "blocked": budget.blocked(),
                "blocked_entries": budget.blocked_entries,
                "blocked_bytes": budget.blocked_bytes,
            },
            // Additive, and three-valued on purpose. `health` reports
            // faults; none of these three is one, so like `daily_budget`
            // this sits beside it rather than inside it.
            "routing": routing,
            // Also additive, and deliberately not folded into `routing`:
            // routing is about reading a proxy's ledger, this is about
            // whether this daemon is hosting one.
            "private_inference_state": private_inference,
        })
    }

    /// The `routing` sub-object of [`Self::status_value`].
    ///
    /// Four states, because the two a boolean can carry are the defect:
    /// "no proxy declared" and "declared but reading nothing" are different
    /// situations with different answers, and only the second is worth
    /// telling a contributor about. `has_rows` alone cannot tell them apart
    /// -- the distinction lives in the `Option` on shared state, which is
    /// why this reads the held instance rather than the settings blob.
    ///
    /// The fourth is [`ROUTING_TOKEN_UNREADABLE`]: declared, and no reader
    /// could be built. The held instance cannot express that one either --
    /// it is `None` for it, exactly as it is for a contributor who declared
    /// nothing -- so the declaration is read as well. Without it the card
    /// says "Off" beside a switch the contributor left on.
    ///
    /// `last_refresh_at` is reported alongside because `has_rows` is a poor
    /// health signal on its own: it says data exists, not that the proxy
    /// answers now. A proxy that died an hour ago still has rows.
    fn routing_value(&self) -> serde_json::Value {
        let Ok(held) = self.routing.read() else {
            return serde_json::json!({"state":ROUTING_UNKNOWN, "derived":false,
                "last_refresh_at":null, "unreadable_rows":0});
        };
        let (declared, ledger, derived) = {
            (
                held.declaration
                    .as_ref()
                    .and_then(super::settings::IronWireDeclaration::port)
                    .is_some(),
                held.ledger.as_ref().map(Arc::clone),
                held.derived,
            )
        };
        drop(held);
        let Some(ledger) = ledger else {
            return serde_json::json!({
                "state": if declared { ROUTING_TOKEN_UNREADABLE } else { ROUTING_NOT_DECLARED },
                "derived": derived,
                // No reader was built, so nothing has ever been checked.
                "last_refresh_at": serde_json::Value::Null,
                "unreadable_rows": 0,
            });
        };
        serde_json::json!({
            "state": if ledger.has_rows() { ROUTING_ROWS_SEEN } else { ROUTING_AWAITING_ROWS },
            "derived": derived,
            "last_refresh_at": ledger.last_refresh_at(),
            // Zero everywhere it is working. Non-zero is the only signal a
            // contributor gets that the proxy is serving rows this client
            // cannot read -- the alternative is enrichment that thins out
            // with nothing anywhere saying so. A count, never a row.
            "unreadable_rows": ledger.unreadable_rows(),
        })
    }

    fn next_digest_at(&self) -> Option<chrono::DateTime<Utc>> {
        let state = self.state.lock().expect("state lock");
        let settings = self.settings.lock().expect("settings lock");
        state
            .last_digest_at
            .map(|t| t + chrono::Duration::seconds(settings.digest_interval_secs as i64))
    }

    fn snapshot_value(&self) -> serde_json::Value {
        let admission_evidence = self.admission_evidence();
        let pending: Vec<serde_json::Value> = {
            let queue = self.queue.lock().expect("queue lock");
            queue
                .pending()
                .iter()
                .map(|e| entry_value(e, admission_evidence))
                .collect()
        };
        serde_json::json!({
            "pending": pending,
            "status": self.status_value(),
        })
    }
}

/// Recompute every queue entry's `project_label` against the current
/// known-key set (every configured project plus every project already in
/// the queue) and rewrite any that changed. Returns whether anything
/// changed, so the caller knows whether to persist and publish.
///
/// This is the single implementation of "what does a project collide
/// with, and should this entry's label change" -- both `watcher::tick`
/// (after every poll) and `set_project_mode` (immediately after a policy
/// edit) call it, so a queue entry's stored label can never be computed by
/// two different pieces of logic that drift apart. It takes already-locked
/// guards rather than locking `DaemonShared` itself, since every caller
/// already holds (or is about to take) both locks at the point it needs
/// this.
pub fn relabel_queue_entries(policy: &ProjectPolicy, queue: &mut Queue) -> bool {
    let known = known_keys(policy, queue.all().iter().map(|e| e.project_key.clone()));
    let updates: Vec<(Uuid, String)> = queue
        .all()
        .iter()
        .filter_map(|e| {
            let fresh = disambiguated_label(&e.project_key, e.project_path.as_deref(), &known);
            (fresh != e.project_label).then_some((e.entry_id, fresh))
        })
        .collect();
    let changed = !updates.is_empty();
    for (entry_id, label) in updates {
        queue.set_project_label(entry_id, label);
    }
    changed
}

/// The wire shape of a queue entry.
///
/// `path` and `project_key` are deliberately absent: both are local
/// filesystem paths, and applications render `project_label`.
///
/// `project_id` is the opaque handle that makes the label useful for more
/// than rendering: it is the only thing a socket client can pass back to
/// `set_project_mode` to arm or silence the project this entry came from.
/// It is a hash of the key, so it carries no path component (see
/// `policy::project_id_for`).
/// Supersede every live queue entry whose path sits under a `subagents/`
/// directory, because such a path is no longer a session the daemon can
/// discover. Returns whether anything changed.
///
/// Matched on the path shape rather than on the source name: it is the
/// layout, not the adapter, that stopped being addressable. Entries in a
/// terminal state are left exactly as they are -- they are history, and a
/// record of what was uploaded must not be rewritten by an upgrade.
fn regroup_subagent_entries(queue: &mut Queue) -> bool {
    let stale: Vec<uuid::Uuid> = queue
        .all()
        .iter()
        .filter(|e| {
            matches!(
                e.state,
                super::queue::QueueState::Pending | super::queue::QueueState::Approved
            ) && e
                .path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == "subagents")
        })
        .map(|e| e.entry_id)
        .collect();
    if stale.is_empty() {
        return false;
    }
    for entry_id in stale {
        queue.set_state(
            entry_id,
            super::queue::QueueState::Superseded,
            Some("regrouped-under-parent".to_string()),
        );
    }
    true
}

/// A local path rendered for display: `~`-abbreviated, never modified
/// otherwise.
///
/// Takes a PATH, not a key. Callers pass `QueueEntry::project_path` (or
/// `ProjectEntry::display_path`) where they have one and the folded key
/// only as a fallback, because the key is lowercased on macOS and Windows
/// and a contributor should not be shown a spelling of their own directory
/// that exists nowhere on their disk.
///
/// This is the ONE place in this crate that deliberately puts a local
/// filesystem path on the socket, and the bound is stated where the
/// function is rather than in a comment somewhere else:
///
/// > A path may be rendered. It may not be logged, audited, notified, or
/// > persisted to history.
///
/// `project_label` remains the basename and remains the only project string
/// that reaches `daemon-audit.jsonl`, notification text, or a
/// `HistoryRecord` -- see `an_audit_entry_never_carries_a_path` and
/// `no_sink_carries_a_project_path`. The relaxation exists because
/// `disambiguated_label` can keep two projects DISTINCT (`api` and
/// `api (3f9c)`) but can never make them IDENTIFIABLE, and a contributor
/// deciding what to upload from which repository needs the second.
pub fn display_path(project_key: &str) -> String {
    if project_key == UNKNOWN_PROJECT_KEY {
        return UNKNOWN_PROJECT_KEY.to_string();
    }
    let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| h.to_string_lossy().to_string())
        .filter(|h| !h.is_empty())
    else {
        return project_key.to_string();
    };
    // The COMPARISON is case-insensitive on macOS and Windows, and stays
    // that way now that the input is unfolded. It is not a workaround for
    // the key's folding -- it is the filesystem's own rule. `$HOME` and
    // `%USERPROFILE%` are whatever the environment was handed; a shell
    // exporting `HOME=/Users/Zaki` against a disk that spells it
    // `/Users/zaki` names one directory, and on a case-insensitive volume
    // the two are the same prefix. Comparing raw there meant the prefix
    // never matched and every path rendered absolute.
    //
    // Only the comparison folds. The rendered string is cut from the
    // ORIGINAL below, so the tail keeps its case -- which is what was
    // missing while the input was itself a folded key: both halves were
    // lowercase, so there was no case left to preserve.
    match crate::daemon::project_key::fold_case(project_key)
        .strip_prefix(&crate::daemon::project_key::fold_case(&home))
    {
        Some("") => "~".to_string(),
        Some(rest) if rest.starts_with('/') || rest.starts_with('\\') => {
            // Rendered from the ORIGINAL tail so the path keeps the case
            // the filesystem holds. Folding can in principle change a
            // string's length, in which case the boundary is not a
            // character boundary and the folded tail is used instead.
            let tail = project_key
                .get(project_key.len().saturating_sub(rest.len())..)
                .unwrap_or(rest);
            format!("~{tail}")
        }
        _ => project_key.to_string(),
    }
}

pub fn entry_value(
    e: &super::queue::QueueEntry,
    admission_evidence: Option<bool>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "entry_id": e.entry_id,
        "session_hash": e.session_hash,
        "source": e.source,
        // Beside `source`, never replacing it: a consumer uses the adapter
        // name to ask for the same session again, while this is what the
        // conversation says it came from. See `QueueEntry::declared_source`.
        "declared_source": e.declared_source,
        "project_id": project_id_for(&e.project_key),
        "project_label": e.project_label,
        // Rendered, never logged -- see `display_path`. The unfolded half
        // when the entry has one, and the folded key when it does not: an
        // entry written before `project_path` existed still names the right
        // directory, just in the case the key was folded to.
        "project_path": display_path(e.project_path.as_deref().unwrap_or(&e.project_key)),
        // Only when the session ran somewhere other than the project root,
        // which is the fact normalization discards and the folder detail
        // view puts back. Null rather than a repeat of `project_path`, so a
        // shell can render the line only when it says something.
        "session_path": e
            .session_cwd
            .as_deref()
            .map(display_path)
            .filter(|p| p != &display_path(e.project_path.as_deref().unwrap_or(&e.project_key)))
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
        "size_bytes": e.size_bytes,
        "discovered_at": e.discovered_at,
        "state": e.state,
        "reason_label": e.reason_label,
        "attempts": e.attempts,
        "retry_after": e.retry_after,
        "submission_id": e.submission_id,
        // Additive, and the reason the card can be honest about its own
        // extent: one entry can stand for a conversation plus a hundred
        // delegated transcripts, which is material to the consent decision
        // rather than decoration. `subagents_dropped` is non-zero only when
        // the conversation was trimmed to fit the byte budget, and a card
        // showing it is the difference between a trimmed trace and a
        // silently partial one. No ordinal is exposed: there is no "1 of 3"
        // to expose, because nothing in the format supplies one.
        "subagent_count": e.subagent_count,
        "subagents_dropped": e.subagents_dropped,
    });
    // ABSENT, NOT `unknown`, WHENEVER THE SIGNUP FLAG IS OFF.
    //
    // An invited contributor has no eligibility question: everything in
    // their queue is contributable, which is why this whole surface stayed
    // invisible for so long. A field answering a question they do not have
    // would put three shells to work rendering an answer to it, and the
    // first thing any of them would render is a caveat on work that has
    // none.
    //
    // A config that could not be read answers `None` here and is treated the
    // same way, for the same reason: it is not known that the question
    // applies, and `unknown` would assert that it does.
    if admission_evidence == Some(true) {
        // A row the daemon never evaluated -- written before these fields
        // existed, or re-offered after its content moved -- is `unknown`
        // rather than absent. Not evaluated is a different fact from not
        // asked, and degrading "could not tell" into "no" invites a
        // contributor to conclude something false about their own work.
        value["eligibility"] = serde_json::Value::from(
            e.eligibility
                .clone()
                .unwrap_or_else(|| super::contribution_eligibility::STATE_UNKNOWN.to_string()),
        );
        if let Some(reason) = e.eligibility_reason.as_deref() {
            value["eligibility_reason"] = serde_json::Value::from(reason);
        }
    }
    // ALSO ALWAYS PRESENT, AND FOR A DIFFERENT REASON THAN `attestation`.
    //
    // One predicate with two readings. A contributor without an invite reads
    // it as "this one is a candidate for submission"; a contributor with one
    // reads it as "this one is cryptographically attested". The fact is the
    // same either way -- a witness certificate is held for the bytes this
    // entry was pinned to -- so the daemon states it once and the shell
    // picks the wording from the invite status it already holds for the
    // eligibility surface. Two fields, or one field emitted only under the
    // signup flag, would put the second reading out of reach of exactly the
    // contributors it is written for.
    //
    // Both witness routes produce it: `/v1/witness` returns a certificate
    // and `/v1/witness/admission` returns a certificate and admission
    // evidence, stored as one artifact under one pin.
    //
    // This is NOT `attestation` below. That says whether the session carries
    // proof of the model call that produced it; this says whether we hold a
    // witness certificate over the reviewed bytes. A session can have either
    // without the other.
    value["holds_certificate"] = serde_json::Value::Bool(e.holds_witness_certificate());
    // What the witness was HANDED when it issued the certificate above:
    // whether a receipt was among the bodies it certified. Present only
    // while a witnessed review is pinned to this entry, and then exactly as
    // the stored review records it: `{"state", "reason"}`. So it is present
    // only when `holds_certificate` is true; the converse does not hold,
    // because a review written before the record existed holds a
    // certificate and says nothing about this. Absent is "not known" -- no
    // review, a review that predates the record, or a local preview -- and a
    // shell must render it as nothing rather than as either answer. Not a
    // third reading of `holds_certificate`: that says a certificate exists,
    // this says whether attested inference was inside it. See
    // `witness::inference_record`.
    if let Some(record) = &e.attested_inference {
        value["attested_inference"] =
            serde_json::to_value(record).expect("a label-only record serializes");
    }
    // ALWAYS PRESENT, FOR EVERY CONTRIBUTOR.
    //
    // The opposite rule to `eligibility` above, and deliberately. That field
    // answers whether this contributor may send this session, which is a
    // question only an evidence-admitted contributor has. This one answers
    // whether the session carries proof of the model call that produced it,
    // which is a fact about the trace -- and there is no contributor for whom
    // that is not worth knowing. It is about to be worth more than that: the
    // credit scoring function is expected to weight attestations, and a
    // contributor who cannot see which of their sessions carry one cannot act
    // on it.
    //
    // A row the daemon never evaluated -- written before this field existed --
    // is `unknown`. Unlike `eligibility` there is no absent case: the question
    // is never inapplicable, so silence could only mean nobody worked the
    // answer out, and `unknown` is what says that.
    value["attestation"] = serde_json::Value::from(
        e.attestation
            .clone()
            .unwrap_or_else(|| super::attestation_mark::MARK_UNKNOWN.to_string()),
    );
    if let Some(reason) = e.attestation_reason.as_deref() {
        value["attestation_reason"] = serde_json::Value::from(reason);
    }
    value
}

/// `?` for a handler that returns a [`Response`] rather than a `Result`.
///
/// The helpers below return `Result<_, Box<Response>>` so the refusal is built
/// once, next to the check that produces it; this unwraps the value or
/// returns the refusal from the enclosing handler. This local macro has textual
/// scope: only handlers below its definition can use it.
macro_rules! try_response {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(response) => return *response,
        }
    };
}

/// The methods the synchronous dispatcher cannot answer, paired with the
/// refusal label each one sends.
///
/// These methods require asynchronous I/O or lifecycle work. Socket and
/// local callers use `handle_request_async`; the synchronous entry point
/// preserves fixed refusal labels instead of returning an unchecked result.
/// Labels are explicit because several methods share a label that cannot
/// be derived from their names, including the onboarding and profile groups.
const ASYNC_ONLY_METHODS: &[(&str, &str)] = &[
    (
        "prepare_admission_session",
        "admission-setup-requires-async",
    ),
    ("near_account_start", "near-signup-requires-async"),
    ("near_ai_account_enroll", "near-signup-requires-async"),
    ("near_account_capabilities", "near-signup-requires-async"),
    (
        "near_ai_credential_start",
        "near-ai-credential-requires-async",
    ),
    ("native_wallet_flow", "near-signup-requires-async"),
    ("near_ai_funding", "near-ai-funding-requires-async"),
    ("witness_preview_request", "witness-review-requires-async"),
    ("preview_body", "preview-body-requires-async"),
    ("preview_turns", "preview-turns-requires-async"),
    ("quiesce", "quiesce-requires-async"),
    ("probe_routing", "probe-routing-requires-async"),
    ("probe_routed_tools", "probe-routed-tools-requires-async"),
    ("enroll", "enroll-requires-async"),
    ("withdraw", "withdraw-requires-async"),
    ("withdraw_bulk", "withdraw-requires-async"),
    ("set_public_profile", "profile-requires-async"),
    ("clear_public_profile", "profile-requires-async"),
];

pub fn handle_request(shared: &DaemonShared, req: &Request) -> Response {
    if let Some(label) = ASYNC_ONLY_METHODS
        .iter()
        .find(|(name, _)| *name == req.method)
        .map(|(_, label)| *label)
    {
        return Response::err(req.id, ERR_UNAVAILABLE, label);
    }
    match req.method.as_str() {
        "hello" => Response::ok(
            req.id,
            serde_json::json!({
                "schema_version": IPC_SCHEMA,
                "supported_versions": SUPPORTED_VERSIONS,
                "methods": METHODS,
                "events": [
                    EVENT_SNAPSHOT, EVENT_QUEUE_CHANGED, EVENT_STATUS_CHANGED,
                    EVENT_DIGEST_DUE, EVENT_RESYNC_REQUIRED,
                ],
                "max_line_bytes": MAX_LINE_BYTES,
            }),
        ),
        "status" => Response::ok(req.id, shared.status_value()),
        "list_pending" => handle_list_pending(shared, req),
        "list_projects" => handle_list_projects(shared, req),
        // The one project worth offering to arm right now, or nothing.
        //
        // A read, with no side effect: asking does not consume the offer.
        // The shell may draw it, redraw it after a refresh, and draw it
        // again next launch until the contributor answers one way or the
        // other -- which is what makes "Not now" a real answer rather than
        // a dismissal that the next queue refresh undoes.
        //
        // Labels and a count only. The project is named by the same opaque
        // id `list_projects` mints, because the key is a full local path
        // the shell is never given.
        "arming_suggestion" => {
            let policy = shared.policy.lock().expect("policy lock");
            match policy.arming_suggestion(Utc::now()) {
                Some(s) => Response::ok(
                    req.id,
                    serde_json::json!({
                        "project_id": s.project_id,
                        "project_label": s.project_label,
                        "contributed_count": s.contributed_count,
                    }),
                ),
                // Absent rather than null-filled: a shell that receives no
                // suggestion must draw no card, and a null-filled object is
                // a claim about a project this daemon never made.
                None => Response::ok(req.id, serde_json::json!({})),
            }
        }
        // "Not now" against one project's arming offer.
        //
        // Silences it for `ARMING_DECLINE_COOLDOWN_DAYS` rather than
        // forever: the button says "Not now", and a suppression that never
        // lifted would make those words a lie. Settings still arms the
        // project at any point in between, without being asked.
        "decline_arming" => {
            let Some(id) = req.params.get("project_id").and_then(|v| v.as_str()) else {
                return Response::err(req.id, ERR_BAD_PARAMS, "project_id-required");
            };
            // Lock order is policy before queue, as everywhere else.
            let mut policy = shared.policy.lock().expect("policy lock");
            let key = {
                let queue = shared.queue.lock().expect("queue lock");
                let known = known_keys(&policy, queue.all().iter().map(|e| e.project_key.clone()));
                match project_key_for_id(id, &known) {
                    Some(key) => key,
                    None => {
                        return Response::err(req.id, ERR_BAD_PARAMS, ERR_PROJECT_ID_UNRECOGNIZED);
                    }
                }
            };
            policy.decline_arming(&key, Utc::now());
            match policy.save(&shared.store) {
                Ok(()) => Response::ok(req.id, serde_json::json!({ "declined": true })),
                Err(e) => Response::err(req.id, ERR_UNAVAILABLE, &e.to_string()),
            }
        }
        "set_project_mode" => handle_set_project_mode(shared, req),
        "dismiss" => {
            let id = try_response!(entry_id_param(req));
            // A dismissed entry is never previewed again, so drop any
            // scheduled preview for it. If one is already building this
            // cannot stop it mid-parse -- see `PreviewScheduler::cancel` --
            // but the result is discarded rather than delivered or cached,
            // which is the part that matters for a trace just declined.
            shared.previews.cancel(id);
            let mut queue = shared.queue.lock().expect("queue lock");
            queue.set_state(
                id,
                QueueState::Refused,
                Some(super::queue::REASON_DISMISSED.to_string()),
            );
            if let Err(_e) = queue.save(&shared.store) {
                return Response::err(req.id, ERR_UNAVAILABLE, "queue-write-failed");
            }
            drop(queue);
            shared.publish(EVENT_QUEUE_CHANGED, serde_json::json!({}));
            Response::ok(req.id, serde_json::json!({ "ok": true }))
        }
        "preview" => {
            // This synchronous handler cannot run the redaction pipeline (it
            // is async), so this arm reports only the entry itself,
            // honestly flagged as incomplete, rather than the raw file size
            // the old code returned. Real callers never see this: every real
            // entry point (the socket loop, and the CLI via `handle_local`)
            // runs `handle_request_async` instead, which answers `"preview"`
            // for real -- see the module doc's "Sync vs. async dispatch"
            // section.
            let id = try_response!(entry_id_param(req));
            let queue = shared.queue.lock().expect("queue lock");
            match queue.get(id) {
                Some(e) => Response::ok(
                    req.id,
                    serde_json::json!({
                        "entry": entry_value(e, shared.admission_evidence()),
                        "preview_requires_async": true,
                    }),
                ),
                None => Response::err(req.id, ERR_BAD_PARAMS, ERR_UNKNOWN_ENTRY_ID),
            }
        }
        "near_account_status" => super::account_onboarding::handle_status(shared, req),
        "near_account_cancel" => super::account_onboarding::handle_cancel(shared, req),
        "near_ai_credential_status" => super::nearai_credential::handle_status(shared, req),
        "near_ai_credential_cancel" => super::nearai_credential::handle_cancel(shared, req),
        "near_ai_credential_forget" => super::nearai_credential::handle_forget(shared, req),

        // Unlike the probe, discovery opens no connection: it reads one
        // small file the proxy left on disk. So it answers here, on the
        // synchronous path, and a shell can call it before it has anything
        // to declare.
        "discover_routing" => handle_discover_routing(req),
        // Three methods, and there is deliberately no fourth that plans and
        // commits in one call. A contributor sees the exact change to a file
        // this application does not own before anything is written, and a
        // shell has no way to skip that step -- `harness_commit` takes a plan
        // id and nothing else. See `daemon::harness`.
        "harness_list" => super::harness::handle_list(shared, req),
        "harness_plan" => super::harness::handle_plan(shared, req),
        "harness_commit" => super::harness::handle_commit(shared, req),
        "pause" => handle_pause(shared, req),
        "resume" => {
            shared.paused.store(false, Ordering::Relaxed);
            {
                let mut state = shared.state.lock().expect("state lock");
                state.paused = false;
                state.paused_until = None;
                if state.save(&shared.store).is_err() {
                    return Response::err(req.id, ERR_UNAVAILABLE, "state-write-failed");
                }
            }
            shared.publish(EVENT_STATUS_CHANGED, serde_json::json!({}));
            Response::ok(req.id, serde_json::json!({ "paused": false }))
        }
        "cancel" => handle_cancel(shared, req),
        "list_audit" => handle_list_audit(shared, req),
        // A count of `reason_label` across every entry currently on the
        // queue, whatever its state -- no state filter is applied, it is
        // simply whichever entries currently carry a label (in practice
        // that's dismissed, refused, expired, and superseded entries, since
        // nothing else sets one). These labels are already computed by the
        // queue and uploader; this is the first surface that rolls them up.
        //
        // Deliberately NOT named `eligibility_reasons`: every source of a
        // `reason_label` applies to an entry that already exists in the
        // queue. It cannot explain the sessions an app most needs explained
        // -- ones `watcher::tick` discarded before an entry was ever
        // created, via a bare `continue` on a non-`Eligible` verdict or an
        // `Ignore`-mode project. Answering "I finished a session, why is
        // nothing pending?" needs a different, not-yet-built method; this
        // name is chosen so that one can be added later without a contract
        // break.
        "queue_outcome_counts" => {
            let queue = shared.queue.lock().expect("queue lock");
            let mut counts: std::collections::BTreeMap<&str, u64> =
                std::collections::BTreeMap::new();
            for e in queue.all() {
                if let Some(label) = e.reason_label.as_deref() {
                    *counts.entry(label).or_insert(0) += 1;
                }
            }
            Response::ok(req.id, serde_json::json!({ "reasons": counts }))
        }
        "consent_options" => Response::ok(req.id, enroll::consent_options()),
        "set_consent_scopes" => enroll::handle_set_consent_scopes(shared, req),
        "acknowledge_near_ai_notice" => enroll::handle_acknowledge_near_ai_notice(shared, req),
        "list_history" => {
            let limit = req
                .params
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(50)
                .min(1000) as usize;
            match HistoryCache::load(&shared.store) {
                Ok(records) => {
                    let page: Vec<_> = records.into_iter().take(limit).collect();
                    Response::ok(req.id, serde_json::json!({ "history": page }))
                }
                Err(_) => Response::err(req.id, ERR_UNAVAILABLE, "history-read-failed"),
            }
        }
        "history_rollup" => match HistoryCache::load(&shared.store) {
            Ok(records) => {
                let now = Utc::now();
                let mut body = serde_json::to_value(rollup(&records, now))
                    .unwrap_or_else(|_| serde_json::json!({}));
                // The public roster standing rides on this answer as an
                // additive `community` object rather than on a method of its
                // own: History is the one screen that draws it, and it
                // already asks for this. A client that ignores the field is
                // unaffected.
                //
                // No network call here. The poller
                // (`daemon::refresh_community`) owns the fetch and this
                // serves what it last cached -- and serves nothing at all
                // when there is no standing, or when the cached one has
                // aged past the roster's withdrawal bound. The field is
                // then absent rather than null-filled, because a client
                // that receives no standing must draw no section, and a
                // null-filled object is a set of claims about someone's
                // public standing that this daemon never received.
                let standing = {
                    let state = shared.state.lock().expect("state lock");
                    state.community.clone()
                };
                if let Some(standing) = standing.filter(|s| s.is_fresh(now)) {
                    if let (Some(object), Ok(value)) =
                        (body.as_object_mut(), serde_json::to_value(&standing))
                    {
                        object.insert("community".to_string(), value);
                    }
                }
                Response::ok(req.id, body)
            }
            Err(_) => Response::err(req.id, ERR_UNAVAILABLE, "history-read-failed"),
        },
        "refresh_history" => {
            // The poller owns the network. This only asks it to run sooner,
            // and says so rather than queueing an unbounded number of asks.
            Response::ok(req.id, serde_json::json!({ "requested": true }))
        }
        "token_storage_status" => handle_token_storage(shared, req),
        "remove_token_local_copies" => handle_token_storage(shared, req),
        "discard_token_reviews" => handle_token_storage(shared, req),
        "get_settings" => {
            let mut value = {
                let settings = shared.settings.lock().expect("settings lock");
                redacted_settings(&settings)
            };
            add_admission_setting(shared, &mut value);
            Response::ok(req.id, value)
        }
        "set_settings" => handle_set_settings(shared, req),

        "shutdown" => {
            shared.shutdown.store(true, Ordering::Relaxed);
            shared.shutdown_signal.notify_one();
            Response::ok(req.id, serde_json::json!({ "stopping": true }))
        }
        "preview_request" => handle_preview_request(shared, req),
        "preview_visible" => handle_preview_visible(shared, req),
        "preview_cancel" => handle_preview_cancel(shared, req),
        // subscribe is handled by the connection loop, which owns the stream.
        "subscribe" => Response::ok(req.id, serde_json::json!({ "subscribed": true })),
        // Reading a public profile back is a local cache read -- there is no
        // server read-back to make, see `daemon::profile` -- so unlike
        // claiming and withdrawing a handle it is complete here.
        "get_public_profile" => super::profile::handle_get_public_profile(shared, req),
        _ => Response::err(req.id, ERR_UNKNOWN_METHOD, "unknown-method"),
    }
}

fn handle_token_storage(shared: &DaemonShared, req: &Request) -> Response {
    let result = (|| -> anyhow::Result<serde_json::Value> {
        let journal =
            crate::token_bundle::BundleJournal::open(&shared.store.dir().join("token-bundles"))?;
        let discard = req.method == "discard_token_reviews";
        if discard {
            anyhow::ensure!(
                req.params
                    .get("confirmed")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true),
                "token-discard-confirmation-required"
            );
            let mut queue = shared.queue.lock().expect("queue lock");
            let mut ids = Vec::new();
            for entry in queue.all() {
                if super::approved_envelope::load_witnessed(&shared.store, entry.entry_id)?
                    .is_some_and(|a| a.token_bundle.is_some())
                {
                    anyhow::ensure!(
                        !matches!(
                            entry.state,
                            super::queue::QueueState::Approved
                                | super::queue::QueueState::Uploading
                        ),
                        "token-review-undo-approval-first"
                    );
                    if entry.state == super::queue::QueueState::Pending {
                        ids.push(entry.entry_id);
                    }
                }
            }
            shared
                .token_review_generation
                .fetch_add(1, Ordering::AcqRel);
            for id in &ids {
                queue.set_state(
                    *id,
                    super::queue::QueueState::Refused,
                    Some("token-review-discarded".into()),
                );
            }
            queue.save(&shared.store)?;
            for id in ids {
                super::approved_envelope::remove(&shared.store, id)?;
            }
        }
        if req.method != "token_storage_status" {
            journal.remove_local_copies(discard)?;
        }
        let mut value = journal.storage_status(chrono::Utc::now().timestamp().max(0) as u64)?;
        let enabled = shared
            .settings
            .lock()
            .expect("settings lock")
            .token_capture_enabled;
        decorate_token_storage(&mut value, enabled);
        Ok(value)
    })();
    match result {
        Ok(value) => Response::ok(req.id, value),
        Err(_) => Response::err(req.id, ERR_BAD_PARAMS, "token-storage-action-unavailable"),
    }
}

fn decorate_token_storage(value: &mut serde_json::Value, enabled: Option<bool>) {
    if !value.is_object() {
        return;
    }
    value["capture_enabled"] = serde_json::json!(enabled == Some(true));
    value["capture_label"] = serde_json::json!(if enabled == Some(true) {
        "Disable local token capture"
    } else {
        "Enable local token capture"
    });
    value["capture_confirmation"] = serde_json::json!(
        "Token capture stores raw request and response data on this device. It requires configured, supported model targets and restarts the hosted proxy. Contribution and witness sharing remain separate choices."
    );
    value["capture_notice"] = serde_json::json!(match enabled {
        Some(true) =>
            "Local capture requested. The Private AI connection status reports whether the proxy started successfully.",
        Some(false) =>
            "Local capture disabled for the hosted proxy. Existing captures retain their expiry and cleanup rules.",
        None =>
            "Local capture follows the proxy configuration. External proxies are configured separately.",
    });
}

fn add_admission_setting(shared: &DaemonShared, value: &mut serde_json::Value) {
    // What the hosted proxy is actually doing, beside the `private_inference`
    // boolean that says what was asked for. See
    // `DaemonShared::private_inference_value`.
    value["private_inference_state"] = shared.private_inference_value();
    let root = shared.store.dir().join("token-bundles");
    value["token_storage"] = crate::token_bundle::BundleJournal::open(&root)
        .and_then(|j| j.storage_status(chrono::Utc::now().timestamp().max(0) as u64))
        .unwrap_or(serde_json::Value::Null);
    let enabled = value
        .get("token_capture_enabled")
        .and_then(serde_json::Value::as_bool);
    decorate_token_storage(&mut value["token_storage"], enabled);
    value["admission_evidence_required"] = match shared.store.load_config() {
        Ok(cfg) => serde_json::json!(
            cfg.and_then(|c| c.witness)
                .is_some_and(|w| w.admission_evidence)
        ),
        Err(_) => serde_json::Value::Null,
    };
}

fn handle_list_pending(shared: &DaemonShared, req: &Request) -> Response {
    // Read once for the whole list, and outside the queue lock: it reads the
    // config file, and holding the queue across that would put a file read
    // in front of every other queue caller.
    let admission_evidence = shared.admission_evidence();
    let queue = shared.queue.lock().expect("queue lock");
    let entries: Vec<serde_json::Value> = queue
        .pending()
        .iter()
        .map(|e| entry_value(e, admission_evidence))
        .collect();
    Response::ok(req.id, serde_json::json!({ "pending": entries }))
}

// Every project the daemon knows about -- configured *and* merely
// discovered -- with the mode actually in force for each.
//
// It used to report `policy.projects` alone, which meant a project
// the daemon had seen but the contributor had never ruled on was
// invisible here. That is precisely the set an onboarding "which of
// these should never be uploaded" screen has to show: a project
// becomes configured only by being ruled on, so listing only
// configured projects lists only the ones already decided. A
// contributor could not exclude their employer's repository before
// anything was sent, because the screen could not name it.
//
// A discovered row carries `configured: false` and `added_at:
// null`; its `mode` is the effective one, which for an unruled
// project is the notify-only default. Nothing new crosses the
// socket: the label and the id are the same two daemon-derived
// fields the queue entry for that project already carries.
//
// `is_unresolved_bucket` marks the row holding sessions whose
// working directory had no usable final segment. Clients show it
// with a permanent note that these can never be armed -- which is
// enforcement they are REPORTING, not performing: `Policy` refuses
// `auto_upload` for this key independently of any client.
//
// The daemon says so explicitly because it is the only side that
// knows it for free. A client deriving it would have to re-implement
// `project_id_for`'s hash to compare ids, and a client matching on
// `project_label` would break the day that string is reworded --
// which every shell does to it, because the raw label is a slug no
// contributor should read. Clients MUST NOT recognise this row by
// label.
fn handle_list_projects(shared: &DaemonShared, req: &Request) -> Response {
    // What a group-level send would actually do, answerable before the
    // press.
    //
    // A shell has to be able to say "send the 3 of 7 that can be sent"
    // without enumerating rows and classifying them itself -- three shells
    // reimplementing one filter is what put this hole here. It goes on the
    // project row rather than into a dry-run reply because the row is
    // already being fetched to draw the group, the answer has no side
    // effects, and a dry run would cost a second round trip plus an
    // approve-shaped call whose "I did nothing" has to be taken on trust.
    //
    // `contributable_count` is ABSENT when eligibility does not apply, on
    // the same rule as the entry field: an invited contributor has no
    // "3 of 7" to be told about, and `pending_count` alone is their answer.
    let group_filters = super::contribution_eligibility::evidence_flag(
        shared.store.load_config().ok().flatten().as_ref(),
    );
    let policy = shared.policy.lock().expect("policy lock");
    let queue = shared.queue.lock().expect("queue lock");
    let counts = |key: &str| {
        let pending: Vec<&super::queue::QueueEntry> = queue
            .pending()
            .iter()
            .copied()
            .filter(|e| e.project_key == key)
            .collect();
        let contributable = pending
            .iter()
            .filter(|e| {
                super::contribution_eligibility::contributable_in_a_group(e.eligibility.as_deref())
            })
            .count();
        (pending.len(), group_filters.then_some(contributable))
    };
    // Inserted rather than written into the literal, so an inapplicable
    // count is an ABSENT key and not a null. A client tests for the key,
    // exactly as it does for `eligibility`; a null would be one more thing
    // three shells each decide how to read.
    let with_counts = |mut row: serde_json::Value, counts: (usize, Option<usize>)| {
        row["pending_count"] = serde_json::Value::from(counts.0);
        if let Some(contributable) = counts.1 {
            row["contributable_count"] = serde_json::Value::from(contributable);
        }
        row
    };
    let known = known_keys(&policy, queue.all().iter().map(|e| e.project_key.clone()));
    let discovered: std::collections::BTreeMap<String, Option<String>> = queue
        .all()
        .iter()
        .map(|e| (e.project_key.clone(), e.project_path.clone()))
        .filter(|(key, _)| !policy.projects.contains_key(key))
        .collect();
    let projects: Vec<serde_json::Value> = policy
        .projects
        .iter()
        .map(|(key, entry)| {
            let shown = entry.display_path.as_deref().unwrap_or(key);
            with_counts(
                serde_json::json!({
                "project_id": project_id_for(key),
                "project_label": disambiguated_label(key, entry.display_path.as_deref(), &known),
                "project_path": display_path(shown),
                "mode": policy.resolve(key),
                "added_at": entry.added_at,
                "configured": true,
                "is_unresolved_bucket": key == UNKNOWN_PROJECT_KEY,
                }),
                counts(key),
            )
        })
        .chain(discovered.iter().map(|(key, shown)| {
            with_counts(
                serde_json::json!({
                "project_id": project_id_for(key),
                "project_label": disambiguated_label(key, shown.as_deref(), &known),
                "project_path": display_path(shown.as_deref().unwrap_or(key)),
                "mode": policy.resolve(key),
                "added_at": serde_json::Value::Null,
                "configured": false,
                "is_unresolved_bucket": key == UNKNOWN_PROJECT_KEY,
                }),
                counts(key),
            )
        }))
        .collect();
    Response::ok(req.id, serde_json::json!({ "projects": projects }))
}

// Two ways to name a project, for two different callers.
//
// `project_id` is for anything that learned about the project over
// this socket -- a queue entry or a `list_projects` row. It is the
// only identifier such a caller holds, because keys are paths and
// paths do not cross this socket. Without it this method was
// unreachable from every GUI: a label is not an admissible key, and
// the only writer of `policy.projects` is this method itself, so
// there was no way in.
//
// `project_key` is for a caller standing in a terminal, where the
// human types the path: `daemon project <path> --mode ignore`. That
// flow must keep working *before* the project's first session,
// which is exactly when the daemon has no id to offer for it -- it
// cannot mint one for a project it has never discovered. So both
// are supported, deliberately, rather than one replacing the other.
//
// `project_id` wins when both are sent.
fn handle_set_project_mode(shared: &DaemonShared, req: &Request) -> Response {
    let id_param = req.params.get("project_id").and_then(|v| v.as_str());
    let key_param = req.params.get("project_key").and_then(|v| v.as_str());
    if id_param.is_none() && key_param.is_none() {
        return Response::err(req.id, ERR_BAD_PARAMS, "project_id-or-project_key-required");
    }
    let mode: ProjectMode = match req
        .params
        .get("mode")
        .cloned()
        .map(serde_json::from_value::<ProjectMode>)
    {
        Some(Ok(m)) => m,
        _ => return Response::err(req.id, ERR_BAD_PARAMS, "mode-invalid"),
    };
    // A `label` param is accepted on the wire for compatibility with
    // older clients and then IGNORED. It used to be stored verbatim
    // and echoed back by `list_projects` and written into
    // `daemon-audit.jsonl`, so any socket client could inject a
    // path, a token, or a transcript fragment into both of the
    // sinks this crate's label-only rule exists to protect. The
    // label is now derived from the key inside `set_mode`.
    // Lock order is policy before queue, as everywhere else.
    let mut policy = shared.policy.lock().expect("policy lock");
    let (key, audit_label) = {
        let queue = shared.queue.lock().expect("queue lock");
        let known = known_keys(&policy, queue.all().iter().map(|e| e.project_key.clone()));
        // Whichever way the project was named, what comes out of
        // here is a key the daemon itself already holds or has just
        // corroborated on disk -- never a caller's string. That is
        // what keeps the derived label, and so `list_projects` and
        // `daemon-audit.jsonl`, un-injectable.
        let key = match id_param {
            Some(id) => match project_key_for_id(id, &known) {
                Some(key) => key,
                None => {
                    return Response::err(req.id, ERR_BAD_PARAMS, ERR_PROJECT_ID_UNRECOGNIZED);
                }
            },
            None => {
                let key = key_param.unwrap_or_default();
                if !project_key_is_admissible(key, &known) {
                    return Response::err(req.id, ERR_BAD_PARAMS, ERR_PROJECT_KEY_UNRECOGNIZED);
                }
                key.to_string()
            }
        };
        let shown = crate::daemon::policy::display_path_for_key(&key);
        let label = disambiguated_label(&key, shown.as_deref(), &known);
        (key, label)
    };

    // The audit entry goes down FIRST, before anything is armed,
    // the way `acknowledge_near_ai_notice` does it.
    //
    // The reverse order looked equivalent and was not. It saved the
    // policy, then appended, then on an append failure restored the
    // in-memory policy and wrote it back best-effort -- but the
    // disk-full or permissions failure that broke the append breaks
    // that write back just as reliably, and the daemon loads its
    // policy from disk on restart. The fail-closed guarantee did not
    // survive a reboot: autonomy stayed armed on disk with no record
    // of it ever having been armed. Recording first means there is
    // nothing to roll back, so nothing that has to succeed twice.
    //
    // This is visibility, not a security control -- see
    // `daemon::audit` -- but it is the *only* visibility there is
    // here, and the terminal-only restriction it replaced was
    // itself a visibility mechanism.
    //
    // Both locks are dropped for the append itself: it is a
    // whole-file read-modify-write on a synchronous socket handler,
    // and the queue lock in particular is contended with the upload
    // pass. The policy lock is retaken immediately after; a
    // concurrent `set_project_mode` can only interleave two
    // record-then-arm sequences, never produce an armed policy with
    // no record.
    if mode == ProjectMode::AutoUpload {
        drop(policy);
        if let Err(_e) = audit::append(
            &shared.store,
            &AuditEntry {
                at: Utc::now(),
                action: "armed-auto-upload".to_string(),
                project_label: Some(audit_label),
                detail: None,
            },
        ) {
            return Response::err(req.id, ERR_UNAVAILABLE, "audit-write-failed");
        }
        policy = shared.policy.lock().expect("policy lock");
    }

    if let Err(e) = policy.set_mode(&key, mode, Utc::now()) {
        return Response::err(req.id, ERR_BAD_PARAMS, &one_line_label(&e.to_string()));
    }
    if let Err(_e) = policy.save(&shared.store) {
        return Response::err(req.id, ERR_UNAVAILABLE, "policy-write-failed");
    }
    // A newly-configured project can turn a previously-unique queue
    // label into a collision (or vice versa) immediately -- e.g.
    // configuring the client's "api" the moment after "api" was
    // queued bare from the contributor's own repo. Relabel now
    // rather than leaving the queue to lag until the next poll,
    // which would leave two same-basename projects briefly
    // indistinguishable in the one place uploads are approved from.
    // Ignoring a project clears what it already has waiting. Doing
    // it here rather than in the UI means Settings, onboarding and
    // the CLI all get it: before this, ignoring from Settings left
    // the contributor staring at the cards they had just declined.
    //
    // Pending only. See `refuse_pending_for_project`.
    //
    // Leaving `Ignore` undoes exactly that, and only that: see
    // `clear_project_ignored`, which is what makes the
    // confirmation's "You can undo this in Settings" true for a
    // *finished* session -- the ordinary case, and the one the
    // ignore was aimed at. It is the same arm because the two are
    // one setting, and every route that can set it (Settings,
    // onboarding, the CLI, the Waiting screen) must get both halves.
    //
    // The policy is already saved at this point, so a `queue.save`
    // failure below leaves disk disagreeing with memory: the project
    // is durably `Ignore` while its entries are still durably
    // `Pending`, and a restart brings the cleared cards back. The
    // error is reported and the daemon keeps the in-memory truth, so
    // the contributor sees the right thing until then. Ordering the
    // two writes the other way does not help -- the relabel below
    // reads the *new* policy, so the queue cannot be written first --
    // and a real fix wants both files under one atomic write, which
    // the store does not offer.
    let (queue_changed, purged) = {
        let mut queue = shared.queue.lock().expect("queue lock");
        let purged = if mode == ProjectMode::Ignore {
            queue.refuse_pending_for_project(&key)
        } else {
            0
        };
        let restored = if mode == ProjectMode::Ignore {
            0
        } else {
            queue.clear_project_ignored(&key)
        };
        let relabelled = relabel_queue_entries(&policy, &mut queue);
        if relabelled || purged > 0 || restored > 0 {
            if let Err(_e) = queue.save(&shared.store) {
                return Response::err(req.id, ERR_UNAVAILABLE, "queue-write-failed");
            }
        }
        (relabelled || restored > 0, purged)
    };
    drop(policy);
    if queue_changed || purged > 0 {
        shared.publish(EVENT_QUEUE_CHANGED, serde_json::json!({}));
    }
    Response::ok(req.id, serde_json::json!({ "ok": true, "purged": purged }))
}

fn handle_pause(shared: &DaemonShared, req: &Request) -> Response {
    // An optional timed pause, persisted so it survives a restart of
    // either the daemon or the app that requested it -- an app-side
    // timer alone would die with the app and silently fail to
    // resume the daemon.
    let until = match req.params.get("until").and_then(|v| v.as_str()) {
        Some(s) => match s.parse::<chrono::DateTime<Utc>>() {
            Ok(dt) if dt > Utc::now() => Some(dt),
            // A deadline that has already passed would publish a
            // pause event for a pause the very next status call (or
            // is_paused check) clears -- reject it up front rather
            // than accept a pause that is a lie the instant it's
            // acknowledged.
            Ok(_) => return Response::err(req.id, ERR_BAD_PARAMS, "until-in-the-past"),
            Err(_) => return Response::err(req.id, ERR_BAD_PARAMS, "until-invalid"),
        },
        None => None,
    };
    shared.paused.store(true, Ordering::Relaxed);
    {
        let mut state = shared.state.lock().expect("state lock");
        state.paused = true;
        state.paused_until = until;
        if state.save(&shared.store).is_err() {
            return Response::err(req.id, ERR_UNAVAILABLE, "state-write-failed");
        }
    }
    shared.publish(EVENT_STATUS_CHANGED, serde_json::json!({}));
    Response::ok(
        req.id,
        serde_json::json!({ "paused": true, "paused_until": until }),
    )
}

fn handle_cancel(shared: &DaemonShared, req: &Request) -> Response {
    // `project_id` is the batch form of `cancel`, mirroring
    // `approve`'s selector shape so an Undo of a project-wide
    // approval is one call with the same argument -- the daemon
    // decides which entries it covers, rather than the shell
    // deriving "what I saw pending minus what was reported
    // skipped" and racing the queue to cancel them one at a time.
    // `project_id` and `entry_id` are mutually exclusive;
    // `project_id` wins when both are sent, the same precedence
    // `approve` uses between its own selectors.
    let project_id = req.params.get("project_id").and_then(|v| v.as_str());
    if let Some(pid) = project_id {
        // Unrecognized is refused exactly as `approve` refuses it
        // for the same selector: a handle the caller never
        // received is a client bug, and answering `canceled: 0`
        // would be indistinguishable from "that project had
        // nothing to cancel". Lock order is policy before queue,
        // as everywhere else.
        let policy = shared.policy.lock().expect("policy lock");
        let mut queue = shared.queue.lock().expect("queue lock");
        let known = known_keys(&policy, queue.all().iter().map(|e| e.project_key.clone()));
        let Some(key) = project_key_for_id(pid, &known) else {
            return Response::err(req.id, ERR_BAD_PARAMS, ERR_PROJECT_ID_UNRECOGNIZED);
        };
        // Only `Approved`: those are the entries an Undo would be
        // undoing. A `Pending` entry has nothing to cancel, and a
        // project-wide call must not touch it. Matched by the id
        // `entry_value` publishes, never `project_label`, same as
        // `approve`.
        let ids: Vec<Uuid> = queue
            .all()
            .iter()
            .filter(|e| e.project_key == key && e.state == QueueState::Approved)
            .map(|e| e.entry_id)
            .collect();
        let project_audit_label = disambiguated_label(
            &key,
            crate::daemon::policy::display_path_for_key(&key).as_deref(),
            &known,
        );
        // Same ordering as `approve`'s `bulk-approved` row: written
        // before anything is canceled, so a rollback never has to
        // write to the disk that just refused a write. Undoing a
        // batch is the same class of act as approving one -- bulk,
        // unattended, previously terminal-only -- so it gets the
        // same visibility. A selector that matched nothing writes
        // no row, for the same reason `approve` writes none: no
        // entries were canceled, and a shell polling an empty
        // project would rotate real records out of a capped log.
        if !ids.is_empty() {
            if let Err(_e) = audit::append(
                &shared.store,
                &AuditEntry {
                    at: Utc::now(),
                    action: "bulk-canceled".to_string(),
                    project_label: Some(project_audit_label),
                    detail: Some(ids.len().to_string()),
                },
            ) {
                return Response::err(req.id, ERR_UNAVAILABLE, "audit-write-failed");
            }
        }
        let mut canceled = 0usize;
        for id in &ids {
            // Selection and cancellation happen under one
            // continuous hold of the queue lock, so every id
            // selected above is still `Approved` when `cancel`
            // runs on it; nothing else can have moved it.
            if queue.cancel(*id).is_ok() {
                canceled += 1;
            }
        }
        if let Err(_e) = queue.save(&shared.store) {
            return Response::err(req.id, ERR_UNAVAILABLE, "queue-write-failed");
        }
        drop(queue);
        shared.publish(EVENT_QUEUE_CHANGED, serde_json::json!({}));
        return Response::ok(req.id, serde_json::json!({ "canceled": canceled }));
    }
    let id = try_response!(entry_id_param(req));
    let mut queue = shared.queue.lock().expect("queue lock");
    if queue.cancel(id).is_err() {
        return Response::err(req.id, ERR_BAD_PARAMS, "not-cancelable");
    }
    if let Err(_e) = queue.save(&shared.store) {
        return Response::err(req.id, ERR_UNAVAILABLE, "queue-write-failed");
    }
    drop(queue);
    shared.publish(EVENT_QUEUE_CHANGED, serde_json::json!({}));
    Response::ok(req.id, serde_json::json!({ "ok": true }))
}

fn handle_list_audit(shared: &DaemonShared, req: &Request) -> Response {
    // Same cap as `list_history`: the log is append-by-whole-file
    // rewrite and otherwise unbounded.
    let limit = req
        .params
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .min(1000) as usize;
    match audit::load(&shared.store) {
        Ok(mut entries) => {
            // Newest first, matching `list_history`'s convention.
            entries.reverse();
            entries.truncate(limit);
            Response::ok(req.id, serde_json::json!({ "entries": entries }))
        }
        Err(_) => Response::err(req.id, ERR_UNAVAILABLE, "audit-read-failed"),
    }
}

fn handle_set_settings(shared: &DaemonShared, req: &Request) -> Response {
    let Ok(locks) = crate::daemon::nearai_credential::session::coordination(shared.store.dir())
    else {
        return Response::err(req.id, ERR_UNAVAILABLE, "settings-write-failed");
    };
    let Ok(_commit) = locks.commit.lock() else {
        return Response::err(req.id, ERR_UNAVAILABLE, "settings-write-failed");
    };
    let Ok(persisted) = crate::daemon::settings::DaemonSettings::load(&shared.store) else {
        return Response::err(req.id, ERR_UNAVAILABLE, "settings-write-failed");
    };
    let mut settings = shared.settings.lock().expect("settings lock");
    // Advance lifecycle consent only after this candidate is persisted.
    // Routing separately retains its warm reader when its endpoint is unchanged.
    let private_inference_before = settings.private_inference;
    let capture_before = settings.token_capture_enabled;
    // `apply_settings_object` is the same validation
    // `tc_daemon_start_with_settings` (the C ABI's pre-start
    // settings override) uses, so there is one definition of "a
    // valid settings object" for both. See its doc for why an
    // unrecognized key is rejected rather than ignored.
    // Rejected or unpersisted values must never reach the supervisor.
    let mut candidate = settings.clone();
    // A browser ceremony writes outside this daemon's in-memory settings.
    // Preserve its newest credentials when editing unrelated preferences.
    let credential_changed = if persisted.cloud_credentials.is_some() {
        if crate::daemon::cloud_credential_lifecycle::ensure_current(&persisted, &candidate)
            .is_err()
        {
            return Response::err(req.id, ERR_UNAVAILABLE, "settings-write-failed");
        }
        false
    } else {
        let changed = candidate.near_ai_inference != persisted.near_ai_inference;
        candidate.near_ai_inference = persisted.near_ai_inference;
        candidate.near_ai_session = persisted.near_ai_session;
        changed
    };
    candidate.cloud_credentials = persisted.cloud_credentials;
    match super::settings::apply_settings_object(&mut candidate, &req.params) {
        Ok(false) => Response::err(req.id, ERR_BAD_PARAMS, "no-known-setting-supplied"),
        Ok(true) => {
            if let Err(_e) = candidate.save_locked(&shared.store) {
                return Response::err(req.id, ERR_UNAVAILABLE, "settings-write-failed");
            }
            *settings = candidate;
            if settings.private_inference != private_inference_before
                || settings.token_capture_enabled != capture_before
                || credential_changed
            {
                shared
                    .private_inference_generation
                    .fetch_add(1, Ordering::Release);
            }
            // Apply the proxy declaration to this running daemon.
            // Without this the contributor would have to restart the
            // daemon to make a port they just typed take effect,
            // which reads as the feature being broken. Done after
            // the save so a declaration that takes effect is always
            // one that survives a restart too.
            shared.rebuild_effective_routing(&settings);
            let mut value = redacted_settings(&settings);
            drop(settings);
            add_admission_setting(shared, &mut value);
            Response::ok(req.id, value)
        }
        Err(label) => Response::err(req.id, ERR_BAD_PARAMS, label),
    }
}

/// `set_settings`, plus the one thing it cannot do synchronously: start or
/// stop the hosted IronWire.
///
/// Starting a proxy is an await, so the sync handler cannot do it, and
/// leaving it to the poll tick would mean a contributor who just turned
/// private inference on waited a minute to find out whether it worked --
/// the same friction `rebuild_effective_routing` exists to avoid for a typed port.
/// The reported state is re-read after the reconcile so the answer describes
/// what happened rather than what was true a moment before it.
async fn handle_set_settings_async(shared: &DaemonShared, req: &Request) -> Response {
    shared.absorb_near_ai_credential_change().await;
    let mut response = handle_set_settings(shared, req);
    if response.error.is_some() {
        return response;
    }
    shared.reconcile_private_inference().await;
    if let Some(result) = response.result.as_mut() {
        result["private_inference_state"] = shared.private_inference_value();
    }
    response
}

/// The complete dispatcher: answers the async methods (`"approve"`,
/// `"preview"`, `"preview_body"`, `"preview_turns"`, `"probe_routing"`,
/// `"probe_routed_tools"`,
/// `"quiesce"`, `"enroll"`, `"near_ai_credential_status"`,
/// `"near_ai_credential_forget"`,
/// `"withdraw"`, `"withdraw_bulk"`, `"set_public_profile"`,
/// `"clear_public_profile"`) for real and delegates every other method,
/// unchanged, to the synchronous `handle_request`. See the module doc's
/// "Sync vs. async dispatch" section for why this is the only place that
/// decides which methods are async, and why both real callers (the socket
/// loop and `handle_local`) always go through this function rather than
/// `handle_request` directly.
pub async fn handle_request_async(shared: &DaemonShared, req: &Request) -> Response {
    match req.method.as_str() {
        "native_wallet_flow" => super::native_flow::handle_wallet(shared, req).await,
        "prepare_admission_session" => super::native_flow::admission_response(
            super::admission_setup::handle_prepare_admission_session(shared, req).await,
            chrono::Utc::now().timestamp(),
        ),
        "near_account_start" => super::account_onboarding::handle_start(shared, req).await,
        "near_ai_account_enroll" => super::nearai_onboarding::handle_enroll(shared, req).await,
        "near_ai_credential_start" => super::nearai_credential::handle_start(shared, req).await,
        // Both of these answer identically on the sync path -- they are in
        // `handle_request` too, and that is what defines the response. The
        // override exists so the reconcile that makes the answer true of the
        // running proxy happens before the caller is told, exactly as
        // `set_settings` does it.
        "near_ai_credential_status" => {
            super::nearai_credential::handle_status_async(shared, req).await
        }
        "near_ai_credential_forget" => {
            super::nearai_credential::handle_forget_async(shared, req).await
        }
        "near_ai_balance" => super::nearai_credential::handle_balance(shared, req).await,
        "near_ai_funding" => crate::daemon::nearai_credential::handle_funding(shared, req).await,
        "near_account_capabilities" => {
            super::account_onboarding::handle_capabilities(shared, req).await
        }
        "set_settings" => handle_set_settings_async(shared, req).await,
        "witness_preview_request" => {
            witness_review_response(handle_witness_preview_request(shared, req).await)
        }
        "approve" => handle_approve(shared, req).await,
        "preview" => handle_preview(shared, req).await,
        "preview_body" => handle_preview_body(shared, req).await,
        "quiesce" => handle_quiesce(shared, req).await,
        "preview_turns" => handle_preview_turns(shared, req).await,
        "search_original" => handle_search_original(shared, req).await,
        "probe_routing" => handle_probe_routing(req).await,
        "probe_routed_tools" => handle_probe_routed_tools(req).await,
        "enroll" => enroll::handle_enroll(shared, req).await,
        "withdraw" => super::withdraw::handle_withdraw(shared, req).await,
        "withdraw_bulk" => super::withdraw::handle_withdraw_bulk(shared, req).await,
        "set_public_profile" => super::profile::handle_set_public_profile(shared, req).await,
        "clear_public_profile" => super::profile::handle_clear_public_profile(shared, req).await,
        _ => handle_request(shared, req),
    }
}

/// The timeout `quiesce` will actually honour.
///
/// A caller cannot park uploads for a week, and a caller that asks for zero
/// gets the default rather than an instant refusal.
fn clamp_quiesce_timeout(requested: Option<u64>) -> u64 {
    match requested {
        Some(0) | None => DEFAULT_QUIESCE_TIMEOUT_SECS,
        Some(n) => n.min(MAX_QUIESCE_TIMEOUT_SECS),
    }
}

/// Park the upload queue and wait for anything already in flight to finish.
///
/// The flag is set first, so nothing new is claimed while the wait runs, and
/// then in-flight work is allowed to complete on its own terms. On timeout
/// the flag is cleared and the caller is refused: the update stays staged and
/// retries later. There is no forced path -- a half-uploaded trace is not an
/// acceptable cost for an update.
async fn handle_quiesce(shared: &DaemonShared, req: &Request) -> Response {
    let requested = match req.params.get("timeout_secs") {
        None => None,
        Some(v) => match v.as_u64() {
            Some(n) => Some(n),
            None => return Response::err(req.id, ERR_BAD_PARAMS, "timeout-secs-invalid"),
        },
    };
    let timeout = std::time::Duration::from_secs(clamp_quiesce_timeout(requested));

    shared.quiesced.store(true, Ordering::Relaxed);
    let started = std::time::Instant::now();
    loop {
        let in_flight = {
            let queue = shared.queue.lock().expect("queue lock");
            queue.all().iter().any(|e| e.state == QueueState::Uploading)
        };
        if !in_flight {
            return Response::ok(
                req.id,
                serde_json::json!({
                    "quiesced": true,
                    "waited_ms": started.elapsed().as_millis() as u64,
                }),
            );
        }
        if started.elapsed() >= timeout {
            shared.quiesced.store(false, Ordering::Relaxed);
            return Response::err(req.id, ERR_BUSY, ERR_QUIESCE_TIMEOUT);
        }
        tokio::time::sleep(std::time::Duration::from_millis(QUIESCE_POLL_MS)).await;
    }
}

/// Run the real, async redaction pipeline for one queue entry and report the
/// actual bytes and redactions a contributor is about to consent to.
///
/// `handle_request` cannot run this (it is synchronous) and answers
/// `"preview"` on its own with an honest `preview_requires_async: true`
/// marker rather than a wrong byte count; only `handle_request_async`
/// resolves it completely.
async fn handle_approve(shared: &DaemonShared, req: &Request) -> Response {
    let all = req
        .params
        .get("all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Validated up front, before anything is approved and before the
    // bulk-approval audit row is written. A refused call must approve
    // nothing and leave no record of a batch that did not happen.
    //
    // Refused rather than ignored: a contributor who answered meant to say
    // something, and coercing a typo to `Unknown` would silently discard
    // the answer. Same rule the `--outcome` flag applies.
    let verdict = match req.params.get("outcome") {
        None => None,
        Some(v) => {
            let Some(name) = v.as_str() else {
                return Response::err(req.id, ERR_BAD_PARAMS, ERR_BAD_VERDICT);
            };
            if crate::envelope::ContributorVerdict::parse(name).is_none() {
                return Response::err(req.id, ERR_BAD_PARAMS, ERR_BAD_VERDICT);
            }
            Some(name.to_string())
        }
    };
    // Validated in the same place and for the same reason as the verdict:
    // before anything is approved, before the audit row, and refused rather
    // than coerced.
    //
    // Whitespace is not a correction, so it is normalised away here and the
    // call proceeds as an ordinary uncorrected approval. Everything else is
    // a refusal the caller has to see: a correction the daemon silently
    // dropped is worse than one it declined, because the contributor was
    // shown a caption promising their words would be stored as written.
    let correction = match req.params.get("correction") {
        None => None,
        Some(v) => {
            let Some(text) = v.as_str() else {
                return Response::err(req.id, ERR_BAD_PARAMS, ERR_BAD_CORRECTION);
            };
            let text = text.trim();
            if text.is_empty() {
                None
            } else {
                if text.chars().count() > crate::envelope::MAX_CORRECTION_CHARS {
                    return Response::err(req.id, ERR_BAD_PARAMS, ERR_CORRECTION_TOO_LONG);
                }
                Some(text.to_string())
            }
        }
    };
    if correction.is_some() {
        if !matches!(verdict.as_deref(), Some("partly") | Some("failed")) {
            return Response::err(req.id, ERR_BAD_PARAMS, ERR_CORRECTION_NEEDS_VERDICT);
        }
        if all || req.params.get("project_id").is_some() {
            return Response::err(req.id, ERR_BAD_PARAMS, ERR_CORRECTION_NEEDS_ENTRY);
        }
    }
    // Read before the queue lock is taken, so the settings lock is
    // never held under it.
    //
    // What is being approved is not just a session: it is that
    // session under the consent scopes and the
    // envelope-determining configuration in force right now. Both
    // are recorded on the entry so the uploader can refuse if
    // either moves before it sends. An approval with no readable
    // config records neither, which the uploader treats as
    // "unknown, re-ask" -- fail-closed.
    let cfg = shared.store.load_config().ok().flatten();
    let scopes = cfg
        .as_ref()
        .map(|c| c.consent_scopes.clone())
        .unwrap_or_default();
    // One instant for the whole call, so `approve: {"all": true}`
    // holds every entry it approved for the same window and reports
    // one deadline that is true of all of them -- rather than a
    // deadline that happens to describe the first entry and expires
    // early for the rest.
    let approved_at = Utc::now();
    let approval_hold_secs = shared
        .settings
        .lock()
        .expect("settings lock")
        .approval_hold_secs;
    // `None`, not `Some("")`, when there is no readable config:
    // every call site expresses "unknown" the same way, and the
    // uploader treats it as "re-ask" -- fail-closed.
    let inputs = cfg.as_ref().map(|c| {
        let (near_ai, attested_bodies) = {
            let s = shared.settings.lock().expect("settings lock");
            (s.near_ai.clone(), s.ironwire_attested_bodies)
        };
        super::preview::input_fingerprint(c, near_ai.as_ref(), attested_bodies)
    });
    // Whether a GROUP-level selector filters to what can actually be sent.
    //
    // `approve {project_id}` and `approve {all}` each offer one control that
    // sends every pending session they name. A group holding one eligible
    // and four permanently-ineligible rows would send all five: the per-row
    // gate cannot reach it, because a group approve has no row to check. So
    // "offer only the eligible ones" was true of rows and false of groups,
    // and the shells could not fix it -- three shells enumerating and
    // classifying rows themselves is three implementations of one filter,
    // which is how this surface got here.
    //
    // A group-level submit therefore means "all eligible", never "all". The
    // alternative either fails partway or succeeds at sending exactly what
    // the surface just finished saying could not be sent.
    //
    // Read through the same rule `entry_value` reads, from the same `cfg`,
    // so the filter cannot disagree with what the shell was shown. Off for
    // an invited contributor: nothing is filtered and this path behaves
    // exactly as it did.
    //
    // A single `entry_id` is deliberately NOT filtered -- see
    // `contribution_eligibility::contributable_in_a_group`.
    let group_filters = super::contribution_eligibility::evidence_flag(cfg.as_ref());
    // How many pending entries a group selector left out for being
    // ineligible. Reported so a shell can say what became of the rest rather
    // than infer it from a count that came back smaller than the one it drew
    // a button for.
    let mut excluded_ineligible: u64 = 0;
    let project_id = req.params.get("project_id").and_then(|v| v.as_str());
    // Three mutually exclusive selectors; `all` wins over `project_id` wins
    // over `entry_id` when more than one is sent -- same precedence rule as
    // `set_project_mode` above.
    //
    // `project_audit_label` is the display label of the project a
    // `project_id` call resolved to, for the audit row below. It is derived
    // from the key the daemon itself holds, never from the caller's string
    // -- the same rule `set_project_mode` follows, and the reason
    // `daemon-audit.jsonl` cannot be injected into.
    let (ids, project_audit_label): (Vec<Uuid>, Option<String>) = if all {
        let queue = shared.queue.lock().expect("queue lock");
        // `all` is the largest group there is and carries the same hole for
        // the same reason. Filtering it here as well as the project path is
        // deliberate: leaving it out would keep the defect alive behind a
        // different button.
        let (ids, excluded) = group_selection(queue.pending().iter().copied(), group_filters);
        excluded_ineligible = excluded;
        (ids, None)
    } else if let Some(pid) = project_id {
        // An id naming no project the daemon knows is refused, exactly as
        // `set_project_mode` refuses it on this same socket with this same
        // handle, and for the same reason an unknown `entry_id` is refused
        // below: a handle the caller never received is a client bug, and
        // answering it `approved: 0` is indistinguishable from "that
        // project had nothing pending" -- a shell holding a typo'd or stale
        // id would render "Sent 0 sessions" and never learn otherwise.
        //
        // "Known" is policy plus every project in the queue in ANY state,
        // so a project whose entries were all just approved or swept is
        // still recognised and still answers `approved: 0`. The genuinely
        // empty case therefore stays a success, distinguishable from an id
        // that names no project at all.
        //
        // Lock order is policy before queue, as everywhere else.
        let policy = shared.policy.lock().expect("policy lock");
        let queue = shared.queue.lock().expect("queue lock");
        let known = known_keys(&policy, queue.all().iter().map(|e| e.project_key.clone()));
        let Some(key) = project_key_for_id(pid, &known) else {
            return Response::err(req.id, ERR_BAD_PARAMS, ERR_PROJECT_ID_UNRECOGNIZED);
        };
        // Only `Pending`: an entry already approved has had its terms
        // fixed, and a project-wide call must not silently re-pin them.
        let (ids, excluded) = group_selection(
            queue
                .pending()
                .iter()
                .copied()
                .filter(|e| e.project_key == key),
            group_filters,
        );
        excluded_ineligible = excluded;
        // The unknown-cwd sentinel resolves here like any other project.
        // Approving what is already in that bucket is an ordinary consent
        // decision about entries the contributor can see; it is *arming*
        // the bucket that `set_mode` refuses, which is a standing grant.
        (
            ids,
            Some(disambiguated_label(
                &key,
                crate::daemon::policy::display_path_for_key(&key).as_deref(),
                &known,
            )),
        )
    } else {
        let queue = shared.queue.lock().expect("queue lock");
        let id = try_response!(entry_id_param(req));
        // An id the caller never held is a client bug, not something to
        // fold into the skip accounting below -- refused up front, the same
        // way `preview` refuses the same input, rather than reported as a
        // labelled skip of a call that otherwise ran. `all` and
        // `project_id` cannot reach this branch: their ids are read from
        // the queue itself a few lines above, so every id they produce
        // already names a real entry at the moment of selection.
        if queue.get(id).is_none() {
            return Response::err(req.id, ERR_BAD_PARAMS, ERR_UNKNOWN_ENTRY_ID);
        }
        (vec![id], None)
    };
    // A local, label-only record that a batch was bulk-approved, written
    // BEFORE anything is approved -- same ordering, and the same reason, as
    // `set_project_mode`: a rollback that has to write to the disk that just
    // refused a write is not a rollback. This is visibility, not a security
    // control (see `daemon::audit`), but it is the only visibility there is
    // for a call that used to require a terminal.
    //
    // Both bulk selectors are recorded, not only `all`. A tray click that
    // approves a whole project unattended is the same class of act as
    // approving the whole queue -- bulk, unattended, previously
    // terminal-only -- and leaving it unrecorded would drain the queue with
    // nothing in `daemon-audit.jsonl` to show for it. A single `entry_id`
    // approval is the always-was, one-click-at-a-time path and stays
    // unaudited.
    //
    // Written before the envelope builds below, not merely before the
    // approve loop: those builds persist artifacts of their own, and "the
    // record could not be written, so nothing happened" has to stay true of
    // everything this call does.
    //
    // The count is of entries eligible to be approved when the queue was
    // read. It is an upper bound: an entry no artifact can be built for is
    // skipped below, and `approve` can refuse one that moved. The record
    // says the batch was bulk-approved at all, which is what it exists for.
    //
    // A project selector that matched nothing writes no row: nothing was
    // approved and, the selection having been taken under the queue lock,
    // nothing could have been -- a row would record an act that did not
    // happen, and a shell polling a project with an empty queue would
    // rotate real records out of a capped log. `all` keeps writing
    // unconditionally: it names the queue rather than a subset of it, and
    // "the whole queue was bulk-approved" is a statement about the request,
    // which `bulk_approval_over_the_socket_is_now_allowed_and_appends_an_audit_entry`
    // fixes in place.
    if all || (project_audit_label.is_some() && !ids.is_empty()) {
        if let Err(_e) = audit::append(
            &shared.store,
            &AuditEntry {
                at: Utc::now(),
                action: "bulk-approved".to_string(),
                project_label: project_audit_label,
                detail: Some(ids.len().to_string()),
            },
        ) {
            return Response::err(req.id, ERR_UNAVAILABLE, "audit-write-failed");
        }
    }
    // Entries nobody previewed have no artifact behind them. Build one now.
    //
    // What is at stake if this is not done, or is done and does not stick:
    // an entry with no pin is not refused at upload. `approved_envelope_for`
    // returns `Ok(None)` for a missing pin, and `submit` treats `None` as
    // "build one" -- so the uploader silently constructs a fresh envelope
    // and sends it. Approving from the tray without this would mean sending
    // bytes no contributor was ever shown, reported back as a success.
    //
    // The build is async and must not run under the queue lock, so the
    // entries are cloned out under a short lock of their own and the lock
    // is retaken for the approve loop below.
    //
    // A correction forces a rebuild even for an entry that was previewed:
    // the pinned artifact was built before the contributor had written
    // anything, so it carries neither the correction nor the
    // `correction_included` declaration that enrols it for the PII backstop,
    // and credential detection has never run over the text. Re-pinning here
    // is what makes the approval cover the bytes the correction is part of.
    // `correction` is only ever `Some` for a single `entry_id`, refused
    // above otherwise, so this rebuilds exactly one entry.
    let unpinned: Vec<(Uuid, super::queue::QueueEntry)> = {
        let queue = shared.queue.lock().expect("queue lock");
        ids.iter()
            .filter_map(|id| queue.all().iter().find(|e| e.entry_id == *id))
            .filter(|e| e.previewed_envelope_digest.is_none() || correction.is_some())
            .map(|e| (e.entry_id, e.clone()))
            .collect()
    };
    // Fixed labels, one per entry that could not be given an artifact.
    // Nothing here is approved: sending something the contributor was never
    // shown is worse than a refusal they can see.
    let mut skipped: Vec<(Uuid, &'static str)> = Vec::new();
    // What the response's toast is built from: redaction counts summed by
    // category across every entry approve itself built a preview for (an
    // entry that was already previewed before this call contributes
    // nothing here -- its preview response already told the caller this),
    // and how many of those builds carried a PII label. Counts and labels
    // only, per the hash-only rule -- never the text a redaction removed.
    //
    // The "already previewed contributes nothing" half of that stops being
    // true for a corrected entry, which is rebuilt above whatever its pin
    // said. Its counts are reported again here, and that is the right
    // answer rather than a double count: the artifact is not the one the
    // preview described, so what this toast names is what the approval
    // actually covers.
    let mut redactions: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut flagged: u64 = 0;
    // The entries whose refusal has to outlive this response. See the size
    // check below, and the write under the queue lock further down.
    let mut too_large: Vec<Uuid> = Vec::new();
    for (id, entry) in unpinned {
        // An unenrolled build is never pinned -- it is a placeholder
        // -identity artifact, not the one an upload would send -- so there
        // is nothing for approve to do with it. This is an optimisation of
        // the pin re-check below, which would skip such an entry anyway,
        // and it exists only so the caller gets the specific label rather
        // than a generic one.
        if cfg.is_none() {
            skipped.push((id, "not-enrolled"));
            continue;
        }
        match build_and_pin_preview(shared, id, &entry, cfg.as_ref(), correction.as_deref()).await {
            Ok((summary, _body, _envelope)) => {
                // `build_preview` does not size-check the raw contribution
                // (only `submit`'s path does); `approved_envelope::save`
                // does, on exactly this measurement -- so the pin
                // `build_and_pin_preview` just attempted has already been
                // refused for size, and this entry is unpinned. Repeating
                // the measurement here is what gives an oversized session
                // its own label instead of the generic `not-pinned` the pin
                // re-check below would otherwise give it -- this one is
                // permanent, and retrying the same session can never
                // succeed, which `not-pinned`'s other causes do not imply.
                if summary.would_send_bytes > crate::envelope::MAX_ENVELOPE_BYTES {
                    skipped.push((id, super::queue::REASON_TOO_LARGE));
                    // Reported *and* recorded. Reporting alone left the
                    // entry `Pending`, which is the state that means "still
                    // waiting on the contributor" -- so the watcher kept
                    // finding a live offer at this path and the card sat
                    // there for a session no click could ever get past this
                    // very check. A decision that can never come out
                    // differently for these bytes is a decision, and it
                    // belongs on the entry like every other one.
                    too_large.push(id);
                    continue;
                }
                for (category, count) in &summary.redactions {
                    *redactions.entry(category.clone()).or_insert(0) += count;
                }
                if !summary.pii_labels_present.is_empty() {
                    flagged += 1;
                }
            }
            Err((_code, label)) => skipped.push((id, label)),
        }
    }
    let skipped_ids: std::collections::HashSet<Uuid> = skipped.iter().map(|(id, _)| *id).collect();
    let mut queue = shared.queue.lock().expect("queue lock");
    // Written under the same lock that approves, and saved by the same
    // `queue.save` below, so the refusal and the approvals in this batch
    // land together or not at all.
    //
    // Guarded on `Pending`, which is what `set_state` does not check for
    // itself: the build ran without the lock held, and an entry that was
    // cancelled, dismissed or superseded in that window has a newer
    // decision on it than this one.
    //
    // `Refused` is the right terminal state and `REASON_TOO_LARGE` the
    // right label, but they are deliberately *not* `REASON_DISMISSED`:
    // `Queue::dismissed_at_path` suppresses a whole conversation forever,
    // and that is reserved for a contributor saying no. This is the
    // pipeline's verdict on one envelope built under one set of consent
    // scopes -- narrower scopes can yield a smaller envelope from the same
    // conversation -- so it binds to the entry, and a session that has
    // moved on is offered again exactly as it is after any other pipeline
    // refusal.
    for id in &too_large {
        if queue.get(*id).map(|e| e.state) == Some(QueueState::Pending) {
            queue.set_state(
                *id,
                QueueState::Refused,
                Some(super::queue::REASON_TOO_LARGE.to_string()),
            );
        }
    }
    let mut approved_ids = Vec::new();
    for id in &ids {
        let id = *id;
        if skipped_ids.contains(&id) {
            continue;
        }
        // The pin is re-checked here, under the lock that approves, rather
        // than inferred from the build returning `Ok`. `build_and_pin_preview`
        // is `Ok` whenever the *build* succeeded, and `pin_previewed_envelope`
        // declines silently when the envelope could not be written, and when
        // the entry was not `Pending` by the time the pin was attempted.
        // Trusting `Ok` would approve an entry with no
        // artifact behind it, which is the one thing the uploader does not
        // catch. An entry that is still unpinned here is left `Pending` for
        // the contributor to approve again.
        if queue
            .get(id)
            .is_none_or(|e| e.previewed_envelope_digest.is_none())
        {
            // The build reported `Ok` (or this entry had a stale pin to
            // begin with) but nothing is pinned now: `pin_previewed_envelope`
            // declined to write because `approved_envelope::save` failed, or
            // because the entry was no longer `Pending` when the pin was
            // attempted; or (for `all`/`project_id`) the entry was removed
            // from the queue entirely in that same window. (A failed queue
            // *save* inside `pin_previewed_envelope` does not land here: it
            // leaves the pin in memory, which is what this check reads.)
            //
            // Which label that deserves depends on where the entry stands
            // now, and the two documented labels promise different things
            // to a client. `not-pinned` is documented transient -- retry is
            // expected to work once the race passed -- and that is only
            // true while the entry is still `Pending`. An entry that is
            // both unpinned and no longer `Pending` (dismissed, expired,
            // superseded, or approved through some other path without ever
            // being previewed) can never be approved by a retry: every pin
            // path refuses a non-`Pending` entry, so retrying loops
            // forever. That case gets `not-pending`, whose documented
            // advice -- refresh queue state rather than retry blindly -- is
            // the correct one for it. An entry gone from the queue entirely
            // is reported `not-pinned`: it was `Pending` when it was
            // selected, and its disappearance is the transient race.
            //
            // Either way the entry is left as it stands -- but it must not
            // vanish from the response. An entry counted in neither
            // `approved` nor `skipped` is exactly the silent hole the pin
            // re-check above this loop exists to close for the uploader;
            // the caller deserves the same guarantee.
            let label = match queue.get(id).map(|e| e.state) {
                Some(QueueState::Pending) | None => "not-pinned",
                Some(_) => "not-pending",
            };
            skipped.push((id, label));
            continue;
        }
        if let Some(entry) = queue
            .get(id)
            .filter(|entry| entry.holds_witness_certificate())
        {
            let valid = cfg
                .as_ref()
                .zip(inputs.as_deref())
                .is_some_and(|(cfg, fingerprint)| {
                    super::approved_envelope::load_witnessed(&shared.store, id)
                        .ok()
                        .flatten()
                        .is_some_and(|artifact| {
                            artifact.digest().ok().as_deref()
                                == entry.previewed_envelope_digest.as_deref()
                                && artifact
                                    .validate(
                                        cfg,
                                        &entry.session_hash,
                                        fingerprint,
                                        verdict.as_deref(),
                                        correction.as_deref(),
                                    )
                                    .is_ok()
                        })
                });
            if !valid {
                skipped.push((id, "witness-review-stale"));
                continue;
            }
        }
        if queue.approve(
            id,
            &scopes,
            inputs.as_deref(),
            verdict.as_deref(),
            correction.as_deref(),
            Some(approved_at),
        ) {
            approved_ids.push(id);
        } else {
            // `Queue::approve` refuses anything not `Pending`, and this
            // entry just passed the pin check above under the same held
            // lock -- so it exists and nothing else can have touched it
            // since. The only way it still lands here is that its state
            // was already something other than `Pending` when this call
            // started: `previewed_envelope_digest` is never cleared by
            // `approve` or by the terminal states `cancel` moves an entry
            // through, so an entry that was approved (or otherwise moved
            // off `Pending`) earlier keeps looking pinned forever. The
            // deterministic repro is approving the same `entry_id` twice
            // in a row. Reported, not dropped, for the same reason as
            // `not-pinned`: an id this call was asked to act on must show
            // up somewhere in the response.
            skipped.push((id, "not-pending"));
        }
    }
    let approved = approved_ids.len();
    // The deadline the daemon will actually honour, taken from an
    // entry it just wrote rather than recomputed here, so a client
    // counting down against it is counting down against the same
    // value `drain_approved` compares. `null` when nothing was
    // approved or the hold is configured off -- a client must then
    // offer no undo, rather than invent one.
    let hold_until = approved_ids
        .first()
        .and_then(|id| queue.get(*id))
        .and_then(|e| e.hold_until(approval_hold_secs));
    if let Err(_e) = queue.save(&shared.store) {
        // The approvals exist only in memory and would not survive a
        // restart; a queue that disagrees with its own file is worse
        // than no approval. `cancel` refuses anything past
        // `Approved`, and these were set `Approved` a few lines ago
        // under this same lock, so no upload pass can have claimed
        // one.
        for id in approved_ids {
            let _ = queue.cancel(id);
        }
        return Response::err(req.id, ERR_UNAVAILABLE, "queue-write-failed");
    }
    drop(queue);
    shared.publish(EVENT_QUEUE_CHANGED, serde_json::json!({}));
    // The signal the contributor sees instead of a preview: "Sent --
    // scrubbing removed N things, M flagged." Counts and labels only -- a
    // redaction count names a category, never the text it removed, and a
    // skip reason is a fixed label, never a path or trace content.
    let mut result = serde_json::json!({
            "approved": approved,
            "hold_secs": approval_hold_secs,
            "hold_until": hold_until,
            "flagged": flagged,
            "redactions": redactions,
            "skipped": skipped
                .iter()
                .map(|(id, label)| serde_json::json!({
                    "entry_id": id,
                    "reason_label": label,
                }))
                .collect::<Vec<_>>(),
    });
    // Absent, not zero, for an invited contributor and for a single-entry
    // approve. Zero would read as "nothing was left out", which is a claim
    // about a filter that did not run.
    if group_filters && (all || project_id.is_some()) {
        result["excluded_ineligible"] = serde_json::Value::from(excluded_ineligible);
    }
    Response::ok(req.id, result)
}

/// The entries a group selector acts on, and how many it left out.
///
/// One implementation for both group selectors, so `all` and `project_id`
/// cannot come to disagree about what a group means.
fn group_selection<'a>(
    entries: impl Iterator<Item = &'a super::queue::QueueEntry>,
    filters: bool,
) -> (Vec<Uuid>, u64) {
    let mut ids = Vec::new();
    let mut excluded = 0u64;
    for entry in entries {
        if filters
            && !super::contribution_eligibility::contributable_in_a_group(
                entry.eligibility.as_deref(),
            )
        {
            excluded += 1;
            continue;
        }
        ids.push(entry.entry_id);
    }
    (ids, excluded)
}

/// The socket's `"preview"` handler -- the queue-card summary.
///
/// This is called once per row shown in the queue (the app fires it for
/// every entry `awaitingDecision` at once), so it deliberately does the
/// *least* work of any preview surface: [`preview::build_preview_card`]
/// skips both the envelope digest and the pretty-printed body, neither of
/// which a card renders. It also does not pin the entry -- see that
/// function's doc for why skipping the digest makes that the only safe
/// choice, and why nothing downstream relies on a card load to have
/// happened: the preview sheet (`open_preview`, below) and an on-demand
/// rebuild inside `handle_approve` are the two paths that actually pin, and
/// either one runs regardless of whether a card was ever loaded for the
/// entry.
/// One explicit, user-confirmed remote review. Ordinary preview paths never call it.
async fn handle_witness_preview_request(shared: &DaemonShared, req: &Request) -> Response {
    handle_witness_preview_request_inner(
        shared,
        req,
        #[cfg(test)]
        None,
    )
    .await
}

/// Attach the refusal's sentence to a review response.
///
/// The mirror of `native_flow::admission_response`, and it is here for the
/// same reason: **the daemon chooses the words, not the shells.** Three shells
/// each mapping the same label would be three mappings, and
/// `witness_copy::witness_refusal_line`'s own doc says why that is the thing
/// to avoid. GTK reaches the same function directly because it is Rust and has
/// no `view` to read.
///
/// Written onto `result` even though this is an error response, exactly as
/// `admission_response` does: `result` and `error` both serialize, and a shell
/// too old to look for the view simply does not find one.
fn witness_review_response(mut response: Response) -> Response {
    let Some(error) = response.error.as_ref() else {
        return response;
    };
    let message = crate::witness_copy::witness_refusal_line(Some(error.message.as_str()));
    let value = response.result.get_or_insert_with(|| serde_json::json!({}));
    value["view"] = serde_json::json!({"state": "Refused", "message": message});
    response
}

/// The word a refused review is reported under.
///
/// A witness refusal passes through under its own name; everything else
/// collapses to the fixed word.
///
/// **The message is not forwarded.** Errors on this path are internal strings
/// -- `secret-leak-detected`, `pii-filter-unavailable`, whatever a future
/// `bail!` adds -- and a route that handed `anyhow`'s message to a shell would
/// put them in front of a contributor and break the never-name-the-mechanism
/// rule by the shortest route available. `refusal_label_from` matches against
/// the closed set and returns that crate's own constant, so the only strings
/// that can cross are ones a shell has words for.
fn witness_review_refusal(error: &anyhow::Error) -> &'static str {
    crate::witness::WitnessTrustError::refusal_label_from(&error.to_string())
        .unwrap_or("witness-review-failed")
}

async fn handle_witness_preview_request_inner(
    shared: &DaemonShared,
    req: &Request,
    // Recorded signed responses exercise persistence/approval without pretending
    // that local fixtures are Intel-signed quotes. Absent from production builds.
    //
    // A `Result`, not a `WitnessPreview`: the refusal branch below decides what
    // word a shell is given, and a seam that can only inject success leaves
    // that decision with no way to be tested at all.
    #[cfg(test)] recorded: Option<anyhow::Result<super::preview::WitnessPreview>>,
) -> Response {
    if req
        .params
        .get("raw_session_confirmed")
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return Response::err(req.id, ERR_BAD_PARAMS, "witness-review-consent-required");
    }
    let id = match parse_entry_id(&req.params) {
        Ok(id) => id,
        Err(label) => return Response::err(req.id, ERR_BAD_PARAMS, label),
    };
    let verdict = match req
        .params
        .get("outcome")
        .or_else(|| req.params.get("verdict"))
    {
        None => None,
        Some(value) => match value
            .as_str()
            .and_then(crate::envelope::ContributorVerdict::parse)
        {
            Some(verdict) => Some(verdict),
            None => return Response::err(req.id, ERR_BAD_PARAMS, ERR_BAD_VERDICT),
        },
    };
    let correction = match req.params.get("correction") {
        None => None,
        Some(value) => match value.as_str() {
            Some(text) if text.trim().is_empty() => None,
            Some(text) if text.trim().chars().count() <= crate::envelope::MAX_CORRECTION_CHARS => {
                Some(text.trim())
            }
            _ => return Response::err(req.id, ERR_BAD_PARAMS, ERR_BAD_CORRECTION),
        },
    };
    if correction.is_some()
        && !matches!(
            verdict,
            Some(
                crate::envelope::ContributorVerdict::Partly
                    | crate::envelope::ContributorVerdict::Failed
            )
        )
    {
        return Response::err(req.id, ERR_BAD_PARAMS, ERR_CORRECTION_NEEDS_VERDICT);
    }
    let entry = {
        let queue = shared.queue.lock().expect("queue lock");
        match queue.get(id) {
            Some(entry) if entry.state == QueueState::Pending => entry.clone(),
            Some(_) => return Response::err(req.id, ERR_BAD_PARAMS, "not-pending"),
            None => return Response::err(req.id, ERR_BAD_PARAMS, ERR_UNKNOWN_ENTRY_ID),
        }
    };
    // Repeated requests must not replace an existing certified artifact.
    if entry.holds_witness_certificate() {
        return Response::err(req.id, ERR_BAD_PARAMS, "witness-review-already-pinned");
    }
    let cfg = match shared.store.load_config() {
        Ok(Some(cfg)) => cfg,
        _ => return Response::err(req.id, ERR_UNAVAILABLE, "witness-review-not-enrolled"),
    };
    let token_generation = shared.token_review_generation.load(Ordering::Acquire);
    let initial_settings = shared.settings.lock().expect("settings lock").clone();
    let near_ai = initial_settings.near_ai.clone();
    let bodies = initial_settings.ironwire_attested_bodies;
    let roots = shared.source_roots_with_routing();
    let sources = crate::source::all_sources(&roots);
    let Some((source, session_ref)) = super::find_session(&sources, &entry) else {
        return Response::err(req.id, ERR_BAD_PARAMS, "session-file-vanished");
    };
    let token_control = if initial_settings.token_distributions_contribution {
        let Some(declaration) = initial_settings.ironwire.as_ref() else {
            return Response::err(req.id, ERR_UNAVAILABLE, "token-capture-proxy-unavailable");
        };
        match super::token_capture::client(declaration) {
            Ok(client) => Some(client),
            Err(_) => {
                return Response::err(req.id, ERR_UNAVAILABLE, "token-capture-proxy-unavailable");
            }
        }
    } else {
        None
    };
    let build = super::preview::build_witnessed_preview(
        &shared.store,
        &cfg,
        near_ai,
        source,
        &session_ref,
        super::preview::WitnessPreviewOptions {
            raw_session_confirmed: true,
            token_capture: token_control.as_ref(),
            expected_session_hash: &entry.session_hash,
            include_inference_bodies: bodies,
            verdict,
            correction,
        },
    );
    #[cfg(test)]
    let built = match recorded {
        Some(review) => review,
        None => build.await,
    };
    #[cfg(not(test))]
    let built = build.await;
    let review = match built {
        Ok(review) => review,
        Err(error) => {
            return Response::err(req.id, ERR_UNAVAILABLE, witness_review_refusal(&error));
        }
    };
    let mut pin_guard = crate::token_bundle::ReviewPinGuard::new(
        shared.store.dir(),
        review.artifact.token_bundle.as_ref(),
    );
    // The async network operation is over. Recheck identity, consent and source
    // before either persistent write, and keep the queue locked through both.
    let current_cfg = match shared.store.load_config() {
        Ok(Some(cfg)) => cfg,
        _ => return Response::err(req.id, ERR_UNAVAILABLE, "witness-review-stale"),
    };
    let settings = shared.settings.lock().expect("settings lock");
    let fingerprint = super::preview::input_fingerprint(
        &current_cfg,
        settings.near_ai.as_ref(),
        settings.ironwire_attested_bodies,
    );
    if *settings != initial_settings
        || fingerprint != review.summary.input_fingerprint
        || source
            .load(&session_ref)
            .map(|t| t.session_hash != entry.session_hash)
            .unwrap_or(true)
    {
        return Response::err(req.id, ERR_UNAVAILABLE, "witness-review-stale");
    }
    let mut queue = shared.queue.lock().expect("queue lock");
    if queue.get(id) != Some(&entry)
        || shared.token_review_generation.load(Ordering::Acquire) != token_generation
    {
        return Response::err(req.id, ERR_UNAVAILABLE, "witness-review-stale");
    }
    if super::approved_envelope::save_witnessed(&shared.store, id, &review.artifact).is_err() {
        return Response::err(req.id, ERR_UNAVAILABLE, "witness-review-save-failed");
    }
    let previous_queue = queue.clone();
    if !queue.record_previewed_envelope(
        id,
        &review.summary.envelope_digest,
        review.artifact.attested_inference().cloned(),
    ) || queue.save(&shared.store).is_err()
    {
        *queue = previous_queue;
        return Response::err(req.id, ERR_UNAVAILABLE, "witness-review-save-failed");
    }
    pin_guard.disarm();
    Response::ok(
        req.id,
        serde_json::json!({"status": "ready", "summary": review.summary}),
    )
}

async fn handle_preview(shared: &DaemonShared, req: &Request) -> Response {
    let id = try_response!(entry_id_param(req));
    let entry = try_response!(entry_by_id(shared, req, id));
    if entry.holds_witness_certificate() {
        return match open_preview(shared, id).await {
            Ok((summary, _)) => {
                let mut value =
                    serde_json::to_value(summary).expect("preview summary serialization");
                value["entry"] = entry_value(&entry, shared.admission_evidence());
                Response::ok(req.id, value)
            }
            Err(label) => Response::err(req.id, ERR_UNAVAILABLE, label),
        };
    }

    // No enrollment is not a refusal. Preview does no network I/O and needs
    // neither the daemon's lock nor its running loop, so requiring a config
    // here was incidental -- and it forced anyone who wanted to *see* what
    // would be sent to enrol first, which is the wrong way round. Without a
    // config the pipeline builds the same placeholder-identity,
    // deterministic-only envelope the CLI's unenrolled `--dry-run` builds,
    // and the response says so. See `preview::build_preview`.
    let cfg = shared.store.load_config().ok().flatten();
    let near_ai = {
        let s = shared.settings.lock().expect("settings lock");
        s.near_ai.clone()
    };
    let source_roots = shared.source_roots_with_routing();
    let sources = crate::source::all_sources(&source_roots);
    let Some((source, session_ref)) = super::find_session(&sources, &entry) else {
        return Response::err(req.id, ERR_BAD_PARAMS, "session-file-vanished");
    };

    let attested_bodies = {
        let s = shared.settings.lock().expect("settings lock");
        s.ironwire_attested_bodies
    };
    match super::preview::build_preview_card(
        cfg.as_ref(),
        near_ai,
        attested_bodies,
        source,
        &session_ref,
    )
    .await
    {
        Ok(summary) => {
            // The card shape lives in `preview_card_value`, shared with the
            // scheduler's ready event so the two cannot drift. `entry` is
            // added only here: this response describes an entry the caller
            // just named, while a cached summary outlives that state.
            let mut value = preview_card_value(&summary);
            value["entry"] = entry_value(&entry, shared.admission_evidence());
            Response::ok(req.id, value)
        }
        Err(_) => Response::err(req.id, ERR_UNAVAILABLE, "preview-failed"),
    }
}

/// The summary object both `preview` and the scheduler report.
///
/// One definition, so the blocking method and the scheduled one cannot
/// describe the same build differently. It deliberately does **not** carry
/// `entry`: the scheduler caches this object and a queue entry's state
/// changes underneath it, so embedding one would let a cached preview
/// assert a stale state. `preview` adds a freshly read `entry` on top; the
/// scheduler's callers already hold entries from `list_pending` and the
/// `snapshot` event.
/// The card shape, without the entry.
///
/// Two surfaces render it -- the socket's `preview` response, which adds
/// `entry` on top, and the scheduler's `preview_ready` event, which
/// deliberately omits it because a cached summary outlives the entry state
/// it was built beside. They share this function so the field set cannot
/// drift between them.
///
/// There is no `envelope_digest` here, and that is the point: a card build
/// never produces one. See `preview::build_preview_card`.
pub(crate) fn preview_card_value(
    summary: &super::preview::PreviewCardSummary,
) -> serde_json::Value {
    serde_json::json!({
        "would_send_bytes": summary.would_send_bytes,
        "raw_session_bytes": summary.raw_session_bytes,
        "event_count": summary.event_count,
        "opening_prompt": summary.opening_prompt,
        "redactions": summary.redactions,
        "pii_labels_present": summary.pii_labels_present,
        "consent_scopes": summary.consent_scopes,
        "residual_risk": summary.residual_risk,
        // The configuration fingerprint -- cheap, a hash of the config
        // rather than of the envelope -- so it still rides along. There is
        // no `envelope_digest`: this build never made one and never pinned
        // the entry.
        "input_fingerprint": summary.input_fingerprint,
        // False when this device is not enrolled: the summary describes a
        // placeholder-identity, deterministic-only build, and the
        // fingerprint above is not bindable to a later approval.
        "enrolled": summary.enrolled,
    })
}

/// The fingerprint of every input other than the session bytes that decides
/// what a preview says.
///
/// Part of the scheduler's cache key, so a device that changes its consent
/// scopes, its identity, or its privacy-filter settings does not keep being
/// shown cards built under the old configuration.
///
/// An unenrolled device gets a fixed label rather than the placeholder
/// config's fingerprint. Hashing the placeholder would be hashing a
/// constant, and the value that matters -- that enrolling invalidates every
/// unenrolled preview -- holds either way.
pub(crate) fn preview_config_fingerprint(shared: &DaemonShared) -> String {
    let cfg = shared.store.load_config().ok().flatten();
    let (near_ai, attested_bodies) = {
        let s = shared.settings.lock().expect("settings lock");
        (s.near_ai.clone(), s.ironwire_attested_bodies)
    };
    match cfg {
        Some(c) => super::preview::input_fingerprint(&c, near_ai.as_ref(), attested_bodies),
        None => "unenrolled".to_string(),
    }
}

/// Ask the scheduler for a preview and return promptly.
///
/// The difference from `preview` is the whole point: this never runs the
/// redaction pipeline on the connection's time. It answers from cache, or
/// says the work is queued and lets the `preview_ready` event carry the
/// result. A shell drawing a list calls this once per card and blocks on
/// nothing.
fn handle_preview_request(shared: &DaemonShared, req: &Request) -> Response {
    let id = try_response!(entry_id_param(req));
    let entry = try_response!(entry_by_id(shared, req, id));
    let key = PreviewKey::for_entry(
        &entry.path,
        entry.size_bytes,
        preview_config_fingerprint(shared),
    );
    match shared.previews.request(id, key, entry.size_bytes) {
        RequestState::Cached(outcome) => Response::ok(req.id, outcome.to_value(id)),
        RequestState::Queued => Response::ok(
            req.id,
            serde_json::json!({
                "entry_id": id.to_string(),
                "state": super::preview_scheduler::STATE_QUEUED,
            }),
        ),
        RequestState::Running => Response::ok(
            req.id,
            serde_json::json!({
                "entry_id": id.to_string(),
                "state": super::preview_scheduler::STATE_RUNNING,
            }),
        ),
    }
}

/// Declare which entries are on screen, so their previews are built first.
///
/// Wholesale replacement of the visible set, and cheap enough to call on
/// every scroll: it takes one lock and moves no work. Visibility decides
/// order, never membership -- an entry that scrolls away keeps its place in
/// the queue until someone calls `preview_cancel`.
fn handle_preview_visible(shared: &DaemonShared, req: &Request) -> Response {
    let Some(raw) = req.params.get("entry_ids") else {
        return Response::err(req.id, ERR_BAD_PARAMS, "entry-ids-required");
    };
    let Some(list) = raw.as_array() else {
        return Response::err(req.id, ERR_BAD_PARAMS, "entry-ids-invalid");
    };
    let mut ids = Vec::with_capacity(list.len());
    for item in list {
        match item.as_str().and_then(|s| Uuid::parse_str(s).ok()) {
            Some(id) => ids.push(id),
            None => return Response::err(req.id, ERR_BAD_PARAMS, "entry-ids-invalid"),
        }
    }
    let visible = shared.previews.set_visible(ids);
    Response::ok(req.id, serde_json::json!({ "visible": visible }))
}

/// Drop a scheduled preview.
///
/// `dropped: false` means there was nothing to drop -- already finished,
/// already cancelled, or never requested. It is not an error: a shell that
/// cancels on every card leaving the viewport will hit that case constantly
/// and has nothing to do about it.
fn handle_preview_cancel(shared: &DaemonShared, req: &Request) -> Response {
    let id = try_response!(entry_id_param(req));
    let dropped = shared.previews.cancel(id);
    Response::ok(
        req.id,
        serde_json::json!({ "entry_id": id.to_string(), "dropped": dropped }),
    )
}

/// Build the redacted envelope for one queue entry, pin the entry to it, and
/// hand back the summary, the redacted body, and the envelope.
///
/// This is the pinning path -- `open_preview` (the C ABI's in-process full
/// preview, behind the preview sheet), `handle_preview_body` (the socket's
/// body, when there is no stored envelope to read instead), and
/// `handle_approve`'s on-demand rebuild for an entry no card or sheet ever
/// pinned all go through it. `handle_preview` (the socket's card summary,
/// above) deliberately does **not**: see its doc comment and
/// `preview::build_preview_card` for why a card load skips both the digest
/// and the pin. Errors are `(code, fixed label)` -- no path, no entry
/// content -- and the callers that need a bare label discard the code.
/// `correction` is the contributor's written correction for this entry, when
/// the call that is building this artifact carried one. It is folded in
/// before redaction runs, so the pinned bytes are the ones the correction is
/// part of -- and so credential detection gets to refuse before anything is
/// pinned. Only `handle_approve` ever passes one.
async fn build_and_pin_preview(
    shared: &DaemonShared,
    entry_id: Uuid,
    entry: &super::queue::QueueEntry,
    cfg: Option<&crate::config::ContributorConfig>,
    correction: Option<&str>,
) -> Result<
    (
        super::preview::PreviewSummary,
        String,
        trace_commons_protocol::trace_contribution::TraceContributionEnvelope,
    ),
    (&'static str, &'static str),
> {
    let (near_ai, attested_bodies) = {
        let s = shared.settings.lock().expect("settings lock");
        (s.near_ai.clone(), s.ironwire_attested_bodies)
    };
    let source_roots = shared.source_roots_with_routing();
    let sources = crate::source::all_sources(&source_roots);
    let (source, session_ref) =
        super::find_session(&sources, entry).ok_or((ERR_BAD_PARAMS, "session-file-vanished"))?;
    if entry.holds_witness_certificate() {
        let unavailable = (
            ERR_UNAVAILABLE,
            super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE,
        );
        let artifact = super::approved_envelope::load_witnessed(&shared.store, entry_id)
            .map_err(|_| unavailable)?
            .ok_or(unavailable)?;
        if artifact.digest().map_err(|_| unavailable)?.as_str()
            != entry
                .previewed_envelope_digest
                .as_deref()
                .ok_or(unavailable)?
        {
            return Err(unavailable);
        }
        let transcript = source.load(&session_ref).map_err(|_| unavailable)?;
        if transcript.session_hash != entry.session_hash {
            return Err((ERR_UNAVAILABLE, "witness-review-stale"));
        }
        return super::preview::summarize_witnessed_preview(
            &artifact,
            cfg.ok_or(unavailable)?,
            near_ai,
            &transcript,
            session_ref.size_bytes,
            attested_bodies,
        )
        .map_err(|_| (ERR_UNAVAILABLE, "witness-review-stale"));
    }
    let (summary, body, envelope) = super::preview::build_preview_with_correction(
        &shared.store,
        cfg,
        near_ai,
        source,
        &session_ref,
        correction,
        attested_bodies,
    )
    .await
    .map_err(|e| {
        // The one refusal a contributor can act on gets its own label so a
        // shell can say what happened and what to do about it. Compared
        // against the fixed label `redact_to_envelope` produces, never
        // rendered from the error, so no text can ride out on this path.
        if e.to_string() == REASON_CORRECTION_CREDENTIAL {
            (ERR_BAD_PARAMS, REASON_CORRECTION_CREDENTIAL)
        } else {
            (ERR_UNAVAILABLE, "preview-failed")
        }
    })?;
    // An unenrolled preview is never pinned: it was built from a placeholder
    // identity, so it is not the artifact any later approval would send.
    if summary.enrolled {
        pin_previewed_envelope(shared, entry_id, &summary, &envelope);
    }
    Ok((summary, body, envelope))
}

/// Full preview -- summary *and* redacted body -- for one queue entry, for a
/// caller that already holds `shared` directly rather than issuing a
/// request/response frame. This is what the C ABI's `tc_preview_open` uses.
///
/// A socket client reaches the same body through `"preview_body"`
/// (`handle_preview_body`, below), which pages it under the 1 MiB line cap.
/// That method exists because this function's `&DaemonShared` is only
/// available to the process holding the daemon lock -- which, on a
/// systemd-hosted daemon with the window as a socket client, is never the
/// window. Errors are fixed labels, matching every other surface at this
/// boundary -- no path, no entry content.
/// Count occurrences of `needle` in an entry's PRE-redaction session text.
///
/// This is the only call in this crate that reads unredacted session bytes on
/// behalf of a socket client, and the bound is what makes it acceptable: it
/// returns a COUNT. No offsets, no context, no bytes, nothing that can be
/// reassembled into content. A caller learns only the answer to a question
/// they already knew how to ask, about a needle they typed themselves.
///
/// It exists because `preview_search` scans the REDACTED body, so a value that
/// redaction removed returns zero matches -- which is indistinguishable from a
/// value that was never in the session at all. Those are precisely the two
/// answers a contributor checking for a client name needs to tell apart, and
/// without this the search tab cannot tell them apart either.
///
/// The file is read, counted, and dropped inside this function. Nothing
/// retains it. That is why this takes an entry id rather than hanging off an
/// open preview: a preview lives as long as a sheet is on screen, and an
/// unredacted transcript must not.
///
/// Errors are fixed labels, never a path or a fragment of content.
pub async fn search_original(
    shared: &DaemonShared,
    entry_id: Uuid,
    needle: &str,
) -> Result<u32, &'static str> {
    if needle.is_empty() {
        return Ok(0);
    }
    let path = {
        let queue = shared.queue.lock().expect("queue lock");
        queue
            .get(entry_id)
            .map(|e| e.path.clone())
            .ok_or(ERR_UNKNOWN_ENTRY_ID)?
    };
    let body = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| "session-unreadable")?;
    let mut count: u32 = 0;
    let mut start = 0usize;
    while let Some(pos) = body[start..].find(needle) {
        count = count.saturating_add(1);
        start = start + pos + needle.len();
        if start > body.len() {
            break;
        }
    }
    Ok(count)
}

pub async fn open_preview(
    shared: &DaemonShared,
    entry_id: Uuid,
) -> Result<(super::preview::PreviewSummary, String), &'static str> {
    let entry = {
        let queue = shared.queue.lock().expect("queue lock");
        queue.get(entry_id).cloned().ok_or(ERR_UNKNOWN_ENTRY_ID)?
    };
    // As with the socket's `"preview"`: no enrollment yields a
    // placeholder-identity, deterministic-only preview rather than a
    // refusal, and `summary.enrolled` says which one this is.
    let cfg = shared.store.load_config().map_err(|_| "not-logged-in")?;
    // Same pinning as the socket's `"preview"`: the entry now holds the
    // artifact this caller was shown, so an approval that follows covers
    // that artifact and nothing else.
    let (summary, body, _envelope) =
        build_and_pin_preview(shared, entry_id, &entry, cfg.as_ref(), None)
            .await
            .map_err(|(_code, label)| label)?;
    Ok((summary, body))
}

/// The redacted preview body for one queue entry, over the socket, in pages.
///
/// # Why this exists
///
/// `open_preview` needs `&DaemonShared`, so only the process holding the
/// daemon lock can call it. On the recommended Linux arrangement the daemon
/// is a systemd unit and the window is a socket client, so the window is
/// never that process: without this method its "search" and "exactly what
/// would be sent" surfaces cannot work at all. Search in particular is the
/// affordance that lets a contributor under an NDA check in seconds whether
/// a trace names their client, and it was dead on the platform's primary
/// deployment.
///
/// # Paging, and why the body is not searched here
///
/// A redacted envelope may approach `MAX_ENVELOPE_BYTES`, above the 1 MiB
/// `MAX_LINE_BYTES` frame, so the body is paged: `offset` in, `chunk` plus
/// `next_offset` out, `next_offset: null` at the end. Nothing is ever
/// silently truncated -- a client that believed it had searched a whole
/// trace when it had searched the first megabyte would report a confident,
/// false "0 matches", which is the exact failure this affordance exists to
/// prevent.
///
/// The daemon ships the body and does not search it. A server-side matcher
/// would have to reproduce the client's own notion of a match (case folding,
/// word boundaries, how an event boundary is spanned) and would still have
/// to ship surrounding text for the client to render, so the client would
/// end up holding the body anyway -- but with a second matcher to keep in
/// step with the one displaying results. One body, one text, one search:
/// what the contributor searched is what the contributor is looking at.
///
/// The property that must survive either choice is that **a client can never
/// report a trace clean when it could not actually look**, and paging is the
/// only thing that could quietly break it. Two things hold it up: the client
/// is told `total_bytes` and can refuse to report a result until it has
/// received `[0, total_bytes)`, and a continuation page must carry the
/// `body_digest` of the page it continues. A body that changed underneath a
/// paging client is refused with [`ERR_PREVIEW_BODY_CHANGED`] rather than
/// spliced -- which matters because a rebuild is not reproducible: event ids
/// are minted per build, and under an LLM-backed privacy filter the
/// redaction spans move too.
///
/// # Where the body comes from
///
/// A previewed, pinned entry has its envelope on disk, and that stored
/// artifact is what is read -- the same bytes the upload will send, so
/// paging is stable across calls and identical to what `open_preview`
/// returns. Only an entry with no stored envelope runs the pipeline (which
/// pins it, exactly as `preview` does). An entry that *is* pinned but whose
/// bytes are missing or unusable is refused with
/// `approved-envelope-unavailable` rather than rebuilt: a rebuild would show
/// a contributor something other than what they approved.
///
/// Trace content, under the preview exemption in this module's doc: only for
/// an entry the caller already holds, post-redaction only, and never onward.
async fn handle_search_original(shared: &DaemonShared, req: &Request) -> Response {
    let id = try_response!(entry_id_param(req));
    let needle = match req.params.get("needle") {
        Some(v) => match v.as_str() {
            Some(n) => n,
            None => return Response::err(req.id, ERR_BAD_PARAMS, "needle-invalid"),
        },
        None => return Response::err(req.id, ERR_BAD_PARAMS, "needle-required"),
    };
    match search_original(shared, id, needle).await {
        // A count and nothing else. See `search_original` for why that is the
        // whole bound of this method.
        Ok(matches) => Response::ok(req.id, serde_json::json!({ "matches": matches })),
        Err(label) => Response::err(req.id, ERR_BAD_PARAMS, label),
    }
}

async fn handle_preview_body(shared: &DaemonShared, req: &Request) -> Response {
    let id = try_response!(entry_id_param(req));
    let offset = match req.params.get("offset") {
        None => 0usize,
        Some(v) => match v.as_u64() {
            Some(n) => n as usize,
            None => return Response::err(req.id, ERR_BAD_PARAMS, "offset-invalid"),
        },
    };
    let limit = match req.params.get("limit") {
        None => MAX_PREVIEW_BODY_CHUNK_BYTES,
        Some(v) => match v.as_u64() {
            // A larger ask is capped, not refused: the cap is a framing
            // limit, and a client that asks for the whole body in one go is
            // making a reasonable request the transport cannot grant.
            Some(n) if n > 0 => (n as usize).min(MAX_PREVIEW_BODY_CHUNK_BYTES),
            _ => return Response::err(req.id, ERR_BAD_PARAMS, "limit-invalid"),
        },
    };
    let expected_digest = match req.params.get("body_digest") {
        None => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s.to_string()),
            None => return Response::err(req.id, ERR_BAD_PARAMS, "body-digest-invalid"),
        },
    };
    // Fail-closed rather than best-effort: an unanchored continuation is
    // indistinguishable from a continuation of a body that no longer exists.
    if offset > 0 && expected_digest.is_none() {
        return Response::err(req.id, ERR_BAD_PARAMS, ERR_BODY_DIGEST_REQUIRED);
    }

    let (body, envelope_digest, enrolled) = match resolve_preview_body(shared, id).await {
        Ok(v) => v,
        Err((code, label)) => return Response::err(req.id, code, label),
    };
    let body_digest = format!("sha256:{:x}", Sha256::digest(body.as_bytes()));
    if let Some(expected) = expected_digest {
        if expected != body_digest {
            return Response::err(req.id, ERR_UNAVAILABLE, ERR_PREVIEW_BODY_CHANGED);
        }
    }

    let total = body.len();
    if offset > total || !body.is_char_boundary(offset) {
        return Response::err(req.id, ERR_BAD_PARAMS, "offset-invalid");
    }
    let mut end = offset.saturating_add(limit).min(total);
    // The body is UTF-8 and `chunk` is a JSON string, so a page may not
    // split a character. Walk the end down to a boundary; if that leaves no
    // progress at all (a `limit` smaller than the character it lands in),
    // walk up instead, so a paging client can never stall.
    while end > offset && !body.is_char_boundary(end) {
        end -= 1;
    }
    if end == offset && offset < total {
        end = offset + 1;
        while end < total && !body.is_char_boundary(end) {
            end += 1;
        }
    }
    let next_offset = (end < total).then_some(end);

    Response::ok(
        req.id,
        serde_json::json!({
            "entry_id": id,
            "total_bytes": total,
            "offset": offset,
            "chunk": &body[offset..end],
            "next_offset": next_offset,
            // The token that anchors the next page to this body, and the
            // digest of the envelope the body came from -- the same value
            // `preview` reports, so an app can tie the body it is showing to
            // the summary it displayed.
            "body_digest": body_digest,
            "envelope_digest": envelope_digest,
            "enrolled": enrolled,
            "max_chunk_bytes": MAX_PREVIEW_BODY_CHUNK_BYTES,
        }),
    )
}

/// An index of the turns in the redacted preview body: where each one starts
/// inside the body and what to label it. **An overlay, never a replacement.**
///
/// # Why this is an index and not a rendered transcript
///
/// The transcript surface a contributor approves from is titled "exactly
/// what would be sent", and that is meant literally: what it shows is
/// `preview_body`'s bytes, the same bytes the upload sends. Re-rendering
/// those events as prose turns would drop everything that has no prose form
/// -- `structured_payload`, `token_counts`, `latency_ms`, `cost_usd`,
/// `failure_modes` -- and so would show *less* than the artifact under a
/// heading promising the whole of it. So the daemon does not re-render. It
/// says where the turns begin in the body the client already has, and the
/// client draws separators there over text it renders verbatim.
///
/// `preview::turns_of` computes the offsets from `preview::body_of`'s own
/// output, so there is exactly one definition of how events map to bytes,
/// and one test asserts each span re-parses to the event it claims.
///
/// # Anchoring
///
/// `body_digest` is **required**, on the first call and every call, and is
/// the same anchoring rule `preview_body`'s continuation pages use. An index
/// is a set of offsets into a specific string; against any other string it
/// is not merely stale but wrong, and wrong in the invisible way -- a
/// separator drawn over the wrong text still looks like a transcript. A
/// rebuilt envelope is a different artifact (event ids are minted per build,
/// and an LLM-backed privacy filter does not reproduce its own spans), so a
/// mismatch is refused with [`ERR_PREVIEW_BODY_CHANGED`] exactly as a
/// mis-anchored page is, and the correct response is the same: re-read the
/// body from `offset: 0` and ask again with the digest it returns.
///
/// # Framing
///
/// Unpaged, and it fits: a turn serializes to well under 100 bytes, and an
/// envelope is capped at `MAX_ENVELOPE_BYTES` (1.5 MB) while one
/// pretty-printed event costs upwards of 170 of those bytes, so the index
/// stays a fraction of the 1 MiB line cap even for an envelope at the
/// ceiling. If that ceiling ever rises materially, this has to page the way
/// `preview_body` does rather than truncate -- a truncated index is a
/// transcript with turns silently missing from the end.
///
/// The index itself carries no redacted trace text -- an event-type label,
/// the tool name the envelope already records as metadata, and byte offsets.
/// It is still only served for an entry the caller already holds, under the
/// same rule as the rest of the preview surface, because the shape of a
/// transcript is itself something a contributor has not offered anyone.
async fn handle_preview_turns(shared: &DaemonShared, req: &Request) -> Response {
    let id = try_response!(entry_id_param(req));
    let expected_digest = match req.params.get("body_digest") {
        // Fail-closed, and required from the first call: an index is only
        // meaningful against the body the caller is holding.
        None => return Response::err(req.id, ERR_BAD_PARAMS, ERR_BODY_DIGEST_REQUIRED),
        Some(v) => match v.as_str() {
            Some(s) => s.to_string(),
            None => return Response::err(req.id, ERR_BAD_PARAMS, "body-digest-invalid"),
        },
    };

    let (envelope, envelope_digest, _enrolled) = match resolve_preview_envelope(shared, id).await {
        Ok(v) => v,
        Err((code, label)) => return Response::err(req.id, code, label),
    };
    let body = match super::preview::body_of(&envelope) {
        Ok(b) => b,
        Err(_) => return Response::err(req.id, ERR_UNAVAILABLE, "preview-failed"),
    };
    let body_digest = format!("sha256:{:x}", Sha256::digest(body.as_bytes()));
    if expected_digest != body_digest {
        return Response::err(req.id, ERR_UNAVAILABLE, ERR_PREVIEW_BODY_CHANGED);
    }
    let turns = match super::preview::turns_of(&envelope) {
        Ok(t) => t,
        Err(_) => {
            return Response::err(
                req.id,
                ERR_UNAVAILABLE,
                super::preview::REASON_TURN_INDEX_FAILED,
            );
        }
    };

    Response::ok(
        req.id,
        serde_json::json!({
            "entry_id": id,
            "body_digest": body_digest,
            "envelope_digest": envelope_digest,
            "turn_count": turns.len(),
            "turns": turns,
        }),
    )
}

/// The turn index for one entry, for a caller that already holds `shared`
/// directly rather than issuing a request/response frame -- the C ABI's
/// `tc_preview_turns_json`. Anchored by the same rule as the socket method:
/// the caller passes the digest of the body it is showing, and a body that
/// is not that one is refused rather than indexed.
///
/// Returns the same JSON object `"preview_turns"` puts in its `result`, so
/// the two surfaces cannot describe the same entry differently.
pub async fn open_preview_turns(
    shared: &DaemonShared,
    entry_id: Uuid,
    expected_body_digest: &str,
) -> Result<String, &'static str> {
    let (envelope, envelope_digest, _enrolled) = resolve_preview_envelope(shared, entry_id)
        .await
        .map_err(|(_code, label)| label)?;
    let body = super::preview::body_of(&envelope).map_err(|_| "preview-failed")?;
    let body_digest = format!("sha256:{:x}", Sha256::digest(body.as_bytes()));
    if expected_body_digest != body_digest {
        return Err(ERR_PREVIEW_BODY_CHANGED);
    }
    let turns = super::preview::turns_of(&envelope)
        .map_err(|_| super::preview::REASON_TURN_INDEX_FAILED)?;
    serde_json::to_string(&serde_json::json!({
        "entry_id": entry_id,
        "body_digest": body_digest,
        "envelope_digest": envelope_digest,
        "turn_count": turns.len(),
        "turns": turns,
    }))
    .map_err(|_| "turns-serialize-failed")
}

/// The redacted body for one entry, plus its envelope digest and whether the
/// build behind it was an enrolled one. See `handle_preview_body` for which
/// of the two sources is used and why.
async fn resolve_preview_body(
    shared: &DaemonShared,
    entry_id: Uuid,
) -> Result<(String, String, bool), (&'static str, &'static str)> {
    let (envelope, digest, enrolled) = resolve_preview_envelope(shared, entry_id).await?;
    let body =
        super::preview::body_of(&envelope).map_err(|_| (ERR_UNAVAILABLE, "preview-failed"))?;
    Ok((body, digest, enrolled))
}

/// The redacted envelope one preview surface is describing, resolved once so
/// the body and the turn index over it can never come from two different
/// builds. `handle_preview_body` documents which of the two sources is used
/// and why a pinned-but-missing artifact is refused rather than rebuilt.
async fn resolve_preview_envelope(
    shared: &DaemonShared,
    entry_id: Uuid,
) -> Result<
    (
        trace_commons_protocol::trace_contribution::TraceContributionEnvelope,
        String,
        bool,
    ),
    (&'static str, &'static str),
> {
    let entry = {
        let queue = shared.queue.lock().expect("queue lock");
        queue
            .get(entry_id)
            .cloned()
            .ok_or((ERR_BAD_PARAMS, ERR_UNKNOWN_ENTRY_ID))?
    };
    if entry.holds_witness_certificate() {
        let cfg = shared.store.load_config().ok().flatten();
        let (summary, _, envelope) =
            build_and_pin_preview(shared, entry_id, &entry, cfg.as_ref(), None).await?;
        return Ok((envelope, summary.envelope_digest, true));
    }
    match super::approved_envelope::load(&shared.store, entry_id) {
        Ok(Some(envelope)) => {
            let digest = super::preview::envelope_digest(&envelope)
                .map_err(|_| (ERR_UNAVAILABLE, "preview-failed"))?;
            // Only an enrolled preview is ever stored.
            Ok((envelope, digest, true))
        }
        // Pinned, but the bytes are not there. Refuse rather than rebuild:
        // a rebuild is a different artifact from the one this entry is
        // pinned to, and showing it as "what would be sent" would be false.
        Ok(None) if entry.previewed_envelope_digest.is_some() => Err((
            ERR_UNAVAILABLE,
            super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE,
        )),
        Ok(None) => {
            let cfg = shared.store.load_config().ok().flatten();
            let (summary, _body, envelope) =
                build_and_pin_preview(shared, entry_id, &entry, cfg.as_ref(), None).await?;
            Ok((envelope, summary.envelope_digest, summary.enrolled))
        }
        Err(_) => Err((
            ERR_UNAVAILABLE,
            super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE,
        )),
    }
}

/// Store the redacted envelope a preview just built and pin the entry to
/// it, so an upload that follows sends exactly those bytes rather than
/// building a second envelope.
///
/// The order matters and is the whole contract: the bytes go down first,
/// and the entry is only pinned once they are on disk. "Pinned" is what the
/// uploader reads as "the approved bytes exist"; a pin recorded without
/// them turns an ordinary upload into a fail-closed re-offer.
///
/// Best effort, deliberately. A preview is a read, and a state directory
/// that cannot take the write should still let the contributor *see* what
/// would be sent. An unpinned entry falls back to the pipeline building the
/// envelope at upload time under the input fingerprint the approval
/// records -- which is where every entry stood before any of this existed,
/// and is still fail-closed. It is never no check at all.
///
/// The queue lock is held across both writes so an entry cannot change
/// state underneath them. Previewing an entry that is no longer `Pending`
/// must not touch the stored bytes at all: an already-approved entry is
/// pinned to the artifact it was approved as, and overwriting or deleting
/// that would revoke a live approval for no reason.
fn pin_previewed_envelope(
    shared: &DaemonShared,
    entry_id: Uuid,
    summary: &super::preview::PreviewSummary,
    envelope: &trace_commons_protocol::trace_contribution::TraceContributionEnvelope,
) {
    let mut queue = shared.queue.lock().expect("queue lock");
    if queue.get(entry_id).map(|e| e.state) != Some(QueueState::Pending) {
        return;
    }
    if super::approved_envelope::save(&shared.store, entry_id, envelope).is_err() {
        return;
    }
    if queue.record_previewed_envelope(entry_id, &summary.envelope_digest, None) {
        // A failed queue write leaves the pin in memory and the bytes on
        // disk -- consistent with each other, and the next queue save
        // persists it. Nothing is removed here: the bytes are what the
        // in-memory pin refers to.
        let _ = queue.save(&shared.store);
    }
}

/// Settings as returned over IPC: the privacy-filter credential is reported
/// as present or absent, never echoed.
fn redacted_settings(s: &DaemonSettings) -> serde_json::Value {
    let mut v = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = v.as_object_mut() {
        let configured = s.near_ai.is_some();
        obj.remove("near_ai");
        obj.insert(
            "near_ai_configured".to_string(),
            serde_json::Value::Bool(configured),
        );
        // The inference credential is a second, different credential in the
        // same document -- see `DaemonSettings::near_ai_inference` -- and gets
        // the same treatment for the same reason. `skip_serializing_if` keeps
        // the absent case out of the blob already; the `remove` is what
        // matters, because without it the whole record, key included, crosses
        // the socket to every shell that asks for settings.
        let inference_configured = s.near_ai_inference.is_some();
        obj.remove("near_ai_inference");
        obj.insert(
            "near_ai_inference_configured".to_string(),
            serde_json::Value::Bool(inference_configured),
        );
        // And a third: the retained session. It is the *widest* of the three
        // -- a refresh token can mint further API keys and read the account,
        // where the key above only buys inference -- so if any of them must
        // not cross the socket it is this one. Without the `remove` the whole
        // record, refresh token included, is serialized to every shell that
        // asks for settings.
        //
        // Presence only, and it is worth reporting: a shell that knows a
        // session is stored knows the balance surface is worth showing, and
        // one that sees `false` knows to offer the ceremony instead.
        let session_retained = s.near_ai_session.is_some();
        obj.remove("near_ai_session");
        obj.remove("cloud_credentials");
        obj.insert(
            "near_ai_session_retained".to_string(),
            serde_json::Value::Bool(session_retained),
        );
        // claude_root / codex_root are local filesystem paths. entry_value
        // is scrupulous about never putting a path on the wire; this
        // serialized-wholesale settings blob was not, and leaked one
        // whenever either root was overridden from the conventional
        // location. Report presence only.
        //
        // `*_root_configured` stays true only for a source pointed at a
        // folder. A source declared OFF is answered but has no folder, so
        // reporting it as configured would tell a settings screen to print
        // "sessions folder set" about an agent the contributor said they do
        // not use. The mode carries that distinction, and carries no path.
        obj.remove("claude_root");
        obj.remove("codex_root");
        for source in crate::source::registered_source_names() {
            let Some(key) = crate::daemon::settings::source_settings_key(source) else {
                continue;
            };
            let declaration = obj.remove(key);
            let mode = match declaration
                .as_ref()
                .and_then(|v| v.get("mode"))
                .and_then(serde_json::Value::as_str)
            {
                Some("watch") => "watch",
                Some("off") => "off",
                _ => "unset",
            };
            obj.insert(format!("{key}_mode"), mode.into());
        }
        // A future unmapped declaration must still never expose its path.
        obj.retain(|key, _| !key.ends_with("_source"));
        // Legacy presence aliases; new sources expose only their mode.
        for source in ["claude", "codex"] {
            let watched = obj
                .get(&format!("{source}_source_mode"))
                .and_then(serde_json::Value::as_str)
                == Some("watch");
            obj.insert(format!("{source}_root_configured"), watched.into());
        }
    }
    v
}

fn parse_entry_id(params: &serde_json::Value) -> Result<Uuid, &'static str> {
    params
        .get("entry_id")
        .and_then(|v| v.as_str())
        .ok_or("entry_id-required")?
        .parse()
        .map_err(|_| "entry_id-invalid")
}

/// `req`'s `entry_id` parameter, or the refusal to send in its place.
///
/// Ten handlers wanted the same four lines around [`parse_entry_id`]; this
/// is those four lines once, and with [`try_response!`] the call sites read
/// as a `?`. The refusal is exactly what they each built by hand:
/// `ERR_BAD_PARAMS` carrying `entry_id-required` or `entry_id-invalid`.
fn entry_id_param(req: &Request) -> Result<Uuid, Box<Response>> {
    parse_entry_id(&req.params).map_err(|m| Box::new(Response::err(req.id, ERR_BAD_PARAMS, m)))
}

/// The queue entry `id` names, cloned out from under the lock, or the
/// refusal to send in its place.
///
/// The lock is taken and released inside this function, exactly as the
/// inline blocks it replaces did: callers go on to do slow work with the
/// clone and must not be holding the queue lock while they do it.
fn entry_by_id(
    shared: &DaemonShared,
    req: &Request,
    id: Uuid,
) -> Result<QueueEntry, Box<Response>> {
    let queue = shared.queue.lock().expect("queue lock");
    queue
        .get(id)
        .cloned()
        .ok_or_else(|| Box::new(Response::err(req.id, ERR_BAD_PARAMS, ERR_UNKNOWN_ENTRY_ID)))
}

/// Collapse an internal error string to a single-line label. Nothing
/// multi-line or free-form crosses the socket.
fn one_line_label(s: &str) -> String {
    s.split_whitespace()
        .take(6)
        .collect::<Vec<_>>()
        .join("-")
        .replace(':', "")
}

/// The kernel's limit on a unix socket path, conservatively the smallest of
/// the common values (macOS allows 104 bytes, Linux 108).
#[cfg(unix)]
const MAX_SOCKET_PATH_BYTES: usize = 104;

/// Bind the daemon socket, refusing unless the state directory is private.
#[cfg(unix)]
pub async fn bind(store: &ConfigStore) -> Result<UnixListener> {
    ensure_private_dir(store.dir())?;
    let path = store.daemon_path(DAEMON_SOCK_FILE);

    // The kernel truncates rather than explains, and the resulting error names
    // a constant most people have never heard of. Say what is actually wrong
    // and what to do about it.
    // The message names the length and the fix, but not the path: this
    // error is returned to `daemon run`, which under a service manager
    // writes it to the journal, and a state-directory path there carries
    // the OS username. The length plus the file name is enough to act on.
    let len = path.as_os_str().len();
    if len >= MAX_SOCKET_PATH_BYTES {
        bail!(
            "the daemon socket path is {len} bytes, over the {MAX_SOCKET_PATH_BYTES}-byte \
             kernel limit for unix sockets (the path is your state directory plus \
             {DAEMON_SOCK_FILE}). Use a shorter state directory, \
             e.g. TRACE_COMMONS_CONTRIBUTOR_DIR=~/.config/trace-commons"
        );
    }

    // A socket left behind by a crashed daemon would block binding. The
    // single-instance lock, not this file, is what prevents two daemons.
    let _ = std::fs::remove_file(&path);
    UnixListener::bind(&path).context("binding the daemon socket in the state directory")
}

/// The 0700 directory is the access control for the socket, because
/// `UnixListener::bind` does not portably apply a mode to the socket itself.
///
/// Checking the mode is sufficient: a directory at 0700 belonging to someone
/// else is not writable by this process, so binding a socket inside it fails
/// on its own. Only a directory that is both ours and private gets served.
#[cfg(unix)]
fn ensure_private_dir(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta =
        std::fs::metadata(dir).context("reading permissions of the daemon state directory")?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        bail!(
            "refusing to serve from a state directory that is not 0700 \
             (found {mode:o}): the directory is the only access control on \
             the daemon socket"
        );
    }
    Ok(())
}

/// Serve connections until shutdown is requested.
#[cfg(unix)]
pub async fn serve(listener: UnixListener, shared: Arc<DaemonShared>) -> Result<()> {
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = serve_connection(stream, shared).await;
        });
    }
}

/// Serve one client connection.
///
/// Generic over the stream so the unix-socket and Windows named-pipe
/// transports share one implementation: the protocol, the framing, and the
/// error taxonomy are identical on both, and three applications are built
/// against one contract document. Only the listening and connecting ends
/// differ per platform.
pub async fn serve_connection<S>(stream: S, shared: Arc<DaemonShared>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut subscription: Option<broadcast::Receiver<Event>> = None;
    let mut line = String::new();

    loop {
        line.clear();
        tokio::select! {
            read = reader.read_line(&mut line) => {
                let n = match read {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(_) => return Ok(()),
                };
                if n > MAX_LINE_BYTES {
                    let resp = Response::err(0, ERR_BAD_PARAMS, "line-too-long");
                    write_json(&mut write_half, &resp).await?;
                    return Ok(());
                }
                let req: Request = match serde_json::from_str(line.trim()) {
                    Ok(r) => r,
                    Err(_) => {
                        let resp = Response::err(0, ERR_BAD_PARAMS, "malformed-request");
                        write_json(&mut write_half, &resp).await?;
                        return Ok(());
                    }
                };
                let is_subscribe = req.method == "subscribe";
                let resp = handle_request_async(&shared, &req).await;
                write_json(&mut write_half, &resp).await?;
                if is_subscribe && resp.error.is_none() {
                    // Snapshot first, so an application never has to race the
                    // event stream against a separate list call.
                    subscription = Some(shared.events.subscribe());
                    let snap = Event {
                        event: EVENT_SNAPSHOT.to_string(),
                        data: shared.snapshot_value(),
                    };
                    write_json(&mut write_half, &snap).await?;
                }
            }
            event = async {
                match subscription.as_mut() {
                    Some(rx) => rx.recv().await,
                    // No subscription: park forever rather than spinning.
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Ok(ev) => write_json(&mut write_half, &ev).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let ev = Event {
                            event: EVENT_RESYNC_REQUIRED.to_string(),
                            data: serde_json::json!({}),
                        };
                        write_json(&mut write_half, &ev).await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

async fn write_json<W, T>(w: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut body = serde_json::to_vec(value).context("serializing ipc frame")?;
    body.push(b'\n');
    w.write_all(&body).await.context("writing ipc frame")?;
    w.flush().await.context("flushing ipc frame")?;
    Ok(())
}

/// Convenience for the CLI, which drives the same handlers in-process.
///
/// Every method, not only the async ones, is answered through
/// `handle_request_async` via `block_on_ipc` -- see the module doc's "Sync
/// vs. async dispatch" section for why routing everything through the one
/// real dispatcher, rather than special-casing individual methods here, is
/// what guarantees a CLI caller and a socket caller can never get different
/// answers to the same request.
pub fn handle_local(shared: &DaemonShared, method: &str, params: serde_json::Value) -> Response {
    let req = Request {
        id: 0,
        method: method.to_string(),
        params,
    };
    block_on_ipc(shared, &req)
}

/// Run `handle_request_async` to completion from a synchronous caller.
///
/// The CLI binary is itself async (`#[tokio::main]`, multi-thread flavor),
/// so a call from it executes on a tokio worker thread -- but plenty of test
/// callers of `handle_local` run inside a default (current-thread)
/// `#[tokio::test]`, and some might not be inside any runtime at all. Both
/// `tokio::task::block_in_place` (needs the multi-thread flavor) and
/// building a second `Runtime` and calling `.block_on()` on the *same*
/// thread (tokio refuses to re-enter a runtime context on one thread) would
/// panic in one of those cases. A scoped OS thread sidesteps all of it: it
/// carries no tokio context of its own, so a throwaway current-thread
/// runtime on it can always `block_on` the real `handle_request_async`, and
/// `std::thread::scope` lets it borrow `shared`/`req` without requiring
/// `'static`.
fn block_on_ipc(shared: &DaemonShared, req: &Request) -> Response {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return Response::err(req.id, ERR_UNAVAILABLE, "runtime-unavailable"),
                };
                rt.block_on(handle_request_async(shared, req))
            })
            .join()
            .unwrap_or_else(|_| Response::err(req.id, ERR_UNAVAILABLE, "ipc-thread-panicked"))
    })
}

/// How long a probe waits for the proxy before calling it unreachable.
///
/// A loopback call to a process on the same machine, and one a human is
/// waiting on with a settings dialog open. Short for both reasons.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// `probe_routing`: the proxy answered and the token was accepted.
pub const PROBE_REACHABLE: &str = "reachable";
/// `probe_routing`: the token could not be used. Carries `token_path`, the
/// absolute path that was tried -- never the token.
///
/// Covers both halves of the same contributor-fixable mistake: no readable
/// `control.token` at the resolved path, and a proxy that answered and
/// refused the one that was there. A GUI daemon never sees `IRONWIRE_HOME`,
/// so it reads `~/.ironwire/control.token` whatever the contributor set in
/// a shell -- which produces a missing file on one machine and a stale
/// token on another. Both are fixed by naming the directory, so both name
/// the path.
pub const PROBE_TOKEN_UNREADABLE: &str = "token_unreadable";
/// `probe_routing`: nothing usable answered on the port. Carries `port`.
///
/// Also the answer when something answered but did not serve the ledger --
/// a 404 or a 500. The contributor's actionable fact there is still the
/// port: the usual cause is a number naming some other local service.
pub const PROBE_UNREACHABLE: &str = "unreachable";

/// Ask the declared proxy whether it is there, and say what was found.
///
/// The counterpart to the rule `routing/mod.rs` lives by. On the submission
/// path absence and failure are deliberately the same state, because a
/// proxy that vanished must never cost anyone a trace. **Declaring is the
/// other path, and it must answer**: as `main` stood, a contributor could
/// name a wrong port or an unreachable token, get no error and no
/// indicator, and have every trace silently carry no routing data.
///
/// Nothing here touches daemon state and nothing here can affect a
/// submission: it takes no `DaemonShared`, it runs only when a human asks,
/// and its whole effect is the answer it returns.
///
/// Three outcomes, each distinguishable by the caller, and **none of them
/// ever carries the token**. `IronWireLedger`'s hand-written `Debug` keeps
/// the token out of logs because it is a credential for an API that can
/// rewrite the contributor's agent configuration; the same reasoning holds
/// at the IPC boundary, where the answer crosses a socket to a shell.
///
/// The token *directory* is a different thing and is the point: the path is
/// what makes the failure fixable.
/// Answer what a running IronWire says about itself, so the app does not
/// have to ask a contributor for it.
///
/// The declaring flow's counterpart to `probe_routing`. The probe checks a
/// port and a token the contributor already named; this reports the port
/// and token path a *running* proxy published, before there is anything
/// declared to check.
///
/// Result shape, and the reason for it:
///
/// ```json
/// { "found": true, "port": 8463, "token_path": "/home/x/.ironwire/control.token" }
/// { "found": false }
/// ```
///
/// A boolean rather than a named outcome. There is exactly one distinction
/// to draw here -- a pointer was read, or it was not -- and every reason it
/// was not (never installed, not running, a version that does not publish,
/// a file this reader will not act on) is the same fact to the caller and
/// the same next step for the contributor: type the port. A vocabulary of
/// outcome strings would invite a caller to match on one, and a string that
/// is a prefix of another is how a shell comes to treat "unreachable" as
/// "reachable".
///
/// **Never carries a token.** `token_path` is a path, for display beside
/// the port; the daemon opens it itself, at call time, when it builds a
/// reader. Discovery is advisory throughout: nothing here writes settings,
/// touches daemon state, or can affect a submission.
fn handle_discover_routing(req: &Request) -> Response {
    let Some(pointer) = super::ironwire_pointer::read_pointer() else {
        return Response::ok(req.id, serde_json::json!({ "found": false }));
    };
    let mut result = serde_json::Map::new();
    result.insert("found".to_string(), serde_json::Value::Bool(true));
    result.insert("port".to_string(), serde_json::json!(pointer.port));
    if let Some(token_path) = pointer.token_path.as_ref() {
        result.insert(
            "token_path".to_string(),
            serde_json::json!(token_path.to_string_lossy()),
        );
    }
    Response::ok(req.id, serde_json::Value::Object(result))
}

/// `token_unreadable`, naming the path when one resolved.
///
/// **Absent, not null**, when nothing resolved at all: there is no path to
/// name, and an empty string would send a contributor to look at "".
fn token_unreadable(req: &Request, token_path: Option<&std::path::Path>) -> Response {
    match token_path {
        Some(path) => Response::ok(
            req.id,
            serde_json::json!({
                "outcome": PROBE_TOKEN_UNREADABLE,
                "token_path": path.to_string_lossy(),
            }),
        ),
        None => Response::ok(
            req.id,
            serde_json::json!({ "outcome": PROBE_TOKEN_UNREADABLE }),
        ),
    }
}

/// The port, the credential, and the path it came from: everything both
/// proxy-facing calls need before they can open a connection.
///
/// Extracted so `probe_routing` and `probe_routed_tools` cannot drift into
/// two answers about one machine. Every refusal here is already a
/// well-formed answer to either caller -- a bad-params error, or
/// `token_unreadable` naming the path -- so it is returned whole rather
/// than re-derived per call site.
///
/// **Never returns the token to a caller.** It is handed back so the
/// request can carry it; nothing in either handler's result contains it.
/// The refusal is boxed: a `Response` is large, and an unboxed one on
/// the error side of every call trips `result_large_err`, which the
/// clippy gate fails the build on.
fn probe_credential(req: &Request) -> Result<(u16, String, std::path::PathBuf), Box<Response>> {
    let port = match req.params.get("port").and_then(serde_json::Value::as_u64) {
        // Port 0 is not a port a proxy listens on; it is the ask-the-kernel
        // sentinel, and accepting it would probe whatever it resolved to.
        Some(port) if port > 0 && port <= u64::from(u16::MAX) => port as u16,
        _ => {
            return Err(Box::new(Response::err(
                req.id,
                ERR_BAD_PARAMS,
                "port-invalid",
            )));
        }
    };
    let token_dir = match req.params.get("token_dir") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => match value.as_str() {
            // An empty string is not a directory. Refused rather than
            // treated as absent, because falling through to the
            // environment would answer about a path the caller did not ask
            // about.
            Some(dir) if !dir.is_empty() => Some(std::path::PathBuf::from(dir)),
            _ => {
                return Err(Box::new(Response::err(
                    req.id,
                    ERR_BAD_PARAMS,
                    "token-dir-invalid",
                )));
            }
        },
    };

    // The same resolution the reader uses, through the same function, so a
    // probe cannot send a contributor to fix a file nothing reads.
    let Some(path) = super::settings::ironwire_token_path(token_dir.as_deref()) else {
        // Nothing resolved at all: no declared directory, no
        // `IRONWIRE_HOME`, no discoverable home. There is no path to name.
        return Err(Box::new(token_unreadable(req, None)));
    };
    // Lexical, not a canonicalization: `std::path::absolute` touches no
    // filesystem and resolves a relative path against the same working
    // directory `fs::read_to_string` would, so what is reported and what is
    // read stay the same file.
    let reported = std::path::absolute(&path).unwrap_or_else(|_| path.clone());

    let token = match std::fs::read_to_string(&path) {
        Ok(token) => token.trim().to_string(),
        Err(_) => return Err(Box::new(token_unreadable(req, Some(&reported)))),
    };
    if token.is_empty() {
        // A file that exists with nothing in it. There is no credential to
        // send, so this is the same fixable state as no file at all.
        return Err(Box::new(token_unreadable(req, Some(&reported))));
    }
    Ok((port, token, reported))
}

async fn handle_probe_routing(req: &Request) -> Response {
    let (port, token, reported) = match probe_credential(req) {
        Ok(found) => found,
        Err(refusal) => return *refusal,
    };

    let Ok(client) = reqwest::Client::builder().build() else {
        // The platform trust store would not load. Not a fact about the
        // proxy, and saying "unreachable" would send the contributor to
        // check a port that is fine.
        return Response::err(req.id, ERR_UNAVAILABLE, "probe-client-unavailable");
    };
    let response = client
        .get(format!("http://127.0.0.1:{port}/_ironwire/log?limit=1"))
        .timeout(PROBE_TIMEOUT)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await;
    let Ok(response) = response else {
        return Response::ok(
            req.id,
            serde_json::json!({ "outcome": PROBE_UNREACHABLE, "port": port }),
        );
    };
    let status = response.status();
    if status.is_success() {
        return Response::ok(req.id, serde_json::json!({ "outcome": PROBE_REACHABLE }));
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return token_unreadable(req, Some(&reported));
    }
    Response::ok(
        req.id,
        serde_json::json!({ "outcome": PROBE_UNREACHABLE, "port": port }),
    )
}

/// The largest `/_ironwire/settings` body this reader will accumulate.
///
/// Another process's output, arriving from a port anything on the machine
/// can bind. The real body is a few kilobytes; the bound is here so a
/// process that streams forever cannot make a settings dialog eat the
/// machine's memory while a human waits on it.
const ROUTED_TOOLS_BODY_LIMIT: usize = 64 * 1024;

/// The most tool rows echoed back to a shell. Same reasoning, one layer up.
const ROUTED_TOOLS_LIMIT: usize = 64;

/// Ask the declared proxy which tools on this machine are pointed at it.
///
/// The per-tool counterpart to `probe_routing`, and the reason it exists:
/// declaring a proxy in *this* app says nothing about whether Codex or
/// Gemini CLI are configured to send through it, so a shell that renders
/// one switch as three tool verdicts is inventing two of them. IronWire
/// answers the question itself -- `ironwire connect` is what edits those
/// config files, so a second detector here would be a second answer on one
/// machine, and ours would be the wrong one.
///
/// Result shape:
///
/// ```json
/// { "outcome": "reachable", "tools": [ { "id": "claude", "installed": true, "wired": true } ] }
/// { "outcome": "unreachable", "port": 8463 }
/// { "outcome": "token_unreadable", "token_path": "/home/x/.ironwire/control.token" }
/// ```
///
/// The outcome vocabulary is `probe_routing`'s, deliberately: it is the
/// same connection to the same proxy with the same credential, and a
/// caller that already reads one must not have to learn a second set of
/// words for the identical three states.
///
/// **What `wired` does and does not evidence.** It is true for any loopback
/// host on any port whose path is `/anthropic` -- deliberately upstream, so
/// that `connect` can follow a port change -- and nothing on the response
/// carries a port or a URL. So it evidences the *local hop* and not the
/// destination: "IronWire is handling this tool" is supportable, "this
/// tool's work is private" is not. Copy built on this must say the first.
///
/// An answer that arrives but cannot be read reports `reachable` with no
/// tools rather than `unreachable`. The proxy did answer -- sending a
/// contributor to check a port that is fine would be the wrong next step --
/// and an empty list is exactly the right amount of evidence about every
/// tool: none.
///
/// Only `id`, `installed` and `wired` cross the socket. `config_path` and
/// `connect_command` are a path and a shell command from another process,
/// and nothing here renders either.
async fn handle_probe_routed_tools(req: &Request) -> Response {
    let (port, token, reported) = match probe_credential(req) {
        Ok(found) => found,
        Err(refusal) => return *refusal,
    };

    let Ok(client) = reqwest::Client::builder().build() else {
        return Response::err(req.id, ERR_UNAVAILABLE, "probe-client-unavailable");
    };
    let unreachable = || {
        Response::ok(
            req.id,
            serde_json::json!({ "outcome": PROBE_UNREACHABLE, "port": port }),
        )
    };
    let response = client
        .get(format!("http://127.0.0.1:{port}/_ironwire/settings"))
        .timeout(PROBE_TIMEOUT)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await;
    let Ok(mut response) = response else {
        return unreachable();
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return token_unreadable(req, Some(&reported));
    }
    if !status.is_success() {
        return unreachable();
    }

    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > ROUTED_TOOLS_BODY_LIMIT {
                    // Over the bound. The proxy answered, so this is not an
                    // unreachable port; it is an answer nothing can read.
                    return Response::ok(
                        req.id,
                        serde_json::json!({ "outcome": PROBE_REACHABLE, "tools": [] }),
                    );
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return unreachable(),
        }
    }

    Response::ok(
        req.id,
        serde_json::json!({ "outcome": PROBE_REACHABLE, "tools": routed_tools(&body) }),
    )
}

/// The tool rows in a `/_ironwire/settings` body, or none.
///
/// Every unreadable shape yields an empty list rather than an error: a body
/// this build cannot parse is the same fact to a shell as a proxy that
/// listed nothing -- no evidence about any tool -- and the shell must
/// render that as "not known", never as a verdict.
fn routed_tools(body: &[u8]) -> Vec<serde_json::Value> {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(tools) = parsed.get("tools").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|tool| {
            let id = tool.get("id").and_then(serde_json::Value::as_str)?;
            if id.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "id": id,
                "installed": tool
                    .get("installed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                "wired": tool
                    .get("wired")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }))
        })
        .take(ROUTED_TOOLS_LIMIT)
        .collect()
}

#[cfg(test)]
#[path = "cloud_credential_recovery_tests.rs"]
mod cloud_credential_recovery_tests;

#[cfg(test)]
mod tests {
    mod witnessed_flow {
        include!("ipc_witness_flow_test.rs");
    }
    use super::*;
    use crate::config::tests_support::temp_store;
    use crate::daemon::policy::UNKNOWN_PROJECT_KEY;

    fn shared() -> DaemonShared {
        let (_d, store) = temp_store();
        // Leak the tempdir for the lifetime of the test process; the store
        // borrows its path.
        std::mem::forget(_d);
        DaemonShared::load(store).unwrap()
    }

    /// A queue entry whose session file holds `body`, so
    /// `search_original` has something real to read.
    fn shared_with_session(body: &str) -> (DaemonShared, Uuid, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        std::fs::write(&path, body).unwrap();

        let s = shared();
        let entry_id = Uuid::new_v4();
        let entry = crate::daemon::queue::QueueEntry {
            entry_id,
            session_hash: "sha256:test".into(),
            source: "claude-code".into(),
            project_key: "/tmp/search-original".into(),
            project_label: "search-original".into(),
            path,
            size_bytes: body.len() as u64,
            discovered_at: chrono::Utc::now(),
            ..Default::default()
        };
        s.queue
            .lock()
            .expect("queue lock")
            .upsert(entry, 500)
            .unwrap();
        (s, entry_id, dir)
    }

    async fn recorded_witness_review() -> (
        DaemonShared,
        Uuid,
        tempfile::TempDir,
        super::super::preview::WitnessPreview,
    ) {
        let body = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"synthetic onboarding task\"},\"cwd\":\"/synthetic/project\",\"timestamp\":\"2026-08-08T10:00:00Z\",\"sessionId\":\"sess-1\",\"uuid\":\"a1\"}\n";
        let (s, id, dir) = shared_with_session(body);
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let path = project.join("sess-1.jsonl");
        std::fs::write(&path, body).unwrap();
        {
            let mut queue = s.queue.lock().unwrap();
            let mut entry = queue.get(id).unwrap().clone();
            entry.path = path;
            entry.session_hash = crate::source::session_hash(body.as_bytes());
            *queue = super::super::queue::Queue::default();
            queue.upsert(entry, 500).unwrap();
        }
        s.settings.lock().unwrap().claude_source =
            Some(super::super::settings::SourceDeclaration::Watch {
                path: dir.path().to_path_buf(),
            });
        let device = crate::identity::DeviceIdentity::load_or_generate(&s.store).unwrap();
        let mut cfg = crate::commands::unenrolled_preview_config();
        cfg.device_key_id = device.device_key_id;
        cfg.tenant_id = "synthetic-tenant".into();
        cfg.user_subject = "synthetic-user".into();
        cfg.consent_scopes = vec!["debugging_evaluation".into()];
        let roots = s.source_roots_with_routing();
        let sources = crate::source::all_sources(&roots);
        let entry = s.queue.lock().unwrap().get(id).unwrap().clone();
        let (source, reference) = super::super::find_session(&sources, &entry).unwrap();
        let (_, _, envelope) = super::super::preview::build_preview_with_correction(
            &s.store,
            Some(&cfg),
            None,
            source,
            &reference,
            None,
            false,
        )
        .await
        .unwrap();
        let (response, address) = crate::witness::transport::signed_fixture(
            serde_json::to_vec_pretty(&envelope).unwrap(),
        );
        cfg.witness = Some(crate::config::WitnessSettings {
            url: "https://synthetic-witness.invalid".into(),
            signing_address: address,
            expected_measurements: vec![format!("mrtd={}", "aa".repeat(48))],
            admission_evidence: false,
        });
        s.store.save_config(&cfg).unwrap();
        let artifact = super::super::approved_envelope::WitnessReviewArtifact::new(
            response,
            entry.session_hash,
            super::super::preview::input_fingerprint(&cfg, None, false),
            None,
            None,
            None,
        );
        let transcript = source.load(&reference).unwrap();
        let (summary, body, _) = super::super::preview::summarize_witnessed_preview(
            &artifact,
            &cfg,
            None,
            &transcript,
            reference.size_bytes,
            false,
        )
        .unwrap();
        (
            s,
            id,
            dir,
            super::super::preview::WitnessPreview {
                summary,
                body,
                artifact,
            },
        )
    }

    /// The sentence a refused review carries, chosen once in the daemon.
    ///
    /// Before this, every witness refusal reached the shells as the same word
    /// and each shell rendered its single `review.failed` sentence, so a
    /// receipt the reviewer declined and a reviewer that was simply down were
    /// the same event on every platform. Carrying the label was not enough on
    /// its own -- all three views substitute the constant and never read it --
    /// so the daemon selects the words the way it already does for admission
    /// preparation.
    #[test]
    fn a_refused_review_carries_the_sentence_for_its_own_refusal() {
        use crate::witness::WitnessTrustError;
        let review = crate::witness_copy::witness_copy().review;
        for (label, expected) in [
            ("admission_evidence_refused", review.failed_receipt_declined),
            ("witness_body_not_stripped", review.failed_bodies_returned),
            ("witness_quote_replayed", review.failed_unproven),
            ("witness_attestation_unavailable", review.failed_unreachable),
        ] {
            let response = witness_review_response(Response::err(1, ERR_UNAVAILABLE, label));
            assert_eq!(
                response
                    .result
                    .as_ref()
                    .and_then(|value| value.get("view"))
                    .and_then(|view| view.get("message"))
                    .and_then(|message| message.as_str()),
                Some(expected),
                "{label} did not carry its own sentence"
            );
            assert_eq!(
                response.error.as_ref().map(|e| e.message.as_str()),
                Some(label),
                "{label} lost the label a shell may still key on"
            );
        }
        // Every refusal the client can raise is classified, so none of them
        // reaches a contributor as the sentence for an unclassified one.
        for label in WitnessTrustError::ALL_REFUSAL_LABELS {
            let response = witness_review_response(Response::err(1, ERR_UNAVAILABLE, label));
            let message = response
                .result
                .as_ref()
                .and_then(|value| value.get("view"))
                .and_then(|view| view.get("message"))
                .and_then(|message| message.as_str())
                .expect("a refusal carries a sentence");
            assert_ne!(message, review.failed, "{label} fell through");
            assert!(!message.contains(label), "{label} was rendered raw");
        }
    }

    /// A response that is not a refusal is left exactly as it was, and a
    /// refusal this build cannot classify gets the sentence that admits so.
    #[test]
    fn a_review_that_did_not_refuse_is_left_alone() {
        let ok = witness_review_response(Response::ok(1, serde_json::json!({"a":1})));
        assert!(ok.error.is_none());
        assert_eq!(ok.result, Some(serde_json::json!({"a":1})));

        let unknown =
            witness_review_response(Response::err(1, ERR_UNAVAILABLE, "witness-review-failed"));
        assert_eq!(
            unknown
                .result
                .as_ref()
                .and_then(|value| value.get("view"))
                .and_then(|view| view.get("message"))
                .and_then(|message| message.as_str()),
            Some(crate::witness_copy::witness_copy().review.failed)
        );
    }

    /// A review that the witness refused reaches the shell under its own
    /// name.
    ///
    /// Every witness refusal used to arrive as the single word
    /// `witness-review-failed`: this route discarded the label with `Err(_)`,
    /// so a receipt whose signer was not yet trusted and a witness that was
    /// simply down were the same event to every shell. The label is already
    /// in hand here -- `submit.rs` maps the transport error through
    /// `refusal_label()` and `.map_err(anyhow::Error::msg)` carries it -- so
    /// this route was throwing away something it had.
    ///
    /// The injected label is taken from the variant rather than typed, so a
    /// rename cannot leave this test asserting a word nothing produces.
    #[tokio::test]
    async fn a_refused_review_reaches_the_shell_under_its_own_name() {
        let (s, id, _dir, _review) = recorded_witness_review().await;
        let refusal =
            crate::witness::WitnessTrustError::WitnessAdmissionEvidenceRefused.refusal_label();
        let response = handle_witness_preview_request_inner(
            &s,
            &req(
                "witness_preview_request",
                serde_json::json!({"entry_id":id,"raw_session_confirmed":true}),
            ),
            Some(Err(anyhow::anyhow!(refusal))),
        )
        .await;
        assert_eq!(
            response.error.as_ref().map(|e| e.message.as_str()),
            Some(refusal),
            "the refusal was replaced with a word that names nothing"
        );
    }

    /// The fail-closed half. A failure that is not a witness refusal keeps the
    /// fixed word: the messages on this path are internal strings, and a route
    /// that forwarded whatever `anyhow` happened to hold would put them in
    /// front of a contributor.
    #[tokio::test]
    async fn a_failure_that_is_not_a_witness_refusal_keeps_the_fixed_word() {
        for message in [
            "secret-leak-detected",
            "pii-filter-unavailable",
            "witness-review-source-changed",
            "some internal string nobody should read",
        ] {
            let (s, id, _dir, _review) = recorded_witness_review().await;
            let response = handle_witness_preview_request_inner(
                &s,
                &req(
                    "witness_preview_request",
                    serde_json::json!({"entry_id":id,"raw_session_confirmed":true}),
                ),
                Some(Err(anyhow::anyhow!(message))),
            )
            .await;
            assert_eq!(
                response.error.as_ref().map(|e| e.message.as_str()),
                Some("witness-review-failed"),
                "{message} was forwarded to a shell"
            );
        }
    }

    #[tokio::test]
    async fn recorded_witness_request_reopens_and_approves_the_same_persisted_artifact() {
        let (s, id, _dir, review) = recorded_witness_review().await;
        let expected_digest = review.summary.envelope_digest.clone();
        let expected_body = review.body.clone();
        let response = handle_witness_preview_request_inner(
            &s,
            &req(
                "witness_preview_request",
                serde_json::json!({"entry_id":id,"raw_session_confirmed":true}),
            ),
            Some(Ok(review)),
        )
        .await;
        assert!(response.error.is_none(), "{:?}", response.error);
        assert_eq!(
            s.queue.lock().unwrap().get(id).unwrap().state,
            QueueState::Pending
        );
        let reloaded =
            DaemonShared::load(ConfigStore::open(s.store.dir().to_path_buf()).unwrap()).unwrap();
        // Source settings are persisted independently by the settings API.
        *reloaded.settings.lock().unwrap() = s.settings.lock().unwrap().clone();
        let (summary, body) = open_preview(&reloaded, id).await.unwrap();
        assert_eq!(summary.envelope_digest, expected_digest);
        assert_eq!(body, expected_body);
        let refusal = handle_approve(
            &reloaded,
            &req(
                "approve",
                serde_json::json!({"entry_id":id,"outcome":"failed"}),
            ),
        )
        .await;
        assert_eq!(refusal.result.unwrap()["approved"], 0);
        let approved = handle_approve(
            &reloaded,
            &req("approve", serde_json::json!({"entry_id":id})),
        )
        .await;
        assert_eq!(approved.result.unwrap()["approved"], 1);
        assert_eq!(
            reloaded
                .queue
                .lock()
                .unwrap()
                .get(id)
                .unwrap()
                .previewed_envelope_digest
                .as_deref(),
            Some(expected_digest.as_str())
        );
    }

    #[tokio::test]
    async fn recorded_witness_request_refuses_changed_consent_before_pinning() {
        let (s, id, _dir, review) = recorded_witness_review().await;
        s.settings.lock().unwrap().ironwire_attested_bodies = true;
        let response = handle_witness_preview_request_inner(
            &s,
            &req(
                "witness_preview_request",
                serde_json::json!({"entry_id":id,"raw_session_confirmed":true}),
            ),
            Some(Ok(review)),
        )
        .await;
        assert_eq!(response.error.unwrap().message, "witness-review-stale");
        assert!(
            s.queue
                .lock()
                .unwrap()
                .get(id)
                .unwrap()
                .previewed_envelope_digest
                .is_none()
        );
    }

    #[tokio::test]
    async fn witness_request_requires_confirmation_before_lookup_or_io() {
        let s = shared();
        for params in [
            serde_json::json!({}),
            serde_json::json!({"raw_session_confirmed": false}),
            serde_json::json!({"raw_session_confirmed": "true"}),
        ] {
            let response = handle_request_async(&s, &req("witness_preview_request", params)).await;
            assert_eq!(
                response.error.unwrap().message,
                "witness-review-consent-required"
            );
        }
        assert!(METHODS.contains(&"witness_preview_request"));
    }

    #[tokio::test]
    async fn witness_request_refuses_without_enrollment_and_keeps_pending() {
        let (s, id, _dir) = shared_with_session("{}");
        let response = handle_request_async(
            &s,
            &req(
                "witness_preview_request",
                serde_json::json!({"entry_id": id,"raw_session_confirmed":true}),
            ),
        )
        .await;
        assert_eq!(
            response.error.unwrap().message,
            "witness-review-not-enrolled"
        );
        let queue = s.queue.lock().unwrap();
        assert_eq!(queue.get(id).unwrap().state, QueueState::Pending);
        assert!(queue.get(id).unwrap().previewed_envelope_digest.is_none());
    }

    #[tokio::test]
    async fn missing_witness_artifact_never_falls_back_to_local_preview() {
        let (s, id, _dir) = shared_with_session("{}");
        s.queue
            .lock()
            .unwrap()
            .record_previewed_envelope(id, "witness-sha256:missing", None);
        assert!(open_preview(&s, id).await.is_err());
        assert!(resolve_preview_envelope(&s, id).await.is_err());
        let response = handle_request_async(
            &s,
            &req(
                "witness_preview_request",
                serde_json::json!({"entry_id":id,"raw_session_confirmed":true}),
            ),
        )
        .await;
        assert_eq!(
            response.error.unwrap().message,
            "witness-review-already-pinned"
        );
        assert_eq!(
            s.queue.lock().unwrap().get(id).unwrap().state,
            QueueState::Pending
        );
    }

    /// The reason this call exists. `preview_search` scans the REDACTED
    /// body, so a value redaction removed returns zero there -- which is
    /// indistinguishable from a value that was never in the session. This
    /// reads the original, so it can tell those apart.
    #[tokio::test]
    async fn search_original_counts_a_value_that_redaction_would_remove() {
        let (s, id, _dir) = shared_with_session(
            "{\"secret\":\"planted-secret-value\"}\n{\"note\":\"planted-secret-value again\"}\n",
        );
        assert_eq!(
            search_original(&s, id, "planted-secret-value")
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn search_original_reports_zero_for_a_value_that_was_never_there() {
        let (s, id, _dir) = shared_with_session("{\"note\":\"nothing to see\"}\n");
        assert_eq!(
            search_original(&s, id, "never-appeared-anywhere")
                .await
                .unwrap(),
            0
        );
    }

    /// An empty needle matches nothing rather than every position.
    #[tokio::test]
    async fn search_original_treats_an_empty_needle_as_no_matches() {
        let (s, id, _dir) = shared_with_session("anything at all");
        assert_eq!(search_original(&s, id, "").await.unwrap(), 0);
    }

    /// Overlapping occurrences are counted the way a person reading the
    /// transcript would count them: left to right, non-overlapping.
    #[tokio::test]
    async fn search_original_counts_non_overlapping_matches() {
        let (s, id, _dir) = shared_with_session("aaaa");
        assert_eq!(search_original(&s, id, "aa").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn search_original_refuses_an_unknown_entry() {
        let (s, _id, _dir) = shared_with_session("body");
        assert_eq!(
            search_original(&s, Uuid::new_v4(), "anything").await,
            Err(ERR_UNKNOWN_ENTRY_ID)
        );
    }

    /// The whole bound of this call: it answers with a COUNT and never with
    /// bytes. Asserted on the wire shape, because the wire is what a shell
    /// can actually reach.
    #[tokio::test]
    async fn search_original_puts_no_content_on_the_wire() {
        let (s, id, _dir) = shared_with_session("{\"secret\":\"planted-secret-value\"}");
        let req = Request {
            id: 1,
            method: "search_original".to_string(),
            params: serde_json::json!({
                "entry_id": id.to_string(),
                "needle": "planted-secret-value",
            }),
        };
        let response = handle_search_original(&s, &req).await;
        let body = serde_json::to_string(&response).unwrap();
        assert!(
            body.contains("\"matches\":1"),
            "expected a count, got {body}"
        );
        assert!(
            !body.contains("planted-secret-value"),
            "the needle must never be echoed back: {body}"
        );
    }

    /// A daemon whose settings never declared a proxy builds no ledger and
    /// attempts no connection.
    #[test]
    fn no_proxy_declared_builds_no_ledger() {
        assert!(shared().routing_ledger().is_none());
    }

    /// `source_roots_with_routing` is the one insertion point: bare roots
    /// with no ledger, decorated roots when the daemon holds one.
    #[test]
    fn source_roots_with_routing_reflects_whether_a_ledger_is_held() {
        let s = shared();
        assert!(
            !s.source_roots_with_routing().is_routed(),
            "no ledger held, so the roots must stay bare"
        );

        let s = shared();
        s.routing.write().unwrap().ledger = Some(Arc::new(
            crate::routing::ironwire::IronWireLedger::new(8463, "t".to_string()),
        ));
        assert!(
            s.source_roots_with_routing().is_routed(),
            "a held ledger must be attached"
        );
    }

    /// A refresh against a port nothing is listening on must not fail or
    /// hang the caller -- the same guarantee `IronWireLedger::refresh` makes
    /// on its own, exercised here through the daemon's own entry point.
    #[tokio::test]
    async fn a_refresh_failure_leaves_the_daemon_running_and_the_overlay_empty() {
        // Bind to get a genuinely free loopback port, then drop the
        // listener so nothing answers on it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let s = shared();
        s.routing.write().unwrap().ledger = Some(Arc::new(
            crate::routing::ironwire::IronWireLedger::new(port, "t".to_string()),
        ));
        s.refresh_routing().await;
        assert!(
            !s.routing_ledger().unwrap().has_rows(),
            "an unreachable proxy leaves the snapshot empty, not the daemon down"
        );
        assert!(
            s.source_roots_with_routing().is_routed(),
            "the ledger stays attached even though it has nothing to say"
        );
    }

    /// `has_rows` only gets reported when it changes, not on every poll.
    #[test]
    fn routing_state_reports_only_on_transition() {
        let s = shared();
        assert_eq!(
            s.routing_transition(false),
            None,
            "still empty is not a transition"
        );
        assert_eq!(
            s.routing_transition(true),
            Some(true),
            "empty to reading is a transition"
        );
        assert_eq!(
            s.routing_transition(true),
            None,
            "still reading is not a transition"
        );
        assert_eq!(
            s.routing_transition(false),
            Some(false),
            "reading to empty is a transition"
        );
    }

    /// The full loop: a mock IronWire server, the ledger the daemon owns,
    /// a real session file on disk, and `source_roots_with_routing`'s
    /// output actually run through `all_sources` and `load`. This is the
    /// assertion Task 5 could only pin with a test-only accessor -- here the
    /// routing row is asserted on the transcript a real adapter produced,
    /// not on whether a ledger happens to be reachable.
    #[tokio::test]
    async fn a_refreshed_ledger_reaches_a_loaded_transcript() {
        let claude_root = tempfile::tempdir().unwrap();
        let project_dir = claude_root.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let session_path = project_dir.join("sess-1.jsonl");
        std::fs::write(
            &session_path,
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"},\
             \"cwd\":\"/x/proj\",\"timestamp\":\"2026-08-08T10:00:00Z\",\
             \"version\":\"2.0.1\",\"sessionId\":\"sess-1\",\"uuid\":\"a1\"}\n",
        )
        .unwrap();

        let router = axum::Router::new().route(
            "/_ironwire/log",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "exchanges": [{
                        "started_at": "2026-08-08T10:05:00Z",
                        "client_session_id": "sess-1",
                        "facade": "anthropic",
                        "backend": "claude-sub",
                        "rung": "same_model",
                        "attempts": 1,
                        "status": 200
                    }]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let s = shared();
        {
            let mut settings = s.settings.lock().unwrap();
            settings.claude_source = Some(crate::daemon::settings::SourceDeclaration::Watch {
                path: claude_root.path().to_path_buf(),
            });
        }
        s.routing.write().unwrap().ledger = Some(Arc::new(
            crate::routing::ironwire::IronWireLedger::new(port, "t".to_string()),
        ));

        // This is the seam this task installs: refresh, then build sources
        // off the daemon's own held instance.
        s.refresh_routing().await;
        assert!(
            s.routing_ledger().unwrap().has_rows(),
            "the mock server's row must have reached the snapshot"
        );

        let roots = s.source_roots_with_routing();
        let sources = crate::source::all_sources(&roots);
        let claude = sources
            .iter()
            .find(|src| src.name() == crate::source::SOURCE_CLAUDE_CODE)
            .expect("the claude source is present");
        let refs = claude.discover().expect("discovers the fixture");
        let session_ref = refs
            .into_iter()
            .find(|r| r.path == session_path)
            .expect("the written session was discovered");
        let transcript = claude.load(&session_ref).expect("loads");
        assert_eq!(
            transcript.routing.len(),
            1,
            "the refreshed row reached the loaded transcript"
        );
    }

    /// Every source declaration carries a local filesystem path, and this
    /// blob is serialized wholesale. A source added to `DaemonSettings`
    /// without a matching removal here would put that path on the wire.
    #[test]
    fn the_settings_blob_reports_source_modes_and_never_a_source_path() {
        for source in crate::source::registered_source_names() {
            let key = crate::daemon::settings::source_settings_key(source)
                .expect("every registered source has a settings key");
            for (declaration, expected) in [
                (
                    serde_json::json!({"mode":"watch","path":"/private/source-path-sentinel"}),
                    "watch",
                ),
                (serde_json::json!({"mode":"off"}), "off"),
                (serde_json::Value::Null, "unset"),
            ] {
                let mut settings = DaemonSettings::default();
                crate::daemon::settings::apply_settings_object(
                    &mut settings,
                    &serde_json::json!({key:declaration}),
                )
                .unwrap();
                let v = redacted_settings(&settings);
                assert!(!v.to_string().contains("source-path-sentinel"));
                assert!(v.get(key).is_none(), "raw declaration leaked for {source}");
                assert_eq!(v[format!("{key}_mode")], expected);
            }
        }
    }

    fn req(method: &str, params: serde_json::Value) -> Request {
        Request {
            id: 1,
            method: method.to_string(),
            params,
        }
    }

    use crate::daemon::test_support::at;

    /// A real directory on this machine whose canonical path is an
    /// admissible project key. `set_project_mode` no longer accepts a key
    /// the daemon cannot corroborate, so tests name directories that exist
    /// -- exactly as the CLI's `daemon project <path>` does.
    ///
    /// The tempdir is leaked for the lifetime of the test process: the key
    /// must stay resolvable for as long as the daemon under test might
    /// re-validate it.
    fn tmp_project(basename: &str) -> String {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(basename);
        std::fs::create_dir_all(&p).unwrap();
        std::mem::forget(d);
        std::fs::canonicalize(&p)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn arming_autonomy_over_the_socket_is_now_allowed() {
        // The terminal-only gate is removed: same-user code that can reach
        // this socket can already read the session files directly and
        // install its own watcher, so this call grants it neither the read
        // nor the persistence it would need to exfiltrate anything, and
        // would in fact be a worse channel for an attacker than doing it
        // itself (rate-limited, capped, redacted, delivered somewhere it
        // cannot read back). See the module doc's "Authorization" section.
        let s = shared();
        let key = tmp_project("p");
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": key, "mode": "auto_upload"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(
            s.policy.lock().unwrap().resolve(&key),
            ProjectMode::AutoUpload
        );
    }

    #[test]
    fn arming_autonomy_appends_an_audit_entry() {
        // The audit log is what replaced the removed gate: not a control,
        // but a local record a contributor can read to see when autonomy
        // was granted.
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": tmp_project("p"), "mode": "auto_upload"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        let entries = audit::load(&s.store).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "armed-auto-upload");
        assert_eq!(entries[0].project_label.as_deref(), Some("p"));
    }

    #[test]
    fn arming_suggestion_is_absent_until_a_project_has_contributed_enough() {
        let s = shared();
        let key = tmp_project("api");
        handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": &key, "mode": "notify_only"}),
            ),
        );
        let empty = handle_request(&s, &req("arming_suggestion", serde_json::json!({})));
        assert!(
            empty.result.unwrap().get("project_id").is_none(),
            "no suggestion until the threshold is met"
        );

        {
            let mut policy = s.policy.lock().unwrap();
            for _ in 0..super::super::policy::ARMING_SUGGESTION_THRESHOLD {
                policy.record_contribution(&key);
            }
        }
        let offered = handle_request(&s, &req("arming_suggestion", serde_json::json!({})));
        let body = offered.result.unwrap();
        assert_eq!(body["project_label"], "api");
        assert_eq!(
            body["contributed_count"],
            super::super::policy::ARMING_SUGGESTION_THRESHOLD
        );
        // The key is a full local path and must never cross the socket.
        assert!(
            !body.to_string().contains(&key),
            "a project key must not appear in the answer: {body}"
        );
    }

    /// Asking must not consume the offer: a shell redraws after every queue
    /// refresh, and an offer that vanished on being read would be a
    /// dismissal the contributor never made.
    #[test]
    fn asking_for_the_suggestion_twice_answers_twice() {
        let s = shared();
        let key = tmp_project("api");
        {
            let mut policy = s.policy.lock().unwrap();
            for _ in 0..super::super::policy::ARMING_SUGGESTION_THRESHOLD {
                policy.record_contribution(&key);
            }
        }
        let first = handle_request(&s, &req("arming_suggestion", serde_json::json!({})));
        let second = handle_request(&s, &req("arming_suggestion", serde_json::json!({})));
        assert_eq!(first.result.unwrap(), second.result.unwrap());
    }

    #[test]
    fn declining_arming_silences_the_suggestion_and_survives_a_reload() {
        let s = shared();
        let key = tmp_project("api");
        {
            let mut policy = s.policy.lock().unwrap();
            for _ in 0..super::super::policy::ARMING_SUGGESTION_THRESHOLD {
                policy.record_contribution(&key);
            }
            policy.save(&s.store).unwrap();
        }
        let offered = handle_request(&s, &req("arming_suggestion", serde_json::json!({})));
        let project_id = offered.result.unwrap()["project_id"]
            .as_str()
            .unwrap()
            .to_string();

        let declined = handle_request(
            &s,
            &req(
                "decline_arming",
                serde_json::json!({"project_id": project_id}),
            ),
        );
        assert_eq!(declined.result.unwrap()["declined"], true);

        let after = handle_request(&s, &req("arming_suggestion", serde_json::json!({})));
        assert!(after.result.unwrap().get("project_id").is_none());

        // Persisted, not just held in memory: a restart must not resurrect a
        // question the contributor has already answered.
        let reloaded = super::super::policy::ProjectPolicy::load(&s.store).unwrap();
        assert!(reloaded.arming_suggestion(Utc::now()).is_none());
    }

    #[test]
    fn declining_arming_refuses_an_unrecognized_project_id() {
        let s = shared();
        let out = handle_request(
            &s,
            &req(
                "decline_arming",
                serde_json::json!({"project_id": "proj_deadbeef"}),
            ),
        );
        assert_eq!(out.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn declining_arming_requires_a_project_id() {
        let s = shared();
        let out = handle_request(&s, &req("decline_arming", serde_json::json!({})));
        assert_eq!(out.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn set_project_mode_relabels_the_queue_immediately_with_no_intervening_tick() {
        // Regression for the round-1 residual: a queue entry's stored label
        // must not lag a policy edit until the next poll. Everything here
        // goes through `handle_request` / direct queue seeding -- `tick` is
        // never called -- so any staleness can only come from
        // `set_project_mode` itself failing to relabel the queue.
        let s = shared();

        // "work/api" is configured and already has a queue entry, seeded
        // directly (as if a session had been queued for it earlier while
        // its basename was still unique).
        let work_api = tmp_project("api");
        let client_api = tmp_project("api");
        handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": work_api, "mode": "notify_only"}),
            ),
        );
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: work_api.clone(),
                        project_label: "api".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }

        // A colliding project shows up via a policy edit -- no tick runs.
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": client_api, "mode": "ignore"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);

        let queue_label = {
            let queue = s.queue.lock().unwrap();
            queue.get(entry_id).unwrap().project_label.clone()
        };

        let list = handle_request(&s, &req("list_projects", serde_json::json!({})));
        let projects = list.result.unwrap()["projects"].clone();
        let work_row = projects
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["mode"] == serde_json::json!("notify_only"))
            .expect("work/api row");
        let list_label = work_row["project_label"].as_str().unwrap().to_string();

        assert_eq!(
            queue_label, list_label,
            "queue and list_projects must agree immediately, with no tick in between"
        );
        assert!(
            list_label.starts_with("api ("),
            "expected a collision suffix, got {list_label}"
        );
    }

    #[test]
    fn setting_notify_only_over_the_socket_is_allowed() {
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": tmp_project("p"), "mode": "notify_only"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
    }

    #[tokio::test]
    async fn bulk_approval_over_the_socket_is_now_allowed_and_appends_an_audit_entry() {
        // As with arming autonomy, the terminal-only gate on bulk approval
        // is removed for the same reason: it restricted nothing an attacker
        // with same-user code execution did not already have. The audit
        // entry is the replacement -- visibility, not a control.
        let s = shared();
        let r = handle_request_async(&s, &req("approve", serde_json::json!({"all": true}))).await;
        assert!(r.error.is_none(), "{:?}", r.error);
        let entries = audit::load(&s.store).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "bulk-approved");
        assert_eq!(entries[0].project_label, None);
    }

    #[tokio::test]
    async fn a_single_entry_approval_leaves_the_audit_log_empty() {
        // Only the "approve all" bulk action is consequential enough to
        // audit; approving one entry at a time is the default, always-was
        // path and does not need a new log entry per click.
        let s = shared();
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: "/tmp/p".to_string(),
                        project_label: "p".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }
        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({"entry_id": entry_id.to_string()}),
            ),
        )
        .await;
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(audit::load(&s.store).unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_approval_carries_its_verdict_to_the_entry() {
        let s = shared();
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: "/tmp/p".to_string(),
                        project_label: "p".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        // Already pinned, so `handle_approve` does not try to
                        // build a real preview for a path that does not
                        // exist -- this test is about the verdict, not the
                        // envelope pipeline.
                        previewed_envelope_digest: Some("sha256:preview".to_string()),
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }

        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({"entry_id": entry_id.to_string(), "outcome": "partly"}),
            ),
        )
        .await;
        assert!(r.error.is_none(), "approve should succeed: {:?}", r.error);

        let queue = s.queue.lock().unwrap();
        assert_eq!(
            queue.get(entry_id).unwrap().approved_verdict.as_deref(),
            Some("partly")
        );
    }

    /// A bulk approval applies one verdict to every entry it covers. This is a
    /// coverage-over-precision tradeoff taken deliberately; see the spec.
    #[tokio::test]
    async fn a_bulk_approval_applies_its_verdict_to_every_entry() {
        let s = shared();
        {
            let mut queue = s.queue.lock().unwrap();
            for n in 0..2u8 {
                queue
                    .upsert(
                        super::super::queue::QueueEntry {
                            entry_id: uuid::Uuid::new_v4(),
                            session_hash: format!("sha256:seed{n}"),
                            source: "claude-code".to_string(),
                            project_key: "/tmp/p".to_string(),
                            project_label: "p".to_string(),
                            path: std::path::PathBuf::from(format!("/tmp/seed{n}.jsonl")),
                            size_bytes: 1,
                            discovered_at: Utc::now(),
                            // Already pinned, for the same reason as the
                            // single-entry test above.
                            previewed_envelope_digest: Some(format!("sha256:preview{n}")),
                            ..Default::default()
                        },
                        500,
                    )
                    .unwrap();
            }
        }

        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({"all": true, "outcome": "worked"}),
            ),
        )
        .await;
        assert!(r.error.is_none(), "{:?}", r.error);

        let queue = s.queue.lock().unwrap();
        for e in queue.all() {
            assert_eq!(e.approved_verdict.as_deref(), Some("worked"));
        }
    }

    /// A typo must not silently submit the run as `Unknown`. Same rule the
    /// `--outcome` flag applies, at the IPC boundary.
    #[tokio::test]
    async fn an_unrecognised_verdict_is_refused_and_approves_nothing() {
        let s = shared();
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: "/tmp/p".to_string(),
                        project_label: "p".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }

        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({"entry_id": entry_id.to_string(), "outcome": "sucess"}),
            ),
        )
        .await;

        assert!(r.error.is_some(), "an unknown verdict must be refused");
        let queue = s.queue.lock().unwrap();
        assert_eq!(
            queue.get(entry_id).unwrap().state,
            QueueState::Pending,
            "a refused call must approve nothing"
        );
    }

    /// A pinned, pending entry with a path that does not exist. Enough for
    /// the correction refusals below, every one of which returns before any
    /// envelope is built.
    fn seed_pinned_entry(s: &DaemonShared) -> Uuid {
        let entry_id = Uuid::new_v4();
        let mut queue = s.queue.lock().unwrap();
        queue
            .upsert(
                super::super::queue::QueueEntry {
                    entry_id,
                    session_hash: format!("sha256:{entry_id}"),
                    source: "claude-code".to_string(),
                    project_key: "/tmp/p".to_string(),
                    project_label: "p".to_string(),
                    path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                    size_bytes: 1,
                    discovered_at: Utc::now(),
                    previewed_envelope_digest: Some("sha256:preview".to_string()),
                    ..Default::default()
                },
                500,
            )
            .unwrap();
        entry_id
    }

    /// The verdict gate, enforced by the daemon rather than trusted to the
    /// shells. A run the contributor has just called successful has nothing
    /// to correct, and the field is not shown for it in any client.
    #[tokio::test]
    async fn a_correction_is_refused_without_a_partly_or_failed_outcome() {
        let s = shared();
        let entry_id = seed_pinned_entry(&s);

        for outcome in [Some("worked"), None] {
            let mut params = serde_json::json!({
                "entry_id": entry_id.to_string(),
                "correction": "it edited the wrong config file",
            });
            if let Some(name) = outcome {
                params["outcome"] = serde_json::Value::String(name.to_string());
            }
            let r = handle_request_async(&s, &req("approve", params)).await;
            let err = r.error.expect("a correction without a verdict is refused");
            assert_eq!(err.message, ERR_CORRECTION_NEEDS_VERDICT);
        }

        let queue = s.queue.lock().unwrap();
        assert_eq!(queue.get(entry_id).unwrap().state, QueueState::Pending);
    }

    /// One correction cannot be attached to a batch: it was written about
    /// one session, and every other session in the batch would carry it into
    /// the corpus as the contributor's own words about work it does not
    /// describe.
    #[tokio::test]
    async fn a_correction_is_refused_on_a_bulk_selector() {
        let s = shared();
        seed_pinned_entry(&s);

        for selector in [
            serde_json::json!({"all": true}),
            serde_json::json!({"project_id": "some-project"}),
        ] {
            let mut params = selector;
            params["outcome"] = serde_json::Value::String("failed".to_string());
            params["correction"] = serde_json::Value::String("it did the wrong thing".to_string());
            let r = handle_request_async(&s, &req("approve", params)).await;
            let err = r.error.expect("a bulk correction is refused");
            assert_eq!(err.message, ERR_CORRECTION_NEEDS_ENTRY);
        }
    }

    #[tokio::test]
    async fn a_correction_of_the_wrong_type_or_past_the_cap_is_refused() {
        let s = shared();
        let entry_id = seed_pinned_entry(&s);

        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({
                    "entry_id": entry_id.to_string(),
                    "outcome": "failed",
                    "correction": 7,
                }),
            ),
        )
        .await;
        assert_eq!(
            r.error.expect("a non-string correction is refused").message,
            ERR_BAD_CORRECTION
        );

        let too_long = "x".repeat(crate::envelope::MAX_CORRECTION_CHARS + 1);
        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({
                    "entry_id": entry_id.to_string(),
                    "outcome": "failed",
                    "correction": too_long,
                }),
            ),
        )
        .await;
        assert_eq!(
            r.error.expect("an oversized correction is refused").message,
            ERR_CORRECTION_TOO_LONG
        );

        let queue = s.queue.lock().unwrap();
        assert_eq!(queue.get(entry_id).unwrap().state, QueueState::Pending);
    }

    /// Whitespace is not a correction. It is normalised away rather than
    /// refused, so a contributor who tabbed through the field and typed
    /// nothing gets exactly the 0.5.0 behaviour: an ordinary approval, no
    /// correction recorded, and no rebuild of the artifact they were shown.
    #[tokio::test]
    async fn a_whitespace_only_correction_approves_as_if_none_was_written() {
        let s = shared();
        let entry_id = seed_pinned_entry(&s);

        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({
                    "entry_id": entry_id.to_string(),
                    "correction": "   \n  ",
                }),
            ),
        )
        .await;
        assert!(r.error.is_none(), "should approve: {:?}", r.error);

        let queue = s.queue.lock().unwrap();
        let e = queue.get(entry_id).unwrap();
        assert_eq!(e.state, QueueState::Approved);
        assert_eq!(e.approved_correction, None);
    }

    #[test]
    fn a_caller_supplied_label_never_reaches_list_projects_or_the_audit_log() {
        // `set_project_mode` used to store whatever `label` a socket client
        // sent and hand it straight to `list_projects` and to
        // `daemon-audit.jsonl` -- the two sinks the label-only rule exists
        // to protect. The label is now derived from the key; the param is
        // accepted and ignored.
        let s = shared();
        let key = tmp_project("myproj");
        let injected = "ghp_fakeinjectedtoken/and/a/path";
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({
                    "project_key": key,
                    "label": injected,
                    "mode": "auto_upload",
                }),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);

        let list = handle_request(&s, &req("list_projects", serde_json::json!({})));
        let projects = serde_json::to_string(&list.result.unwrap()).unwrap();
        assert!(
            !projects.contains("ghp_fakeinjectedtoken"),
            "a caller-supplied label reached list_projects: {projects}"
        );
        assert!(
            projects.contains("\"myproj\""),
            "the label must be derived from the key: {projects}"
        );

        let audit_text = serde_json::to_string(&audit::load(&s.store).unwrap()).unwrap();
        assert!(
            !audit_text.contains("ghp_fakeinjectedtoken"),
            "a caller-supplied label reached the audit log: {audit_text}"
        );
        assert_eq!(
            audit::load(&s.store).unwrap()[0].project_label.as_deref(),
            Some("myproj")
        );
    }

    /// Seed one pending entry carrying a recorded eligibility.
    fn seed_entry_with_eligibility(
        s: &DaemonShared,
        project_key: &str,
        eligibility: Option<&str>,
    ) -> uuid::Uuid {
        let entry_id = uuid::Uuid::new_v4();
        let mut queue = s.queue.lock().unwrap();
        queue
            .upsert(
                super::super::queue::QueueEntry {
                    entry_id,
                    session_hash: format!("sha256:{entry_id}"),
                    source: "claude-code".to_string(),
                    project_key: project_key.to_string(),
                    project_label: super::super::policy::project_label_for(project_key),
                    path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                    size_bytes: 1,
                    discovered_at: Utc::now(),
                    eligibility: eligibility.map(str::to_string),
                    ..Default::default()
                },
                500,
            )
            .unwrap();
        entry_id
    }

    /// Write a config that admits this contributor on evidence, which is
    /// what makes a group selector filter at all.
    fn admit_on_evidence(s: &DaemonShared) {
        let cfg: crate::config::ContributorConfig = serde_json::from_value(serde_json::json!({
            "schema_version": crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION,
            "issuer_url": "https://issuer.example",
            "ingest_url": "https://ingest.example",
            "audience": "upload",
            "tenant_id": format!("near-{}", "ab".repeat(32)),
            "instance_id": "",
            "user_subject": "device",
            "device_key_id": "device",
            "consent_scopes": ["debugging_evaluation"],
            "witness": {
                "url": "https://witness.example",
                "signing_address": format!("0x{}", "ab".repeat(20)),
                "expected_measurements": [format!("mrtd={}", "ab".repeat(48))],
                "admission_evidence": true,
            },
        }))
        .unwrap();
        s.store.save_config(&cfg).unwrap();
    }

    /// Seed one eligible row and four that cannot be sent, in one project.
    fn seed_mixed_project(s: &DaemonShared, key: &str) -> uuid::Uuid {
        use crate::daemon::contribution_eligibility as ce;
        let eligible = seed_entry_with_eligibility(s, key, Some(ce::STATE_ELIGIBLE));
        seed_entry_with_eligibility(s, key, Some(ce::STATE_INELIGIBLE_PERMANENT));
        seed_entry_with_eligibility(s, key, Some(ce::STATE_INELIGIBLE_PERMANENT));
        seed_entry_with_eligibility(s, key, Some(ce::STATE_INELIGIBLE_CONFIGURATION));
        // A row the daemon never evaluated. It renders `unknown`, which IS
        // offered the control (the receipt fetch at submission is the only
        // thing that can decide it), so a bulk send includes it alongside
        // the eligible row.
        seed_entry_with_eligibility(s, key, None);
        eligible
    }

    /// **The hole this closes.** A project holding one eligible row and four
    /// others offered one control that sent all five. Now it sends the two
    /// that may be sent -- the eligible row and the unresolved one -- and
    /// leaves the three ineligible rows behind.
    ///
    /// Observed on which entries the call SELECTED, not on how many it
    /// approved: none of these seeds has a session file, so every selected
    /// entry lands in `skipped` further down the pipeline. That is the point
    /// -- `skipped` counts exactly what was chosen, and the three excluded
    /// rows never enter it.
    #[tokio::test]
    async fn a_project_approve_selects_only_what_can_be_sent() {
        let s = shared();
        admit_on_evidence(&s);
        let key = "/tmp/mixedproj";
        let eligible = seed_mixed_project(&s, key);
        let project_id = project_id_for(key);

        let r = handle_request_async(
            &s,
            &req("approve", serde_json::json!({ "project_id": project_id })),
        )
        .await;
        let result = r.result.expect("approve answers");

        assert_eq!(
            result["excluded_ineligible"], 3,
            "three rows could not be sent: {result}"
        );
        let skipped = result["skipped"].as_array().expect("a skipped list");
        assert_eq!(
            skipped.len(),
            2,
            "the eligible row and the unresolved row were selected: {result}"
        );
        assert!(
            skipped
                .iter()
                .any(|s| s["entry_id"] == serde_json::json!(eligible)),
            "the eligible row was selected: {result}"
        );
    }

    /// **The regression that must not happen.** An invited contributor has
    /// no eligibility question, so nothing is filtered and every pending row
    /// in the project is still selected -- including rows carrying a
    /// recorded label, which is exactly the state an upgrade can leave
    /// behind when the flag is later turned off.
    #[tokio::test]
    async fn an_invited_contributors_project_approve_filters_nothing() {
        let s = shared();
        // No config at all: the flag cannot read true, and this is also the
        // unreadable-config case, which must behave the same way.
        let key = "/tmp/mixedproj";
        seed_mixed_project(&s, key);
        let project_id = project_id_for(key);

        let r = handle_request_async(
            &s,
            &req("approve", serde_json::json!({ "project_id": project_id })),
        )
        .await;
        let result = r.result.expect("approve answers");

        assert!(
            !result
                .as_object()
                .expect("an object")
                .contains_key("excluded_ineligible"),
            "no filter ran, so nothing may claim rows were left out: {result}"
        );
        assert_eq!(
            result["skipped"].as_array().expect("a skipped list").len(),
            5,
            "every pending row must still be selected: {result}"
        );
    }

    /// `all` is the largest group there is and carries the same hole.
    #[tokio::test]
    async fn approve_all_selects_only_what_can_be_sent() {
        let s = shared();
        admit_on_evidence(&s);
        seed_mixed_project(&s, "/tmp/mixedproj");

        let r = handle_request_async(&s, &req("approve", serde_json::json!({"all": true}))).await;
        let result = r.result.expect("approve answers");

        // The eligible row and the unresolved one are selected; the three
        // ineligible rows are left behind.
        assert_eq!(result["excluded_ineligible"], 3, "{result}");
        assert_eq!(result["skipped"].as_array().unwrap().len(), 2, "{result}");
    }

    /// A single `entry_id` is not filtered. Naming one entry is an explicit
    /// act about a session the contributor is looking at; the daemon reports
    /// eligibility there and does not enforce it, because an expectation is
    /// not the answer and the server decides.
    #[tokio::test]
    async fn a_named_entry_is_not_filtered_by_its_eligibility() {
        use crate::daemon::contribution_eligibility as ce;
        let s = shared();
        admit_on_evidence(&s);
        let id = seed_entry_with_eligibility(&s, "/tmp/proj", Some(ce::STATE_INELIGIBLE_PERMANENT));

        let r = handle_request_async(
            &s,
            &req("approve", serde_json::json!({ "entry_id": id.to_string() })),
        )
        .await;
        let result = r.result.expect("approve answers");

        assert!(
            !result
                .as_object()
                .expect("an object")
                .contains_key("excluded_ineligible"),
            "a named entry is not a group: {result}"
        );
        assert_eq!(result["skipped"].as_array().unwrap().len(), 1, "{result}");
    }

    /// **One reply, one deadline, covering everything it approved.**
    ///
    /// Two shells found the same trap independently: an undo bar has to
    /// outlast every entry it offers to undo, so a client that fanned a group
    /// submit out into per-entry calls and kept the FIRST reply's hold would
    /// retire Undo while something it covers is still recoverable. A group
    /// approve does not fan out -- it takes one `approved_at` for the whole
    /// call, so every entry it approves shares one deadline and the single
    /// `hold_until` it reports is true of all of them.
    ///
    /// Pinned here rather than left as a property of the code, because it is
    /// the guarantee the contract makes to three shells.
    #[tokio::test]
    async fn a_group_approve_reports_one_hold_that_covers_every_entry() {
        let s = shared();
        let key = "/tmp/holdproj";
        let ids = [
            seed_entry_with_eligibility(&s, key, None),
            seed_entry_with_eligibility(&s, key, None),
            seed_entry_with_eligibility(&s, key, None),
        ];
        // Pin each entry directly: the seeds have no session file, so the
        // build path would skip them before anything could be approved.
        {
            let mut queue = s.queue.lock().unwrap();
            for id in ids {
                assert!(queue.record_previewed_envelope(id, "sha256:pinned", None));
            }
        }

        let r = handle_request_async(
            &s,
            &req(
                "approve",
                serde_json::json!({ "project_id": project_id_for(key) }),
            ),
        )
        .await;
        let result = r.result.expect("approve answers");
        assert_eq!(result["approved"], 3, "{result}");

        // Parsed rather than string-compared: the reply and the entry
        // serialise the same instant at different precisions, and what is
        // being pinned is the instant.
        let reported: chrono::DateTime<Utc> = result["hold_until"]
            .as_str()
            .expect("a deadline")
            .parse()
            .expect("an RFC 3339 instant");
        let queue = s.queue.lock().unwrap();
        let hold_secs = s.settings.lock().unwrap().approval_hold_secs;
        for id in ids {
            let entry_hold = queue
                .get(id)
                .expect("the entry")
                .hold_until(hold_secs)
                .expect("a hold");
            assert!(
                entry_hold <= reported,
                "the reported deadline must outlast every entry it covers: \
                 {entry_hold} > {reported}"
            );
        }
    }

    /// The count a shell draws its button from: "send the 2 of 5 that can be
    /// sent", answerable from the row it already fetched to draw the group.
    /// Two, not one: the eligible row and the unresolved one, which is
    /// offered because only a send can decide it.
    #[test]
    fn a_project_row_says_how_many_of_its_sessions_can_be_sent() {
        let s = shared();
        admit_on_evidence(&s);
        seed_mixed_project(&s, "/tmp/mixedproj");

        let row = projects_of(&s)
            .into_iter()
            .find(|p| p["project_id"] == serde_json::json!(project_id_for("/tmp/mixedproj")))
            .expect("the project is listed");
        assert_eq!(row["pending_count"], 5, "{row}");
        assert_eq!(row["contributable_count"], 2, "{row}");
    }

    /// And an invited contributor gets the pending count with no "of" --
    /// the key is absent, not equal, so nothing renders a distinction that
    /// does not exist for them.
    #[test]
    fn an_invited_contributors_project_row_carries_no_contributable_count() {
        let s = shared();
        seed_mixed_project(&s, "/tmp/mixedproj");

        let row = projects_of(&s)
            .into_iter()
            .find(|p| p["project_id"] == serde_json::json!(project_id_for("/tmp/mixedproj")))
            .expect("the project is listed");
        assert_eq!(row["pending_count"], 5, "{row}");
        assert!(
            !row.as_object()
                .expect("an object")
                .contains_key("contributable_count"),
            "the key must be absent, not null: {row}"
        );
    }

    /// Seed one pending queue entry for `project_key`, the way a poll that
    /// discovered a session would, without running the watcher.
    fn seed_entry(s: &DaemonShared, project_key: &str) -> uuid::Uuid {
        let entry_id = uuid::Uuid::new_v4();
        let mut queue = s.queue.lock().unwrap();
        queue
            .upsert(
                super::super::queue::QueueEntry {
                    entry_id,
                    session_hash: format!("sha256:{entry_id}"),
                    source: "claude-code".to_string(),
                    project_key: project_key.to_string(),
                    project_label: super::super::policy::project_label_for(project_key),
                    path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                    size_bytes: 1,
                    discovered_at: Utc::now(),
                    ..Default::default()
                },
                500,
            )
            .unwrap();
        entry_id
    }

    fn projects_of(s: &DaemonShared) -> Vec<serde_json::Value> {
        handle_request(s, &req("list_projects", serde_json::json!({})))
            .result
            .unwrap()["projects"]
            .as_array()
            .unwrap()
            .clone()
    }

    #[test]
    fn a_project_id_from_list_pending_is_accepted_by_set_project_mode() {
        // The gap this closes. A socket client sees `project_label` and
        // never `project_key`, and a label is not an admissible key -- so
        // before the id existed, a GUI holding a queue entry had no way to
        // say anything at all about the project it came from.
        let s = shared();
        let key = tmp_project("p");
        seed_entry(&s, &key);

        let pending = handle_request(&s, &req("list_pending", serde_json::json!({})))
            .result
            .unwrap()["pending"]
            .as_array()
            .unwrap()
            .clone();
        let project_id = pending[0]["project_id"].as_str().unwrap().to_string();
        assert!(
            pending[0].get("project_key").is_none(),
            "a key must never cross the wire: {:?}",
            pending[0]
        );

        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_id": project_id, "mode": "ignore"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(s.policy.lock().unwrap().resolve(&key), ProjectMode::Ignore);
    }

    #[test]
    fn a_project_id_from_list_projects_is_accepted_by_set_project_mode() {
        let s = shared();
        let key = tmp_project("p");
        seed_entry(&s, &key);

        let row = projects_of(&s)[0].clone();
        let project_id = row["project_id"].as_str().unwrap().to_string();
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_id": project_id, "mode": "auto_upload"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(
            s.policy.lock().unwrap().resolve(&key),
            ProjectMode::AutoUpload
        );
    }

    #[test]
    fn an_unknown_project_id_is_refused_with_a_fixed_label_and_records_nothing() {
        let s = shared();
        let unknown = super::super::policy::project_id_for("/Users/z/never/seen");
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_id": unknown, "mode": "auto_upload"}),
            ),
        );
        let err = r.error.expect("an unknown id must be refused");
        assert_eq!(err.code, ERR_BAD_PARAMS);
        assert_eq!(err.message, ERR_PROJECT_ID_UNRECOGNIZED);
        assert!(s.policy.lock().unwrap().projects.is_empty());
        assert!(
            audit::load(&s.store).unwrap().is_empty(),
            "a refused call must record nothing"
        );
        assert!(projects_of(&s).is_empty());
    }

    #[test]
    fn a_real_canonical_path_is_still_accepted_before_the_project_is_ever_seen() {
        // The CLI's pre-discovery flow: `daemon project <path> --mode
        // ignore` for a project whose first session has not happened, so no
        // id exists for it and none can. This is why the id supplements the
        // key rather than replacing it.
        let s = shared();
        let key = tmp_project("employer-repo");
        assert!(
            projects_of(&s).is_empty(),
            "the project must be genuinely unknown for this test to mean anything"
        );
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": key, "mode": "ignore"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(s.policy.lock().unwrap().resolve(&key), ProjectMode::Ignore);
    }

    #[test]
    fn a_project_id_is_stable_across_a_daemon_restart_and_a_rebuilt_policy_file() {
        // Ids are derived, never stored, so there is nothing for a restart
        // or a from-scratch policy file to lose. A client that cached an id
        // yesterday can still use it today.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let open = || crate::config::ConfigStore::open(state.clone()).unwrap();
        let key = tmp_project("p");

        let first = {
            let s = DaemonShared::load(open()).unwrap();
            let r = handle_request(
                &s,
                &req(
                    "set_project_mode",
                    serde_json::json!({"project_key": key, "mode": "ignore"}),
                ),
            );
            assert!(r.error.is_none(), "{:?}", r.error);
            projects_of(&s)[0]["project_id"]
                .as_str()
                .unwrap()
                .to_string()
        };

        // A second daemon over the same state directory: a restart.
        let s = DaemonShared::load(open()).unwrap();
        assert_eq!(projects_of(&s)[0]["project_id"].as_str().unwrap(), first);

        // And a policy file rebuilt from scratch, holding the same project.
        let mut rebuilt = ProjectPolicy::new();
        rebuilt
            .set_mode(&key, ProjectMode::NotifyOnly, Utc::now())
            .unwrap();
        rebuilt.save(&open()).unwrap();
        let s = DaemonShared::load(open()).unwrap();
        let row = projects_of(&s)[0].clone();
        assert_eq!(row["project_id"].as_str().unwrap(), first);
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_id": first, "mode": "ignore"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
    }

    #[test]
    fn a_project_id_never_carries_a_path_component() {
        let s = shared();
        let key = tmp_project("acme-secret-client");
        seed_entry(&s, &key);
        let wire = format!(
            "{}{}",
            serde_json::to_string(&handle_request(
                &s,
                &req("list_pending", serde_json::json!({}))
            ))
            .unwrap(),
            serde_json::to_string(&projects_of(&s)).unwrap()
        );
        let id = super::super::policy::project_id_for(&key);
        assert!(wire.contains(&id), "the id must be on the wire: {wire}");
        assert!(
            !id.contains("acme") && !id.contains("secret") && !id.contains('/'),
            "the id leaked a path component: {id}"
        );
        // Only segments long enough that a coincidental match is implausible.
        //
        // The id is a prefix plus 16 hex characters, and a temp path on macOS
        // contains short components that are themselves valid hex -- a real
        // one is `/private/var/folders/d8/...`. Asserting the id does not
        // contain "d8" fails about one run in seventeen purely because two
        // hex characters agree, which is not a leak.
        //
        // A security test that cries wolf at that rate is worse than no test:
        // it teaches everyone to re-run it, and a real leak is then waved
        // through with the same shrug. Two separate agents hit this flake on
        // 2026-08-10 while working on unrelated changes. Four characters puts
        // a coincidental hit at roughly one in sixteen thousand while still
        // catching any segment big enough to identify anybody.
        const MIN_DISTINGUISHING_LEN: usize = 4;
        for segment in std::path::Path::new(&key)
            .parent()
            .unwrap()
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .filter(|segment| segment.len() >= MIN_DISTINGUISHING_LEN)
        {
            assert!(
                !id.contains(&segment),
                "the id leaked the path segment {segment}"
            );
        }
    }

    #[test]
    fn list_projects_reports_a_discovered_but_unconfigured_project() {
        // Onboarding's "which of these should never be uploaded" screen
        // needs exactly this set: a project is configured only once it has
        // been ruled on, so listing only configured projects lists only the
        // decisions already made and never the one the contributor is being
        // asked to make.
        let s = shared();
        let key = tmp_project("employer-repo");
        seed_entry(&s, &key);

        let rows = projects_of(&s);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["project_label"], serde_json::json!("employer-repo"));
        assert_eq!(rows[0]["configured"], serde_json::json!(false));
        assert!(rows[0]["added_at"].is_null());
        assert_eq!(
            rows[0]["mode"],
            serde_json::json!("notify_only"),
            "an unruled project reports the effective default"
        );

        // Ruling on it makes it configured, and does not duplicate the row.
        let id = rows[0]["project_id"].as_str().unwrap().to_string();
        handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_id": id, "mode": "ignore"}),
            ),
        );
        let rows = projects_of(&s);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["configured"], serde_json::json!(true));
        assert_eq!(rows[0]["mode"], serde_json::json!("ignore"));
    }

    #[test]
    fn list_projects_marks_only_the_unresolvable_bucket() {
        // The flag exists so a shell never has to re-derive `project_id_for`
        // to know which row this is, and never matches on `project_label` --
        // which every client rewords, because the raw label is a slug.
        let s = shared();
        let ordinary = tmp_project("employer-repo");
        seed_entry(&s, &ordinary);
        seed_entry(&s, UNKNOWN_PROJECT_KEY);

        let rows = projects_of(&s);
        assert_eq!(rows.len(), 2, "{rows:?}");

        let bucket: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["is_unresolved_bucket"] == serde_json::json!(true))
            .collect();
        assert_eq!(bucket.len(), 1, "exactly one row is the bucket: {rows:?}");

        // And it is the right one. Checked through the id the daemon minted
        // for the key, not through the label, so this test cannot pass by
        // agreeing with a display string.
        assert_eq!(
            bucket[0]["project_id"],
            serde_json::json!(project_id_for(UNKNOWN_PROJECT_KEY))
        );

        let ordinary_row = rows
            .iter()
            .find(|r| r["project_id"] == serde_json::json!(project_id_for(&ordinary)))
            .expect("the ordinary project is listed");
        assert_eq!(
            ordinary_row["is_unresolved_bucket"],
            serde_json::json!(false),
            "an ordinary project must never be explained as unresolvable"
        );
    }

    #[test]
    fn the_unresolvable_flag_survives_being_ruled_on() {
        // A contributor can silence the bucket even though it can never be
        // armed. Ignoring it moves it from discovered to configured, and the
        // marker has to hold across that -- otherwise the row loses its
        // explanation exactly when someone has interacted with it.
        let s = shared();
        seed_entry(&s, UNKNOWN_PROJECT_KEY);

        let rows = projects_of(&s);
        let id = rows[0]["project_id"].as_str().unwrap().to_string();
        assert_eq!(rows[0]["is_unresolved_bucket"], serde_json::json!(true));
        assert_eq!(rows[0]["configured"], serde_json::json!(false));

        handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_id": id, "mode": "ignore"}),
            ),
        );

        let rows = projects_of(&s);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["configured"], serde_json::json!(true));
        assert_eq!(rows[0]["mode"], serde_json::json!("ignore"));
        assert_eq!(
            rows[0]["is_unresolved_bucket"],
            serde_json::json!(true),
            "the marker is a property of the key, not of whether it is configured"
        );
    }

    #[test]
    fn nothing_a_client_sends_reaches_list_projects_or_the_audit_log_via_an_id() {
        // The original injection fix must survive the new entry point: the
        // id path resolves to a key the daemon already holds, so the label
        // is still derived and a caller's strings still reach neither sink.
        let s = shared();
        let key = tmp_project("myproj");
        seed_entry(&s, &key);
        let id = super::super::policy::project_id_for(&key);
        let injected = "ghp_fakeinjectedtoken/and/a/path";
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({
                    "project_id": id,
                    "project_key": injected,
                    "label": injected,
                    "mode": "auto_upload",
                }),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);

        let listed = serde_json::to_string(&projects_of(&s)).unwrap();
        assert!(
            !listed.contains("ghp_fakeinjectedtoken"),
            "a caller-supplied string reached list_projects: {listed}"
        );
        assert!(listed.contains("\"myproj\""), "{listed}");
        let audit_text = serde_json::to_string(&audit::load(&s.store).unwrap()).unwrap();
        assert!(
            !audit_text.contains("ghp_fakeinjectedtoken"),
            "a caller-supplied string reached the audit log: {audit_text}"
        );
        assert_eq!(
            audit::load(&s.store).unwrap()[0].project_label.as_deref(),
            Some("myproj")
        );
    }

    #[test]
    fn naming_a_project_neither_way_is_a_bad_params_error() {
        let s = shared();
        let r = handle_request(
            &s,
            &req("set_project_mode", serde_json::json!({"mode": "ignore"})),
        );
        let err = r.error.expect("must be refused");
        assert_eq!(err.code, ERR_BAD_PARAMS);
        assert_eq!(err.message, "project_id-or-project_key-required");
    }

    /// Make the audit log unappendable: `audit::load` reads the file as
    /// UTF-8 and fails on bytes that are not, so every subsequent `append`
    /// fails too. Stands in for a disk-full, permissions, or corruption
    /// failure without needing any of those.
    fn break_the_audit_log(store: &ConfigStore) {
        store
            .write_daemon_file(crate::config::DAEMON_AUDIT_FILE, &[0xff, 0xfe, 0xff])
            .unwrap();
    }

    #[test]
    fn arming_autonomy_is_rolled_back_when_its_audit_entry_cannot_be_written() {
        // The audit entry is the stated replacement for a removed
        // terminal-only restriction. A best-effort append reduced a
        // disk-full or permissions failure to a warning while the call
        // still returned success, silently defeating the whole replacement.
        let s = shared();
        let key = tmp_project("p");
        break_the_audit_log(&s.store);

        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": key, "mode": "auto_upload"}),
            ),
        );
        let err = r.error.expect("an unwritable audit log must fail the call");
        assert_eq!(err.code, ERR_UNAVAILABLE);
        assert_eq!(err.message, "audit-write-failed");
        assert_eq!(
            s.policy.lock().unwrap().resolve(&key),
            ProjectMode::NotifyOnly,
            "autonomy must not stand without a record of it"
        );
        // And the rollback is durable, not only in memory.
        let on_disk = ProjectPolicy::load(&s.store).unwrap();
        assert_eq!(on_disk.resolve(&key), ProjectMode::NotifyOnly);
    }

    #[test]
    fn a_notify_only_change_still_succeeds_with_an_unwritable_audit_log() {
        // Only the consequential actions are audited, so only they are
        // gated on the audit succeeding. Setting notify_only writes no
        // entry and must not be collateral damage.
        let s = shared();
        let key = tmp_project("p");
        break_the_audit_log(&s.store);
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": key, "mode": "notify_only"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
    }

    #[tokio::test]
    async fn bulk_approval_is_rolled_back_when_its_audit_entry_cannot_be_written() {
        let s = shared();
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: "/tmp/p".to_string(),
                        project_label: "p".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }
        break_the_audit_log(&s.store);

        let r = handle_request_async(&s, &req("approve", serde_json::json!({"all": true}))).await;
        let err = r.error.expect("an unwritable audit log must fail the call");
        assert_eq!(err.message, "audit-write-failed");
        let state = s.queue.lock().unwrap().get(entry_id).unwrap().state;
        assert_eq!(
            state,
            QueueState::Pending,
            "an unrecorded bulk approval must not stand"
        );
    }

    #[test]
    fn a_project_key_the_daemon_cannot_corroborate_is_refused() {
        // Deriving the label from the key is not enough on its own: the
        // basename of an attacker-chosen key is still an attacker-chosen
        // string. A key must be the unknown-cwd sentinel, one the daemon
        // already knows, or a real local directory.
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({
                    "project_key": "/nonexistent-xyz/ghp_fakeinjectedtoken",
                    "mode": "auto_upload",
                }),
            ),
        );
        let err = r.error.expect("an unrecognized key must be refused");
        assert_eq!(err.code, ERR_BAD_PARAMS);
        assert_eq!(err.message, ERR_PROJECT_KEY_UNRECOGNIZED);
        assert!(
            s.policy.lock().unwrap().projects.is_empty(),
            "a refused key must not be recorded"
        );
        assert!(audit::load(&s.store).unwrap().is_empty());
    }

    #[test]
    fn a_key_already_known_to_the_daemon_stays_settable() {
        // A project the daemon discovered on a queued session must remain
        // configurable even if its directory has since been deleted --
        // otherwise the contributor loses the ability to say "ignore this"
        // about exactly the sessions already sitting in their queue.
        let s = shared();
        let gone = "/nonexistent-xyz/oldproj";
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id: uuid::Uuid::new_v4(),
                        session_hash: "sha256:known".to_string(),
                        source: "claude-code".to_string(),
                        project_key: gone.to_string(),
                        project_label: "oldproj".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": gone, "mode": "ignore"}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(s.policy.lock().unwrap().resolve(gone), ProjectMode::Ignore);
    }

    #[test]
    fn the_unknown_bucket_cannot_be_armed_even_from_a_terminal() {
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": UNKNOWN_PROJECT_KEY, "mode": "auto_upload"}),
            ),
        );
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    // `bind`'s socket-path-length refusal and `ensure_private_dir`'s 0700
    // check are both properties of the unix-socket transport specifically:
    // Windows has no socket path to overflow and no directory-mode access
    // control (see `win_pipe.rs`, whose DACL plays that role instead), so
    // there is no Windows equivalent of either function to test here.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_bind_failure_never_names_a_local_path() {
        // These errors are returned to `daemon run`, which under a service
        // manager writes them to the journal -- where a state-directory
        // path carries the OS username.
        let deep = std::env::temp_dir().join("a".repeat(120));
        std::fs::create_dir_all(&deep).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = ConfigStore::open(deep.clone()).unwrap();
        let err = bind(&store).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(!text.contains(&*deep.to_string_lossy()), "{text}");
        assert!(
            text.contains("kernel limit"),
            "the message must still say what to do: {text}"
        );
        let _ = std::fs::remove_dir_all(&deep);
    }

    #[cfg(unix)]
    #[test]
    fn a_state_directory_permissions_failure_never_names_a_local_path() {
        let missing = std::env::temp_dir().join("trace-commons-no-such-dir-xyz");
        let _ = std::fs::remove_dir_all(&missing);
        let err = ensure_private_dir(&missing).unwrap_err();
        let text = format!("{err:#}");
        assert!(!text.contains("trace-commons-no-such-dir-xyz"), "{text}");
    }

    #[test]
    fn an_unknown_method_uses_the_taxonomy() {
        let s = shared();
        let r = handle_request(&s, &req("no_such_method", serde_json::json!({})));
        assert_eq!(r.error.unwrap().code, ERR_UNKNOWN_METHOD);
    }

    #[test]
    fn hello_advertises_the_schema_and_method_set() {
        let s = shared();
        let r = handle_request(&s, &req("hello", serde_json::json!({})));
        let result = r.result.unwrap();
        assert_eq!(result["schema_version"], IPC_SCHEMA);
        assert_eq!(result["methods"].as_array().unwrap().len(), METHODS.len());
    }

    #[test]
    fn status_exposes_every_field_a_tray_needs() {
        let s = shared();
        let r = handle_request(&s, &req("status", serde_json::json!({})));
        let v = r.result.unwrap();
        for key in ["logged_in", "paused", "queue_depth", "health"] {
            assert!(!v[key].is_null(), "status missing {key}");
        }
        assert_eq!(v["logged_in"], false);
    }

    /// An approved queue entry of a given size, for budget assertions.
    /// `n` only distinguishes it from its siblings -- the queue dedupes on
    /// the session hash, so a fixture that reused one would silently
    /// collapse fourteen entries into one.
    fn approved_entry_n(n: usize, size_bytes: u64) -> super::super::queue::QueueEntry {
        super::super::queue::QueueEntry {
            entry_id: uuid::Uuid::new_v4(),
            session_hash: format!("sha256:{n:04x}"),
            source: "claude-code".to_string(),
            project_key: "/tmp/p".to_string(),
            project_label: "p".to_string(),
            path: std::path::PathBuf::from("/tmp/s.jsonl"),
            size_bytes,
            discovered_at: Utc::now(),
            state: QueueState::Approved,
            ..Default::default()
        }
    }

    fn approved_entry(size_bytes: u64) -> super::super::queue::QueueEntry {
        approved_entry_n(0, size_bytes)
    }

    #[test]
    fn status_reports_the_daily_budget_with_the_real_numbers() {
        // The condition that made a working app look broken: the byte
        // budget all but spent, 14 approved entries waiting, and a health
        // slot occupied by something else entirely -- so the cap was
        // invisible. `daily_budget` is reported independently of `health`
        // for exactly that reason, and this pins the numbers rather than
        // the presence of a key.
        let s = shared();
        {
            let mut state = s.state.lock().unwrap();
            state.day_bucket = Some(Utc::now().format("%Y-%m-%d").to_string());
            state.bytes_today = 204_659_969;
            state.uploads_today = 12;
        }
        {
            let mut q = s.queue.lock().unwrap();
            let max = s.settings.lock().unwrap().max_queue_entries;
            for n in 0..14 {
                q.upsert(approved_entry_n(n, 14_900_000), max).unwrap();
            }
        }
        // Something else already holds the single health slot, exactly as
        // `queue-full` did on the machine this came from.
        s.health
            .lock()
            .unwrap()
            .fail(crate::daemon::health::LABEL_QUEUE_FULL, Utc::now());

        let r = handle_request(&s, &req("status", serde_json::json!({})));
        let v = r.result.unwrap();
        let b = &v["daily_budget"];
        assert_eq!(v["health"]["last_error_label"], "queue-full");
        assert_eq!(b["blocked"], true);
        assert_eq!(b["blocked_entries"], 14);
        assert_eq!(b["blocked_bytes"], 14_900_000u64 * 14);
        assert_eq!(b["bytes_today"], 204_659_969u64);
        assert_eq!(b["max_bytes_per_day"], 209_715_200u64);
        assert_eq!(b["bytes_remaining"], 5_055_231u64);
        assert_eq!(b["uploads_today"], 12);
        assert_eq!(b["max_uploads_per_day"], 50);
        assert_eq!(b["uploads_remaining"], 38);
        assert!(!b["resets_at"].is_null());
    }

    #[test]
    fn status_reports_an_unspent_budget_as_not_blocking_anything() {
        let s = shared();
        {
            let mut q = s.queue.lock().unwrap();
            let max = s.settings.lock().unwrap().max_queue_entries;
            q.upsert(approved_entry(1_024), max).unwrap();
        }
        let v = handle_request(&s, &req("status", serde_json::json!({})))
            .result
            .unwrap();
        assert_eq!(v["daily_budget"]["blocked"], false);
        assert_eq!(v["daily_budget"]["blocked_entries"], 0);
        assert_eq!(v["daily_budget"]["bytes_today"], 0);
        assert_eq!(v["daily_budget"]["bytes_remaining"], 209_715_200u64);
    }

    #[test]
    fn polling_status_does_not_hand_back_a_fresh_budget() {
        // `budget_snapshot` rolls the day on a copy. If it rolled the real
        // one, a client polling `status` across midnight -- or a state file
        // left from yesterday -- would silently reset the counters the cap
        // is enforced against.
        let s = shared();
        {
            let mut state = s.state.lock().unwrap();
            state.day_bucket = Some("2020-01-01".to_string());
            state.bytes_today = 204_659_969;
            state.uploads_today = 12;
        }
        let _ = handle_request(&s, &req("status", serde_json::json!({})));
        let state = s.state.lock().unwrap();
        assert_eq!(state.bytes_today, 204_659_969);
        assert_eq!(state.uploads_today, 12);
        assert_eq!(state.day_bucket.as_deref(), Some("2020-01-01"));
    }

    #[test]
    fn a_stale_day_bucket_reports_todays_budget_as_untouched() {
        // The counters on disk belong to a day that has passed, so what
        // `status` reports is a full budget rather than yesterday's spend.
        let s = shared();
        {
            let mut state = s.state.lock().unwrap();
            state.day_bucket = Some("2020-01-01".to_string());
            state.bytes_today = 209_715_200;
            state.uploads_today = 50;
        }
        {
            let mut q = s.queue.lock().unwrap();
            let max = s.settings.lock().unwrap().max_queue_entries;
            q.upsert(approved_entry(14_900_000), max).unwrap();
        }
        let v = handle_request(&s, &req("status", serde_json::json!({})))
            .result
            .unwrap();
        assert_eq!(v["daily_budget"]["bytes_today"], 0);
        assert_eq!(v["daily_budget"]["blocked"], false);
    }

    #[test]
    fn the_daily_budget_carries_no_identifier_of_any_kind() {
        // Counts and timestamps only: no entry id, no hash, no path.
        let s = shared();
        {
            let mut q = s.queue.lock().unwrap();
            let max = s.settings.lock().unwrap().max_queue_entries;
            q.upsert(approved_entry(1_024), max).unwrap();
        }
        let v = handle_request(&s, &req("status", serde_json::json!({})))
            .result
            .unwrap();
        let body = serde_json::to_string(&v["daily_budget"]).unwrap();
        assert!(!body.contains("sha256"), "{body}");
        assert!(!body.contains('/'), "{body}");
    }

    #[test]
    fn pause_and_resume_round_trip() {
        let s = shared();
        handle_request(&s, &req("pause", serde_json::json!({})));
        assert_eq!(s.status_value()["paused"], true);
        handle_request(&s, &req("resume", serde_json::json!({})));
        assert_eq!(s.status_value()["paused"], false);
    }

    #[test]
    fn settings_never_echo_the_privacy_filter_credential() {
        let s = shared();
        s.settings.lock().unwrap().near_ai = Some(crate::envelope::NearAiSettings {
            api_key: "super-secret-key".into(),
            base_url: None,
            model: None,
        });
        let r = handle_request(&s, &req("get_settings", serde_json::json!({})));
        let body = serde_json::to_string(&r.result.unwrap()).unwrap();
        assert!(!body.contains("super-secret-key"), "{body}");
        assert!(body.contains("near_ai_configured"));
    }

    /// The ceremony is reachable over the socket, and forgetting says what it
    /// actually did rather than implying a revocation it cannot perform.
    #[test]
    fn the_credential_ceremony_is_dispatched_and_forgetting_claims_nothing_extra() {
        let s = shared();
        // A machine with nothing on it says so, in one word, to a caller
        // that names no attempt. It refused this once; a shell left to infer
        // "no key here" from an error is a shell that eventually infers it
        // wrongly and offers a second sign-in.
        let r = handle_request(&s, &req("near_ai_credential_status", serde_json::json!({})));
        let body = r.result.expect("the resting state is not a secret");
        assert_eq!(body["state"], "absent");
        // And it still names no attempt to a caller that could not name one.
        assert!(body.get("attempt_id").is_none(), "{body}");
        assert!(body.get("attempt_status").is_none(), "{body}");
        // Cancelling, which acts rather than reads, still refuses.
        let r = handle_request(
            &s,
            &req(
                "near_ai_credential_cancel",
                serde_json::json!({"attempt_id": "never-began"}),
            ),
        );
        assert_eq!(r.error.unwrap().message, "near_ai_credential_unknown");

        s.settings.lock().unwrap().near_ai_inference =
            Some(crate::daemon::settings::NearAiInferenceCredential {
                key: "sk-super-secret-key".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-min".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
                minted_at: chrono::Utc::now(),
            });
        s.settings.lock().unwrap().save_for_test(&s.store).unwrap();
        // A stored key reads as present, and the state says so without the
        // key, the prefix or an account of any kind crossing the socket.
        let r = handle_request(&s, &req("near_ai_credential_status", serde_json::json!({})));
        let body = r.result.unwrap();
        assert_eq!(body["state"], "present");
        assert!(
            !serde_json::to_string(&body).unwrap().contains("sk-super"),
            "{body}"
        );
        let r = handle_request(&s, &req("near_ai_credential_forget", serde_json::json!({})));
        let body = r.result.unwrap();
        assert_eq!(body["removed"], true);
        // Local only. Revoking needs a session, and the session was discarded
        // the moment the key was minted.
        assert_eq!(body["revoked"], false);
        assert!(
            DaemonSettings::load(&s.store)
                .unwrap()
                .near_ai_inference
                .is_none()
        );
        assert!(
            !serde_json::to_string(&body).unwrap().contains("sk-super"),
            "{body}"
        );
    }

    /// The credential gate on a connect asks about the destination this
    /// daemon hosts, and about nothing else.
    ///
    /// Three states, and the third is the one worth pinning: a proxy the
    /// contributor declared and runs themselves answers from an account whose
    /// key was never handed to us, so demanding ours would refuse a connect
    /// that works and leave no way to make it work.
    #[test]
    fn only_a_destination_we_host_is_gated_on_our_credential() {
        let s = shared();

        // Nothing hosted and nothing declared. Already refused for having no
        // destination at all; naming it "uncredentialed" would be wrong.
        assert!(s.destination_credentialed());

        *s.private_inference_state.lock().unwrap() =
            crate::daemon::private_inference::PrivateInferenceState::Running { port: 8463 };
        assert!(
            !s.destination_credentialed(),
            "a listener of ours with no credential behind it cannot answer"
        );

        s.settings.lock().unwrap().near_ai_inference =
            Some(crate::daemon::settings::NearAiInferenceCredential {
                key: "sk-super-secret-key".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-sup".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
                minted_at: chrono::Utc::now(),
            });
        assert!(s.destination_credentialed());

        // A proxy the contributor runs themselves, and our credential gone.
        s.settings.lock().unwrap().near_ai_inference = None;
        *s.private_inference_state.lock().unwrap() =
            crate::daemon::private_inference::PrivateInferenceState::Off;
        s.settings.lock().unwrap().ironwire =
            Some(crate::daemon::settings::IronWireDeclaration::Watch {
                port: 9999,
                token_dir: None,
            });
        assert_eq!(s.destination_port(), Some(9999));
        assert!(
            s.destination_credentialed(),
            "their proxy answers from their account, which is not ours to ask about"
        );
    }

    /// The list says why it is offering no connect, and never says it with a
    /// credential.
    #[test]
    fn the_harness_list_reports_an_uncredentialed_destination() {
        let s = shared();
        *s.private_inference_state.lock().unwrap() =
            crate::daemon::private_inference::PrivateInferenceState::Running { port: 8463 };

        let r = handle_request(&s, &req("harness_list", serde_json::json!({})));
        let body = r.result.expect("harness_list answers");
        assert_eq!(body["destination_credentialed"], false);
        for row in body["harnesses"].as_array().expect("rows") {
            assert_eq!(
                row["can_connect"], false,
                "no row may offer a connect the plan refuses: {row}"
            );
        }

        s.settings.lock().unwrap().near_ai_inference =
            Some(crate::daemon::settings::NearAiInferenceCredential {
                key: "sk-super-secret-key".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-sup".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
                minted_at: chrono::Utc::now(),
            });
        let r = handle_request(&s, &req("harness_list", serde_json::json!({})));
        let body = serde_json::to_string(&r.result.expect("harness_list answers")).unwrap();
        assert!(body.contains("\"destination_credentialed\":true"), "{body}");
        assert!(!body.contains("sk-super-secret-key"), "{body}");
    }

    /// A second credential in the same document as the privacy-filter one,
    /// and the same rule: presence crosses the socket, the value never does.
    #[test]
    fn settings_never_echo_the_inference_credential() {
        let s = shared();
        s.settings.lock().unwrap().near_ai_inference =
            Some(crate::daemon::settings::NearAiInferenceCredential {
                key: "sk-super-secret-key".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-sup".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
                minted_at: chrono::Utc::now(),
            });
        let r = handle_request(&s, &req("get_settings", serde_json::json!({})));
        let body = serde_json::to_string(&r.result.unwrap()).unwrap();
        assert!(!body.contains("sk-super-secret-key"), "{body}");
        assert!(
            body.contains("\"near_ai_inference_configured\":true"),
            "{body}"
        );
        // The two are near-homonyms and must not be conflated: the
        // privacy-filter credential is absent here and must still report so.
        assert!(body.contains("\"near_ai_configured\":false"), "{body}");
    }

    /// The third credential in the same document, and the widest of them.
    ///
    /// `skip_serializing_if` keeps the absent case out of the blob on its own,
    /// which is exactly why this asserts the populated case: without the
    /// `remove` in `redacted_settings` the whole record -- refresh token
    /// included -- crosses the socket to every shell that asks for settings.
    #[test]
    fn settings_never_echo_the_retained_session() {
        let s = shared();
        s.settings.lock().unwrap().near_ai_session = Some(crate::daemon::settings::NearAiSession {
            refresh_token: "rt_super-secret-session".into(),
            refresh_token_expires_at: Some(chrono::Utc::now()),
            stored_at: chrono::Utc::now(),
        });
        let r = handle_request(&s, &req("get_settings", serde_json::json!({})));
        let body = serde_json::to_string(&r.result.unwrap()).unwrap();
        assert!(!body.contains("rt_super-secret-session"), "{body}");
        assert!(!body.contains("refresh_token"), "{body}");
        assert!(body.contains("\"near_ai_session_retained\":true"), "{body}");

        // And absent reports absent rather than being missing from the blob.
        s.settings.lock().unwrap().near_ai_session = None;
        let r = handle_request(&s, &req("get_settings", serde_json::json!({})));
        let body = serde_json::to_string(&r.result.unwrap()).unwrap();
        assert!(
            body.contains("\"near_ai_session_retained\":false"),
            "{body}"
        );
    }

    /// An unnamed cancel stops the ceremony without handing back its id.
    ///
    /// Both halves matter. A shell restarted while the daemon kept running
    /// holds no attempt id and is still told a sign-in is in flight, so it
    /// must be able to stop one -- that is the whole reason the id became
    /// optional. But `near_ai_credential_status` deliberately withholds the id
    /// from exactly this caller, and that refusal would be pointless if cancel
    /// handed the same value to the same caller a moment later.
    #[tokio::test]
    async fn an_unnamed_cancel_acts_without_disclosing_the_attempt_it_acted_on() {
        let s = shared();
        let started = crate::daemon::nearai_credential::ceremony::begin(&s.store, "github")
            .await
            .expect("a ceremony to cancel");
        let id = started["attempt_id"].as_str().unwrap().to_string();

        // Naming nothing: the caller learns the outcome and not the identity.
        let r = handle_request(&s, &req("near_ai_credential_cancel", serde_json::json!({})));
        let body = r
            .result
            .expect("an unnamed cancel is answered, not refused");
        assert_eq!(body["status"], "cancelled");
        assert!(
            body.get("attempt_id").is_none(),
            "an unnamed cancel disclosed the attempt id: {body}"
        );
        assert!(
            !serde_json::to_string(&body).unwrap().contains(&id),
            "the attempt id reached a caller that could not name it: {body}"
        );

        // And the ceremony really is stopped, not merely reported so.
        let r = handle_request(&s, &req("near_ai_credential_status", serde_json::json!({})));
        assert_eq!(r.result.unwrap()["state"], "cancelled");
    }

    /// Forgetting takes the session with the credential, on disk *and* in the
    /// running process.
    ///
    /// A residual session is the worst outcome this pair can produce: the
    /// contributor believes they revoked this machine's access to their NEAR
    /// AI account, and the daemon is left holding the wider of the two
    /// credentials -- one that can mint further API keys and read the account.
    ///
    /// Exercised through `handle_request_async`, which is the path the daemon
    /// actually dispatches this method on, and the only one that reaches
    /// `reconcile_private_inference`. The sync handler clears the session; the
    /// reconcile clears the key and takes it back out of the running proxy.
    /// Asserting against the sync handler alone would pass while the proxy
    /// went on answering with a withdrawn key.
    #[tokio::test]
    async fn forgetting_the_credential_takes_the_session_with_it() {
        let s = shared();
        {
            let mut settings = s.settings.lock().unwrap();
            settings.near_ai_inference = Some(crate::daemon::settings::NearAiInferenceCredential {
                key: "sk-super-secret-key".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-sup".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
                minted_at: chrono::Utc::now(),
            });
            settings.near_ai_session = Some(crate::daemon::settings::NearAiSession {
                refresh_token: "rt_super-secret-session".into(),
                refresh_token_expires_at: None,
                stored_at: chrono::Utc::now(),
            });
            settings.save_for_test(&s.store).unwrap();
        }

        let r = handle_request_async(&s, &req("near_ai_credential_forget", serde_json::json!({})))
            .await;
        assert_eq!(r.result.unwrap()["removed"], true);

        let on_disk = DaemonSettings::load(&s.store).unwrap();
        assert!(on_disk.near_ai_inference.is_none());
        assert!(on_disk.near_ai_session.is_none());
        // The file is what survives a restart; the in-memory copy is what
        // every read in this process consults. Clearing one and not the other
        // leaves the daemon using both until something restarts it.
        let in_memory = s.settings.lock().unwrap().clone();
        assert!(in_memory.near_ai_inference.is_none());
        assert!(in_memory.near_ai_session.is_none());
    }

    /// A daemon with no session answers a named state, over the socket, and
    /// not a zero.
    #[tokio::test]
    async fn the_balance_surface_answers_a_named_state_rather_than_a_number() {
        let s = shared();
        let r = handle_request_async(&s, &req("near_ai_balance", serde_json::json!({}))).await;
        // Never an IPC error: a shell has four different sentences to render
        // and an error plus a null would make all four read the same.
        assert!(r.error.is_none());
        let body = r.result.unwrap();
        assert_eq!(body["state"], "no_session");
        assert!(body["remaining_nanos"].is_null(), "{body}");
        assert!(body["total_spent_nanos"].is_null(), "{body}");
        assert!(body["observed_at"].is_null(), "{body}");
        assert_eq!(body["currency"], "USD");
        assert_eq!(body["scale"], 9);
    }

    #[tokio::test]
    async fn funding_dispatch_preserves_id_and_returns_canonical_refusals() {
        use crate::daemon::nearai_credential::funding::FundingReport;
        let s = shared();
        for (params, expected) in [
            (serde_json::json!({}), FundingReport::NoSession),
            (serde_json::Value::Null, FundingReport::InvalidRequest),
            (
                serde_json::json!({"expected_organization_id": "org-synthetic"}),
                FundingReport::InvalidRequest,
            ),
        ] {
            let request = Request {
                id: 7361,
                method: "near_ai_funding".into(),
                params,
            };
            let response = handle_request_async(&s, &request).await;
            assert_eq!(response.id, request.id);
            assert!(response.error.is_none());
            let body = response.result.unwrap();
            assert_eq!(
                body["state"],
                serde_json::to_value(&expected).unwrap()["state"]
            );
            assert_eq!(
                body["view"]["message"],
                crate::private_inference_copy::funding_message(&expected)
            );
            assert!(body.get("browser_url").is_none());
            assert!(body.get("organization_id").is_none());
        }
    }

    #[test]
    fn get_settings_never_carries_a_local_filesystem_path() {
        // The wholesale-serialized settings blob used to leak claude_root /
        // codex_root verbatim whenever either was overridden from the
        // conventional location -- exactly what entry_value is scrupulous
        // about avoiding for queue entries.
        let s = shared();
        {
            let mut settings = s.settings.lock().unwrap();
            settings.claude_source = Some(crate::daemon::settings::SourceDeclaration::Watch {
                path: std::path::PathBuf::from("/Users/z/.claude/projects"),
            });
            settings.codex_source = Some(crate::daemon::settings::SourceDeclaration::Watch {
                path: std::path::PathBuf::from("/Users/z/.codex/sessions"),
            });
        }
        let r = handle_request(&s, &req("get_settings", serde_json::json!({})));
        let result = r.result.unwrap();
        let body = serde_json::to_string(&result).unwrap();
        assert!(!body.contains('/'), "path leaked to the wire: {body}");
        assert_eq!(result["claude_root_configured"], true);
        assert_eq!(result["codex_root_configured"], true);
    }

    /// The session file's path never crosses the socket, and the only path
    /// that does is the rendered project directory.
    ///
    /// This asserted "no path at all" until `project_path` was added.
    /// Relaxing it to "no path but that one" is the whole of the
    /// relaxation, and it is stated as an equality rather than a substring
    /// check so that a second path appearing on this shape fails here --
    /// `display_path`'s doc comment carries the reasoning.
    #[test]
    fn a_queue_entry_on_the_wire_carries_no_session_file_path() {
        use crate::daemon::queue::{QueueEntry, entry_id_for};
        let e = QueueEntry {
            entry_id: entry_id_for("sha256:aa"),
            session_hash: "sha256:aa".into(),
            source: "claude-code".into(),
            project_key: "/Users/z/code/secret-client-project".into(),
            project_label: "secret-client-project".into(),
            path: "/Users/z/.claude/projects/x/s.jsonl".into(),
            size_bytes: 10,
            discovered_at: Utc::now(),
            ..Default::default()
        };
        let v = entry_value(&e, None);
        let body = serde_json::to_string(&v).unwrap();
        assert!(
            !body.contains(".claude"),
            "the session file's path leaked to the wire: {body}"
        );
        assert_eq!(
            v["project_path"], "/Users/z/code/secret-client-project",
            "the project directory is the one path this shape may carry"
        );
        assert!(
            body.matches("/Users/z").count() == 1,
            "exactly one path, and it is project_path: {body}"
        );
        assert!(body.contains("secret-client-project"));
    }

    #[test]
    fn the_upgrade_retires_entries_that_stand_for_a_lone_subagent_transcript() {
        // Discovery no longer yields a `subagents/` path, so these entries
        // are unreachable: an approved one would fail `session-file-vanished`
        // and a pending one would sit until it aged out. Worse, each still
        // offers a fragment whose opening prompt was written by the parent
        // agent. Say what happened instead, and leave the top-level entry --
        // and anything already resolved -- exactly as it was.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let open = || crate::config::ConfigStore::open(state.clone()).unwrap();

        let seed =
            |hash: &str, path: &str, entry_state: QueueState| super::super::queue::QueueEntry {
                entry_id: super::super::queue::entry_id_for(hash),
                session_hash: hash.to_string(),
                source: "claude-code".to_string(),
                project_key: "/tmp/p".to_string(),
                project_label: "p".to_string(),
                path: std::path::PathBuf::from(path),
                size_bytes: 1,
                discovered_at: Utc::now(),
                state: entry_state,
                ..Default::default()
            };
        let mut queue = Queue::new();
        queue
            .upsert(
                seed(
                    "sha256:top",
                    "/p/-Users-z-proj/aaa.jsonl",
                    QueueState::Pending,
                ),
                500,
            )
            .unwrap();
        queue
            .upsert(
                seed(
                    "sha256:sub",
                    "/p/-Users-z-proj/aaa/subagents/agent-1.jsonl",
                    QueueState::Pending,
                ),
                500,
            )
            .unwrap();
        queue
            .upsert(
                seed(
                    "sha256:subapproved",
                    "/p/-Users-z-proj/aaa/subagents/agent-2.jsonl",
                    QueueState::Approved,
                ),
                500,
            )
            .unwrap();
        queue
            .upsert(
                seed(
                    "sha256:subdone",
                    "/p/-Users-z-proj/aaa/subagents/agent-3.jsonl",
                    QueueState::Uploaded,
                ),
                500,
            )
            .unwrap();
        queue.save(&open()).unwrap();

        let s = DaemonShared::load(open()).unwrap();
        let q = s.queue.lock().unwrap();
        let by_hash = |h: &str| q.all().iter().find(|e| e.session_hash == h).unwrap();
        assert_eq!(by_hash("sha256:top").state, QueueState::Pending);
        assert_eq!(by_hash("sha256:sub").state, QueueState::Superseded);
        assert_eq!(
            by_hash("sha256:sub").reason_label.as_deref(),
            Some("regrouped-under-parent")
        );
        assert_eq!(by_hash("sha256:subapproved").state, QueueState::Superseded);
        assert_eq!(
            by_hash("sha256:subdone").state,
            QueueState::Uploaded,
            "an upload already recorded must not be rewritten by an upgrade"
        );
    }

    /// One pending queue card, for the `entry_value` tests below.
    fn card_entry() -> super::super::queue::QueueEntry {
        super::super::queue::QueueEntry {
            entry_id: uuid::Uuid::new_v4(),
            session_hash: "sha256:aa".to_string(),
            source: "claude-code".to_string(),
            project_key: "/tmp/p".to_string(),
            project_label: "p".to_string(),
            path: std::path::PathBuf::from("/tmp/s.jsonl"),
            size_bytes: 1,
            discovered_at: Utc::now(),
            subagent_count: 114,
            subagents_dropped: 2,
            ..Default::default()
        }
    }

    /// **The rule the whole field exists for.** An invited contributor gets
    /// NO eligibility field at all -- not `unknown`, not `eligible`, not an
    /// explicit null. Everything in their queue is contributable; a field
    /// answering a question they do not have is three shells' worth of
    /// caveat on work that carries none.
    ///
    /// Asserted on the JSON rather than on the entry, because the entry
    /// carrying a value and the wire suppressing it is exactly the state a
    /// contributor's config can produce.
    #[test]
    fn an_invited_contributor_is_handed_no_eligibility_field() {
        let mut e = card_entry();
        e.eligibility = Some(super::super::contribution_eligibility::STATE_ELIGIBLE.to_string());
        e.eligibility_reason = None;

        for flag in [Some(false), None] {
            let v = entry_value(&e, flag);
            let object = v.as_object().expect("an object");
            assert!(
                !object.contains_key("eligibility"),
                "the key itself must be absent, not null: {v}"
            );
            assert!(!object.contains_key("eligibility_reason"));
        }
    }

    /// And with the flag on, the recorded answer crosses whole.
    #[test]
    fn an_evidence_contributor_is_handed_the_recorded_answer() {
        use super::super::contribution_eligibility as ce;
        let mut e = card_entry();
        e.eligibility = Some(ce::STATE_INELIGIBLE_PERMANENT.to_string());
        e.eligibility_reason = Some(ce::REASON_NO_CALL.to_string());

        let v = entry_value(&e, Some(true));
        assert_eq!(v["eligibility"], ce::STATE_INELIGIBLE_PERMANENT);
        assert_eq!(v["eligibility_reason"], ce::REASON_NO_CALL);
    }

    /// An eligible row carries no reason: there is nothing to explain, and a
    /// reason beside it would be a caveat with no content.
    #[test]
    fn an_eligible_row_carries_no_reason() {
        use super::super::contribution_eligibility as ce;
        let mut e = card_entry();
        e.eligibility = Some(ce::STATE_ELIGIBLE.to_string());
        e.eligibility_reason = None;

        let v = entry_value(&e, Some(true));
        assert_eq!(v["eligibility"], ce::STATE_ELIGIBLE);
        assert!(
            !v.as_object()
                .expect("an object")
                .contains_key("eligibility_reason"),
            "an eligible row must carry no reason: {v}"
        );
    }

    /// A row this build never evaluated -- written before the fields
    /// existed, or re-offered after its content moved -- is `unknown` and
    /// not absent. Not evaluated is a different fact from not asked.
    #[test]
    fn an_unevaluated_row_is_unknown_rather_than_absent() {
        use super::super::contribution_eligibility as ce;
        let e = card_entry();
        assert!(e.eligibility.is_none());

        let v = entry_value(&e, Some(true));
        assert_eq!(v["eligibility"], ce::STATE_UNKNOWN);
    }

    /// **The rule the attestation mark exists for, and the exact opposite of
    /// the eligibility rule above.** An invited contributor is handed no
    /// eligibility field and IS handed the mark, for every flag value
    /// including the unreadable-config one.
    ///
    /// A single assertion covering both fields, because the pair is the
    /// contract: the same session, one question answered and the other
    /// correctly silent.
    #[test]
    fn an_invited_contributor_is_still_handed_the_attestation_mark() {
        use super::super::attestation_mark as am;
        let mut e = card_entry();
        e.attestation = Some(am::MARK_ATTESTED.to_string());

        for flag in [Some(false), None] {
            let v = entry_value(&e, flag);
            let object = v.as_object().expect("an object");
            assert!(
                !object.contains_key("eligibility"),
                "the permission question must stay unasked: {v}"
            );
            assert_eq!(
                v["attestation"],
                am::MARK_ATTESTED,
                "the mark describes the trace and is owed to everyone: {v}"
            );
        }
    }

    /// The positive case crosses whole. Unlike eligibility, whose surface
    /// only ever spoke up to explain a refusal, a session that IS attested
    /// says so -- and says it with no reason beside it, because there is
    /// nothing to explain.
    #[test]
    fn an_attested_row_says_so_and_explains_nothing() {
        use super::super::attestation_mark as am;
        let mut e = card_entry();
        e.attestation = Some(am::MARK_ATTESTED.to_string());
        e.attestation_reason = None;

        let v = entry_value(&e, Some(true));
        assert_eq!(v["attestation"], am::MARK_ATTESTED);
        assert!(
            !v.as_object()
                .expect("an object")
                .contains_key("attestation_reason"),
            "an attested row must carry no reason: {v}"
        );
    }

    /// An unattested row carries its own reason, and the reason is the
    /// shared label rather than a second spelling of it.
    #[test]
    fn an_unattested_row_carries_its_reason() {
        use super::super::attestation_mark as am;
        let mut e = card_entry();
        e.attestation = Some(am::MARK_UNATTESTED_PERMANENT.to_string());
        e.attestation_reason = Some(am::REASON_NO_CALL.to_string());

        let v = entry_value(&e, Some(true));
        assert_eq!(v["attestation"], am::MARK_UNATTESTED_PERMANENT);
        assert_eq!(v["attestation_reason"], am::REASON_NO_CALL);
    }

    /// A row written before the field existed is `unknown` and never absent.
    /// The question is never inapplicable, so an absent key could only be a
    /// shell's bug; `unknown` is the only honest silence.
    #[test]
    fn an_unevaluated_row_is_an_unknown_mark_rather_than_absent() {
        use super::super::attestation_mark as am;
        let e = card_entry();
        assert!(e.attestation.is_none());

        for flag in [Some(true), Some(false), None] {
            let v = entry_value(&e, flag);
            assert_eq!(v["attestation"], am::MARK_UNKNOWN, "{v}");
        }
    }

    /// **`unknown` is the one mark that may arrive with OR without a reason,
    /// and a shell must branch on the key rather than on the mark.**
    ///
    /// Two different things produce it. A row the daemon never evaluated has
    /// no reason -- nobody worked anything out, so there is nothing to
    /// explain. A row whose send was turned away because the receipt could
    /// not be fetched is `unknown` WITH `receipt_unavailable`: the claim was
    /// retracted, and the reason is the only thing telling the contributor it
    /// may work later.
    ///
    /// A shell that assumed the mark implies the shape lays out for a case
    /// that cannot occur, or drops the one sentence that says "try later".
    #[test]
    fn an_unknown_mark_carries_a_reason_only_when_one_was_established() {
        use super::super::attestation_mark as am;

        // Never evaluated: no reason at all.
        let unevaluated = card_entry();
        assert!(unevaluated.attestation.is_none());
        let v = entry_value(&unevaluated, Some(true));
        assert_eq!(v["attestation"], am::MARK_UNKNOWN);
        assert!(
            !v.as_object()
                .expect("an object")
                .contains_key("attestation_reason"),
            "an unevaluated row establishes no reason: {v}"
        );

        // Retracted by a send that could not fetch the receipt: same mark,
        // and a reason. Built through `writeback_for` rather than spelled
        // out, so this cannot drift from the rule that produces it.
        let retracted = am::writeback_for("admission_receipt_unavailable")
            .expect("a receipt-unavailable refusal retracts the mark");
        assert_eq!(retracted.state, am::MARK_UNKNOWN);
        let mut e = card_entry();
        e.attestation = Some(retracted.state.to_string());
        e.attestation_reason = retracted.reason.map(str::to_string);
        let v = entry_value(&e, Some(true));
        assert_eq!(v["attestation"], am::MARK_UNKNOWN);
        assert_eq!(v["attestation_reason"], am::REASON_RECEIPT_UNAVAILABLE);
    }

    /// The origin has to cross the IPC boundary, not merely exist on the ref.
    ///
    /// The desktop apps read this JSON and nothing else. An equivalent
    /// hand-off is exactly what broke while `declared_source` was being
    /// added to `SessionRef`, so it is asserted at the boundary rather than
    /// one layer below it.
    #[test]
    fn an_entry_reports_both_its_adapter_and_its_declared_origin() {
        let mut e = card_entry();
        e.source = "trajectory".to_string();
        e.declared_source = Some("antigravity".to_string());

        let v = entry_value(&e, None);
        assert_eq!(
            v["source"], "trajectory",
            "the adapter that loads it must stay reportable"
        );
        assert_eq!(v["declared_source"], "antigravity");
    }

    #[test]
    fn a_queue_entry_carries_a_displayable_project_path() {
        let mut e = card_entry();
        e.project_key = "/tmp/somewhere/repo".to_string();
        e.session_cwd = Some("/tmp/somewhere/repo/crates/inner".to_string());

        let v = entry_value(&e, None);
        assert_eq!(v["project_path"], "/tmp/somewhere/repo");
        assert_eq!(v["session_path"], "/tmp/somewhere/repo/crates/inner");
    }

    #[test]
    fn a_home_relative_project_path_is_abbreviated() {
        // `home_dir` rather than `$HOME`: Windows sets `%USERPROFILE%` and
        // no `HOME`, which is exactly the fallback `display_path` itself
        // uses. Reading only `HOME` here made this test unrunnable there.
        let home = crate::daemon::project_key::home_dir()
            .expect("a home directory must be discoverable in the test environment");
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            display_path(&format!("{}{sep}code{sep}api", home.display())),
            format!("~{sep}code{sep}api")
        );
        let elsewhere = crate::daemon::test_paths::abs("opt/elsewhere");
        assert_eq!(display_path(&elsewhere), elsewhere);
    }

    /// The bug the `HOME`-only test above could not see.
    ///
    /// A real project key has been through `normalize_project_key`, which
    /// case-folds on macOS and Windows. `$HOME` and `%USERPROFILE%` have
    /// not: they are `/Users/z` and `C:\Users\z`, capital letter and all.
    /// Comparing the folded key against the unfolded home meant the prefix
    /// never matched and every path rendered absolute.
    #[test]
    fn a_normalized_key_under_home_is_still_abbreviated() {
        let home = crate::daemon::project_key::home_dir()
            .expect("a home directory must be discoverable in the test environment");
        let key = crate::daemon::policy::project_key_for(Some(
            &home.join("code").join("api").to_string_lossy(),
        ));
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(display_path(&key), format!("~{sep}code{sep}api"));
    }

    /// What the contributor reads keeps its capitals; what the daemon
    /// decides on does not.
    ///
    /// Both halves in one test deliberately. Unfolding the key to fix the
    /// display would let one project mint two keys and an `Ignore` lapse
    /// under the other spelling; re-folding the display to keep the key
    /// tidy puts `~/code/ironwire` back in front of someone whose disk has
    /// no such directory. Only doing both is passing.
    ///
    /// Every expected string is derived by running the real
    /// `policy::project_for` over a real on-disk directory, from a
    /// SUBDIRECTORY of it, rather than assembled here -- a test that
    /// concatenates `$HOME` itself is how the broken `~` abbreviation went
    /// unnoticed on this branch once already.
    #[test]
    fn a_mixed_case_project_keeps_its_capitals_while_its_key_stays_folded() {
        let home = crate::daemon::project_key::home_dir()
            .expect("a home directory must be discoverable in the test environment");
        // Inside the real home, because the `~` abbreviation is half of
        // what is being asserted and `display_path` reads the environment.
        let dir = tempfile::Builder::new()
            .prefix("tc-case-")
            .tempdir_in(&home)
            .expect("a temporary directory under home");
        let root = dir.path().join("IronWire");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        let sub = root.join("Crates").join("Inner");
        std::fs::create_dir_all(&sub).unwrap();

        let (key, shown) = crate::daemon::policy::project_for(Some(&sub.to_string_lossy()));
        let shown = shown.expect("a directory that resolves has a display path");

        let mut e = card_entry();
        e.project_key = key.clone();
        e.project_path = Some(shown.clone());
        e.project_label = crate::daemon::policy::disambiguated_label(
            &key,
            Some(&shown),
            std::slice::from_ref(&key),
        );

        let v = entry_value(&e, None);
        let rendered = v["project_path"].as_str().expect("a rendered path");
        assert!(
            rendered.ends_with("IronWire"),
            "the displayed path was lowercased: {rendered}"
        );
        assert!(
            rendered.starts_with('~'),
            "a project under home must still abbreviate: {rendered}"
        );
        assert_eq!(
            v["project_label"], "IronWire",
            "the label was lowercased: {v}"
        );

        assert_eq!(
            key,
            crate::daemon::project_key::fold_case(&shown),
            "the key must remain the folded spelling of the same directory"
        );
        // Where folding is a no-op the two are equal by construction, so
        // the inequality is asserted only where it is a real claim.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        assert_ne!(
            key, shown,
            "on a case-insensitive filesystem the key must still be folded"
        );
    }

    #[test]
    fn the_unknown_bucket_has_no_path_to_show() {
        assert_eq!(display_path(UNKNOWN_PROJECT_KEY), UNKNOWN_PROJECT_KEY);
    }

    #[test]
    fn session_path_is_absent_when_it_matches_the_project() {
        let mut e = card_entry();
        e.project_key = "/tmp/somewhere/repo".to_string();
        e.session_cwd = Some("/tmp/somewhere/repo".to_string());
        assert!(entry_value(&e, None)["session_path"].is_null());
    }

    /// The path is on the socket and nowhere else.
    ///
    /// Deliberately asserts over the SINKS rather than over `display_path`:
    /// the risk is not that this function is wrong, it is that some later
    /// change pipes its output into an audit row or a notification. The
    /// audit sink has its own long-standing guard
    /// (`an_audit_entry_never_carries_a_path`); this covers the history
    /// record, which gained a project field in the same change.
    #[test]
    fn no_sink_carries_a_project_path() {
        let key = "/tmp/somewhere/secret-client-name";
        let record = crate::daemon::history::HistoryRecord {
            submission_id: uuid::Uuid::new_v4(),
            submitted_at: chrono::Utc::now(),
            project_id: crate::daemon::policy::project_id_for(key),
            project_label: crate::daemon::policy::project_label_for(key),
            source: "claude_code".to_string(),
            session_hash: "sha256:abc".to_string(),
            status: "accepted".to_string(),
            consent_scopes: vec![],
            credit_points_pending: 0.0,
            credit_points_final: None,
            explanations: vec![],
            last_refreshed_at: None,
            withdrawn_at: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(
            !json.contains("/tmp/somewhere"),
            "a history record must never carry a path: {json}"
        );
        assert!(
            !json.contains(&crate::daemon::ipc::display_path(key)),
            "not even an abbreviated one: {json}"
        );
    }

    /// A native session declares nothing and must not grow an empty label.
    #[test]
    fn an_entry_with_no_declared_origin_reports_null() {
        let v = entry_value(&card_entry(), None);
        assert_eq!(v["source"], "claude-code");
        assert!(
            v["declared_source"].is_null(),
            "absent must serialize as null, not as an empty string"
        );
    }

    #[test]
    fn the_queue_card_reports_how_many_delegated_transcripts_it_covers() {
        // A card standing for a hundred delegated transcripts has to say so:
        // the extent of what is being sent is part of the consent decision,
        // not decoration. No ordinal is exposed -- nothing in the format
        // supplies one.
        let e = card_entry();
        let v = entry_value(&e, None);
        assert_eq!(v["subagent_count"], 114);
        assert_eq!(v["subagents_dropped"], 2);
        let body = serde_json::to_string(&v).unwrap();
        assert!(!body.contains("/tmp/s.jsonl"), "path leaked: {body}");
    }

    /// One predicate, two readings, and therefore one unconditional field.
    ///
    /// `eligibility` above is absent for an invited contributor because they
    /// have no eligibility question. This is the opposite case: both
    /// audiences have the question, they just read the answer differently --
    /// a contributor without an invite reads it as "this one is a candidate
    /// for submission", one with an invite reads it as "this one is
    /// cryptographically attested". Same fact. So the daemon states it
    /// once, unconditionally, and the shell chooses the wording using the
    /// invite status it already holds for the eligibility surface.
    ///
    /// Emitting it only under `Some(true)` would leave invited contributors
    /// -- the ones for whom it reads as attestation -- unable to see it at
    /// all.
    #[test]
    fn every_contributor_is_told_which_entries_hold_a_certificate() {
        let pinned = QueueEntry {
            previewed_envelope_digest: Some(format!(
                "{}{}",
                super::super::approved_envelope::WITNESS_PIN_PREFIX,
                "ab".repeat(32)
            )),
            ..card_entry()
        };
        for admission_evidence in [Some(true), Some(false), None] {
            assert_eq!(
                entry_value(&pinned, admission_evidence)["holds_certificate"],
                serde_json::Value::Bool(true),
                "a witnessed entry did not say so at {admission_evidence:?}"
            );
            assert_eq!(
                entry_value(&card_entry(), admission_evidence)["holds_certificate"],
                serde_json::Value::Bool(false),
                "an unwitnessed entry did not say so at {admission_evidence:?}"
            );
        }
    }

    #[test]
    fn a_bad_entry_id_is_a_param_error_not_a_panic() {
        let s = shared();
        let r = handle_request(
            &s,
            &req("dismiss", serde_json::json!({"entry_id": "not-a-uuid"})),
        );
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn admission_requirement_survives_settings_write() {
        let s = shared();
        let mut cfg = crate::commands::unenrolled_preview_config();
        cfg.witness = Some(crate::config::WitnessSettings {
            url: "https://witness.example".into(),
            signing_address: "0x0000000000000000000000000000000000000000".into(),
            expected_measurements: vec!["measurement".into()],
            admission_evidence: true,
        });
        s.store.save_config(&cfg).unwrap();
        for method in ["get_settings", "set_settings"] {
            let response = handle_request(
                &s,
                &req(method, serde_json::json!({"max_uploads_per_day": 200})),
            );
            assert_eq!(
                response.result.unwrap()["admission_evidence_required"],
                true
            );
        }
    }

    #[test]
    fn set_settings_rejects_a_payload_with_nothing_known_in_it() {
        let s = shared();
        let r = handle_request(&s, &req("set_settings", serde_json::json!({"nonsense": 1})));
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn set_settings_raises_the_daily_caps_persists_and_the_next_upload_pass_sees_it() {
        // The scenario this exists for: a contributor whose byte budget was
        // already spent, with approved traces waiting, raises the cap
        // through `set_settings` -- no restart, no hand-edited file.
        let s = shared();
        {
            let mut state = s.state.lock().unwrap();
            state.uploads_today =
                super::super::settings::DaemonSettings::default().max_uploads_per_day;
            state.bytes_today = 204_659_969;
        }
        assert!(
            !super::super::uploader::cap_check(
                &s.state.lock().unwrap(),
                1,
                &s.settings.lock().unwrap(),
            ),
            "sanity: the default budget is exhausted before the raise"
        );

        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"max_uploads_per_day": 200, "max_bytes_per_day": 2_147_483_648u64}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        let body = r.result.unwrap();
        assert_eq!(body["max_uploads_per_day"], 200);
        assert_eq!(body["max_bytes_per_day"], 2_147_483_648u64);

        // Live: the in-memory settings the next upload pass reads are
        // already updated, with no restart.
        assert!(
            super::super::uploader::cap_check(
                &s.state.lock().unwrap(),
                1,
                &s.settings.lock().unwrap(),
            ),
            "the raised cap must be visible to the very next cap check"
        );

        // Persisted: reloading from disk (what a restart does) must agree
        // with the live value, or a restart would silently revert what the
        // contributor just did.
        let reloaded = super::super::settings::DaemonSettings::load(&s.store).unwrap();
        assert_eq!(reloaded.max_uploads_per_day, 200);
        assert_eq!(reloaded.max_bytes_per_day, 2_147_483_648);
    }

    #[test]
    fn set_settings_accepts_ironwire_and_persists_it() {
        // Before this, `ironwire` was not in `apply_settings_object`'s
        // whitelist, so the only way to declare the proxy overlay was
        // hand-editing settings.json. `set_settings` now persists the
        // declaration the same way. This test asserts the live settings
        // value and the persisted file; that the overlay itself activates
        // without a restart is
        // `a_declaration_change_takes_effect_without_a_restart`.
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"ironwire": {"mode": "watch", "port": 8463}}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(
            s.settings.lock().unwrap().ironwire,
            Some(super::super::settings::IronWireDeclaration::Watch {
                port: 8463,
                token_dir: None
            })
        );

        // Persisted: a restart must see the same declaration.
        let reloaded = super::super::settings::DaemonSettings::load(&s.store).unwrap();
        assert_eq!(
            reloaded.ironwire,
            Some(super::super::settings::IronWireDeclaration::Watch {
                port: 8463,
                token_dir: None
            })
        );

        // null turns it back off.
        let r = handle_request(
            &s,
            &req("set_settings", serde_json::json!({"ironwire": null})),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(s.settings.lock().unwrap().ironwire, None);
    }

    #[tokio::test]
    async fn private_inference_derives_metadata_only_and_withdraws_on_accepted_off() {
        let s = shared();
        s.adopt_runtime();
        let home = tempfile::tempdir().unwrap();
        s.install_private_inference_for_test(home.path().to_path_buf(), 0);
        assert!(s.routing_ledger().is_none());
        let result = handle_set_settings_async(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference":true}),
            ),
        )
        .await;
        assert!(result.error.is_none(), "{:?}", result.error);
        let first = s
            .routing_ledger()
            .expect("owned proxy supplies metadata reader");
        let expected = super::super::settings::IronWireDeclaration::Watch {
            port: s.private_inference_value()["port"].as_u64().unwrap() as u16,
            token_dir: Some(home.path().canonicalize().unwrap()),
        };
        assert_eq!(s.routing.read().unwrap().declaration, Some(expected));
        assert!(s.routing.read().unwrap().derived);
        assert_eq!(s.routing_value()["derived"], true);
        let persisted = DaemonSettings::load(&s.store).unwrap();
        assert!(persisted.private_inference);
        assert!(persisted.ironwire.is_none());
        assert!(!persisted.ironwire_attested_bodies);
        assert!(format!("{:?}", s.source_roots_with_routing()).contains("attested_bodies: false"));
        assert!(
            handle_set_settings(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"private_inference":true})
                )
            )
            .error
            .is_none()
        );
        assert!(Arc::ptr_eq(&first, &s.routing_ledger().unwrap()));
        // A stale body opt-in does not turn an automatic metadata declaration
        // into permission to read the owned proxy's verbatim body store.
        assert!(
            handle_set_settings(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"ironwire_attested_bodies":true})
                )
            )
            .error
            .is_none()
        );
        assert!(format!("{:?}", s.source_roots_with_routing()).contains("attested_bodies: false"));
        let settings_path = s.store.daemon_path(crate::config::DAEMON_SETTINGS_FILE);
        let saved = std::fs::read(&settings_path).unwrap();
        std::fs::remove_file(&settings_path).unwrap();
        std::fs::create_dir(&settings_path).unwrap();
        let refused = handle_set_settings(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference":false}),
            ),
        );
        assert_eq!(refused.error.unwrap().message, "settings-write-failed");
        assert!(s.settings.lock().unwrap().private_inference);
        assert!(Arc::ptr_eq(&first, &s.routing_ledger().unwrap()));
        std::fs::remove_dir(&settings_path).unwrap();
        std::fs::write(&settings_path, saved).unwrap();
        // Withdrawal happens in the accepted settings transaction, before any
        // asynchronous lifecycle reconcile or listener cleanup can complete.
        assert!(
            handle_set_settings(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"private_inference":false})
                )
            )
            .error
            .is_none()
        );
        assert!(s.routing_ledger().is_none());
        assert!(!s.routing.read().unwrap().derived);
        s.stop_private_inference().await;
    }

    #[tokio::test]
    async fn private_inference_preserves_explicit_off_and_custom_watch_during_teardown() {
        use super::super::settings::IronWireDeclaration;
        for off in [true, false] {
            let s = shared();
            s.adopt_runtime();
            let home = tempfile::tempdir().unwrap();
            let custom = token_dir_holding("explicit-metadata-token");
            let declaration = if off {
                IronWireDeclaration::Off
            } else {
                IronWireDeclaration::Watch {
                    port: 4321,
                    token_dir: Some(custom.path().to_path_buf()),
                }
            };
            assert!(
                handle_set_settings(
                    &s,
                    &req("set_settings", serde_json::json!({"ironwire":declaration}))
                )
                .error
                .is_none()
            );
            let before = s.routing_ledger();
            s.install_private_inference_for_test(home.path().to_path_buf(), 0);
            assert!(
                handle_set_settings_async(
                    &s,
                    &req(
                        "set_settings",
                        serde_json::json!({"private_inference":true})
                    )
                )
                .await
                .error
                .is_none()
            );
            assert_eq!(
                s.routing.read().unwrap().declaration,
                Some(declaration.clone())
            );
            assert!(!s.routing.read().unwrap().derived);
            assert_eq!(s.routing_value()["derived"], false);
            s.stop_private_inference().await;
            assert_eq!(s.routing.read().unwrap().declaration, Some(declaration));
            if let Some(before) = before {
                assert!(Arc::ptr_eq(&before, &s.routing_ledger().unwrap()));
            } else {
                assert!(s.routing_ledger().is_none());
            }
        }
    }

    #[test]
    fn poisoned_routing_reports_unknown_without_a_token_diagnosis() {
        let s = shared();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = s.routing.write().unwrap();
            panic!("controlled routing state panic");
        }));
        assert_eq!(
            s.routing_value(),
            serde_json::json!({"state":"unknown", "derived":false, "last_refresh_at":null, "unreadable_rows":0})
        );
    }

    #[tokio::test]
    async fn derived_routing_refresh_withdraws_an_observed_exited_proxy_first() {
        let s = shared();
        s.adopt_runtime();
        let home = tempfile::tempdir().unwrap();
        s.install_private_inference_for_test(home.path().to_path_buf(), 0);
        assert!(
            handle_set_settings_async(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"private_inference":true})
                )
            )
            .await
            .error
            .is_none()
        );
        assert!(s.routing_ledger().is_some());
        s.private_inference
            .lock()
            .await
            .as_mut()
            .unwrap()
            .end_owned_for_test()
            .await;
        // The shared status is deliberately stale, as it is between poll ticks.
        assert_ne!(s.private_inference_value()["state"], "crashed");
        s.refresh_routing().await;
        assert_eq!(s.private_inference_value()["state"], "crashed");
        assert!(s.routing_ledger().is_none());
        assert_eq!(s.routing_value()["derived"], false);
        s.stop_private_inference().await;
    }

    #[tokio::test]
    async fn private_inference_foreign_owner_never_supplies_derived_metadata() {
        // A future-loosening guard: before automatic derivation there was
        // also no reader for a foreign owner.
        let home = tempfile::tempdir().unwrap();
        let owner = ironwire_proxy::embed::start(home.path(), Some(0))
            .await
            .unwrap();
        let s = shared();
        s.adopt_runtime();
        s.install_private_inference_for_test(home.path().to_path_buf(), 0);
        assert!(
            handle_set_settings_async(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"private_inference":true})
                )
            )
            .await
            .error
            .is_none()
        );
        assert_eq!(s.private_inference_value()["state"], "running_elsewhere");
        assert!(s.routing_ledger().is_none());
        s.stop_private_inference().await;
        assert!(!owner.is_finished());
        owner.shutdown().await;
    }

    #[tokio::test]
    async fn private_inference_transition_wakes_an_idle_supervisor() {
        let s = shared();
        s.adopt_runtime();
        let home = tempfile::tempdir().unwrap();
        s.install_private_inference_for_test(home.path().to_path_buf(), 0);
        assert!(
            handle_set_settings_async(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"private_inference":true})
                )
            )
            .await
            .error
            .is_none()
        );
        // Consume the start notification: the supervisor can now be waiting
        // with its conditional cleanup timer disabled because it saw Running.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            s.private_inference_changed.notified(),
        )
        .await
        .unwrap();
        assert!(
            handle_set_settings_async(
                &s,
                &req(
                    "set_settings",
                    serde_json::json!({"private_inference":false})
                )
            )
            .await
            .error
            .is_none()
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            s.private_inference_changed.notified(),
        )
        .await
        .expect("stop transition must wake the existing select");
        s.stop_private_inference().await;
    }

    #[test]
    fn stopping_without_runtime_does_not_invent_owned_cleanup() {
        let s = shared();
        s.request_private_inference_stop();
        assert_eq!(s.private_inference_value()["state"], "off");
        assert!(s.private_inference_stop_task.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn stopping_foreign_instance_does_not_publish_its_port_as_owned() {
        let s = shared();
        s.adopt_runtime();
        *s.private_inference_state.lock().unwrap() =
            super::super::private_inference::PrivateInferenceState::RunningElsewhere { port: 1234 };
        s.stop_private_inference().await;
        assert_eq!(
            s.private_inference_value(),
            serde_json::json!({"state":"off", "port":null})
        );
        assert!(s.private_inference_stop_task.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn private_inference_stop_deadline_keeps_drain_without_retaining_daemon() {
        let s = Arc::new(shared());
        s.adopt_runtime();
        let home = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = pending.await;
            drop(listener);
            true
        });
        *s.private_inference.lock().await = Some(
            super::super::private_inference::PrivateInference::with_shutdown_for_test(
                home.path().join("unused"),
                port,
                task,
            ),
        );
        assert!(
            !s.finish_private_inference_stop(std::time::Duration::from_millis(25))
                .await
        );
        assert_eq!(
            s.private_inference_value(),
            serde_json::json!({"state":"stopping", "port":port})
        );
        s.settings.lock().unwrap().private_inference = true;
        s.reconcile_private_inference().await;
        assert_eq!(s.private_inference_value()["state"], "stopping");
        let weak = Arc::downgrade(&s);
        drop(s);
        assert!(
            weak.upgrade().is_none(),
            "cleanup must not retain contributor queues"
        );
        assert!(
            tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpListener::bind(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn private_inference_superseded_start_never_publishes_running() {
        for cancel_caller in [false, true] {
            let s = Arc::new(shared());
            s.adopt_runtime();
            let home = tempfile::tempdir().unwrap();
            let start_home = home.path().to_path_buf();
            let (release, pending) = tokio::sync::oneshot::channel::<()>();
            let starting = tokio::spawn(async move {
                pending.await.unwrap();
                ironwire_proxy::embed::start(&start_home, Some(0)).await
            });
            *s.private_inference.lock().await = Some(
                super::super::private_inference::PrivateInference::with_pending_start_for_test(
                    home.path().to_path_buf(),
                    starting,
                ),
            );
            assert!(
                handle_set_settings(
                    &s,
                    &req(
                        "set_settings",
                        serde_json::json!({"private_inference":true})
                    )
                )
                .error
                .is_none()
            );
            let caller_shared = Arc::clone(&s);
            let caller = tokio::spawn(async move {
                caller_shared.reconcile_private_inference().await;
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while s.private_inference.try_lock().is_ok() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if cancel_caller {
                caller.abort();
            }
            assert!(
                handle_set_settings(
                    &s,
                    &req(
                        "set_settings",
                        serde_json::json!({"private_inference":false})
                    )
                )
                .error
                .is_none()
            );
            assert!(
                handle_set_settings(
                    &s,
                    &req(
                        "set_settings",
                        serde_json::json!({"private_inference":true})
                    )
                )
                .error
                .is_none()
            );
            if cancel_caller {
                assert!(caller.await.unwrap_err().is_cancelled());
                s.reconcile_private_inference().await;
                assert_eq!(
                    s.private_inference_value(),
                    serde_json::json!({"state":"stopping", "port":null})
                );
                release.send(()).unwrap();
            } else {
                release.send(()).unwrap();
                caller.await.unwrap();
                assert_eq!(s.private_inference_value()["state"], "stopping");
            }
            s.stop_private_inference().await;
            assert_eq!(s.private_inference_value()["state"], "off");
            assert!(!home.path().join("endpoint.json").exists());
        }
    }

    #[tokio::test]
    async fn private_inference_stop_budget_includes_waiting_for_lifecycle_lock() {
        let s = shared();
        s.adopt_runtime();
        let held = s.private_inference.lock().await;
        assert!(
            !s.finish_private_inference_stop(std::time::Duration::from_millis(25))
                .await
        );
        drop(held);
        assert!(
            s.finish_private_inference_stop(std::time::Duration::from_secs(2))
                .await
        );
    }

    #[tokio::test]
    async fn rejected_private_inference_settings_never_reach_reconcile() {
        let s = shared();
        let home = tempfile::tempdir().unwrap();
        let absent_home = home.path().join("never-created");
        *s.private_inference.lock().await = Some(
            super::super::private_inference::PrivateInference::with_port(absent_home.clone(), 0),
        );
        let response = handle_set_settings_async(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference": true, "zz_unknown": true}),
            ),
        )
        .await;
        assert!(response.error.is_some());
        assert!(!s.settings.lock().unwrap().private_inference);
        assert!(!DaemonSettings::load(&s.store).unwrap().private_inference);
        s.reconcile_private_inference().await;
        assert_eq!(s.private_inference_value()["state"], "off");
        assert!(!absent_home.exists());
    }

    /// A key obtained after the daemon started still reaches the proxy, and
    /// a key removed stops reaching it. The reconcile pass reads it from the
    /// same lock as the switch, so neither needs a daemon restart.
    #[tokio::test]
    async fn a_minted_key_reaches_the_proxy_from_settings_and_leaving_stops_it() {
        let s = shared();
        let home = tempfile::tempdir().unwrap();
        *s.private_inference.lock().await = Some(
            super::super::private_inference::PrivateInference::with_port(
                home.path().join("never-created"),
                0,
            ),
        );
        s.reconcile_private_inference().await;
        assert!(
            !s.private_inference
                .lock()
                .await
                .as_ref()
                .unwrap()
                .holds_credential(),
            "a daemon that has obtained nothing must hand IronWire nothing"
        );

        s.settings.lock().unwrap().near_ai_inference =
            Some(crate::daemon::settings::NearAiInferenceCredential {
                key: "sk-minted".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-min".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
                minted_at: chrono::Utc::now(),
            });
        s.reconcile_private_inference().await;
        assert!(
            s.private_inference
                .lock()
                .await
                .as_ref()
                .unwrap()
                .holds_credential()
        );

        s.settings.lock().unwrap().near_ai_inference = None;
        s.reconcile_private_inference().await;
        assert!(
            !s.private_inference
                .lock()
                .await
                .as_ref()
                .unwrap()
                .holds_credential(),
            "a revoked key must stop being offered"
        );
    }

    /// A ceremony that finishes while the daemon runs reaches IronWire, and
    /// forgetting takes the key back out -- neither waits for a restart.
    ///
    /// The assertion that matters is `starts()`, not `holds_credential()`.
    /// Handing the key to the host is what already happened before this and
    /// changed nothing a contributor could see: IronWire resolves its
    /// credentials once, while building the registry, so a key that arrives
    /// without a rebuild is a key nothing answers with. A proxy started again
    /// is the whole observable difference between a credential that works and
    /// one that sits in a file.
    #[tokio::test]
    async fn a_ceremony_that_finishes_mid_run_rebuilds_the_proxy_on_the_new_key() {
        let s = shared();
        let home = tempfile::tempdir().unwrap();
        // On, persisted, and running a real proxy: the case where a cycle
        // costs something. A proxy that is off has nothing to interrupt.
        s.settings.lock().unwrap().private_inference = true;
        s.settings.lock().unwrap().save(&s.store).unwrap();
        *s.private_inference.lock().await = Some(
            super::super::private_inference::PrivateInference::with_port(
                home.path().to_path_buf(),
                0,
            ),
        );
        s.reconcile_private_inference().await;
        {
            let held = s.private_inference.lock().await;
            let host = held.as_ref().unwrap();
            assert!(!host.holds_credential(), "nothing has been minted yet");
            assert_eq!(host.starts(), 1, "{:?}", host.state());
        }

        // Exactly what the ceremony's last leg does, from exactly where it
        // does it: a settings write against the config directory, with no
        // handle to this daemon and no IPC call to hang anything on.
        crate::daemon::nearai_credential::ceremony::persist(
            s.store.dir(),
            crate::daemon::nearai_credential::api::MintedKey {
                key: "sk-minted-secret".into(),
                key_id: "key-1".into(),
                key_prefix: "sk-min".into(),
                organization_id: "org-1".into(),
                workspace_id: "ws-1".into(),
            },
            // The ceremony now stores a session beside the key, so this
            // stands in for the refresh token its last leg carries. The
            // coupling includes the retained session reaching the running
            // daemon so balance and enrollment work without a restart.
            "refresh-token-for-the-reconcile-test".to_string(),
        )
        .unwrap();

        s.reconcile_private_inference().await;
        assert_eq!(
            s.settings
                .lock()
                .unwrap()
                .near_ai_session
                .as_ref()
                .map(|session| session.refresh_token.as_str()),
            Some("refresh-token-for-the-reconcile-test")
        );
        {
            let held = s.private_inference.lock().await;
            let host = held.as_ref().unwrap();
            assert!(host.holds_credential(), "the minted key never arrived");
            assert_eq!(
                host.starts(),
                2,
                "the key reached the host and the registry was never rebuilt, \
                 which is the ceremony that succeeds and changes nothing"
            );
        }
        // The in-memory document took the credential and nothing else: the
        // ceremony wrote from disk, where this was never true.
        assert!(s.settings.lock().unwrap().private_inference);

        // Forgetting is the other half, and it must not linger either.
        let r = handle_request_async(&s, &req("near_ai_credential_forget", serde_json::json!({})))
            .await;
        assert_eq!(r.result.unwrap()["removed"], true);
        {
            let held = s.private_inference.lock().await;
            let host = held.as_ref().unwrap();
            assert!(!host.holds_credential(), "a forgotten key is still held");
            assert_eq!(
                host.starts(),
                3,
                "the proxy kept answering with a key the contributor withdrew"
            );
        }
        assert!(s.settings.lock().unwrap().near_ai_inference.is_none());

        // A second forget removed nothing and must not cycle a live proxy for
        // it -- the counter is only advanced by a real change.
        let r = handle_request_async(&s, &req("near_ai_credential_forget", serde_json::json!({})))
            .await;
        assert_eq!(r.result.unwrap()["removed"], false);
        {
            let held = s.private_inference.lock().await;
            assert_eq!(held.as_ref().unwrap().starts(), 3);
        }

        s.private_inference
            .lock()
            .await
            .as_mut()
            .unwrap()
            .finish_stop()
            .await;
    }

    #[tokio::test]
    async fn unpersisted_private_inference_opt_in_never_reaches_reconcile() {
        let s = shared();
        let home = tempfile::tempdir().unwrap();
        let absent_home = home.path().join("never-created");
        *s.private_inference.lock().await = Some(
            super::super::private_inference::PrivateInference::with_port(absent_home.clone(), 0),
        );
        let path = s.store.daemon_path(crate::config::DAEMON_SETTINGS_FILE);
        std::fs::create_dir_all(&path).unwrap();
        let response = handle_set_settings_async(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference": true}),
            ),
        )
        .await;
        assert_eq!(response.error.unwrap().message, "settings-write-failed");
        assert!(!s.settings.lock().unwrap().private_inference);
        s.reconcile_private_inference().await;
        assert_eq!(s.private_inference_value()["state"], "off");
        assert!(!absent_home.exists());
        assert!(path.is_dir());
    }

    /// The switch is a settable key, it persists, and it is off until
    /// somebody sets it. An upgrade must never start a proxy because a
    /// settings file predates the key.
    #[test]
    fn set_settings_accepts_private_inference_and_persists_it() {
        let s = shared();
        assert!(
            !s.settings.lock().unwrap().private_inference,
            "the switch must be off before anyone asks"
        );

        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference": true}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(s.settings.lock().unwrap().private_inference);

        let reloaded = super::super::settings::DaemonSettings::load(&s.store).unwrap();
        assert!(
            reloaded.private_inference,
            "a restart must not silently revert the switch"
        );

        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference": false}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(!s.settings.lock().unwrap().private_inference);
    }

    /// The offer marker is readable, settable and survives a restart --
    /// and recording that the question was asked starts nothing.
    ///
    /// A shell that could not read the marker back would have to keep its
    /// own copy, and a shell whose write did not persist would ask again on
    /// every launch, which is the nagging this key exists to prevent.
    #[test]
    fn the_offer_marker_round_trips_and_starts_nothing() {
        let s = shared();
        let before = handle_request(&s, &req("get_settings", serde_json::json!({})));
        let before = before.result.expect("get_settings answers");
        assert_eq!(
            before["private_inference_offer_seen"],
            serde_json::json!(false),
            "a daemon nobody has asked through reports the offer unanswered"
        );

        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"private_inference_offer_seen": true}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        let echoed = r.result.expect("set_settings answers");
        assert_eq!(
            echoed["private_inference_offer_seen"],
            serde_json::json!(true)
        );
        assert_eq!(
            echoed["private_inference"],
            serde_json::json!(false),
            "answering the question is not answering the switch"
        );
        assert_eq!(
            echoed["private_inference_state"]["state"],
            serde_json::json!(super::super::private_inference::LABEL_OFF),
            "recording the answer must not have started anything"
        );

        let reloaded = super::super::settings::DaemonSettings::load(&s.store).unwrap();
        assert!(
            reloaded.private_inference_offer_seen,
            "a restart must not put the question back"
        );
        assert!(!reloaded.private_inference);
    }

    /// Ask 127.0.0.1:`port` for IronWire's health endpoint using nothing
    /// but the standard library.
    ///
    /// Deliberately synchronous and tokio-free. The defect this guards
    /// against is a proxy started on a runtime that is dropped the moment
    /// the call returns, so the probe must not itself construct, enter, or
    /// keep alive any runtime -- it has to ask the operating system whether
    /// something is really listening once every runtime in the story is
    /// gone.
    fn health_answers(port: u16) -> bool {
        use std::io::{Read, Write};
        let Ok(mut conn) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
            return false;
        };
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        if conn
            .write_all(
                b"GET /_ironwire/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .is_err()
        {
            return false;
        }
        let mut buf = Vec::new();
        let _ = conn.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200")
    }

    /// Wait for `port` to stop answering, up to `within`.
    ///
    /// **The instant assertion this replaces was wrong about the contract.**
    /// `set_settings` does not promise the listener is closed by the time it
    /// returns, and `PrivateInference::apply` is explicit about it: turning the
    /// switch off spawns the shutdown onto the daemon runtime, sets
    /// `PrivateInferenceState::Stopping`, and returns. Both off-path sites do
    /// this, and the join handle is reaped later by `poll`. So between the
    /// call returning and the spawned task running, the accept loop may serve
    /// one more connection. Locally the spawned task wins every time; under CI
    /// load it need not, which is #823.
    ///
    /// Waiting is therefore not a workaround for flakiness -- it is the
    /// assertion matching the promise. What the daemon guarantees is that the
    /// port *is* released, not that it is released synchronously, and that is
    /// what this checks.
    ///
    /// It fails closed: a port still answering at the deadline returns false
    /// and the caller's assertion fires. Widening the deadline would not hide
    /// a regression that stopped releasing the port at all, because no
    /// deadline makes a leaked listener stop answering.
    fn health_stops_answering_within(port: u16, within: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        loop {
            if !health_answers(port) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// The switch flipped through the synchronous path leaves a proxy that
    /// is still serving after the call returns.
    ///
    /// `handle_local` is the path `tc_call` uses -- the FFI both desktop
    /// apps are built on -- and the CLI's in-process path. It answers by
    /// running the real dispatcher on a throwaway current-thread runtime
    /// inside a scoped thread, and that runtime is dropped the instant the
    /// scope returns. A proxy whose server task was spawned onto it dies
    /// there, while the response the contributor sees says `running` with a
    /// port on it: the green light over a dead proxy that
    /// `running_no_backends` exists to prevent, arriving by a different
    /// road.
    ///
    /// So this asserts the port *after* the call has returned, from a
    /// thread with no runtime on it at all.
    #[test]
    fn a_switch_flipped_through_the_sync_path_leaves_a_serving_proxy() {
        // The daemon runtime, standing in for the one `start_embedded` runs
        // on: multi-thread, and alive for the whole test because the daemon
        // outlives every request it answers. `adopt_runtime` is called from
        // inside it exactly as `start_embedded` does.
        let daemon_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a daemon runtime");

        let s = shared();
        daemon_runtime.block_on(async { s.adopt_runtime() });

        let home = tempfile::tempdir().expect("a temp home");
        s.install_private_inference_for_test(home.path().to_path_buf(), 0);

        // Called from the test thread, which is inside no runtime -- the
        // position an FFI caller is in.
        let r = handle_local(
            &s,
            "set_settings",
            serde_json::json!({"private_inference": true}),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        let reported = r.result.expect("set_settings answers")["private_inference_state"].clone();
        let label = reported["state"].as_str().unwrap_or_default().to_string();
        // Any of the running family. This test is about whether the sync
        // path started a proxy, not about which account answers -- and the
        // destination is legitimately unknown here, because nothing has read
        // the proxy's status yet. Pinning "running" alone would make this
        // test fail for the honest answer.
        assert!(
            matches!(
                label.as_str(),
                "running"
                    | "running_no_backends"
                    | "running_answered_elsewhere"
                    | "running_destination_unknown"
            ),
            "the sync path must actually start the proxy, got {reported}"
        );
        let port = u16::try_from(reported["port"].as_u64().expect("a bound port")).expect("a port");

        assert!(
            health_answers(port),
            "the proxy must still answer after handle_local returned; \
             reporting {label} on port {port} while the runtime that owned \
             it has been dropped is a green light over a dead proxy"
        );

        let off = handle_local(
            &s,
            "set_settings",
            serde_json::json!({"private_inference": false}),
        );
        assert!(off.error.is_none(), "{:?}", off.error);
        // Not `!health_answers(port)` on its own: see
        // `health_stops_answering_within`. The switch answers while the state
        // is `Stopping` and the shutdown is still a spawned task, so the
        // promise being checked is that the port is released, not that it is
        // released before the call returns.
        assert!(
            health_stops_answering_within(port, std::time::Duration::from_secs(10)),
            "turning it off through the same path must release the port"
        );
    }

    /// A settings file that predates the key loads with private inference
    /// off. This is the whole safety property of the default.
    #[test]
    fn a_settings_file_without_the_key_loads_with_private_inference_off() {
        let s = shared();
        let body = serde_json::json!({
            "schema_version": super::super::settings::DAEMON_SETTINGS_SCHEMA,
            "poll_interval_secs": 60,
            "quiescence_secs": 1800,
            "digest_interval_secs": 14_400,
            "queue_ttl_days": 14,
            "growth_factor": 2.0,
            "growth_min_new_bytes": 65_536,
            "max_reuploads": 3,
            "max_uploads_per_day": 50,
            "max_bytes_per_day": 209_715_200u64,
            "max_queue_entries": 500,
            "history_poll_secs": 1800,
            "canary_interval_secs": 3600,
            "local_notifications": false,
        });
        s.store
            .write_daemon_file(
                crate::config::DAEMON_SETTINGS_FILE,
                serde_json::to_string(&body).unwrap().as_bytes(),
            )
            .unwrap();
        let loaded = super::super::settings::DaemonSettings::load(&s.store).unwrap();
        assert!(!loaded.private_inference);
    }

    /// Both settings surfaces report what the hosted proxy is actually
    /// doing, not only what was asked for. A shell that had to infer the
    /// state from the boolean would show a proxy as on while it refused to
    /// start.
    #[test]
    fn the_reported_state_is_off_before_anything_is_asked() {
        let s = shared();
        let settings = handle_request(&s, &req("get_settings", serde_json::json!({})))
            .result
            .expect("get_settings answers");
        assert_eq!(
            settings["private_inference_state"],
            serde_json::json!({ "state": "off", "port": null })
        );
        let status = s.status_value();
        assert_eq!(
            status["private_inference_state"],
            serde_json::json!({ "state": "off", "port": null })
        );
    }

    #[test]
    fn set_settings_rejects_a_daily_cap_above_the_ceiling() {
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"max_uploads_per_day": 1_000_001u64}),
            ),
        );
        let err = r.error.expect("an out-of-range cap must be refused");
        assert_eq!(err.code, ERR_BAD_PARAMS);
        assert_eq!(err.message, "settings-invalid-value");
        // Unchanged: the default is untouched by the rejected write.
        assert_eq!(
            s.settings.lock().unwrap().max_uploads_per_day,
            super::super::settings::DaemonSettings::default().max_uploads_per_day
        );
    }

    fn seed_entry_in_state(s: &DaemonShared, state: QueueState) -> Uuid {
        let entry_id = uuid::Uuid::new_v4();
        let mut queue = s.queue.lock().unwrap();
        queue
            .upsert(
                super::super::queue::QueueEntry {
                    entry_id,
                    session_hash: format!("sha256:{entry_id}"),
                    source: "claude-code".to_string(),
                    project_key: "/tmp/p".to_string(),
                    project_label: "p".to_string(),
                    path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                    size_bytes: 1,
                    discovered_at: Utc::now(),
                    ..Default::default()
                },
                500,
            )
            .unwrap();
        queue.set_state(entry_id, state, None);
        entry_id
    }

    fn seed_approved_entry(s: &DaemonShared) -> Uuid {
        seed_entry_in_state(s, QueueState::Approved)
    }

    #[test]
    fn acknowledging_the_near_ai_notice_clears_the_blocking_health_label() {
        // Without this an app-only contributor (never touching the CLI,
        // which shows the same notice on stdout) is stuck forever.
        let s = shared();
        s.health.lock().unwrap().fail(
            crate::daemon::health::LABEL_NEAR_AI_NOTICE_PENDING,
            Utc::now(),
        );
        let r = handle_request(
            &s,
            &req("acknowledge_near_ai_notice", serde_json::json!({})),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(s.store.near_ai_notice_shown());
        assert!(s.health.lock().unwrap().ok());
    }

    #[test]
    fn cancel_returns_an_approved_entry_to_pending() {
        let s = shared();
        let id = seed_approved_entry(&s);
        let r = handle_request(
            &s,
            &req("cancel", serde_json::json!({"entry_id": id.to_string()})),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(
            s.queue.lock().unwrap().get(id).unwrap().state,
            QueueState::Pending
        );
    }

    #[test]
    fn cancel_refuses_once_the_upload_is_in_flight() {
        let s = shared();
        let id = seed_entry_in_state(&s, QueueState::Uploading);
        let r = handle_request(
            &s,
            &req("cancel", serde_json::json!({"entry_id": id.to_string()})),
        );
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn cancel_of_an_unknown_entry_is_a_param_error() {
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "cancel",
                serde_json::json!({"entry_id": uuid::Uuid::new_v4().to_string()}),
            ),
        );
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn a_timed_pause_is_persisted_so_it_survives_a_restart() {
        // An app-side timer would die with the app and silently un-pause.
        let s = shared();
        let until = "2030-01-01T00:00:00Z";
        handle_request(&s, &req("pause", serde_json::json!({"until": until})));
        assert_eq!(
            s.state.lock().unwrap().paused_until.map(|t| t.to_rfc3339()),
            Some(until.parse::<chrono::DateTime<Utc>>().unwrap().to_rfc3339())
        );
    }

    #[test]
    fn pause_rejects_a_deadline_already_in_the_past() {
        // Accepting it would publish a pause event for a pause the very next
        // status call (or is_paused check) clears -- a lie the instant it's
        // acknowledged.
        let s = shared();
        let r = handle_request(
            &s,
            &req(
                "pause",
                serde_json::json!({"until": "2020-01-01T00:00:00Z"}),
            ),
        );
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
        assert!(!s.paused.load(Ordering::Relaxed));
    }

    #[test]
    fn a_lapsed_timed_pause_clears_itself_when_checked() {
        // A deadline that was in the future when set, and has since passed
        // (unlike the request-time validation above, which only catches a
        // deadline that was already past when submitted).
        let s = shared();
        handle_request(
            &s,
            &req(
                "pause",
                serde_json::json!({"until": "2030-01-01T00:00:00Z"}),
            ),
        );
        assert!(s.is_paused(at("2029-12-31T00:00:00Z")));
        assert!(
            !s.is_paused(at("2030-06-01T00:00:00Z")),
            "an elapsed pause is not a pause"
        );
        assert_eq!(s.status_value()["paused"], false);
    }

    #[test]
    fn a_lapsed_timed_pause_publishes_status_changed() {
        let s = shared();
        handle_request(
            &s,
            &req(
                "pause",
                serde_json::json!({"until": "2030-01-01T00:00:00Z"}),
            ),
        );
        let mut rx = s.events.subscribe();
        assert!(!s.is_paused(at("2030-06-01T00:00:00Z")));
        let ev = rx.try_recv().expect("no status_changed event published");
        assert_eq!(ev.event, EVENT_STATUS_CHANGED);
    }

    #[test]
    fn an_untimed_pause_never_lapses_on_its_own() {
        let s = shared();
        handle_request(&s, &req("pause", serde_json::json!({})));
        assert_eq!(s.status_value()["paused"], true);
    }

    #[test]
    fn an_invalid_until_is_a_param_error() {
        let s = shared();
        let r = handle_request(
            &s,
            &req("pause", serde_json::json!({"until": "not-a-timestamp"})),
        );
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[test]
    fn list_audit_reads_back_what_set_project_mode_appended() {
        let s = shared();
        handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": tmp_project("p"), "mode": "auto_upload"}),
            ),
        );
        let r = handle_request(&s, &req("list_audit", serde_json::json!({})));
        let entries = r.result.unwrap()["entries"].as_array().unwrap().clone();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["action"], "armed-auto-upload");
    }

    #[test]
    fn list_audit_honors_a_limit_and_reports_the_most_recent_entries() {
        // The log is append-by-whole-file-rewrite and otherwise unbounded,
        // same reason list_history caps.
        let s = shared();
        for key in [tmp_project("a"), tmp_project("b"), tmp_project("c")] {
            handle_request(
                &s,
                &req(
                    "set_project_mode",
                    serde_json::json!({"project_key": key, "mode": "auto_upload"}),
                ),
            );
        }
        let r = handle_request(&s, &req("list_audit", serde_json::json!({"limit": 2})));
        let entries = r.result.unwrap()["entries"].as_array().unwrap().clone();
        assert_eq!(entries.len(), 2, "{entries:?}");
        // Newest first: the last-armed project ("c") comes back before "b".
        assert_eq!(entries[0]["project_label"], "c");
        assert_eq!(entries[1]["project_label"], "b");
    }

    #[test]
    fn list_audit_caps_an_oversize_limit_at_one_thousand() {
        let s = shared();
        handle_request(
            &s,
            &req(
                "set_project_mode",
                serde_json::json!({"project_key": tmp_project("p"), "mode": "auto_upload"}),
            ),
        );
        let r = handle_request(
            &s,
            &req("list_audit", serde_json::json!({"limit": 999_999})),
        );
        // Never panics or misbehaves on an absurd limit; still bounded.
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.result.unwrap()["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn consent_change_and_notice_acknowledgement_both_appear_in_list_audit() {
        // Both are at least as consequential as arming auto-upload and were
        // previously silent.
        let s = shared();
        s.store
            .save_config(&crate::config::ContributorConfig {
                inference_receipt_endpoint: None,
                inference_receipt_check_attestation: false,
                schema_version: crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION.to_string(),
                issuer_url: "https://issuer.invalid".to_string(),
                ingest_url: "https://ingest.invalid".to_string(),
                audience: "aud".to_string(),
                tenant_id: "tenant-1".to_string(),
                instance_id: "instance-1".to_string(),
                user_subject: "alice".to_string(),
                device_key_id: "sha256:aa".to_string(),
                consent_scopes: vec!["debugging_evaluation".to_string()],
                pii_filter: None,
                allowed_hosts: None,
                display_handle: None,
                public_bio: None,
                public_since: None,
                witness: None,
            })
            .unwrap();
        handle_request(
            &s,
            &req(
                "set_consent_scopes",
                serde_json::json!({"scopes": ["model_training"]}),
            ),
        );
        handle_request(
            &s,
            &req("acknowledge_near_ai_notice", serde_json::json!({})),
        );

        let r = handle_request(&s, &req("list_audit", serde_json::json!({})));
        let entries = r.result.unwrap()["entries"].as_array().unwrap().clone();
        let actions: Vec<String> = entries
            .iter()
            .map(|e| e["action"].as_str().unwrap().to_string())
            .collect();
        assert!(
            actions.contains(&"consent-scopes-changed".to_string()),
            "{actions:?}"
        );
        assert!(
            actions.contains(&"near-ai-notice-acknowledged".to_string()),
            "{actions:?}"
        );
    }

    #[test]
    fn queue_outcome_counts_counts_reason_labels_already_on_the_queue() {
        let s = shared();
        let id = seed_entry_in_state(&s, QueueState::Pending);
        s.queue.lock().unwrap().set_state(
            id,
            QueueState::Expired,
            Some("expired-without-decision".to_string()),
        );
        let r = handle_request(&s, &req("queue_outcome_counts", serde_json::json!({})));
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.result.unwrap()["reasons"]["expired-without-decision"], 1);
    }

    #[test]
    fn consent_options_is_reachable_over_the_dispatcher() {
        let s = shared();
        let r = handle_request(&s, &req("consent_options", serde_json::json!({})));
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(
            r.result.unwrap()["scopes"].as_array().unwrap().len(),
            crate::consent::VALID_SCOPES.len()
        );
    }

    #[tokio::test]
    async fn handle_local_and_handle_request_async_answer_an_async_method_identically() {
        // Regression guard: an async method must be answered the same way
        // whether it's reached through the socket path
        // (`handle_request_async`) or the CLI path (`handle_local`). This
        // plan already hit the failure mode once, where an async method was
        // wired into only one of the two dispatchers and a CLI caller
        // silently got a degraded answer.
        let s = shared();
        let via_async = handle_request_async(&s, &req("enroll", serde_json::json!({}))).await;
        let via_local = handle_local(&s, "enroll", serde_json::json!({}));
        assert_eq!(
            via_async.result, via_local.result,
            "{via_async:?} vs {via_local:?}"
        );
        assert_eq!(
            via_async.error.map(|e| e.code),
            via_local.error.map(|e| e.code)
        );
    }

    #[tokio::test]
    async fn quiesce_parks_the_queue_when_nothing_is_in_flight() {
        let s = shared();
        let r = handle_request_async(&s, &req("quiesce", serde_json::json!({}))).await;
        let v = r.result.expect("quiesce should succeed with an idle queue");
        assert_eq!(v["quiesced"], true);
        assert!(s.quiesced.load(Ordering::Relaxed), "the flag must be set");
    }

    #[tokio::test]
    async fn quiesce_times_out_rather_than_forcing_its_way_past_an_upload() {
        let s = shared();
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: "/tmp/p".to_string(),
                        project_label: "p".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        state: QueueState::Uploading,
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }
        let r =
            handle_request_async(&s, &req("quiesce", serde_json::json!({"timeout_secs": 1}))).await;
        let err = r.error.expect("an in-flight upload must not be abandoned");
        assert_eq!(err.code, ERR_BUSY);
        assert_eq!(err.message, ERR_QUIESCE_TIMEOUT);
        // A failed quiesce must leave the daemon working: the update stays
        // staged and retries, rather than parking uploads indefinitely.
        assert!(!s.quiesced.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn quiesce_completes_once_the_in_flight_upload_finishes() {
        let s = std::sync::Arc::new(shared());
        let entry_id = uuid::Uuid::new_v4();
        {
            let mut queue = s.queue.lock().unwrap();
            queue
                .upsert(
                    super::super::queue::QueueEntry {
                        entry_id,
                        session_hash: "sha256:seed".to_string(),
                        source: "claude-code".to_string(),
                        project_key: "/tmp/p".to_string(),
                        project_label: "p".to_string(),
                        path: std::path::PathBuf::from("/tmp/seed.jsonl"),
                        size_bytes: 1,
                        discovered_at: Utc::now(),
                        state: QueueState::Uploading,
                        ..Default::default()
                    },
                    500,
                )
                .unwrap();
        }
        let finisher = std::sync::Arc::clone(&s);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let mut queue = finisher.queue.lock().unwrap();
            queue.set_state(entry_id, QueueState::Uploaded, None);
        });
        let r = handle_request_async(&s, &req("quiesce", serde_json::json!({"timeout_secs": 10})))
            .await;
        assert_eq!(r.result.expect("drained")["quiesced"], true);
    }

    #[test]
    fn a_synchronous_quiesce_is_refused_rather_than_answered_wrongly() {
        let s = shared();
        let r = handle_request(&s, &req("quiesce", serde_json::json!({})));
        let err = r.error.unwrap();
        assert_eq!(err.code, ERR_UNAVAILABLE);
        assert_eq!(err.message, "quiesce-requires-async");
    }

    #[test]
    fn synchronous_onboarding_requests_keep_their_existing_refusal_labels() {
        let s = shared();
        for (method, label) in [
            (
                "prepare_admission_session",
                "admission-setup-requires-async",
            ),
            ("near_account_start", "near-signup-requires-async"),
            ("near_ai_account_enroll", "near-signup-requires-async"),
            ("near_account_capabilities", "near-signup-requires-async"),
            ("native_wallet_flow", "near-signup-requires-async"),
            ("witness_preview_request", "witness-review-requires-async"),
        ] {
            let request = req(method, serde_json::Value::Null);
            let response = handle_request(&s, &request);
            assert_eq!(response.id, request.id);
            let error = response.error.expect("synchronous dispatcher must refuse");
            assert_eq!(error.code, ERR_UNAVAILABLE);
            assert_eq!(error.message, label);
        }
    }

    #[test]
    fn every_async_only_method_is_advertised_and_refused_synchronously() {
        let s = shared();
        assert_eq!(ASYNC_ONLY_METHODS.len(), 18);
        let mut seen = std::collections::BTreeSet::new();
        for &(method, label) in ASYNC_ONLY_METHODS {
            assert!(
                METHODS.contains(&method),
                "async-only method must be advertised: {method}"
            );
            assert!(seen.insert(method), "duplicate async-only method: {method}");
            let request = req(method, serde_json::Value::Null);
            let response = handle_request(&s, &request);
            assert_eq!(response.id, request.id);
            assert!(response.result.is_none());
            let error = response.error.expect("synchronous dispatcher must refuse");
            assert_eq!(error.code, ERR_UNAVAILABLE);
            assert_eq!(error.message, label);
        }
    }

    #[tokio::test]
    async fn an_absurd_quiesce_timeout_is_capped_rather_than_honoured() {
        let s = shared();
        let r = handle_request_async(
            &s,
            &req("quiesce", serde_json::json!({"timeout_secs": 999_999})),
        )
        .await;
        // The queue is idle, so this returns immediately; the point is that a
        // caller cannot ask the daemon to park uploads for a week.
        assert_eq!(r.result.expect("idle")["quiesced"], true);
        assert_eq!(
            clamp_quiesce_timeout(Some(999_999)),
            MAX_QUIESCE_TIMEOUT_SECS
        );
        assert_eq!(clamp_quiesce_timeout(None), DEFAULT_QUIESCE_TIMEOUT_SECS);
        assert_eq!(clamp_quiesce_timeout(Some(0)), DEFAULT_QUIESCE_TIMEOUT_SECS);
        assert_eq!(clamp_quiesce_timeout(Some(5)), 5);
    }

    // --- probe_routing -------------------------------------------------

    /// A `probe_routing` request naming `port`, and a token directory when
    /// the test needs the answer to be hermetic.
    ///
    /// Every probe test passes one: with `token_dir` absent the resolution
    /// falls through to `IRONWIRE_HOME` and then `~/.ironwire`, so a test
    /// that omitted it would read whatever the machine running it happens
    /// to have and would pass or fail for reasons that are not about this
    /// code.
    fn probe_request(port: u16, token_dir: Option<&std::path::Path>) -> Request {
        let mut params = serde_json::Map::new();
        params.insert("port".to_string(), serde_json::json!(port));
        if let Some(dir) = token_dir {
            params.insert(
                "token_dir".to_string(),
                serde_json::json!(dir.to_string_lossy()),
            );
        }
        Request {
            id: 7,
            method: "probe_routing".to_string(),
            params: serde_json::Value::Object(params),
        }
    }

    /// A directory holding a `control.token` with this exact content.
    fn token_dir_holding(token: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("control.token"), token).expect("write token");
        dir
    }

    /// Serve `router` on a free loopback port and return the port.
    async fn serve_on_loopback(router: axum::Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        port
    }

    #[tokio::test]
    async fn a_probe_against_a_dead_port_reports_unreachable_with_the_port() {
        // Bind and drop, so the port is real and definitely closed. The
        // token is readable, so nothing but the connection can explain the
        // answer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let dir = token_dir_holding("a-readable-token");
        let response = handle_probe_routing(&probe_request(port, Some(dir.path()))).await;

        let result = response
            .result
            .expect("a probe answers with a result, never an IPC error");
        assert_eq!(result["outcome"], PROBE_UNREACHABLE);
        assert_eq!(
            result["port"],
            serde_json::json!(port),
            "the port that was tried is the actionable fact"
        );
    }

    #[tokio::test]
    async fn a_probe_that_cannot_read_the_token_names_the_path_it_tried() {
        // An empty directory: the resolution succeeds, the read does not.
        // This is the failure a GUI contributor actually hits, and today it
        // is silently identical to "off".
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = dir.path().join("control.token");
        assert!(
            !expected.exists(),
            "the fixture must not accidentally hold a token"
        );

        // A live proxy on the port, so "unreachable" cannot be the answer
        // and the outcome can only be about the token.
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/log",
            axum::routing::get(|| async { r#"{"enabled":true,"exchanges":[]}"# }),
        ))
        .await;

        let response = handle_probe_routing(&probe_request(port, Some(dir.path()))).await;
        let result = response
            .result
            .expect("a probe answers with a result, never an IPC error");
        assert_eq!(result["outcome"], PROBE_TOKEN_UNREADABLE);
        let reported = result["token_path"]
            .as_str()
            .expect("the path that was tried is carried, not merely the failure");
        assert!(
            std::path::Path::new(reported).is_absolute(),
            "a relative path is not something a contributor can act on: {reported}"
        );
        assert_eq!(
            std::path::Path::new(reported),
            expected,
            "the reported path must be the file the reader would actually read"
        );
    }

    #[tokio::test]
    async fn a_probe_never_returns_the_token() {
        // A reachable proxy that accepts the token: the outcome that has
        // most reason to echo it back.
        const SECRET: &str = "c0ntrol-token-that-must-never-be-echoed";
        let dir = token_dir_holding(SECRET);
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/log",
            axum::routing::get(|| async { r#"{"enabled":true,"exchanges":[]}"# }),
        ))
        .await;

        let response = handle_probe_routing(&probe_request(port, Some(dir.path()))).await;
        let wire = serde_json::to_string(&response).expect("a response serializes");
        assert!(
            !wire.contains(SECRET),
            "the token is a credential for an API that can rewrite agent configs: {wire}"
        );
        // Field equality, not a substring of the frame: "unreachable"
        // contains "reachable", so a substring check here would call a
        // failed probe a successful one and quietly stop testing the
        // outcome this test claims to cover.
        assert_eq!(
            response
                .result
                .expect("a result, never an IPC error")
                .get("outcome")
                .and_then(serde_json::Value::as_str),
            Some(PROBE_REACHABLE),
            "the test must have exercised the outcome it claims to: {wire}"
        );
    }

    #[tokio::test]
    async fn a_successful_probe_reports_reachable() {
        const TOKEN: &str = "the-right-token";
        let dir = token_dir_holding(TOKEN);
        // The proxy checks the header, so "reachable" also means the token
        // was accepted rather than merely that something answered.
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/log",
            axum::routing::get(|req: axum::extract::Request| async move {
                let authorized = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    == Some(concat!("Bearer ", "the-right-token"));
                if authorized {
                    axum::response::Response::builder()
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(r#"{"enabled":true,"exchanges":[]}"#))
                        .expect("response builds")
                } else {
                    axum::response::Response::builder()
                        .status(401)
                        .body(axum::body::Body::empty())
                        .expect("response builds")
                }
            }),
        ))
        .await;

        let response = handle_probe_routing(&probe_request(port, Some(dir.path()))).await;
        let result = response
            .result
            .expect("a probe answers with a result, never an IPC error");
        assert_eq!(result["outcome"], PROBE_REACHABLE);
        assert_eq!(
            result.get("token_path"),
            None,
            "nothing about the token belongs in a successful answer"
        );
    }

    /// A proxy that answers but rejects the token is the *likely* GUI
    /// failure: a daemon that never saw `IRONWIRE_HOME` read a stale
    /// `~/.ironwire/control.token` and got a live proxy's 401. The
    /// contributor fixes it by naming the directory, so the answer carries
    /// the path, not the port.
    #[tokio::test]
    async fn a_proxy_that_refuses_the_token_reports_it_unreadable_with_the_path() {
        const STALE: &str = "a-stale-token";
        let dir = token_dir_holding(STALE);
        let expected = dir.path().join("control.token");
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/log",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(401)
                    .body(axum::body::Body::empty())
                    .expect("response builds")
            }),
        ))
        .await;

        let response = handle_probe_routing(&probe_request(port, Some(dir.path()))).await;
        let wire = serde_json::to_string(&response).expect("a response serializes");
        assert!(!wire.contains(STALE), "the refused token is still a token");
        let result = response.result.expect("a result, never an IPC error");
        assert_eq!(result["outcome"], PROBE_TOKEN_UNREADABLE);
        assert_eq!(
            result["token_path"].as_str().map(std::path::Path::new),
            Some(expected.as_path())
        );
    }

    /// An empty `control.token` is unreadable in the only sense that
    /// matters: there is no credential in it to send.
    #[tokio::test]
    async fn an_empty_token_file_is_treated_as_unreadable() {
        let dir = token_dir_holding("   \n");
        let response = handle_probe_routing(&probe_request(9, Some(dir.path()))).await;
        let result = response.result.expect("a result, never an IPC error");
        assert_eq!(result["outcome"], PROBE_TOKEN_UNREADABLE);
        assert_eq!(
            result["token_path"].as_str().map(std::path::Path::new),
            Some(dir.path().join("control.token").as_path())
        );
    }

    #[tokio::test]
    async fn a_probe_without_a_usable_port_is_refused() {
        let dir = token_dir_holding("t");
        for params in [
            serde_json::json!({}),
            serde_json::json!({"port": 0}),
            serde_json::json!({"port": 70000}),
            serde_json::json!({"port": "8463"}),
        ] {
            let req = Request {
                id: 7,
                method: "probe_routing".to_string(),
                params,
            };
            let error = handle_probe_routing(&req)
                .await
                .error
                .expect("a probe with no usable port is refused");
            assert_eq!(error.code, ERR_BAD_PARAMS);
            assert_eq!(error.message, "port-invalid");
        }
        // And a token_dir that is not a string is refused rather than
        // silently falling through to the environment.
        let req = Request {
            id: 7,
            method: "probe_routing".to_string(),
            params: serde_json::json!({"port": 8463, "token_dir": 5}),
        };
        let error = handle_probe_routing(&req)
            .await
            .error
            .expect("a non-string token_dir is refused");
        assert_eq!(error.code, ERR_BAD_PARAMS);
        assert_eq!(error.message, "token-dir-invalid");
        drop(dir);
    }

    /// The probe does network I/O, so the synchronous dispatcher says so
    /// rather than answering something it did not perform -- the same
    /// pattern `quiesce` and `preview_body` follow.
    #[test]
    fn the_sync_dispatcher_refuses_probe_routing_as_async_only() {
        let response = handle_request(&shared(), &probe_request(8463, None));
        let error = response.error.expect("the sync path cannot answer a probe");
        assert_eq!(error.code, ERR_UNAVAILABLE);
        assert_eq!(error.message, "probe-routing-requires-async");
    }

    /// The wiring, not the handler. Without the entry in
    /// `handle_request_async` every test above still passes and the method
    /// is dead on the socket -- the async dispatcher is the only path a
    /// real client's request takes, so it is the one that has to answer.
    #[tokio::test]
    async fn the_async_dispatcher_answers_a_probe_for_real() {
        let dir = tempfile::tempdir().expect("tempdir");
        let response =
            handle_request_async(&shared(), &probe_request(8463, Some(dir.path()))).await;
        assert!(
            response.error.is_none(),
            "the async dispatcher must answer rather than refuse: {:?}",
            response.error
        );
        assert_eq!(
            response
                .result
                .expect("a real answer")
                .get("outcome")
                .and_then(serde_json::Value::as_str),
            Some(PROBE_TOKEN_UNREADABLE),
            "an empty token directory is the outcome a real dispatch must reach"
        );
    }

    /// The constants are what the tests above compare against, so a change
    /// to one of their *values* would move the wire contract and every one
    /// of those tests would still pass. These literals are the ones written
    /// into `docs/contributor-daemon-ipc-v1_1.md`, which is what a shell is
    /// built against.
    #[test]
    fn the_probe_outcome_names_are_the_documented_wire_values() {
        assert_eq!(PROBE_REACHABLE, "reachable");
        assert_eq!(PROBE_TOKEN_UNREADABLE, "token_unreadable");
        assert_eq!(PROBE_UNREACHABLE, "unreachable");
    }

    /// `hello`'s method list and the dispatchers are one contract, checked
    /// here in BOTH directions against this file's own source.
    ///
    /// The expensive direction is an advertised name with no arm: that is a
    /// promise the daemon cannot keep, and a negotiating client would call
    /// it and get `unknown_method`. The other direction is what #777 was --
    /// `near_ai_balance` dispatched and unadvertised, so `hello` denied a
    /// call the daemon answers. Neither is visible by reading either list
    /// alone, which is why this reads the source rather than a second
    /// hand-written list: a hand-written expectation would be a copy of the
    /// array that agrees with it by construction.
    ///
    /// The arm counts are pinned because set equality alone is blind to a
    /// symmetric change. Delete a method from a dispatcher and from
    /// `METHODS` in the same commit and the two sets still agree perfectly;
    /// the counts are what notice that the dispatch surface moved at all.
    /// They are a size check on what this scan sees, not a style check, so
    /// adding an arm moves a count here and `METHODS` together. (A `"name"
    /// =>` split across lines by rustfmt is still found -- the scan skips
    /// whitespace before the arrow -- so that is not what these guard.)
    #[test]
    fn every_advertised_method_is_dispatched_and_the_reverse() {
        /// The body of the first `match req.method.as_str()` after `marker`.
        fn dispatcher_body<'a>(src: &'a str, marker: &str) -> &'a str {
            let from = src.find(marker).expect("the dispatcher is in this file");
            let m = src[from..]
                .find("match req.method.as_str()")
                .expect("the dispatcher matches on the method")
                + from;
            let open = src[m..].find('{').expect("a match body") + m;
            let mut depth = 0usize;
            for (i, c) in src[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return &src[open + 1..open + i];
                        }
                    }
                    _ => {}
                }
            }
            panic!("unbalanced match body");
        }

        /// Every `"name" =>` literal in one match body.
        fn arm_names(body: &str) -> std::collections::BTreeSet<String> {
            let mut out = std::collections::BTreeSet::new();
            let mut i = 0usize;
            while let Some(open) = body[i..].find('"') {
                let open = i + open;
                let Some(close) = body[open + 1..].find('"') else {
                    break;
                };
                let close = open + 1 + close;
                let name = &body[open + 1..close];
                let rest = body[close + 1..].trim_start();
                if rest.starts_with("=>")
                    && !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    out.insert(name.to_string());
                }
                i = close + 1;
            }
            out
        }

        let src = include_str!("ipc.rs");
        let sync = arm_names(dispatcher_body(src, "pub fn handle_request(shared"));
        let asy = arm_names(dispatcher_body(
            src,
            "pub async fn handle_request_async(shared",
        ));
        assert_eq!(sync.len(), 40, "synchronous dispatcher arms: {sync:?}");
        assert_eq!(asy.len(), 25, "asynchronous dispatcher arms: {asy:?}");

        let dispatched: std::collections::BTreeSet<String> = sync.union(&asy).cloned().collect();
        let advertised: std::collections::BTreeSet<String> =
            METHODS.iter().map(|m| (*m).to_string()).collect();
        assert_eq!(
            advertised.len(),
            METHODS.len(),
            "a duplicate member would make hello advertise the same call twice"
        );

        let promised_only: Vec<&String> = advertised.difference(&dispatched).collect();
        assert!(
            promised_only.is_empty(),
            "hello advertises a method no dispatcher answers: {promised_only:?}"
        );
        let dispatched_only: Vec<&String> = dispatched.difference(&advertised).collect();
        assert!(
            dispatched_only.is_empty(),
            "the daemon answers a method hello hides: {dispatched_only:?}"
        );
    }

    /// A shell has to be able to reach all three, and `hello` is where it
    /// finds out they exist.
    #[test]
    fn the_three_harness_methods_are_advertised() {
        for method in ["harness_list", "harness_plan", "harness_commit"] {
            assert!(
                METHODS.contains(&method),
                "a method hello does not advertise is a method no shell will call: {method}"
            );
        }
    }

    /// Deliberately absent: there is no method that plans and commits in one
    /// call. The preview is the safety property, and a convenience call would
    /// be the way around it.
    #[test]
    fn there_is_no_one_call_connect() {
        for method in METHODS {
            assert!(
                !matches!(*method, "harness_connect" | "harness_disconnect"),
                "a one-call write would let a shell skip the preview: {method}"
            );
        }
    }

    /// The list answers on the synchronous dispatcher -- it reads the
    /// filesystem and an in-memory snapshot, and nothing on it awaits.
    #[test]
    fn harness_list_answers_with_the_built_in_tools_and_an_activity_block() {
        let shared = shared();
        let req = Request {
            id: 1,
            method: "harness_list".to_string(),
            params: serde_json::Value::Null,
        };
        let response = handle_request(&shared, &req);
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.expect("a real answer");

        let harnesses = result["harnesses"].as_array().expect("a list");
        let ids: Vec<&str> = harnesses
            .iter()
            .map(|h| h["id"].as_str().expect("an id"))
            .collect();
        assert_eq!(ids, vec!["claude", "codex"]);
        // Every row carries a state, and with no ledger no row may claim a
        // call arrived.
        for row in harnesses {
            let state = row["state"].as_str().expect("a state");
            assert!(
                crate::harness_state::HarnessState::from_label(state).is_some(),
                "a state label no build can read: {state}"
            );
            assert_ne!(state, "answering", "no ledger, no answering");
        }
        // The list says what it is a list OF, so a surface can say so too.
        assert_eq!(result["catalog_present"], serde_json::json!(false));
        // A call can be reported without a tool being named. Here there is
        // no readable ledger, so nothing is claimed at all.
        assert_eq!(result["activity"]["readable"], serde_json::json!(false));
        assert!(result["activity"]["last_call_at"].is_null());
    }

    /// With no ledger, the amount is UNKNOWN and not zero, and the wire says
    /// so in a field a shell cannot mistake for a figure.
    ///
    /// The defect this pins is the one that makes the number worth nothing:
    /// a `spend` block that answered `0` on a machine with no ledger would
    /// tell every contributor without one that they had spent nothing today,
    /// which is a claim nothing supports.
    #[test]
    fn harness_list_reports_an_unknown_amount_rather_than_zero() {
        let shared = shared();
        let req = Request {
            id: 1,
            method: "harness_list".to_string(),
            params: serde_json::Value::Null,
        };
        let result = handle_request(&shared, &req).result.expect("an answer");
        let spend = &result["spend"];
        assert_eq!(spend["known"], serde_json::json!(false));
        assert!(
            spend["micros"].is_null(),
            "an unmeasured amount must not carry a number: {spend}"
        );
    }

    #[test]
    fn harness_plan_refuses_an_unknown_tool_by_name() {
        let shared = shared();
        let req = Request {
            id: 2,
            method: "harness_plan".to_string(),
            params: serde_json::json!({"id": "not-a-tool", "action": "connect"}),
        };
        let error = handle_request(&shared, &req)
            .error
            .expect("an unknown tool has no plan");
        assert_eq!(error.code, ERR_BAD_PARAMS);
        assert_eq!(error.message, crate::daemon::harness::ERR_UNKNOWN_HARNESS);
    }

    #[test]
    fn harness_plan_refuses_an_action_it_does_not_have() {
        let shared = shared();
        let req = Request {
            id: 3,
            method: "harness_plan".to_string(),
            params: serde_json::json!({"id": "claude", "action": "take-over"}),
        };
        let error = handle_request(&shared, &req).error.expect("refused");
        assert_eq!(error.code, ERR_BAD_PARAMS);
        assert_eq!(error.message, "action-invalid");
    }

    /// A commit takes a plan id and nothing else, so an id this daemon does
    /// not hold cannot be turned into a write by supplying the rest.
    #[test]
    fn harness_commit_refuses_a_plan_it_never_minted() {
        let shared = shared();
        let req = Request {
            id: 4,
            method: "harness_commit".to_string(),
            params: serde_json::json!({
                "plan_id": Uuid::new_v4().to_string(),
                "id": "claude",
                "action": "connect",
            }),
        };
        let error = handle_request(&shared, &req).error.expect("refused");
        assert_eq!(error.code, ERR_UNAVAILABLE);
        assert_eq!(error.message, crate::daemon::harness::ERR_PLAN_UNKNOWN);
    }

    #[test]
    fn harness_commit_refuses_a_plan_id_that_is_not_one() {
        let shared = shared();
        let req = Request {
            id: 5,
            method: "harness_commit".to_string(),
            params: serde_json::json!({"plan_id": "the-last-one"}),
        };
        let error = handle_request(&shared, &req).error.expect("refused");
        assert_eq!(error.code, ERR_BAD_PARAMS);
        assert_eq!(error.message, "plan-id-invalid");
    }

    #[test]
    fn probe_routing_is_advertised() {
        assert!(
            METHODS.contains(&"probe_routing"),
            "a method hello does not advertise is a method no shell will call"
        );
    }

    /// A poisoned routing lock reads as no ledger, and never as a panic.
    ///
    /// Before the ledger could be hot-swapped this was a plain `Option`
    /// that could not fail, and the promise made of the submission path --
    /// which reaches `routing_ledger` through `source_roots_with_routing`
    /// -- was that it cannot. Poisoning is near-unreachable, which is
    /// exactly why nothing would have caught the regression.
    #[test]
    fn a_poisoned_routing_lock_costs_a_trace_nothing() {
        let (_dir, store) = temp_store();
        let shared = Arc::new(DaemonShared::load(store).expect("load"));

        let poisoner = Arc::clone(&shared);
        let panicked = std::thread::spawn(move || {
            let _held = poisoner.routing.write().expect("first write succeeds");
            panic!("poison the lock");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread must have panicked");
        assert!(
            shared.routing.read().is_err(),
            "the lock must actually be poisoned, or this proves nothing"
        );

        // Absence is the state every caller already handles, and the state
        // a vanished proxy produces.
        assert!(shared.routing_ledger().is_none());
        // And the submission path's own reader still answers.
        let _roots = shared.source_roots_with_routing();
    }

    // --- probe_routed_tools --------------------------------------------

    /// The same request shape as the probe, against the tool-list method.
    fn routed_tools_request(port: u16, token_dir: Option<&std::path::Path>) -> Request {
        let mut req = probe_request(port, token_dir);
        req.method = "probe_routed_tools".to_string();
        req
    }

    /// The whole point of the method: three tools, three different answers,
    /// from one declaration. A shell rendering one switch as three verdicts
    /// would get two of these wrong.
    #[tokio::test]
    async fn the_tool_list_is_per_tool_and_not_one_switch() {
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/settings",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "tools": [
                        { "id": "claude", "name": "Claude Code", "installed": true, "wired": true },
                        { "id": "codex", "name": "Codex", "installed": true, "wired": false },
                    ]
                }))
            }),
        ))
        .await;
        let dir = token_dir_holding("a-readable-token");

        let response =
            handle_probe_routed_tools(&routed_tools_request(port, Some(dir.path()))).await;
        let result = response.result.expect("an answer, never an IPC error");

        assert_eq!(result["outcome"], PROBE_REACHABLE);
        let tools = result["tools"].as_array().expect("a list");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["id"], "claude");
        assert_eq!(tools[0]["wired"], true);
        assert_eq!(tools[1]["id"], "codex");
        assert_eq!(
            tools[1]["wired"], false,
            "the second tool must be able to differ from the first"
        );
        // Gemini CLI is absent upstream entirely, which is the state a
        // shell has to render as "not known" rather than as a verdict.
        assert!(
            !tools.iter().any(|tool| tool["id"] == "gemini"),
            "nothing may invent a row the proxy did not send"
        );
    }

    /// Neither a path nor a shell command crosses the socket.
    #[tokio::test]
    async fn the_tool_list_carries_no_path_and_no_command() {
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/settings",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "tools": [ {
                        "id": "claude",
                        "config_path": "/home/x/.claude/settings.json",
                        "connect_command": "ironwire connect claude",
                        "installed": true,
                        "wired": true,
                    } ]
                }))
            }),
        ))
        .await;
        let dir = token_dir_holding("a-readable-token");

        let response =
            handle_probe_routed_tools(&routed_tools_request(port, Some(dir.path()))).await;
        let rendered = serde_json::to_string(&response.result.expect("a result")).expect("json");
        for leaked in [
            "config_path",
            "connect_command",
            ".claude",
            "ironwire connect",
        ] {
            assert!(!rendered.contains(leaked), "{leaked} in: {rendered}");
        }
        assert!(!rendered.contains("a-readable-token"), "{rendered}");
    }

    /// A dead port is `unreachable`, with the port, exactly as the probe
    /// reports it. One vocabulary for one connection.
    #[tokio::test]
    async fn a_tool_list_against_a_dead_port_reports_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let dir = token_dir_holding("a-readable-token");

        let response =
            handle_probe_routed_tools(&routed_tools_request(port, Some(dir.path()))).await;
        let result = response.result.expect("a result");
        assert_eq!(result["outcome"], PROBE_UNREACHABLE);
        assert_eq!(result["port"], serde_json::json!(port));
        assert!(result.get("tools").is_none(), "no tools without an answer");
    }

    /// A refused credential is the token state, naming the path, and never
    /// an empty tool list that a shell could read as "nothing is wired".
    #[tokio::test]
    async fn a_refused_credential_is_a_token_answer_and_not_an_empty_list() {
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/settings",
            axum::routing::get(|| async { axum::http::StatusCode::UNAUTHORIZED }),
        ))
        .await;
        let dir = token_dir_holding("a-stale-token");

        let response =
            handle_probe_routed_tools(&routed_tools_request(port, Some(dir.path()))).await;
        let result = response.result.expect("a result");
        assert_eq!(result["outcome"], PROBE_TOKEN_UNREADABLE);
        assert!(
            result["token_path"]
                .as_str()
                .expect("a path")
                .ends_with("control.token"),
            "{result}"
        );
        assert!(result.get("tools").is_none());
    }

    /// An answer that arrives but cannot be read is `reachable` with no
    /// tools: the proxy did answer, so nobody is sent to check a port that
    /// is fine, and no tool gets a verdict off a body nothing parsed.
    #[tokio::test]
    async fn an_unreadable_body_yields_no_tools_rather_than_a_wrong_port() {
        let port = serve_on_loopback(axum::Router::new().route(
            "/_ironwire/settings",
            axum::routing::get(|| async { "this is not the json you are looking for" }),
        ))
        .await;
        let dir = token_dir_holding("a-readable-token");

        let response =
            handle_probe_routed_tools(&routed_tools_request(port, Some(dir.path()))).await;
        let result = response.result.expect("a result");
        assert_eq!(result["outcome"], PROBE_REACHABLE);
        assert_eq!(result["tools"], serde_json::json!([]));
    }

    /// Bounds, on a body written by another process on this machine.
    #[test]
    fn the_tool_list_is_bounded_and_ignores_shapes_it_cannot_read() {
        assert!(routed_tools(b"").is_empty());
        assert!(routed_tools(b"{}").is_empty());
        assert!(routed_tools(br#"{"tools":{}}"#).is_empty());
        // No id, or an empty one, is not a tool.
        assert!(routed_tools(br#"{"tools":[{"wired":true},{"id":"","wired":true}]}"#).is_empty());
        // Missing booleans read as false rather than as a claim.
        let one = routed_tools(br#"{"tools":[{"id":"claude"}]}"#);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0]["installed"], false);
        assert_eq!(one[0]["wired"], false);

        let many: Vec<String> = (0..ROUTED_TOOLS_LIMIT + 40)
            .map(|n| format!(r#"{{"id":"t{n}"}}"#))
            .collect();
        let body = format!(r#"{{"tools":[{}]}}"#, many.join(","));
        assert_eq!(routed_tools(body.as_bytes()).len(), ROUTED_TOOLS_LIMIT);
    }

    /// Advertised, and refused on the synchronous path rather than answered
    /// without asking.
    #[test]
    fn the_tool_list_is_advertised_and_is_async_only() {
        assert!(METHODS.contains(&"probe_routed_tools"), "{METHODS:?}");
        let (_dir, store) = temp_store();
        let shared = DaemonShared::load(store).expect("load");
        let response = handle_request(
            &shared,
            &Request {
                id: 1,
                method: "probe_routed_tools".to_string(),
                params: serde_json::json!({ "port": 8463 }),
            },
        );
        assert_eq!(
            response.error.expect("the sync path refuses").code,
            ERR_UNAVAILABLE
        );
    }

    // --- discover_routing ----------------------------------------------

    fn discover_request() -> Request {
        Request {
            id: 11,
            method: "discover_routing".to_string(),
            params: serde_json::Value::Null,
        }
    }

    /// A pointer on disk naming a token file that holds `token`. Returns the
    /// tempdir, which must outlive the assertions.
    fn pointer_dir(port: u16, token: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("control.token");
        std::fs::write(&token_path, token).expect("write token");
        // Built with serde, not by interpolation: a Windows temp path is
        // full of backslashes, which are invalid JSON escapes, so a
        // hand-formatted document parses on Unix and fails on Windows --
        // and the failure looks exactly like "no proxy is running".
        std::fs::write(
            dir.path().join("endpoint.json"),
            serde_json::to_string(&serde_json::json!({
                "control_url": format!("http://127.0.0.1:{port}"),
                "token_path": token_path,
            }))
            .expect("pointer serialises"),
        )
        .expect("write pointer");
        dir
    }

    #[test]
    fn discovery_reports_what_a_running_proxy_published() {
        let dir = pointer_dir(9143, "a-secret-token");
        // `IronWireAt::pointer` pins the token directory to the pointer's
        // own directory, which is where this fixture's token is. A
        // `token_path` outside it is refused, so a test that did not pin it
        // would be asserting the refusal rather than the discovery.
        let _at = super::super::ironwire_pointer::test_support::IronWireAt::pointer(
            &dir.path().join("endpoint.json"),
        );

        let result = handle_discover_routing(&discover_request())
            .result
            .expect("discovery answers with a result, never an IPC error");

        assert_eq!(result["found"], serde_json::json!(true));
        assert_eq!(result["port"], serde_json::json!(9143));
        // Canonicalized, because the confinement compares resolved paths and
        // returns the resolved one -- on macOS a temp dir under `/var` is a
        // symlink to `/private/var`.
        assert_eq!(
            result["token_path"],
            serde_json::json!(
                std::fs::canonicalize(dir.path().join("control.token"))
                    .expect("token canonicalises")
                    .to_string_lossy()
            ),
        );
    }

    /// The rule the whole feature hangs on. A machine without IronWire is
    /// the ordinary case, and it must answer -- not error -- so the app can
    /// fall back to asking.
    #[test]
    fn no_pointer_is_answered_as_not_found_rather_than_as_an_error() {
        let _none = super::super::ironwire_pointer::test_support::IronWireAt::none();

        let response = handle_discover_routing(&discover_request());

        assert!(
            response.error.is_none(),
            "a machine without IronWire is not an error: {:?}",
            response.error
        );
        let result = response.result.expect("a real answer");
        assert_eq!(result["found"], serde_json::json!(false));
        assert!(
            result.get("port").is_none(),
            "there is no port to report, and reporting one would be invented"
        );
    }

    /// The pointer names a token path; the answer must carry the path and
    /// never the credential at it. This answer crosses a socket to a shell.
    #[test]
    fn discovery_never_carries_the_token() {
        let dir = pointer_dir(9143, "a-secret-token");
        let _at = super::super::ironwire_pointer::test_support::IronWireAt::pointer(
            &dir.path().join("endpoint.json"),
        );

        let response = handle_discover_routing(&discover_request());
        let wire = serde_json::to_string(&response.result.expect("a result")).unwrap();

        assert!(
            !wire.contains("a-secret-token"),
            "the token must not appear anywhere in the answer: {wire}"
        );
    }

    /// Answered by the synchronous dispatcher, which is the path a shell's
    /// request actually takes for a method that opens no connection.
    #[test]
    fn the_sync_dispatcher_answers_discovery_for_real() {
        let _none = super::super::ironwire_pointer::test_support::IronWireAt::none();

        let response = handle_request(&shared(), &discover_request());

        assert!(
            response.error.is_none(),
            "discovery must answer on the sync path: {:?}",
            response.error
        );
        assert_eq!(response.result.expect("a result")["found"], false);
    }

    #[test]
    fn discover_routing_is_advertised() {
        assert!(
            METHODS.contains(&"discover_routing"),
            "a method hello does not advertise is a method no shell will call"
        );
    }

    // --- hot swap and the routing status block -------------------------

    /// A declared proxy whose `control.token` is readable, so
    /// `ironwire_ledger_for` actually builds a ledger. Returns the
    /// directory, which must outlive the assertions.
    fn declared_token_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(super::super::settings::IRONWIRE_TOKEN_FILE),
            "tok\n",
        )
        .unwrap();
        dir
    }

    fn watch_params(port: u16, dir: &std::path::Path) -> serde_json::Value {
        serde_json::json!({
            "ironwire": {
                "mode": "watch",
                "port": port,
                "token_dir": dir.to_string_lossy(),
            }
        })
    }

    /// The point of the hot swap: a contributor who declares the proxy in
    /// the app must get enrichment on the next poll, not after a restart.
    /// Nothing here reloads `DaemonShared`.
    #[test]
    fn a_declaration_change_takes_effect_without_a_restart() {
        let dir = declared_token_dir();
        let s = shared();
        assert!(
            !s.source_roots_with_routing().is_routed(),
            "nothing declared yet, so the roots start bare"
        );

        let r = handle_request(&s, &req("set_settings", watch_params(8463, dir.path())));
        assert!(r.error.is_none(), "{:?}", r.error);

        assert!(
            s.source_roots_with_routing().is_routed(),
            "the declaration must take effect on this same daemon instance"
        );
        assert!(
            s.routing_ledger().is_some(),
            "the rebuilt instance is the one the daemon holds"
        );
    }

    /// `null` means off, and off must actually stop reading.
    #[test]
    fn clearing_the_declaration_drops_the_ledger() {
        let dir = declared_token_dir();
        let s = shared();
        let r = handle_request(&s, &req("set_settings", watch_params(8463, dir.path())));
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(s.routing_ledger().is_some(), "declared, so a ledger exists");

        let r = handle_request(
            &s,
            &req("set_settings", serde_json::json!({"ironwire": null})),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(
            s.routing_ledger().is_none(),
            "off must drop the instance, not just the declaration"
        );
        assert!(
            !s.source_roots_with_routing().is_routed(),
            "a dropped ledger must stop reaching the loaded transcript"
        );
    }

    /// A settings write that does not touch the declaration must not throw
    /// away a warm snapshot. Rebuilding on every `set_settings` would blank
    /// the overlay whenever a contributor moved an unrelated slider.
    #[test]
    fn an_unrelated_settings_change_keeps_the_same_ledger() {
        let dir = declared_token_dir();
        let s = shared();
        handle_request(&s, &req("set_settings", watch_params(8463, dir.path())));
        let before = s.routing_ledger().expect("declared");

        let r = handle_request(
            &s,
            &req(
                "set_settings",
                serde_json::json!({"max_uploads_per_day": 7}),
            ),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        let after = s.routing_ledger().expect("still declared");
        assert!(
            Arc::ptr_eq(&before, &after),
            "an unrelated edit must leave the live instance alone"
        );
    }

    /// Cold start is not an error state and must not be reported as one.
    #[test]
    fn a_rebuilt_ledger_reports_declared_but_nothing_seen() {
        let dir = declared_token_dir();
        let s = shared();
        handle_request(&s, &req("set_settings", watch_params(8463, dir.path())));

        let routing = s.status_value()["routing"].clone();
        assert_eq!(
            routing["state"], ROUTING_AWAITING_ROWS,
            "a freshly rebuilt ledger is declared, not broken: {routing}"
        );
        assert_eq!(
            routing["last_refresh_at"],
            serde_json::Value::Null,
            "nothing has refreshed yet"
        );
    }

    /// The state neither `has_rows()` nor the held ledger can express.
    ///
    /// This is the ordinary shape of a declared-but-not-running proxy: the
    /// switch is on, the settings file says `watch`, and the token file the
    /// reader needs is not there -- so `ironwire_ledger_for` builds nothing
    /// and the daemon holds no ledger, exactly as it does for a contributor
    /// who declared nothing at all. Reporting `not_declared` for it printed
    /// "Off" under a switch the contributor could see was on.
    #[test]
    fn a_declared_proxy_whose_token_cannot_be_read_is_not_reported_as_undeclared() {
        // A directory with no `control.token` in it, which is what a
        // stopped proxy leaves behind.
        let dir = tempfile::tempdir().unwrap();
        let s = shared();
        let r = handle_request(&s, &req("set_settings", watch_params(8463, dir.path())));
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(
            s.routing_ledger().is_none(),
            "no token file means no reader -- the premise of this test"
        );

        let routing = s.status_value()["routing"].clone();
        assert_eq!(
            routing["state"], ROUTING_TOKEN_UNREADABLE,
            "the declaration is on; the status must not say otherwise: {routing}"
        );
        assert_ne!(routing["state"], ROUTING_NOT_DECLARED, "{routing}");
        assert_eq!(
            routing["last_refresh_at"],
            serde_json::Value::Null,
            "nothing was built, so nothing was ever checked"
        );

        // And the words a shell renders from it: neither "off" nor an
        // all-clear.
        use crate::routing_copy::{
            IRONWIRE_STATE_OFF, StateTone, ironwire_state_line, ironwire_state_tone,
        };
        let state = routing["state"].as_str().expect("a state string");
        assert_ne!(ironwire_state_line(state), IRONWIRE_STATE_OFF);
        assert_eq!(ironwire_state_tone(state), StateTone::Attention);
    }

    /// The state `has_rows()` alone cannot express.
    #[test]
    fn status_reports_not_declared_when_no_proxy_is_declared() {
        let s = shared();
        let routing = s.status_value()["routing"].clone();
        assert_eq!(routing["state"], ROUTING_NOT_DECLARED, "{routing}");
        assert_eq!(routing["last_refresh_at"], serde_json::Value::Null);
    }

    /// The third state, and the one that proves `last_refresh_at` reports a
    /// refresh that actually reached the proxy rather than one that was
    /// merely attempted.
    #[tokio::test]
    async fn status_reports_rows_seen_after_a_refresh_that_reached_the_proxy() {
        let router = axum::Router::new().route(
            "/_ironwire/log",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "exchanges": [{
                        "started_at": "2026-08-08T10:05:00Z",
                        "client_session_id": "sess-1",
                        "facade": "anthropic",
                        "backend": "claude-sub",
                        "rung": "same_model",
                        "attempts": 1,
                        "status": 200
                    }]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let dir = declared_token_dir();
        let s = shared();
        handle_request(&s, &req("set_settings", watch_params(port, dir.path())));
        assert_eq!(
            s.status_value()["routing"]["state"],
            ROUTING_AWAITING_ROWS,
            "declared but not yet refreshed"
        );

        s.refresh_routing().await;

        let routing = s.status_value()["routing"].clone();
        assert_eq!(routing["state"], ROUTING_ROWS_SEEN, "{routing}");
        assert!(
            routing["last_refresh_at"].as_str().is_some(),
            "a refresh that reached the proxy stamps a time: {routing}"
        );
    }

    /// An unreachable proxy leaves `last_refresh_at` null: the timestamp
    /// exists so a contributor can tell "the proxy answered and had nothing"
    /// from "the proxy has not answered at all", and stamping it on a failed
    /// attempt would erase that difference.
    #[tokio::test]
    async fn an_unreachable_proxy_stamps_no_refresh_time() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let dir = declared_token_dir();
        let s = shared();
        handle_request(&s, &req("set_settings", watch_params(port, dir.path())));
        s.refresh_routing().await;

        let routing = s.status_value()["routing"].clone();
        assert_eq!(routing["state"], ROUTING_AWAITING_ROWS, "{routing}");
        assert_eq!(
            routing["last_refresh_at"],
            serde_json::Value::Null,
            "an attempt that never reached the proxy is not a refresh"
        );
    }

    /// The whole point of the block is that a shell reads it off the socket.
    /// Unit-testing `status_value` alone would not catch a `status` method
    /// that never returns it -- the failure mode this plan already hit once
    /// with async dispatch.
    #[tokio::test]
    async fn the_routing_block_reaches_a_shell_through_the_real_dispatcher() {
        let dir = declared_token_dir();
        let s = shared();

        let response = handle_request_async(&s, &req("status", serde_json::json!({}))).await;
        let result = response.result.expect("status answers");
        assert_eq!(
            result["routing"]["state"], ROUTING_NOT_DECLARED,
            "{result:?}"
        );

        let response =
            handle_request_async(&s, &req("set_settings", watch_params(8463, dir.path()))).await;
        assert!(response.error.is_none(), "{:?}", response.error);

        let response = handle_request_async(&s, &req("status", serde_json::json!({}))).await;
        let result = response.result.expect("status answers");
        assert_eq!(
            result["routing"]["state"], ROUTING_AWAITING_ROWS,
            "the hot swap must be visible over the socket: {result:?}"
        );
    }

    /// The state names are what every assertion above compares against, so a
    /// change to one of their *values* would move the wire contract with
    /// every one of those tests still green. These literals are the ones
    /// written into `docs/contributor-daemon-ipc-v1_1.md`.
    ///
    /// They are also deliberately chosen so that none is a substring of
    /// another: a shell (or a test) that reached for `contains` rather than
    /// equality would still be answering the right question.
    #[test]
    fn the_routing_state_names_are_the_documented_wire_values() {
        assert_eq!(ROUTING_NOT_DECLARED, "not_declared");
        assert_eq!(ROUTING_AWAITING_ROWS, "awaiting_rows");
        assert_eq!(ROUTING_ROWS_SEEN, "rows_seen");
        assert_eq!(ROUTING_TOKEN_UNREADABLE, "token_unreadable");
        for (a, b) in [
            (ROUTING_NOT_DECLARED, ROUTING_TOKEN_UNREADABLE),
            (ROUTING_AWAITING_ROWS, ROUTING_TOKEN_UNREADABLE),
            (ROUTING_ROWS_SEEN, ROUTING_TOKEN_UNREADABLE),
            (ROUTING_NOT_DECLARED, ROUTING_AWAITING_ROWS),
            (ROUTING_AWAITING_ROWS, ROUTING_ROWS_SEEN),
            (ROUTING_ROWS_SEEN, ROUTING_NOT_DECLARED),
        ] {
            assert!(!a.contains(b) && !b.contains(a), "{a} and {b} overlap");
        }
    }
}
