# Token distribution bundles (implementation preview)

This feature is disabled by default and is not qualified for production. The explicit desktop review path is connected. Live provider qualification and the production pilot remain pending. Do not enable it merely because its unit tests pass.

The current implementation accepts one attested Chat Completions response per bundle. It preserves provider token bytes, chosen-token probabilities and screened alternatives without renormalization. Full-vocabulary logits, Responses API, tools, reasoning and incomplete streams are unavailable. Actual deterministic and classifier edits are composed in private byte maps. Unchanged positions survive when their mapping is exact; missing or oversized provenance drops the segment. Alternatives are screened in sanitized context, with removed secret fragments and uncertain candidates omitted. Retained distributions are restricted research data, not anonymous data.

## Independent controls

Ironwire's `capture.token_capture` configuration has an empty target list by default. Enabling it requires ordinary capture to be enabled and explicit backend/model targets. The initial limits are top-20 alternatives, 512 MiB capture storage and three-day unleased retention. Leases may be renewed but never beyond seven days from capture. A full spool refuses new captures and keeps active leases.

The server additionally requires `TRACE_COMMONS_BUNDLE_SERVER_ID`, service-owned encrypted object storage, PostgreSQL bundle support, and an explicit allowlist entry for witness policy `token-distribution-restricted-v1`. The witness requires configured provider admission trust and a classifier-backed redaction pipeline. Deploying a changed witness requires the existing measurement/pin rollout; this implementation does not update deployment pins.

## API and durability

- `GET /v1/token-bundles`: authenticated version/policy/destination capability discovery.
- `POST /v1/token-bundles`: witness-signed canonical manifest; starts a 24-hour staging revision.
- `PUT /v1/token-bundles/{submission}/{revision}/{artifact}`: exact attachment bytes. The reserved `envelope` object is the exact certified envelope.
- `POST /v1/token-bundles/{submission}/{revision}`: exact envelope and its witness/admission headers; runs ordinary admission and verifies all stored artifacts before committing a receipt.
- `GET /v1/token-bundles/{submission}/{revision}`: authenticated owner status and receipt.
- `GET /v1/token-bundles/{submission}/{revision}/{artifact}`: owner-only token attachment read; verifies current sanitized-event correspondence, refuses revoked/expired/stale bundles, and sends `Cache-Control: no-store`.

The manifest binds envelope, consent, event and attachment digests. PostgreSQL temporarily stores encrypted publication packets so retries publish identical ciphertext after a crash. It clears those packets after object readback succeeds. Finalization requires a persisted parent submission and all ready objects. New revisions cannot overwrite an existing manifest. Committed research attachments have a 30-day retention interval in this initial implementation.

Client cleanup requires an authenticated receipt matching the configured server, tenant, account, submission, revision and manifest. The client writes and syncs its receipt journal before releasing its own immutable Ironwire lease. A background task retries cleanup at startup and every five minutes. Discarded reviews release their own lease, and unapproved review payloads expire after three days. Approved queue entries renew their leases in bounded batches and retain review bytes for at most seven days. Expiration is recorded as abandonment, not successful submission. Local approval and bundle stores share a locked 256 MiB budget. Logout clears token review state; remaining capture leases retain their independent bounded expiry. It never deletes original agent session files. Missing or incompatible peers leave cleanup pending.

Withdrawal blocks bundle access through the parent revocation trigger. Existing withdrawal and retention maintenance retry object deletion under the same database locks used for publication. These locks and provider delete calls are not proof that cloud object versions, backups or external copies are erased. Qualify actual backend timeout/versioning semantics, backup restoration and concurrent publication/deletion before production cleanup receipts are enabled.

Raw alternatives are absent from normal transcript/vector APIs. Owner-scoped downloads record an export manifest and source item in the existing export lineage tables before returning bytes; response headers identify the export and bundle digest. Ordinary corpus exports do not include attachments. Broader researcher access remains disabled.

## Client setup and qualification

Capture and contribution are separate. Configure Ironwire only after qualifying
an exact backend/model pair. For example, in its configuration:

```toml
[capture]
enabled = true

[capture.token_capture]
top_k = 20
max_bytes = 536870912
retain_seconds = 259200

[[capture.token_capture.targets]]
backend = "YOUR_QUALIFIED_BACKEND"
model = "YOUR_QUALIFIED_MODEL"
```

Restart Ironwire after editing its configuration. On macOS, Windows or Linux,
the witness settings contain a separate **Include token probabilities** action
with disclosure. CLI users can set the same permission:

```sh
trace-commons-contributor daemon settings --set token_distributions_contribution=true
```

Captured inference-body permission is also required. Explicit witness review
negotiates server capability before sending raw data, acquires an exact matching
capture snapshot, and shows included/removed token and alternative counts.
Approval pins the original certificate, manifest and payload; retries never
re-run the witness. Revoke the permission to require a new compatible review.

The synthetic qualification tool sends only the fixed prompt “Reply exactly:
blue sky.” It compares baseline, JSON logprobs and SSE logprobs, retaining only
metadata and elapsed times:

```sh
python3 scripts/token-distributions/qualify.py \
  --endpoint https://YOUR_PROVIDER/v1/chat/completions \
  --backend YOUR_BACKEND --model YOUR_MODEL --output qualification.json
```

Read the provider key from `TOKEN_PROBE_API_KEY` (or `--token-env`), never a
command-line token. No fixture run establishes serving semantics, model
revision, provider attestation, production storage erasure, or sustained
performance. Record those separately before populating qualified targets.
