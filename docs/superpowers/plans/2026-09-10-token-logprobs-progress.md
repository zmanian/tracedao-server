# Token distribution implementation status

The implementation is in Trace Commons PR #866 and nearai/ironwire PR #57.
The contributor, both lockfiles, and generated Flatpak sources pin Ironwire
`d622d11417f1e70f3eada0877673e3866ba5f31f`. Registry packages and the Ironclaw
revision are unchanged. No dependency packages were added.

The [accepted plan](2026-09-10-token-logprobs-lifecycle.md) remains the reference.
The supported initial profile is one verified final Chat Completions exchange,
JSON or complete SSE. Responses API, tools, reasoning, incomplete streams and
unqualified backend/model pairs remain unavailable.

## Changes following the development audit

| Audit area | Implemented behavior | Regression evidence |
| --- | --- | --- |
| Cleanup fairness | Independent renewal/release batches, persisted per-intent backoff, confirmed expiry and renewal failure status | Journal restart/fairness and expiry tests |
| Capture discovery and limits | Exact digest lookup across the full session, ambiguity refusal, separate session/global byte budgets | More than 128 retained turns; one busy session cannot fill global capacity |
| Windows private storage | Protected current-user ACLs on hosted state and spool metadata; raw files inherit protected directory permissions; reparse paths refused | Native Windows ACL inspection, second local account denied, junction and sharing failures, canonical host paths |
| Retention holds | Parent policy checked while holding the lifecycle lock before token object deletion; reads revoked immediately | Held ciphertext remains readable to storage test, later deletion succeeds; API reports retained/held/pending/completed |
| Failed/canceled reviews | Durable intent immediately after acquisition; OS lock protects a live review; guards abandon failures during preview and queue publication; discard invalidates in-flight results | Cancellation/restart and failed-pin journal tests |
| Revision processing | Commit atomically publishes a revision-scoped processing intent; bounded worker produces summaries with retry backoff | PostgreSQL first processing/replay and HTTP lost-response recovery |
| Restricted consumption | Owner and separately gated researcher query/download routes; filters for model, semantics, evidence, K, coverage and tokenizer availability; versioned chosen-token surprise summaries | Tenant/owner isolation, filtered query, idempotent processing, withdrawal and restored-child exclusion |
| Client lifecycle controls | Shared Rust copy and IPC for capture override, remove submitted local copies, discard reviews, renewal/expiry status and token-aware withdrawal results | macOS, GTK, Windows interop and Rust contracts; CLI `daemon token-storage` |
| Provenance and absence | Requested K, provider-reported model, signed response coverage, sampling metadata, distinct omission reasons; durable bounded capture-absence counters | Signed witness/parser tests and classifier budget-boundary test |
| Fault/performance harness | Real ingest HTTP and encrypted PostgreSQL storage joined to client signed approval/receipt journal; lost finalize response and restart; synthetic stream timing/process sampler | `token_bundle_http_journey`, `token_bundle_pg`, `scripts/token-distributions/test_qualify.py` |

## Processing and privacy boundaries

The ordinary transcript admission path may finish before bundle commit. Token
attachments are not available to restricted consumers until the revision commits;
summary discovery additionally requires processing to finish. Retry returns the
same durable receipt. The HTTP fixture verifies unchanged parent score/credit
across receipt recovery. Processing keys are tenant/submission/revision and do
not insert a second vector or reevaluate credit. Existing text indexing retains
its ordinary submission identity. Configure the existing retention maintenance
scheduler to drain pending processing and deletion after restart; foreground
bundle requests also run a bounded recovery pass.

The outbox stores no token strings or probability arrays. Summary records include
counts, coverage, provenance and finite chosen-token mean surprisal under
`chosen-surprisal-v1`; omitted positions are never treated as observed tokens.
No token-based credit model or broad/public token export is enabled.

Research access additionally requires `TRACE_COMMONS_TOKEN_RESEARCH_EXPORTS`, an
exporter role, tenant grant, current evaluation consent, low residual risk,
retention eligibility and the ordinary export ABAC policy. Downloads register
export lineage and recheck state, policy and event bytes after object I/O.
Research downloads include the exact attachment and manifest bytes as base64,
the manifest certificate/signature, corresponding sanitized event text and
processing summary. Owner downloads retain their exact attachment-byte response.
Parent tombstones and withdrawal records override restored child state. Object
retention holds prevent erasure, not revocation of access.

Capture, sending inference bodies to the pinned witness, and contributing token
data are three separate choices. The hosted capture override enables only
explicitly configured qualified targets; it does not invent provider support.
External proxies keep their own configuration. Local removal preserves original
agent files and server contributions. Discard requires confirmation and refuses
approved/uploading reviews until approval is undone. Local status caching avoids
repeatedly decoding large payloads during settings polling.

## Running the integration and measurement fixtures

The joined fixture uses a synthetic provider response and a cryptographic witness
signer fixture. Actual provider-receipt verification and witness redaction are
covered separately by the signed witness service tests. It is not live provider
or deployed witness evidence.

```sh
TRACE_COMMONS_BUNDLE_SERVER_ID=journey-server \
TRACE_COMMONS_PG_TEST_DATABASE_URL=postgres://... \
RUSTFLAGS='-D warnings' cargo test --locked -p trace-commons-server \
  --bin trace-commons-ingest token_bundle_http_journey -- --nocapture

TRACE_COMMONS_PG_TEST_DATABASE_URL=postgres://... \
RUSTFLAGS='-D warnings' cargo test --locked -p trace-commons-server \
  --test token_bundle_pg

python3 -m unittest discover -s scripts/token-distributions
python3 scripts/token-distributions/qualify.py \
  --endpoint http://127.0.0.1:PORT/openai/v1/chat/completions \
  --backend BACKEND --model MODEL --matrix --repeats 3 \
  --process-pid PROXY_PID --output qualification.json
```

The probe requires the named token environment variable. It writes metadata only:
response byte counts, total latency, time to first content chunk, content-chunk
intervals and optional local-process CPU/RSS samples. Chunk intervals are not
invented per-token arrival times when a provider batches tokens. The matrix covers
baseline, chosen-only, K=5 and K=20, for JSON and SSE. The HTTP fixture emits
approval/upload-recovery/cleanup durations, attempts and cleanup backlog.

## Remaining rollout gates

- Qualify actual provider/model probability semantics, signed response coverage,
  useful alternative retention and witness work/latency on representative data.
- Measure a bounded pilot, including proxy and witness resource usage, upload
  retries, cleanup backlog and cross-platform UI behavior.
- Verify deployed object version/soft-delete behavior and backup retention. The
  local tombstone fixture does not certify a cloud provider or restored fleet.
- Merge upstream, confirm the downstream dependency revision, and perform the
  witness measurement/pin deployment before enabling capture or research exports.

These are explicit rollout gates. The changes are review candidates, not a claim
that live provider support, deployment or erasure from distributed copies has
been established.
