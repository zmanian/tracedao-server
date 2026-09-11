//! The redacted envelope a contributor was actually shown, kept on disk so
//! the upload can send exactly those bytes.
//!
//! An earlier design pinned a *digest* of the previewed envelope on the
//! queue entry and re-derived it immediately before the upload, refusing if
//! the two disagreed. That guard was correct and it broke the feature under
//! the configuration the pilot actually runs. With `pii_filter =
//! "near-ai"` the redaction step is an LLM-backed service, and an LLM does
//! not return identical spans for identical text: preview pins D1, the
//! upload rebuilds and gets D2, the entry is refused and re-offered with
//! the pin cleared, the next preview pins D3 which will not reproduce
//! either. Nothing unsafe ships -- it fails closed -- but the primary
//! consent path never completes. Every test used the deterministic local
//! redactor, so nothing caught it.
//!
//! So the divergence class is eliminated rather than detected: the envelope
//! a preview built is written here, and the upload sends precisely those
//! bytes instead of building a second envelope and comparing. "What you saw
//! is what was sent" stops being an equality check and becomes literally
//! true.
//!
//! One bounded exception. The uploader stamps the contributor's verdict onto
//! `outcome.task_success` after loading and digest-checking these bytes, so
//! the envelope sent differs from the envelope stored by exactly that field.
//! The verdict is collected at approval time, after the preview was rendered,
//! and it is an output of the approval rather than an input that existed when
//! the preview was built. The digest pin therefore describes the previewed
//! bytes; it is not a claim about the final wire bytes. See
//! `envelope::apply_verdict`.
//!
//! **These files are redacted trace content at rest.** That is the same
//! deliberate, bounded exemption `preview` already carries (see the
//! `preview` module doc and the IPC contract's "The preview exemption"):
//! post-redaction content only, only for an entry the contributor asked
//! about, and never onward into a log line, an audit entry, a history
//! record, notification text, a receipt, or an IPC response. The bounds
//! this file adds are:
//!
//! * **Same protection as the device key.** The files live in the 0700
//!   state directory, are written 0600 through the same atomic temp-then
//!   -rename path as every other daemon file, and are removed by
//!   `ConfigStore::wipe` on logout.
//! * **Bounded in bytes, not just in count.** One file per pinned entry,
//!   local envelopes at most `MAX_ENVELOPE_BYTES`, certified records at
//!   most twice that for base64 and certificate overhead. Live entries are
//!   capped by `max_queue_entries`, but their product is too large to be
//!   the practical disk bound. `MAX_STORE_BYTES` is the real
//!   ceiling, and `release_stale_pins` holds the store under it by
//!   releasing the oldest pending previews.
//! * **Kept only while somebody is waiting on it.** The at-rest exemption
//!   is for "an entry the contributor asked about", and a preview nobody
//!   acted on stops being that. `release_stale_pins` drops the pin on a
//!   `Pending` entry whose stored envelope is older than `PIN_MAX_AGE`;
//!   opening the entry again rebuilds and re-pins it. An `Approved` or
//!   `Uploading` entry is never released this way -- its bytes are the
//!   bytes the upload will send.
//! * **Deleted as soon as it is not needed.** `sweep` removes every stored
//!   envelope whose entry has reached a terminal state or has lost its pin
//!   -- to a revoked approval, an undone one, or a released one -- and runs
//!   after every upload pass and every watcher tick.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use crate::witness::inference_record::InferenceAttestationRecord;
use crate::witness::transport::{WitnessedEnvelope, parse_witnessed_envelope, verify_certificate};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::{ConfigStore, DAEMON_APPROVED_ENVELOPE_PREFIX};
use crate::daemon::queue::{Queue, QueueEntry, QueueState};
use crate::envelope::MAX_ENVELOPE_BYTES;
use trace_commons_protocol::trace_contribution::TraceContributionEnvelope;

/// How long a `Pending` entry's stored envelope is kept before its pin is
/// released.
///
/// Shorter than `queue_ttl_days` (14) on purpose. The entry itself is a
/// standing offer and can sit for a fortnight harmlessly; the file behind
/// it is redacted trace content at rest, and three days after a preview the
/// contributor did not act on it is no longer "an entry the contributor
/// asked about". The cost of being wrong is one rebuilt preview when they
/// do open it.
pub const PIN_MAX_AGE: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// The ceiling on the whole store, over every entry at once.
///
/// Per-file bounds and `max_queue_entries` bound how much can be live,
/// but their product is much larger than this aggregate ceiling. This is the number that
/// actually decides how much redacted trace content a contributor's disk
/// can be holding, so it is stated rather than inferred.
pub const MAX_STORE_BYTES: u64 = 256 * 1024 * 1024;

/// Stored envelopes are named `daemon-approved-envelope-{entry_id}.json`.
/// The variable part is a `Uuid` rendered by `Display`, so it can never
/// contain a path separator and the name can never escape the state
/// directory. The prefix is shared with `ConfigStore::wipe`, which sweeps
/// these on logout.
const FILE_PREFIX: &str = DAEMON_APPROVED_ENVELOPE_PREFIX;
const FILE_SUFFIX: &str = ".json";

pub fn file_name(entry_id: Uuid) -> String {
    format!("{FILE_PREFIX}{entry_id}{FILE_SUFFIX}")
}

/// Whether `name` is one of this module's files, and for which entry.
/// Returns `None` for anything else in the state directory, so a sweep can
/// never remove a file it does not own.
pub fn entry_id_of(name: &str) -> Option<Uuid> {
    name.strip_prefix(FILE_PREFIX)?
        .strip_suffix(FILE_SUFFIX)?
        .parse()
        .ok()
}

/// Versioned, single-write record for an explicitly requested witnessed review.
/// No token, raw session, attached inference body, or correction text is stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReviewArtifact {
    review_schema: String,
    source_hash: String,
    input_fingerprint: String,
    verdict: Option<String>,
    correction_hash: Option<String>,
    response: WitnessedEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_bundle: Option<crate::token_bundle::TokenBundleReview>,
    /// Whether the witness was handed a receipt with the bodies it certified.
    /// See `witness::inference_record`. `None` on a review written before
    /// the record existed, and that reads as unknown -- `default` rather
    /// than required, and never serialized when absent, so the pin digest
    /// of every review a contributor already approved is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attested_inference: Option<InferenceAttestationRecord>,
}

const WITNESS_REVIEW_SCHEMA: &str = "trace_commons.witness_review.v1";

/// What marks a queue pin as covering a witnessed preview rather than an
/// ordinary one.
///
/// Produced by [`WitnessReviewArtifact::digest`] and read by
/// [`crate::daemon::queue::QueueEntry::holds_witness_certificate`]. It was
/// spelled as a literal in seven places, which is one definition and six
/// chances to disagree with it.
///
/// An ordinary preview pin is `sha256:`, which does not start with this, so
/// the two are distinguishable in either direction.
pub const WITNESS_PIN_PREFIX: &str = "witness-sha256:";
const MAX_STORED_ARTIFACT_BYTES: usize = MAX_ENVELOPE_BYTES * 2;

impl WitnessReviewArtifact {
    pub(crate) fn new(
        response: WitnessedEnvelope,
        source_hash: String,
        input_fingerprint: String,
        verdict: Option<&str>,
        correction: Option<&str>,
        attested_inference: Option<InferenceAttestationRecord>,
    ) -> Self {
        Self {
            review_schema: WITNESS_REVIEW_SCHEMA.to_string(),
            source_hash,
            input_fingerprint,
            verdict: verdict.map(str::to_string),
            correction_hash: correction.map(correction_hash),
            response,
            token_bundle: None,
            attested_inference,
        }
    }

    /// What the witness was handed alongside these bytes, or `None` when the
    /// review predates the record. `None` is not an answer; see
    /// `witness::inference_record` for why it must not become one.
    pub fn attested_inference(&self) -> Option<&InferenceAttestationRecord> {
        self.attested_inference.as_ref()
    }

    pub fn envelope(&self) -> Result<TraceContributionEnvelope> {
        parse_witnessed_envelope(&self.response)
            .map_err(|_| anyhow::anyhow!("witness-artifact-malformed"))
    }

    /// The queue pin covers every response byte AND every review binding.
    pub fn digest(&self) -> Result<String> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| anyhow::anyhow!("witness-artifact-malformed"))?;
        Ok(format!("{WITNESS_PIN_PREFIX}{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn response(&self) -> &WitnessedEnvelope {
        &self.response
    }

    pub fn validate(
        &self,
        cfg: &crate::config::ContributorConfig,
        source_hash: &str,
        input_fingerprint: &str,
        verdict: Option<&str>,
        correction: Option<&str>,
    ) -> Result<TraceContributionEnvelope> {
        if self.verdict.as_deref() != verdict
            || self.correction_hash != correction.map(correction_hash)
        {
            bail!("witness-review-stale");
        }
        self.validate_stored(cfg, source_hash, input_fingerprint)
    }

    /// Validate a saved review for display without recovering correction text.
    /// Callers must separately compare the complete artifact digest to its pin.
    pub fn validate_stored(
        &self,
        cfg: &crate::config::ContributorConfig,
        source_hash: &str,
        input_fingerprint: &str,
    ) -> Result<TraceContributionEnvelope> {
        if self.review_schema != WITNESS_REVIEW_SCHEMA
            || self.source_hash != source_hash
            || self.input_fingerprint != input_fingerprint
            || self.response.envelope_bytes.len() > MAX_ENVELOPE_BYTES
        {
            bail!("witness-review-stale");
        }
        let settings = cfg
            .witness
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("witness-review-stale"))?;
        // Ordinary signed reviews of pre-inference history are valid for new
        // accounts too. Absence of admission evidence never grants entitlement:
        // the authenticated server must reserve its bounded window at upload.

        if !settings
            .trust()
            .map_err(|_| anyhow::anyhow!("witness-review-stale"))?
            .is_pinned()
        {
            bail!("witness-review-stale");
        }
        verify_certificate(&self.response, &settings.signing_address)
            .map_err(|_| anyhow::anyhow!("witness-certificate-invalid"))?;
        if let Some(headers) = &self.response.admission {
            let evidence: trace_commons_protocol::admission::AdmissionEvidence =
                serde_json::from_str(&headers.evidence_json)
                    .map_err(|_| anyhow::anyhow!("witness-certificate-invalid"))?;
            // Shape only, deliberately. This used to require the tenant id's
            // suffix to equal the anchor -- the client half of the coupling
            // #785 removed from the server's `admission::anchor`. V58 held
            // those equal; V61 made `anchor_hash` a keyed blind index and the
            // tenant id 32 random bytes precisely so a contributor's tenant id
            // is not computable from their NEAR account name, and the equality
            // has since held for no real account. A client cannot re-derive
            // its own anchor and must not try: the authorisation is the
            // server's stored row for (tenant, principal), checked at upload
            // by `verify_admission_evidence`, which refuses evidence bound to
            // any other account.
            if !trace_commons_protocol::admission::is_hash(&evidence.account_anchor_sha256) {
                bail!("witness-certificate-invalid");
            }
        }
        let envelope = self.envelope()?;
        if envelope.submission_id != crate::source::submission_id_for(source_hash)
            || envelope.contributor.tenant_scope_ref.as_deref() != Some(cfg.tenant_id.as_str())
            || envelope.contributor.pseudonymous_contributor_id.as_deref()
                != Some(
                    trace_commons_protocol::onboarding::user_subject_hash(&cfg.user_subject)
                        .as_str(),
                )
        {
            bail!("witness-review-stale");
        }
        Ok(envelope)
    }
}

fn correction_hash(text: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(text.as_bytes()))
}

pub fn save_witnessed(
    store: &ConfigStore,
    entry_id: Uuid,
    artifact: &WitnessReviewArtifact,
) -> Result<()> {
    let bytes =
        serde_json::to_vec(artifact).map_err(|_| anyhow::anyhow!("witness-artifact-malformed"))?;
    if bytes.len() > MAX_STORED_ARTIFACT_BYTES {
        bail!("approved-envelope-too-large");
    }
    crate::token_bundle::with_review_budget(
        store.dir(),
        &store.dir().join(file_name(entry_id)),
        bytes.len() as u64,
        || store.write_daemon_file(&file_name(entry_id), &bytes),
    )
}

/// Absence/legacy local envelope is None; malformed versioned state is an error.
/// Callers with a witness pin MUST refuse None, never rebuild or fall back.
pub fn load_witnessed(
    store: &ConfigStore,
    entry_id: Uuid,
) -> Result<Option<WitnessReviewArtifact>> {
    let Some(bytes) = store.read_daemon_file(&file_name(entry_id))? else {
        return Ok(None);
    };
    if bytes.len() > MAX_STORED_ARTIFACT_BYTES {
        bail!("approved-envelope-too-large");
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("witness-artifact-malformed"))?;
    if value.get("review_schema").is_none() {
        // Validate a legacy envelope before classifying it as local.
        serde_json::from_value::<TraceContributionEnvelope>(value)
            .map_err(|_| anyhow::anyhow!("witness-artifact-malformed"))?;
        return Ok(None);
    }
    let artifact: WitnessReviewArtifact =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!("witness-artifact-malformed"))?;
    if artifact.review_schema != WITNESS_REVIEW_SCHEMA {
        bail!("witness-artifact-version");
    }
    Ok(Some(artifact))
}

/// Persist the redacted envelope a preview just built for `entry_id`.
///
/// Refuses anything over `MAX_ENVELOPE_BYTES`: such an envelope would be
/// refused for size at upload anyway, and the cap is what bounds this
/// directory.
pub fn save(
    store: &ConfigStore,
    entry_id: Uuid,
    envelope: &TraceContributionEnvelope,
) -> Result<()> {
    let body = serde_json::to_vec(envelope).context("serializing approved envelope")?;
    if body.len() > MAX_ENVELOPE_BYTES {
        bail!("approved-envelope-too-large");
    }
    crate::token_bundle::with_review_budget(
        store.dir(),
        &store.dir().join(file_name(entry_id)),
        body.len() as u64,
        || store.write_daemon_file(&file_name(entry_id), &body),
    )
}

/// Read back the envelope stored for `entry_id`, or `None` when there is
/// none. An unreadable or unparseable file is an `Err`, never a silent
/// `None`: the caller must be able to tell "never stored" from "stored and
/// now unusable", because only the second one means an approval has to be
/// revoked.
pub fn load(store: &ConfigStore, entry_id: Uuid) -> Result<Option<TraceContributionEnvelope>> {
    let Some(body) = store.read_daemon_file(&file_name(entry_id))? else {
        return Ok(None);
    };
    if body.len() > MAX_ENVELOPE_BYTES {
        bail!("approved-envelope-too-large");
    }
    let envelope = serde_json::from_slice(&body).context("parsing stored approved envelope")?;
    Ok(Some(envelope))
}

pub fn remove(store: &ConfigStore, entry_id: Uuid) -> Result<()> {
    if let Ok(Some(artifact)) = load_witnessed(store, entry_id) {
        if let Some(bundle) = artifact.token_bundle {
            crate::token_bundle::BundleJournal::open(&store.dir().join("token-bundles"))?
                .abandon_review(bundle.journal_id)?;
        }
    }
    store.remove_daemon_file(&file_name(entry_id))
}

/// Release the pins on stored envelopes nobody is waiting on, so the next
/// `sweep` deletes them. Returns the entries released.
///
/// Two reasons to release, both of them only ever applied to a `Pending`
/// entry (see `Queue::release_preview_pin`):
///
/// * **Age.** The stored envelope is older than `PIN_MAX_AGE`. This is what
///   drains a store left behind by previews the contributor never asked
///   for -- an unbounded preview-on-launch storm, say -- which would
///   otherwise sit at the queue cap forever, because a pending entry has no
///   other reason to resolve.
/// * **Pressure.** The whole store is over `MAX_STORE_BYTES`, in which case
///   the oldest pending previews are released until it is not.
///
/// Age is decided from the file's own modification time rather than from
/// anything in the queue: it is the time the preview was written, it needs
/// no new queue field and no migration for entries that predate this, and
/// a filesystem that reports it as newer than it is only keeps a file
/// longer, which is the safe direction for a correctness-neutral cleanup.
///
/// The caller must save the queue and then `sweep`. That order matters: the
/// pin is the daemon's record that the bytes are on disk, so clearing it
/// first means a crash in the middle leaves an orphan file the next sweep
/// removes, while deleting first would leave a `Pending` entry pinned to
/// bytes that are gone, which refuses its own preview instead of rebuilding.
pub fn release_stale_pins(store: &ConfigStore, queue: &mut Queue) -> Vec<Uuid> {
    release_stale_pins_with(
        store,
        queue,
        SystemTime::now(),
        PIN_MAX_AGE,
        MAX_STORE_BYTES,
    )
}

/// `release_stale_pins` with its clock and its bounds injected, so a test
/// can age a file and fill a store without doing either for real.
fn release_stale_pins_with(
    store: &ConfigStore,
    queue: &mut Queue,
    now: SystemTime,
    max_age: Duration,
    ceiling: u64,
) -> Vec<Uuid> {
    // Every file this module owns, oldest first, with its size.
    let mut files: Vec<(Uuid, SystemTime, u64)> = match std::fs::read_dir(store.dir()) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let id = entry_id_of(&e.file_name().to_string_lossy())?;
                let meta = e.metadata().ok()?;
                Some((id, meta.modified().ok()?, meta.len()))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort_by_key(|(_, modified, _)| *modified);

    // The ceiling is on the whole store, including the files that are not
    // eligible for release: an approved backlog occupies the budget even
    // though nothing here can evict it.
    let mut total: u64 = files.iter().map(|(_, _, len)| len).sum();

    let releasable: HashSet<Uuid> = queue
        .all()
        .iter()
        .filter(|e: &&QueueEntry| {
            e.state == QueueState::Pending && e.previewed_envelope_digest.is_some()
        })
        .map(|e| e.entry_id)
        .collect();

    let mut released = Vec::new();
    for (id, modified, len) in files {
        if !releasable.contains(&id) {
            continue;
        }
        let aged = now
            .duration_since(modified)
            .map(|age| age >= max_age)
            .unwrap_or(false);
        if !(aged || total > ceiling) {
            continue;
        }
        if queue.release_preview_pin(id) {
            released.push(id);
            total = total.saturating_sub(len);
        }
    }
    released
}

/// Delete every stored envelope not in `keep`.
///
/// `keep` is the set of entries that are still live *and* still pinned to a
/// preview (`Queue::pinned_entry_ids`). An entry that reached a terminal
/// state, or whose approval was revoked or undone -- both of which clear
/// the pin -- keeps no trace content on disk. Best-effort per file: one undeletable file does
/// not stop the rest.
pub fn sweep(store: &ConfigStore, keep: &HashSet<Uuid>) -> Result<()> {
    let entries = match std::fs::read_dir(store.dir()) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("reading contributor state dir"),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(id) = entry_id_of(&name) else {
            continue;
        };
        if !keep.contains(&id) {
            let _ = remove(store, id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests_support::temp_store;

    #[tokio::test]
    async fn new_account_receiptless_history_keeps_signed_window_review_through_approval() {
        use crate::witness::transport::{
            GrantedConsent, HttpWitnessTransport, witness_contribution,
        };
        use axum::response::IntoResponse as _;
        use trace_commons_protocol::trace_contribution::{
            ConsentScope, RawTraceCaptureTurn, RawTraceContribution,
            RecordedTraceContributionOptions, TraceAllowedUse,
        };
        let (_dir, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let source_hash = "pre-inference-history";
        // Independent tenant id and anchor, per `v61_account`'s own note: a
        // `near-{anchor}` literal here is what kept the account check in
        // `validate_stored` above from ever being exercised.
        let (tenant, _anchor) = crate::config::tests_support::v61_account();
        let mut envelope = envelope().await;
        envelope.submission_id = crate::source::submission_id_for(source_hash);
        envelope.contributor.tenant_scope_ref = Some(tenant.clone());
        envelope.contributor.pseudonymous_contributor_id = Some(
            trace_commons_protocol::onboarding::user_subject_hash(&device.device_key_id),
        );
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let (response, address) = crate::witness::transport::signed_fixture(bytes.clone());
        let answer = response.clone();
        let router = axum::Router::new().route(
            "/v1/witness",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let answer = answer.clone();
                async move {
                    assert!(body.get("inference_receipt").is_none());
                    let mut response = answer.envelope_bytes.into_response();
                    response.headers_mut().insert(
                        crate::witness::transport::WITNESS_CERTIFICATE_HEADER,
                        answer.certificate_json.parse().unwrap(),
                    );
                    response.headers_mut().insert(
                        crate::witness::transport::WITNESS_SIGNATURE_HEADER,
                        answer.signature_hex.parse().unwrap(),
                    );
                    response
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let cfg:crate::config::ContributorConfig=serde_json::from_value(serde_json::json!({
            "schema_version":crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION,"issuer_url":"http://issuer.invalid","ingest_url":"http://ingest.invalid","audience":"upload","tenant_id":tenant,"instance_id":"","user_subject":device.device_key_id,"device_key_id":device.device_key_id,"consent_scopes":["debugging_evaluation"],
            "witness":{"url":url,"signing_address":address,"expected_measurements":[format!("mrtd={}","aa".repeat(48))],"admission_evidence":true}
        })).unwrap();
        let settings = cfg.witness.as_ref().unwrap();
        let profile =
            crate::submit::admission_profile_for_request(settings.admission_evidence, None)
                .unwrap();
        assert!(!profile);
        let transport = HttpWitnessTransport::new(
            url.clone(),
            cfg.ingest_url.clone(),
            std::sync::Arc::new(
                trace_commons_operator_client::host_allowlist::HostAllowlist::permissive(),
            ),
            Duration::from_secs(5),
        )
        .unwrap()
        .with_admission_evidence(profile);
        // Enclave attestation is injected only at the existing test seam;
        // HTTP, returned artifact signature and approval validation are real.
        let verified = crate::witness::verify::verified_witness_for_test(&url, &address);
        let raw = RawTraceContribution::from_capture_turns(
            &[RawTraceCaptureTurn {
                user_input: "previous useful work".into(),
                response: None,
                tool_calls: Vec::new(),
                started_at: chrono::Utc::now(),
                completed_at: Some(chrono::Utc::now()),
                state: Some("Completed".into()),
            }],
            RecordedTraceContributionOptions::default(),
        );
        let received = witness_contribution(
            &transport,
            &verified,
            raw,
            None,
            &GrantedConsent {
                scopes: vec![ConsentScope::DebuggingEvaluation],
                uses: vec![TraceAllowedUse::Debugging],
            },
        )
        .await
        .unwrap();
        assert!(received.admission.is_none());
        let artifact = WitnessReviewArtifact::new(
            received,
            source_hash.into(),
            "fingerprint".into(),
            None,
            None,
            None,
        );
        let id = Uuid::new_v4();
        save_witnessed(&store, id, &artifact).unwrap();
        let loaded = load_witnessed(&store, id).unwrap().unwrap();
        loaded
            .validate_stored(&cfg, source_hash, "fingerprint")
            .unwrap();
        assert_eq!(loaded.response.envelope_bytes, bytes);
        let opts = crate::submit::SubmitOptions {
            dry_run: false,
            pii_filter: None,
            no_reasoning: false,
            machine_readable: true,
            unenrolled_preview: false,
            remediate_quarantined: false,
            verdict: None,
        };
        let mut context = crate::submit::SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        context.use_approved_witness(loaded.response).unwrap();
        // Server authority is separately exercised by the real-PG
        // actual_postgres_challenge_witness_ingest_and_terminal_retry test:
        // no evidence consumes one window slot; exhaustion refuses upload.
        task.abort();
    }

    #[tokio::test]
    async fn witness_review_persists_exact_bytes_and_refuses_partial_records() {
        let (_dir, store) = temp_store();
        let bytes = serde_json::to_vec_pretty(&envelope().await).unwrap();
        let (response, _) = crate::witness::transport::signed_fixture(bytes.clone());
        let artifact = WitnessReviewArtifact::new(
            response,
            "source-hash".into(),
            "fingerprint".into(),
            Some("worked"),
            Some("correction"),
            None,
        );
        let id = Uuid::new_v4();
        save_witnessed(&store, id, &artifact).unwrap();
        let loaded = load_witnessed(&store, id).unwrap().unwrap();
        assert_eq!(loaded.response.envelope_bytes, bytes);
        assert_eq!(loaded.digest().unwrap(), artifact.digest().unwrap());
        let persisted = std::fs::read_to_string(store.dir().join(file_name(id))).unwrap();
        assert!(!persisted.contains("access_token"));
        assert!(!persisted.contains("\"correction\""));
        assert!(
            load(&store, id).is_err(),
            "old local-only reader must not silently accept a certified record"
        );
        let mut value: serde_json::Value = serde_json::from_str(&persisted).unwrap();
        value["response"]
            .as_object_mut()
            .unwrap()
            .remove("signature_hex");
        store
            .write_daemon_file(&file_name(id), &serde_json::to_vec(&value).unwrap())
            .unwrap();
        assert!(load_witnessed(&store, id).is_err());
    }

    #[tokio::test]
    async fn witness_review_pin_covers_certificate_context_and_all_wire_bytes() {
        let (response, _) = crate::witness::transport::signed_fixture(
            serde_json::to_vec(&envelope().await).unwrap(),
        );
        let artifact = WitnessReviewArtifact::new(
            response,
            "source-hash".into(),
            "fingerprint".into(),
            None,
            None,
            None,
        );
        let pin = artifact.digest().unwrap();
        let mut changed = artifact.clone();
        changed.source_hash.push('x');
        assert_ne!(pin, changed.digest().unwrap());
        changed = artifact.clone();
        changed.input_fingerprint.push('x');
        assert_ne!(pin, changed.digest().unwrap());
        changed = artifact.clone();
        changed.response.signature_hex.push('0');
        assert_ne!(pin, changed.digest().unwrap());
        changed = artifact.clone();
        changed.response.envelope_bytes.push(b' ');
        assert_ne!(pin, changed.digest().unwrap());
        changed = artifact.clone();
        changed.verdict = Some("failed".into());
        assert_ne!(pin, changed.digest().unwrap());
    }

    #[tokio::test]
    async fn legacy_local_envelope_does_not_acquire_a_witness_certificate() {
        let (_dir, store) = temp_store();
        let id = Uuid::new_v4();
        save(&store, id, &envelope().await).unwrap();
        assert!(load_witnessed(&store, id).unwrap().is_none());
    }

    /// A real redacted envelope, built by the same pipeline preview uses.
    async fn envelope() -> TraceContributionEnvelope {
        let (_d, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = crate::config::ContributorConfig {
            inference_receipt_endpoint: None,
            inference_receipt_check_attestation: false,
            schema_version: crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION.into(),
            issuer_url: "http://issuer.invalid".into(),
            ingest_url: "http://ingest.invalid".into(),
            audience: "trace-commons-upload".into(),
            tenant_id: "tenant-abc".into(),
            instance_id: "instance-1".into(),
            user_subject: "alice".into(),
            device_key_id: device.device_key_id,
            consent_scopes: vec!["debugging_evaluation".into()],
            pii_filter: None,
            allowed_hosts: None,
            display_handle: None,
            public_bio: None,
            public_since: None,
            witness: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("44444444-4444-4444-4444-444444444444.jsonl"),
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"},\
             \"cwd\":\"/Users/testuser/code/myproj\",\
             \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
             \"sessionId\":\"44444444-4444-4444-4444-444444444444\",\"uuid\":\"a1\"}\n",
        )
        .unwrap();
        let src = crate::source::claude_code::ClaudeCodeSource::new(root);
        let session_ref = crate::source::TraceSource::discover(&src)
            .unwrap()
            .remove(0);
        let transcript = crate::source::TraceSource::load(&src, &session_ref).unwrap();
        let raw = crate::envelope::build_raw_contribution(&transcript, &cfg, chrono::Utc::now());
        let redactor =
            crate::envelope::build_redactor_with(&cfg, transcript.cwd.as_deref(), None).unwrap();
        crate::envelope::redact_to_envelope(&redactor, raw)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_envelope_round_trips_byte_for_byte() {
        let (_d, store) = temp_store();
        let id = Uuid::new_v4();
        let e = envelope().await;
        save(&store, id, &e).unwrap();
        assert_eq!(load(&store, id).unwrap().unwrap(), e);
    }

    #[test]
    fn a_missing_envelope_reads_back_as_none_not_an_error() {
        let (_d, store) = temp_store();
        assert!(load(&store, Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn an_unparseable_envelope_is_an_error_not_a_silent_none() {
        // The caller has to be able to tell "never stored" from "stored and
        // now unusable": only the second one revokes an approval.
        let (_d, store) = temp_store();
        let id = Uuid::new_v4();
        store
            .write_daemon_file(&file_name(id), b"not json")
            .unwrap();
        assert!(load(&store, id).is_err());
    }

    #[tokio::test]
    async fn sweep_removes_only_envelopes_no_live_entry_still_needs() {
        let (_d, store) = temp_store();
        let keep_id = Uuid::new_v4();
        let drop_id = Uuid::new_v4();
        let e = envelope().await;
        save(&store, keep_id, &e).unwrap();
        save(&store, drop_id, &e).unwrap();
        sweep(&store, &HashSet::from([keep_id])).unwrap();
        assert!(load(&store, keep_id).unwrap().is_some());
        assert!(load(&store, drop_id).unwrap().is_none());
    }

    #[test]
    fn sweep_never_touches_a_file_it_does_not_own() {
        let (_d, store) = temp_store();
        store
            .write_daemon_file(crate::config::DAEMON_QUEUE_FILE, b"{}\n")
            .unwrap();
        sweep(&store, &HashSet::new()).unwrap();
        assert!(
            store
                .read_daemon_file(crate::config::DAEMON_QUEUE_FILE)
                .unwrap()
                .is_some()
        );
    }

    /// A pending queue entry pinned to a stored envelope.
    fn pinned_entry(hash: &str, state: crate::daemon::queue::QueueState) -> QueueEntry {
        QueueEntry {
            entry_id: crate::daemon::queue::entry_id_for(hash),
            session_hash: hash.into(),
            source: "claude-code".into(),
            project_key: "/Users/z/code/proj".into(),
            project_label: "proj".into(),
            path: std::path::PathBuf::from("/Users/z/.claude/projects/x/s.jsonl"),
            size_bytes: 100,
            discovered_at: chrono::Utc::now(),
            state,
            previewed_envelope_digest: Some("sha256:previewed".into()),
            ..Default::default()
        }
    }

    fn queue_with(entries: Vec<QueueEntry>) -> Queue {
        let mut q = Queue::new();
        for e in entries {
            q.upsert(e, 5000).unwrap();
        }
        q
    }

    /// `save` an envelope for every entry in `q` that claims a pin.
    async fn store_envelopes_for(store: &ConfigStore, q: &Queue) {
        let e = envelope().await;
        for entry in q.all() {
            if entry.previewed_envelope_digest.is_some() {
                save(store, entry.entry_id, &e).unwrap();
            }
        }
    }

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    #[tokio::test]
    async fn a_pending_preview_nobody_acted_on_loses_its_pin_once_it_is_old() {
        // The residue this exists for: previews written for entries the
        // contributor never opened, kept indefinitely because the entry
        // stays pending. Dropping the pin lets `sweep` take the bytes; the
        // next preview rebuilds.
        let (_d, store) = temp_store();
        let mut q = queue_with(vec![pinned_entry("sha256:aa", QueueState::Pending)]);
        store_envelopes_for(&store, &q).await;
        let id = q.all()[0].entry_id;

        let released = release_stale_pins_with(
            &store,
            &mut q,
            SystemTime::now() + 4 * DAY,
            PIN_MAX_AGE,
            MAX_STORE_BYTES,
        );

        assert_eq!(released, vec![id]);
        assert_eq!(q.get(id).unwrap().previewed_envelope_digest, None);
        sweep(&store, &q.pinned_entry_ids()).unwrap();
        assert!(load(&store, id).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_fresh_pending_preview_is_kept() {
        // Releasing a preview the contributor is still looking at would
        // make the entry rebuild under them for no benefit.
        let (_d, store) = temp_store();
        let mut q = queue_with(vec![pinned_entry("sha256:aa", QueueState::Pending)]);
        store_envelopes_for(&store, &q).await;
        let id = q.all()[0].entry_id;

        let released = release_stale_pins_with(
            &store,
            &mut q,
            SystemTime::now(),
            PIN_MAX_AGE,
            MAX_STORE_BYTES,
        );

        assert!(released.is_empty());
        assert!(q.get(id).unwrap().previewed_envelope_digest.is_some());
        sweep(&store, &q.pinned_entry_ids()).unwrap();
        assert!(load(&store, id).unwrap().is_some());
    }

    #[tokio::test]
    async fn an_approved_entrys_envelope_is_never_released_however_old() {
        // These are the bytes the upload sends. Age is not a reason to
        // drop them; only the entry resolving is.
        let (_d, store) = temp_store();
        let mut q = queue_with(vec![pinned_entry("sha256:aa", QueueState::Approved)]);
        store_envelopes_for(&store, &q).await;
        let id = q.all()[0].entry_id;

        let released = release_stale_pins_with(
            &store,
            &mut q,
            SystemTime::now() + 400 * DAY,
            PIN_MAX_AGE,
            // A ceiling of zero: even under maximum pressure an approved
            // entry keeps its bytes.
            0,
        );

        assert!(released.is_empty());
        assert!(q.get(id).unwrap().previewed_envelope_digest.is_some());
        sweep(&store, &q.pinned_entry_ids()).unwrap();
        assert!(load(&store, id).unwrap().is_some());
    }

    #[tokio::test]
    async fn the_store_evicts_pending_previews_until_it_is_under_its_ceiling() {
        // The bound the module claims has to be a byte bound, not just a
        // count of entries times the per-envelope cap.
        let (_d, store) = temp_store();
        let mut q = queue_with(vec![
            pinned_entry("sha256:aa", QueueState::Pending),
            pinned_entry("sha256:bb", QueueState::Pending),
            pinned_entry("sha256:cc", QueueState::Pending),
        ]);
        store_envelopes_for(&store, &q).await;
        let one = store
            .read_daemon_file(&file_name(q.all()[0].entry_id))
            .unwrap()
            .unwrap()
            .len() as u64;

        // Room for two of the three.
        let released = release_stale_pins_with(
            &store,
            &mut q,
            SystemTime::now(),
            PIN_MAX_AGE,
            one * 2 + one / 2,
        );

        assert_eq!(released.len(), 1, "evict only as much as the ceiling needs");
        assert_eq!(q.pinned_entry_ids().len(), 2);
        sweep(&store, &q.pinned_entry_ids()).unwrap();
        assert!(load(&store, released[0]).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_stored_envelope_is_removed_on_logout() {
        // It is redacted trace content at rest; a logout must not leave one
        // contributor's transcript on disk for whoever enrolls next.
        let (_d, store) = temp_store();
        let id = Uuid::new_v4();
        save(&store, id, &envelope().await).unwrap();
        store.wipe().unwrap();
        assert!(load(&store, id).unwrap().is_none());
    }
    #[test]
    fn a_stored_review_that_predates_the_record_reads_as_unknown() {
        // Absent is "we do not know", never "uncertified" and never
        // "certified". A review written by a build before this field existed
        // may have carried a verified receipt; nothing says either way.
        let (response, _) = crate::witness::transport::signed_fixture(b"{}".to_vec());
        let legacy = serde_json::json!({
            "review_schema": WITNESS_REVIEW_SCHEMA,
            "source_hash": "sha256:legacy",
            "input_fingerprint": "fp",
            "verdict": null,
            "correction_hash": null,
            "response": response,
        });
        let (_dir, store) = temp_store();
        let id = Uuid::new_v4();
        store
            .write_daemon_file(&file_name(id), &serde_json::to_vec(&legacy).unwrap())
            .unwrap();
        let artifact = load_witnessed(&store, id).unwrap().unwrap();
        assert_eq!(artifact.attested_inference(), None);
    }

    #[test]
    fn a_review_without_a_record_serializes_exactly_as_before() {
        // Existing pins are digests over the serialized artifact. A new
        // optional field that serialized as `null` would move every one of
        // them and refuse every review a contributor already approved.
        let (response, _) = crate::witness::transport::signed_fixture(b"{}".to_vec());
        let artifact =
            WitnessReviewArtifact::new(response, "sha256:aa".into(), "fp".into(), None, None, None);
        let json = serde_json::to_value(&artifact).unwrap();
        assert!(
            json.get("attested_inference").is_none(),
            "an absent record must not appear on the wire: {json}"
        );
    }

    #[test]
    fn a_record_round_trips_and_is_covered_by_the_pin() {
        use crate::witness::inference_record::{
            InferenceAttestationRecord, REASON_RECEIPT_UNAVAILABLE,
        };
        let (response, _) = crate::witness::transport::signed_fixture(b"{}".to_vec());
        let certified = WitnessReviewArtifact::new(
            response.clone(),
            "sha256:aa".into(),
            "fp".into(),
            None,
            None,
            Some(InferenceAttestationRecord::certified()),
        );
        let uncertified = WitnessReviewArtifact::new(
            response,
            "sha256:aa".into(),
            "fp".into(),
            None,
            None,
            Some(InferenceAttestationRecord::uncertified(
                REASON_RECEIPT_UNAVAILABLE,
            )),
        );
        assert_ne!(
            certified.digest().unwrap(),
            uncertified.digest().unwrap(),
            "the pin must cover the record, or a file edit could promote a review"
        );
        let (_dir, store) = temp_store();
        let id = Uuid::new_v4();
        save_witnessed(&store, id, &certified).unwrap();
        let restored = load_witnessed(&store, id).unwrap().unwrap();
        assert_eq!(
            restored.attested_inference(),
            Some(&InferenceAttestationRecord::certified())
        );
        assert_eq!(restored.digest().unwrap(), certified.digest().unwrap());
    }
}
