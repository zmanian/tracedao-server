//! Explicit local import: no discovery, persistence, network, or admission grant.
use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use trace_commons_attestation::receipt::{
    ReceiptAlgo, ReceiptPayload, ReceiptSignatureKind, verify_receipt,
};
use trace_commons_protocol::evidence_import::{EvidenceImport, MAX_IMPORT_BYTES};
use trace_commons_protocol::trace_contribution::TraceContributionEnvelope;

pub struct PreparedImport {
    document: EvidenceImport,
    receipt: Option<ReceiptPayload>,
    call: Option<crate::routing::attested::AttestedCall>,
    session_hash: String,
}

impl std::fmt::Debug for PreparedImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedImport")
            .field("has_inference", &self.call.is_some())
            .finish_non_exhaustive()
    }
}

impl PreparedImport {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let document = EvidenceImport::parse(bytes)?;
        let (receipt, call) = if let Some(inference) = &document.inference {
            let offered = &inference.receipt;
            let signing_algo = ReceiptAlgo::from_wire(&offered.signing_algo)
                .ok_or_else(|| anyhow!("import-receipt-algorithm-unsupported"))?;
            let signature_kind = ReceiptSignatureKind::from_wire(&offered.signature_kind);
            if signature_kind == ReceiptSignatureKind::Unrecognised {
                return Err(anyhow!("import-receipt-kind-unsupported"));
            }
            let receipt = ReceiptPayload {
                text: offered.text.clone(),
                signature: offered.signature.clone(),
                signing_address: offered.signing_address.clone(),
                signing_algo,
                signature_kind,
            };
            let request: serde_json::Value = serde_json::from_str(&inference.request_body)
                .map_err(|_| anyhow!("import-request-malformed"))?;
            let model = request
                .get("model")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("import-request-model-missing"))?;
            // This establishes only signature/body consistency. The witness
            // still binds this signer to its correct nonce-verified report.
            verify_receipt(
                &receipt,
                inference.request_body.as_bytes(),
                inference.response_body.as_bytes(),
                model,
            )
            .map_err(|_| anyhow!("import-receipt-invalid"))?;
            let call = crate::routing::attested::AttestedCall::from_import(inference)?;
            (Some(receipt), Some(call))
        } else {
            (None, None)
        };
        Ok(Self {
            document,
            receipt,
            call,
            session_hash: crate::source::session_hash(bytes),
        })
    }

    /// Receipt-free imports are ordinary, not invalid. This says nothing
    /// about authenticated invite eligibility at the server boundary.
    /// Build only the isolated final-call witness input, using authenticated
    /// configuration and conservative defaults instead of imported authority,
    /// history, outcomes, replay or value claims. Transport appends the call.
    pub fn witness_input(
        &self,
        cfg: &crate::config::ContributorConfig,
    ) -> Result<trace_commons_protocol::trace_contribution::RawTraceContribution> {
        self.call
            .as_ref()
            .ok_or_else(|| anyhow!("import-inference-required"))?;
        let transcript = crate::source::SessionTranscript {
            source: self.document.trace.ironclaw.feature_flags["agent"]
                .clone()
                .into(),
            session_hash: self.session_hash.clone(),
            ..Default::default()
        };
        let raw = crate::envelope::build_preview_raw_contribution(
            &transcript,
            cfg,
            self.document
                .inference
                .as_ref()
                .expect("call requires inference")
                .timestamp,
        );
        let raw = crate::envelope::final_call_witness_input(raw, cfg);
        debug_assert!(raw.events.is_empty());
        Ok(raw)
    }

    /// Signature consistency does not establish authenticated admission.
    pub fn has_inference(&self) -> bool {
        self.call.is_some()
    }

    /// The existing transport takes this borrowed pair; no raw carrier is
    /// inserted into the ordinary trace or serialized by this local importer.
    pub fn attested_inference(&self) -> Option<crate::witness::transport::AttestedInference<'_>> {
        Some(crate::witness::transport::AttestedInference {
            call: self.call.as_ref()?,
            receipt: self.receipt.as_ref(),
        })
    }

    /// `cwd` is explicit redaction context from the originating machine. It is
    /// not opened, canonicalized, discovered, or stored in the preview.
    pub async fn local_preview(&self, cwd: &str) -> Result<ImportPreview> {
        if cwd.trim().is_empty() || cwd.len() > 4096 || cwd.contains('\0') {
            return Err(anyhow!("import-redaction-context-invalid"));
        }
        let redactor = crate::envelope::build_deterministic_preview_redactor(Some(cwd));
        self.preview_with_redactor(&redactor).await
    }

    async fn preview_with_redactor(
        &self,
        redactor: &trace_commons_protocol::trace_contribution::DeterministicTraceRedactor,
    ) -> Result<ImportPreview> {
        let raw =
            crate::envelope::build_import_preview_raw(&self.document.trace, &self.session_hash);
        let envelope = crate::submit::checked_local_redaction(redactor, raw, false)
            .await
            .map_err(anyhow::Error::msg)?;
        let artifact =
            serde_json::to_vec(&envelope).map_err(|_| anyhow!("import-preview-malformed"))?;
        Ok(ImportPreview {
            preview_only: true,
            admission_verified: false,
            evidence: if self.has_inference() {
                "signature-consistent-witness-required"
            } else {
                "ordinary-trace-no-inference-evidence"
            },
            coverage: self.has_inference().then_some("final_call_only"),
            preview_sha256: hex::encode(Sha256::digest(&artifact)),
            envelope,
        })
    }
}

/// Local review only: this artifact is neither a witness certificate nor an
/// authentication/consent grant, and must not be treated as approved submission.
#[derive(serde::Serialize)]
pub struct ImportPreview {
    pub preview_only: bool,
    pub admission_verified: bool,
    pub evidence: &'static str,
    pub coverage: Option<&'static str>,
    pub preview_sha256: String,
    pub envelope: TraceContributionEnvelope,
}

pub fn read_import(path: &std::path::Path) -> Result<PreparedImport> {
    use std::io::Read;
    // Caller explicitly chooses this local file. No path/URL is accepted from
    // inside the document. Metadata and bytes use the same open handle.
    let file = open_import_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("import-file-unreadable"))?;
    if !metadata.is_file() {
        return Err(anyhow!("import-file-not-regular"));
    }
    if metadata.len() > MAX_IMPORT_BYTES as u64 {
        return Err(anyhow!("import-too-large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_IMPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("import-file-unreadable"))?;
    PreparedImport::parse(&bytes)
}

fn open_import_file(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK | O_NOFOLLOW, spelled per-ABI rather than through `libc`,
        // which is not a direct dependency of this permissive crate and is not
        // worth becoming one for two constants. The consequence is deliberate
        // and is the safe direction: a target whose ABI is not enumerated here
        // gets no open at all, not an open with the wrong flags. Adding a
        // target means adding its pair, and the symlink and FIFO tests below
        // are what prove a pair is right. Today that leaves Linux on 32-bit
        // arm, riscv64 and s390x, and every non-Linux non-macOS unix, without
        // local import; they refuse by name rather than silently losing the
        // confinement the flags provide.
        let flags = if cfg!(target_os = "macos") {
            0x4 | 0x100
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            0x800 | 0x20000
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            0x800 | 0x8000
        } else {
            return Err(anyhow!("import-platform-unsupported"));
        };
        options.custom_flags(flags);
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        // Refuse device/pipe and network namespaces before CreateFile can
        // connect or block. Ordinary drive paths (including verbatim disk
        // paths) and relative local paths retain regular-file validation.
        if let Some(Component::Prefix(prefix)) = path.components().next()
            && !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        {
            return Err(anyhow!("import-file-namespace-unsupported"));
        }
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(not(any(unix, windows)))]
    return Err(anyhow!("import-platform-unsupported"));
    let file = options
        .open(path)
        .map_err(|_| anyhow!("import-file-unreadable"))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file
            .metadata()
            .map_err(|_| anyhow!("import-file-unreadable"))?
            .file_attributes()
            & 0x400
            != 0
        {
            return Err(anyhow!("import-file-not-regular"));
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use trace_commons_protocol::evidence_import::{
        ImportedInference, ImportedReceipt, InferenceCoverage,
    };
    use trace_commons_protocol::trace_contribution::{
        RawTraceCaptureTurn, RawTraceContribution, RecordedTraceContributionOptions,
    };

    fn fixture(source: &str, evidence: bool) -> EvidenceImport {
        let mut trace = RawTraceContribution::from_capture_turns(
            &[RawTraceCaptureTurn {
                user_input: "Review the build result".to_owned(),
                response: Some("Build completed".to_owned()),
                tool_calls: Vec::new(),
                started_at: chrono::Utc::now(),
                completed_at: None,
                state: None,
            }],
            RecordedTraceContributionOptions {
                include_message_text: true,
                ..Default::default()
            },
        );
        trace
            .ironclaw
            .feature_flags
            .insert("agent".to_owned(), source.to_owned());
        let inference = evidence.then(|| {
            let request = "{\"model\":\"test-model\", \"messages\":[{\"role\":\"user\",\"content\":\"RAW-INFERENCE-SENTINEL café\"}], \"temperature\":0.30000000000000004}";
            let response = "data: {\"choices\":[{\"delta\":{\"content\":\"done\"}}]}\n\ndata: [DONE]\n\n";
            let request_sha256 = hex::encode(Sha256::digest(request.as_bytes()));
            let response_sha256 = hex::encode(Sha256::digest(response.as_bytes()));
            let text = format!("{request_sha256}:{response_sha256}");
            let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
            ImportedInference {
                exchange_id: "exchange-1".to_owned(), coverage: InferenceCoverage::FinalCallOnly,
                request_body: request.to_owned(), response_body: response.to_owned(), request_sha256, response_sha256,
                upstream_id: "chatcmpl-1".to_owned(), served_model: Some("test-model".to_owned()), status: 200,
                timestamp: chrono::Utc::now(), receipt: ImportedReceipt {
                    signature: hex::encode(key.sign(text.as_bytes()).as_ref()), text,
                    signing_address: hex::encode(key.public_key().as_ref()), signing_algo: "ed25519".to_owned(), signature_kind: "gateway".to_owned(),
                },
            }
        });
        EvidenceImport {
            schema_version: 1,
            trace,
            inference,
        }
    }
    fn encoded(doc: &EvidenceImport) -> Vec<u8> {
        serde_json::to_vec(doc).unwrap()
    }

    #[tokio::test]
    async fn two_applications_can_preview_ordinary_traces_without_receipts() {
        for source in ["opencode", "second-client"] {
            let parsed = PreparedImport::parse(&encoded(&fixture(source, false))).unwrap();
            assert!(!parsed.has_inference());
            let preview = parsed.local_preview("/foreign/work").await.unwrap();
            assert!(preview.preview_only);
            assert!(!preview.admission_verified);
            assert_eq!(preview.coverage, None);
        }
    }

    #[tokio::test]
    async fn exact_inference_bytes_stay_out_of_local_preview_for_both_applications() {
        for source in ["opencode", "second-client"] {
            let doc = fixture(source, true);
            let parsed = PreparedImport::parse(&encoded(&doc)).unwrap();
            let offered = parsed.attested_inference().unwrap();
            assert_eq!(
                offered.call.request_body(),
                doc.inference.as_ref().unwrap().request_body
            );
            let event = crate::routing::attested::attested_exchange_event(offered.call);
            assert_eq!(
                event.structured_payload["request"]["body"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
                offered.call.request_body().as_bytes()
            );
            let preview = parsed.local_preview("/foreign/work").await.unwrap();
            assert!(!preview.admission_verified);
            assert_eq!(preview.coverage, Some("final_call_only"));
            assert!(
                !serde_json::to_string(&preview)
                    .unwrap()
                    .contains("RAW-INFERENCE-SENTINEL")
            );
            assert!(!format!("{parsed:?}").contains("RAW-INFERENCE-SENTINEL"));
        }
    }

    #[tokio::test]
    async fn preview_redacts_credentials_and_foreign_paths_and_discards_imported_authority() {
        let secret = "sk-ant-EXPOSEDsecret0123456789abcdefghij";
        let cwd = "/Volumes/Work/acme-stealth-launch";
        let mut document = fixture("second-client", false);
        document.trace.events[0].content = Some(format!("Read {cwd}/src/main.rs using {secret}"));
        document.trace.contributor.tenant_scope_ref = Some("forged-tenant".into());
        document.trace.consent.scopes.clear();
        document.trace.consent.policy_version = "forged-policy".into();
        document.trace.consent.correction_included = true;
        document.trace.outcome.human_correction = Some("forged-correction".into());
        document.trace.ironclaw.model_name = Some("forged-model".into());
        let prepared = PreparedImport::parse(&encoded(&document)).unwrap();
        let preview = prepared.local_preview(cwd).await.unwrap();
        let output = serde_json::to_string(&preview).unwrap();
        for forbidden in [
            secret,
            cwd,
            "forged-tenant",
            "forged-policy",
            "forged-correction",
            "forged-model",
        ] {
            assert!(
                !output.contains(forbidden),
                "preview leaked an imported value"
            );
        }
        let cfg = crate::commands::unenrolled_preview_config();
        assert_eq!(
            preview.envelope.contributor.tenant_scope_ref,
            Some(cfg.tenant_id)
        );
        assert!(!preview.envelope.consent.correction_included);
        assert!(preview.envelope.consent.message_text_included);
        assert_eq!(
            preview.preview_sha256,
            hex::encode(Sha256::digest(
                serde_json::to_vec(&preview.envelope).unwrap()
            ))
        );
        assert!(prepared.local_preview("").await.is_err());
    }

    #[tokio::test]
    async fn preview_refuses_a_poisoned_redactor() {
        use trace_commons_protocol::trace_contribution::{
            NoopPrivacyFilterAdapter, PrivacyFilterBackendTag,
        };
        let prepared = PreparedImport::parse(&encoded(&fixture("opencode", false))).unwrap();
        let poisoned = crate::envelope::build_deterministic_preview_redactor(Some("/foreign/work"))
            .with_privacy_filter(
                std::sync::Arc::new(NoopPrivacyFilterAdapter),
                PrivacyFilterBackendTag::NearAi,
            );
        assert!(
            prepared.preview_with_redactor(&poisoned).await.is_err(),
            "a no-op backend must fail its canary"
        );
    }

    #[tokio::test]
    async fn preview_refuses_a_finished_residual_secret() {
        let prepared = PreparedImport::parse(&encoded(&fixture("opencode", false))).unwrap();
        let redactor = crate::envelope::build_deterministic_preview_redactor(Some("/foreign/work"));
        let mut clean = prepared
            .preview_with_redactor(&redactor)
            .await
            .unwrap()
            .envelope;
        crate::submit::validate_local_envelope(&redactor, &clean).unwrap();
        // Inject a post-redaction survivor, as the established submit test does.
        clean.events[0].redacted_content = Some("sk-ant-EXPOSEDsecret0123456789abcdefghij".into());
        assert_eq!(
            crate::submit::validate_local_envelope(&redactor, &clean),
            Err("secret-leak-detected")
        );
    }

    #[tokio::test]
    async fn preview_refuses_a_backend_that_injects_a_secret_after_its_canary() {
        use trace_commons_protocol::trace_contribution::*;
        struct InjectAfterCanary;
        #[async_trait::async_trait]
        impl PrivacyFilterAdapter for InjectAfterCanary {
            async fn redact_text(
                &self,
                text: &str,
            ) -> std::result::Result<Option<SafePrivacyFilterRedaction>, TraceContributionError>
            {
                let canaries = synthetic_privacy_filter_canary_values();
                let is_canary = canaries.iter().any(|v| text.contains(v.as_str()));
                let mut rewritten = if is_canary {
                    text.to_owned()
                } else {
                    "sk-ant-EXPOSEDsecret0123456789abcdefghij".into()
                };
                for value in &canaries {
                    rewritten = rewritten.replace(value, "[REDACTED:unknown]");
                }
                Ok(Some(SafePrivacyFilterRedaction {
                    private_edits: None,
                    redacted_text: rewritten,
                    summary: SafePrivacyFilterSummary {
                        schema_version: 1,
                        output_mode: "redacted_text_only".into(),
                        span_count: canaries.len() as u32,
                        by_label: Default::default(),
                        decoded_mismatch: false,
                        classify_policy: None,
                        events_examined: 0,
                        events_skipped_by_policy: 0,
                    },
                    report: Default::default(),
                }))
            }
        }
        let prepared = PreparedImport::parse(&encoded(&fixture("opencode", false))).unwrap();
        let redactor = crate::envelope::build_deterministic_preview_redactor(Some("/foreign/work"))
            .with_privacy_filter(
                std::sync::Arc::new(InjectAfterCanary),
                PrivacyFilterBackendTag::NearAi,
            );
        crate::envelope::canary_self_test_async(&redactor)
            .await
            .unwrap();
        let error = prepared
            .preview_with_redactor(&redactor)
            .await
            .err()
            .expect("injected survivor must refuse the actual preview path");
        // The property is the REFUSAL: a backend that tampers after passing
        // its canary never produces a preview. Which guard catches it first
        // is not the guarantee. This backend rewrites metadata keys as well
        // as trace text, so under the metadata redaction pass the collision
        // guard fires before the whole-envelope residual scan is reached --
        // both are real, both refuse, and pinning one name here would make
        // this test fail whenever the earlier guard improves.
        let label = error.to_string();
        assert!(
            label == crate::envelope::REASON_METADATA_CREDENTIAL
                || label == crate::envelope::REASON_METADATA_KEY_COLLISION,
            "a tampering backend must be refused by a named guard, got {label}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_device_and_pipe_namespaces_are_refused_before_open() {
        for path in [
            r"\\.\pipe\trace-import-test",
            r"\\?\GLOBALROOT\Device\NamedPipe\trace-import-test",
            r"\\server\share\trace.json",
        ] {
            let error = read_import(std::path::Path::new(path)).unwrap_err();
            assert_eq!(error.to_string(), "import-file-namespace-unsupported");
        }
    }

    #[test]
    fn swapped_bytes_or_signer_never_become_prepared_evidence() {
        let mut doc = fixture("opencode", true);
        doc.inference.as_mut().unwrap().request_body.push(' ');
        assert!(PreparedImport::parse(&encoded(&doc)).is_err());
        let body = &doc.inference.as_ref().unwrap().request_body;
        doc.inference.as_mut().unwrap().request_sha256 =
            hex::encode(Sha256::digest(body.as_bytes()));
        assert!(
            PreparedImport::parse(&encoded(&doc)).is_err(),
            "updating unsigned digest does not repair receipt"
        );
        let mut doc = fixture("second-client", true);
        doc.inference.as_mut().unwrap().receipt.signing_address = "00".repeat(32);
        assert!(PreparedImport::parse(&encoded(&doc)).is_err());
        let mut doc = fixture("opencode", true);
        doc.inference.as_mut().unwrap().receipt.signature = "00".repeat(64);
        assert!(PreparedImport::parse(&encoded(&doc)).is_err());
        let mut value = serde_json::to_value(fixture("opencode", true)).unwrap();
        value["inference"]["request_body"] = serde_json::json!([0, 255]);
        assert!(PreparedImport::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn unsupported_discriminators_and_coverage_are_refused() {
        for field in ["signing_algo", "signature_kind"] {
            let mut value = serde_json::to_value(fixture("opencode", true)).unwrap();
            value["inference"]["receipt"][field] = "unknown".into();
            assert!(PreparedImport::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = serde_json::to_value(fixture("opencode", true)).unwrap();
        value["inference"]["coverage"] = "whole_session".into();
        assert!(PreparedImport::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn replayed_import_is_not_a_cached_admission_grant() {
        let bytes = encoded(&fixture("second-client", true));
        for _ in 0..2 {
            let parsed = PreparedImport::parse(&bytes).unwrap();
            assert!(parsed.has_inference());
            // No admission verdict/token exists here. Replay/account binding
            // remains mandatory in the authoritative witness/ingest path.
            assert_eq!(
                parsed.attested_inference().unwrap().call.upstream_id(),
                "chatcmpl-1"
            );
        }
    }

    #[test]
    fn duplicate_events_unknown_retrieval_and_ambiguous_carriers_are_refused() {
        let mut doc = fixture("opencode", true);
        doc.trace.events.push(doc.trace.events[0].clone());
        assert!(PreparedImport::parse(&encoded(&doc)).is_err());
        let mut value = serde_json::to_value(fixture("opencode", true)).unwrap();
        value["inference"]["receipt_url"] = "http://127.0.0.1/private".into();
        assert!(PreparedImport::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut doc = fixture("opencode", true);
        doc.trace.events[0].event_type =
            trace_commons_protocol::trace_contribution::TraceContributionEventType::HttpExchange;
        assert!(PreparedImport::parse(&encoded(&doc)).is_err());
    }

    #[test]
    fn witness_projection_uses_local_authority_and_omits_companion_history() {
        let mut document = fixture("opencode", true);
        document.trace.contributor.tenant_scope_ref = Some("forged-tenant".into());
        document.trace.outcome.human_correction = Some("UNATTESTED-HISTORY-SENTINEL".into());
        let parsed = PreparedImport::parse(&encoded(&document)).unwrap();
        let mut cfg = crate::commands::unenrolled_preview_config();
        cfg.tenant_id = "local-account".into();
        let mut raw = parsed.witness_input(&cfg).unwrap();
        assert!(raw.events.is_empty());
        assert_eq!(
            raw.contributor.tenant_scope_ref.as_deref(),
            Some("local-account")
        );
        assert!(raw.outcome.human_correction.is_none());
        assert!(!raw.replay.replayable);
        let attested = parsed.attested_inference().unwrap();
        raw.events
            .push(crate::routing::attested::attested_exchange_event(
                attested.call,
            ));
        let body = crate::witness::transport::witness_request_body(
            &raw,
            &crate::witness::transport::GrantedConsent::default(),
            attested.receipt,
        )
        .unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            wire["raw_contribution"]["events"].as_array().unwrap().len(),
            1
        );
        assert!(
            !String::from_utf8(body)
                .unwrap()
                .contains("UNATTESTED-HISTORY-SENTINEL")
        );
        assert!(
            PreparedImport::parse(&encoded(&fixture("second-client", false)))
                .unwrap()
                .witness_input(&cfg)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_file_loader_refuses_symlinks_and_oversized_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ordinary.json");
        std::fs::write(&path, encoded(&fixture("second-client", false))).unwrap();
        assert!(read_import(&path).is_ok());
        let link = dir.path().join("alias.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_import(&link).is_err());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_IMPORT_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(
            read_import(&path).unwrap_err().to_string(),
            "import-too-large"
        );
    }

    #[test]
    fn corrupt_and_oversized_imports_fail_before_use() {
        for bytes in [b"{".as_slice(), &[0xff, 0xfe]] {
            assert!(PreparedImport::parse(bytes).is_err());
        }
        assert!(PreparedImport::parse(&vec![b' '; MAX_IMPORT_BYTES + 1]).is_err());
        let mut doc = fixture("opencode", true);
        doc.inference.as_mut().unwrap().response_body =
            "x".repeat(trace_commons_protocol::evidence_import::MAX_IMPORT_BODY_BYTES + 1);
        assert!(PreparedImport::parse(&encoded(&doc)).is_err());
    }
}
