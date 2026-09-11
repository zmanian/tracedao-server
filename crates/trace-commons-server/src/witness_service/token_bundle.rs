// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Restricted token bundles derived from the final verified inference exchange.
//! Earlier calls never inherit the final call's receipt. No raw token arrays
//! supplied by the contributor are accepted by this service.
use super::*;
use trace_commons_protocol::{token_distribution::*, token_distribution_chat::extract_chat_tokens};

pub const TOKEN_BUNDLE_POLICY: &str = "token-distribution-restricted-v1";
const MAX_CANDIDATE_CHECKS: usize = 512;
const MAX_CANDIDATE_BYTES: usize = 65536;

/// Local source identities are attribution; provider evidence binds the bytes.
pub struct TokenBundleOptions {
    pub capture_store_id: String,
    pub capture_id: String,
    pub bundle_revision: String,
    pub restricted_token_consent: bool,
}
pub struct WitnessTokenBundle {
    pub contribution: WitnessContributionResponse,
    pub manifest_bytes: Vec<u8>,
    pub attachment_bytes: Vec<u8>,
    pub certificate: WitnessCertificate,
    pub signature_hex: String,
    pub admission: Option<(trace_commons_protocol::admission::AdmissionEvidence, String)>,
}

struct MappedRedactor<'a> {
    inner: &'a dyn ContributionRedactor,
    maps: std::sync::Mutex<
        std::collections::BTreeMap<
            uuid::Uuid,
            trace_commons_protocol::private_edit_map::PrivateRedactionEdits,
        >,
    >,
}
#[async_trait::async_trait]
impl ContributionRedactor for MappedRedactor<'_> {
    async fn redact(
        &self,
        raw: RawTraceContribution,
    ) -> Result<RedactedContribution, SeamUnavailable> {
        let (result, maps) = self.inner.redact_with_edits(raw).await?;
        *self.maps.lock().map_err(|_| SeamUnavailable)? = maps;
        Ok(result)
    }
}

pub async fn witness_token_bundle(
    mut request: WitnessContributionRequest,
    options: TokenBundleOptions,
    policy: &InferenceAttestationPolicy,
    redactor: &dyn ContributionRedactor,
    alternative_redactor: &dyn TranscriptRedactor,
    signer: &dyn Signer,
    enclave: &dyn Enclave,
) -> Result<WitnessTokenBundle, WitnessError> {
    use trace_commons_protocol::trace_contribution::TraceContributionEventType;
    let refuse = || WitnessError::ArtifactBindingFailed;
    for id in [&options.capture_store_id, &options.capture_id] {
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(refuse());
        }
    }
    if !options.restricted_token_consent || request.offered_receipt.is_none() {
        return Err(WitnessError::InferenceAttestationMissing);
    }
    let verified = check_inference_attestation(
        policy,
        request.offered_receipt.as_ref(),
        &WitnessedSession::Contribution(&request.raw_contribution),
    )?;
    if verified.verified != 1 {
        return Err(WitnessError::InferenceAttestationMissing);
    }
    let exchange = request
        .raw_contribution
        .events
        .iter()
        .rev()
        .find(|e| e.event_type == TraceContributionEventType::HttpExchange)
        .ok_or_else(refuse)?;
    let (request_body, response_body) = inference::exchange_bodies(exchange).ok_or_else(refuse)?;
    let request_json: serde_json::Value =
        serde_json::from_str(request_body).map_err(|_| refuse())?;
    let streaming = request_json
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let requested_model = request_json
        .get("model")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(refuse)?
        .to_string();
    let mut segments =
        extract_chat_tokens(response_body.as_bytes(), streaming).map_err(|_| refuse())?;
    if segments.len() != 1 {
        return Err(refuse());
    }
    let segment = segments.remove(0);
    // Admission accepts exactly one verified HTTP exchange. Derive the
    // assistant event from those receipt-bound bytes inside the witness,
    // rather than trusting an importer-supplied companion transcript.
    if request.raw_contribution.events.len() != 1 {
        return Err(refuse());
    }
    let mut event = exchange.clone();
    event.event_id = uuid::Uuid::new_v4();
    event.event_type = TraceContributionEventType::AssistantMessage;
    event.content = Some(String::from_utf8(segment.text.clone()).map_err(|_| refuse())?);
    event.structured_payload = serde_json::json!({});
    event.parent_event_id = None;
    event.tool_name = None;
    event.tool_call_id = None;
    event.latency_ms = None;
    event.token_counts = None;
    event.cost_usd = None;
    event.success = None;
    event.failure_modes.clear();
    let event_id = event.event_id.to_string();
    request.raw_contribution.events.push(event);
    let source = TokenDistribution {
        version: SCHEMA_VERSION,
        capture_store_id: options.capture_store_id,
        exchange_id: options.capture_id,
        event_id: event_id.clone(),
        choice: segment.choice,
        segment: 0,
        requested_model,
        // A friendly alias is not a verified tokenizer or model revision.
        served_model: None,
        tokenizer: None,
        semantics: ProbabilitySemantics::Unknown,
        conditioning: Conditioning::Unknown,
        requested_alternatives: request_json
            .get("top_logprobs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .min(20) as u32,
        response_digest: ContentDigest::of(&segment.text),
        records: segment.records,
    };
    source.validate(&segment.text).map_err(|_| refuse())?;
    let mapped = MappedRedactor {
        inner: redactor,
        maps: Default::default(),
    };
    let contribution = witness_contribution(request, policy, &mapped, signer, enclave).await?;
    let envelope: TraceContributionEnvelope =
        serde_json::from_slice(&contribution.envelope_bytes).map_err(|_| refuse())?;
    if contribution.certificate.claimed_redaction_policy_version()
        == DETERMINISTIC_REDACTION_PIPELINE_VERSION
    {
        return Err(WitnessError::RedactionFailed);
    }
    let consent_bytes = serde_json::to_vec(&(
        &envelope.consent.scopes,
        &envelope.trace_card.allowed_uses,
        TOKEN_BUNDLE_POLICY,
    ))
    .map_err(|_| refuse())?;
    let sanitized = envelope
        .events
        .iter()
        .find(|e| e.event_id.to_string() == event_id)
        .and_then(|e| e.redacted_content.as_deref())
        .ok_or_else(refuse)?;
    let event_uuid = uuid::Uuid::parse_str(&event_id).map_err(|_| refuse())?;
    let edits = mapped
        .maps
        .lock()
        .map_err(|_| refuse())?
        .remove(&event_uuid)
        .map(|map| map.0)
        .unwrap_or_else(|| {
            if sanitized.as_bytes() == segment.text {
                Vec::new()
            } else {
                vec![RedactionEdit {
                    original: ByteSpan {
                        start: 0,
                        end: segment.text.len() as u64,
                    },
                    replacement: sanitized.as_bytes().to_vec(),
                }]
            }
        });
    // These unscreened alternatives exist only in this private working value.
    // Every retained alternative below must pass the same classifier policy.
    let mut attachment = filter_with_edits(
        &source,
        &segment.text,
        sanitized.as_bytes(),
        &edits,
        TOKEN_BUNDLE_POLICY,
        |source, index, _| Some(vec![true; source.records[index].alternatives.len()]),
    )
    .map_err(|_| refuse())?;
    attachment.metadata.reported_model = segment.reported_model;
    attachment.metadata.evidence = Some(EvidenceCoverage::ProviderResponseVerified);
    for key in [
        "temperature",
        "top_p",
        "seed",
        "presence_penalty",
        "frequency_penalty",
        "max_tokens",
        "max_completion_tokens",
    ] {
        if let Some(value) = request_json.get(key).and_then(serde_json::Value::as_f64) {
            attachment.metadata.sampling.insert(key.into(), value);
        }
    }
    screen_alternatives(
        &mut attachment,
        &segment.text,
        sanitized,
        &edits,
        contribution.certificate.claimed_redaction_policy_version(),
        alternative_redactor,
    )
    .await?;
    attachment
        .validate(sanitized.as_bytes())
        .map_err(|_| refuse())?;
    let attachment_bytes = serde_json::to_vec(&attachment).map_err(|_| refuse())?;
    if attachment_bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(refuse());
    }
    let manifest = ContributionBundleManifest {
        version: SCHEMA_VERSION,
        usage_profile: TokenUsageProfile::RestrictedResearch,
        submission_id: envelope.submission_id.to_string(),
        bundle_revision: options.bundle_revision,
        envelope_digest: ContentDigest::of(&contribution.envelope_bytes),
        consent_digest: ContentDigest::of(&consent_bytes),
        policy_version: TOKEN_BUNDLE_POLICY.into(),
        attachments: vec![AttachmentDescriptor {
            artifact_id: uuid::Uuid::new_v4().to_string(),
            event_id,
            content_digest: ContentDigest::of(&attachment_bytes),
            size_bytes: attachment_bytes.len() as u64,
        }],
    };
    let manifest_bytes = manifest.canonical_bytes().map_err(|_| refuse())?;
    let text = std::str::from_utf8(&manifest_bytes).map_err(|_| refuse())?;
    let proof = check_correspondence(text, text, &[]).map_err(|_| refuse())?;
    let certificate = WitnessCertificate::from_proof(
        proof,
        CertificateDetails {
            residual_risk_verdict: contribution.residual_risk_verdict(),
            redaction_policy_version: TOKEN_BUNDLE_POLICY.into(),
            witness_measurement: enclave
                .measurement()
                .await
                .map_err(|_| WitnessError::MeasurementUnavailable)?,
            timestamp: chrono::Utc::now().timestamp(),
        },
    );
    let signature_hex = signer
        .sign_eip191(&certificate.signing_bytes())
        .map_err(|_| WitnessError::SigningUnavailable)?;
    Ok(WitnessTokenBundle {
        admission: None,
        contribution,
        manifest_bytes,
        attachment_bytes,
        certificate,
        signature_hex,
    })
}

async fn screen_alternatives(
    attachment: &mut SanitizedTokenAttachment,
    original: &[u8],
    sanitized: &str,
    edits: &[RedactionEdit],
    policy_version: &str,
    alternative_redactor: &dyn TranscriptRedactor,
) -> Result<(), WitnessError> {
    let removed_bytes: usize = edits
        .iter()
        .map(|edit| (edit.original.end - edit.original.start) as usize)
        .sum();
    let mut checks = 0usize;
    for record in &mut attachment.records {
        let alternatives = std::mem::take(&mut record.alternatives);
        for alternative in alternatives {
            let mut keep = false;
            let mut unsupported = false;
            let mut budget = checks >= MAX_CANDIDATE_CHECKS
                || sanitized.len() > MAX_CANDIDATE_BYTES
                || removed_bytes > MAX_CANDIDATE_BYTES;
            let sensitive_fragment = removed_bytes > MAX_CANDIDATE_BYTES
                || edits.iter().any(|edit| {
                    let removed =
                        &original[edit.original.start as usize..edit.original.end as usize];
                    !alternative.bytes.is_empty()
                        && removed
                            .windows(alternative.bytes.len())
                            .any(|part| part == alternative.bytes)
                });
            if !sensitive_fragment
                && checks < MAX_CANDIDATE_CHECKS
                && sanitized.len() <= MAX_CANDIDATE_BYTES
            {
                let mut candidate = Vec::new();
                candidate.extend_from_slice(&sanitized.as_bytes()[..record.span.start as usize]);
                candidate.extend_from_slice(&alternative.bytes);
                candidate.extend_from_slice(&sanitized.as_bytes()[record.span.end as usize..]);
                if candidate.len() <= MAX_CANDIDATE_BYTES {
                    if let Ok(candidate) = String::from_utf8(candidate) {
                        checks += 1;
                        let filtered = alternative_redactor
                            .redact(&candidate)
                            .await
                            .map_err(|_| WitnessError::RedactionFailed)?;
                        if filtered.policy_version != policy_version {
                            return Err(WitnessError::RedactionFailed);
                        }
                        keep = filtered.redacted == candidate;
                    } else {
                        unsupported = true;
                    }
                } else {
                    budget = true;
                }
            }
            if keep {
                record.alternatives.push(alternative);
            } else {
                attachment.omitted_alternatives += 1;
                if budget {
                    attachment.metadata.budget_alternatives += 1;
                } else if unsupported {
                    attachment.metadata.unsupported_alternatives += 1;
                } else {
                    attachment.metadata.redacted_alternatives += 1;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token(bytes: &[u8]) -> TokenValue {
        TokenValue {
            bytes: bytes.to_vec(),
            token_id: None,
            logprob: LogProbability::Finite(-1.25),
        }
    }
    fn source(parts: &[&[u8]]) -> TokenDistribution {
        let mut offset = 0;
        TokenDistribution {
            version: SCHEMA_VERSION,
            capture_store_id: "store-1".into(),
            exchange_id: "exchange-1".into(),
            event_id: "event-1".into(),
            choice: 0,
            segment: 0,
            requested_model: "model".into(),
            served_model: None,
            tokenizer: None,
            semantics: ProbabilitySemantics::Unknown,
            conditioning: Conditioning::Original,
            requested_alternatives: 20,
            response_digest: ContentDigest::of(&parts.concat()),
            records: parts
                .iter()
                .enumerate()
                .map(|(i, bytes)| {
                    let start = offset;
                    offset += bytes.len() as u64;
                    TokenRecord {
                        index: i as u64,
                        span: ByteSpan { start, end: offset },
                        chosen: token(bytes),
                        alternatives: vec![token(b"alternative")],
                        returned_alternatives: 1,
                    }
                })
                .collect(),
        }
    }

    struct Classifier {
        fails: bool,
    }
    #[async_trait::async_trait]
    impl TranscriptRedactor for Classifier {
        async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
            if self.fails {
                return Err(SeamUnavailable);
            }
            Ok(RedactedTranscript {
                redacted: raw.replace("Bob", "[name]"),
                report: RedactionReport::default(),
                policy_version: "p1".into(),
            })
        }
    }
    #[tokio::test]
    async fn alternatives_use_shifted_sanitized_context_and_remove_secret_fragments() {
        let mut source = source(&[b"Alice", b" says", b" hello"]);
        source.records[2].alternatives = vec![token(b" Bob"), token(b"Ali"), token(b" goodbye")];
        source.records[2].returned_alternatives = 3;
        let edits = vec![RedactionEdit {
            original: ByteSpan { start: 0, end: 5 },
            replacement: b"[name]".to_vec(),
        }];
        let sanitized = "[name] says hello";
        let mut filtered = filter_with_edits(
            &source,
            b"Alice says hello",
            sanitized.as_bytes(),
            &edits,
            "p1",
            |s, index, _| Some(vec![true; s.records[index].alternatives.len()]),
        )
        .unwrap();
        screen_alternatives(
            &mut filtered,
            b"Alice says hello",
            sanitized,
            &edits,
            "p1",
            &Classifier { fails: false },
        )
        .await
        .unwrap();
        let last = filtered.records.last().unwrap();
        assert_eq!(last.alternatives.len(), 1);
        assert_eq!(last.alternatives[0].bytes, b" goodbye");
        assert!(matches!(
            last.alternatives[0].logprob,
            LogProbability::Finite(-1.25)
        ));
        assert_eq!(last.span, ByteSpan { start: 11, end: 17 });
        filtered.validate(sanitized.as_bytes()).unwrap();
    }
    #[tokio::test]
    async fn final_allowed_classifier_check_is_redaction_not_budget_exhaustion() {
        let words = vec![b"hello".as_slice(); 26];
        let original = b"hello".repeat(26);
        let mut raw = source(&words);
        raw.requested_alternatives = 20;
        for record in &mut raw.records {
            record.alternatives = vec![token(b"Bob"); 20];
            record.returned_alternatives = 20;
        }
        let mut filtered = filter_with_edits(&raw, &original, &original, &[], "p1", |_, _, _| {
            Some(vec![true; 20])
        })
        .unwrap();
        screen_alternatives(
            &mut filtered,
            &original,
            std::str::from_utf8(&original).unwrap(),
            &[],
            "p1",
            &Classifier { fails: false },
        )
        .await
        .unwrap();
        assert_eq!(
            filtered.metadata.redacted_alternatives,
            MAX_CANDIDATE_CHECKS as u64
        );
        assert_eq!(
            filtered.metadata.budget_alternatives,
            520 - MAX_CANDIDATE_CHECKS as u64
        );
        assert_eq!(filtered.omitted_alternatives, 520);
    }

    #[tokio::test]
    async fn classifier_outage_refuses_and_context_budget_omits_alternatives() {
        let source = source(&[b"hello"]);
        let mut filtered = filter_with_edits(&source, b"hello", b"hello", &[], "p1", |_, _, _| {
            Some(vec![true])
        })
        .unwrap();
        assert!(
            screen_alternatives(
                &mut filtered,
                b"hello",
                "hello",
                &[],
                "p1",
                &Classifier { fails: true }
            )
            .await
            .is_err()
        );
        let long = "a".repeat(MAX_CANDIDATE_BYTES + 1);
        let source = source_for_long(&long);
        let mut filtered = filter_with_edits(
            &source,
            long.as_bytes(),
            long.as_bytes(),
            &[],
            "p1",
            |_, _, _| Some(vec![true]),
        )
        .unwrap();
        screen_alternatives(
            &mut filtered,
            long.as_bytes(),
            &long,
            &[],
            "p1",
            &Classifier { fails: true },
        )
        .await
        .unwrap();
        assert!(filtered.records[0].alternatives.is_empty());
        assert_eq!(filtered.omitted_alternatives, 2);
    }
    fn source_for_long(long: &str) -> TokenDistribution {
        source(&[&long.as_bytes()[..32768], &long.as_bytes()[32768..]])
    }
}
