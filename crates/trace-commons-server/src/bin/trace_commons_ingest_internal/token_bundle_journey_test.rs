// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

/// The provider and witness signer are fixtures; ingest HTTP, encrypted storage,
/// PostgreSQL processing, client approval pin and receipt journal are real.
#[tokio::test]
async fn token_bundle_http_journey_recovers_a_lost_finalize_response() {
    use std::sync::atomic::Ordering;
    use trace_commons_contributor::token_bundle::{
        BundleDestination, BundleJournal, BundleLease, BundleLeaseReleaser, CertifiedBundleUpload,
    };
    use trace_commons_contributor::witness::transport::WitnessedEnvelope;
    use trace_commons_protocol::token_distribution::*;
    use trace_commons_protocol::token_distribution_chat::extract_chat_tokens;
    use trace_commons_server::witness_service::token_bundle::TOKEN_BUNDLE_POLICY;
    if std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL").is_err() {
        return;
    }
    let db = postgres_backend_for_ingest_test()
        .await
        .expect("configured journey database must connect and migrate");
    // This fixture is run with an explicit server identifier to avoid mutating
    // process-global settings while the rest of the ingest suite runs.
    if std::env::var("TRACE_COMMONS_BUNDLE_SERVER_ID").is_err() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let objects = tempfile::tempdir().unwrap();
    let (store, _) = fixture_gate_worker_artifact_store(objects.path());
    let mut state = test_state(temp.path().to_path_buf());
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.db_mirror = Some(db.clone());
    mutable.artifact_store = Some(store);
    mutable.require_db_mirror_writes = true;
    mutable.accept_medium_risk_submissions = true;
    mutable.witness_bypass =
        trace_commons_server::redaction_witness::config::witness_bypass_config_from_values(
            Some("true"),
            Some(&witness_receipt::signing_address()),
            Some(&"c1".repeat(32)),
            Some(TOKEN_BUNDLE_POLICY),
            None,
        )
        .unwrap();
    let tenant = authenticate_ctx(&state, &auth_headers("token-a")).unwrap();
    let mut envelope = sample_envelope_with_user_input("blue").await;
    make_metadata_only_low_risk(&mut envelope);
    set_metadata_only_user_message(&mut envelope, "blue");
    let event = envelope
        .events
        .iter_mut()
        .find(|e| e.redacted_content.is_some())
        .unwrap();
    event.event_type =
        trace_commons_protocol::trace_contribution::TraceContributionEventType::AssistantMessage;
    let event_id = event.event_id.to_string();
    let wire = br#"{"id":"fixture","model":"fixture-model","choices":[{"index":0,"finish_reason":"stop","message":{"content":"blue"},"logprobs":{"content":[{"bytes":[98,108,117,101],"logprob":-1.25,"top_logprobs":[]}]}}]}"#;
    let capture = extract_chat_tokens(wire, false).unwrap().remove(0);
    let distribution = TokenDistribution {
        version: 1,
        capture_store_id: "fixture-store".into(),
        exchange_id: "fixture-capture".into(),
        event_id: event_id.clone(),
        choice: 0,
        segment: 0,
        requested_model: "fixture-model".into(),
        served_model: None,
        tokenizer: None,
        semantics: ProbabilitySemantics::Unknown,
        conditioning: Conditioning::Unknown,
        requested_alternatives: 0,
        response_digest: ContentDigest::of(&capture.text),
        records: capture.records,
    };
    let attachment = filter_with_edits(
        &distribution,
        &capture.text,
        b"blue",
        &[],
        TOKEN_BUNDLE_POLICY,
        |_, _, _| Some(vec![]),
    )
    .unwrap();
    let token_bytes = serde_json::to_vec(&attachment).unwrap();
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let manifest = ContributionBundleManifest {
        version: 1,
        usage_profile: TokenUsageProfile::RestrictedResearch,
        submission_id: envelope.submission_id.to_string(),
        bundle_revision: "journey-r1".into(),
        envelope_digest: ContentDigest::of(&envelope_bytes),
        consent_digest: ContentDigest::of(
            &serde_json::to_vec(&(
                &envelope.consent.scopes,
                &envelope.trace_card.allowed_uses,
                TOKEN_BUNDLE_POLICY,
            ))
            .unwrap(),
        ),
        policy_version: TOKEN_BUNDLE_POLICY.into(),
        attachments: vec![AttachmentDescriptor {
            artifact_id: "tokens".into(),
            event_id,
            content_digest: ContentDigest::of(&token_bytes),
            size_bytes: token_bytes.len() as u64,
        }],
    };
    let signed = |bytes: Vec<u8>| {
        let (certificate_json, signature_hex) =
            witness_receipt::certificate_for_policy(&bytes, "low", TOKEN_BUNDLE_POLICY);
        WitnessedEnvelope {
            envelope_bytes: bytes,
            certificate_json,
            signature_hex,
            admission: None,
        }
    };
    let payload = CertifiedBundleUpload {
        pinned_witness_address: witness_receipt::signing_address(),
        envelope: signed(envelope_bytes),
        manifest: signed(manifest.canonical_bytes().unwrap()),
        attachments: BTreeMap::from([("tokens".into(), token_bytes)]),
    };
    let local = tempfile::tempdir().unwrap();
    let journal = BundleJournal::open(&local.path().join("journal")).unwrap();
    let approval_started = std::time::Instant::now();
    let id = journal
        .prepare(
            manifest.clone(),
            BundleDestination {
                server_id: std::env::var("TRACE_COMMONS_BUNDLE_SERVER_ID").unwrap(),
                tenant_id: tenant.tenant_id().into(),
                account_id: tenant.principal_ref().into(),
            },
            BundleLease {
                capture_store_id: "fixture-store".into(),
                lease_id: "fixture-lease".into(),
                owner: "fixture-owner".into(),
                snapshot_digest: "fixture-snapshot".into(),
            },
        )
        .unwrap();
    journal.approve_payload(id, payload).unwrap();
    journal.mark_approved(id).unwrap();
    let approval_ms = approval_started.elapsed().as_millis();
    let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lost_response = lost.clone();
    let router = app(state.clone()).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let lost = lost_response.clone();
            async move {
                let finalize = request.method() == axum::http::Method::POST
                    && request.uri().path().ends_with("/journey-r1");
                let response = next.run(request).await;
                if finalize && response.status().is_success() && !lost.swap(true, Ordering::SeqCst)
                {
                    (StatusCode::SERVICE_UNAVAILABLE, "fixture-lost-response").into_response()
                } else {
                    response
                }
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = trace_commons_operator_client::Client::builder(endpoint, "unused")
        .bearer_token("token-a")
        .build()
        .unwrap();
    let upload_started = std::time::Instant::now();
    assert!(journal.upload_approved(id, &client).await.is_err());
    assert!(
        lost.load(Ordering::SeqCst),
        "the failure must occur after a successful real finalize"
    );
    let committed_parent = db
        .get_trace_submission(tenant.tenant_id(), envelope.submission_id)
        .await
        .unwrap()
        .unwrap();
    struct Release(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl BundleLeaseReleaser for Release {
        async fn release(&self, lease: &BundleLease) -> anyhow::Result<()> {
            assert_eq!(lease.lease_id, "fixture-lease");
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let release = Release(std::sync::atomic::AtomicUsize::new(0));
    assert!(journal.cleanup(id, &release).await.is_err());
    drop(journal);
    let restarted = BundleJournal::open(&local.path().join("journal")).unwrap();
    let receipt = restarted.upload_approved(id, &client).await.unwrap();
    assert_eq!(receipt.bundle_revision, "journey-r1");
    let cleanup_started = std::time::Instant::now();
    restarted.cleanup(id, &release).await.unwrap();
    restarted.cleanup(id, &release).await.unwrap();
    assert_eq!(release.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        db.process_token_bundles(
            tenant.tenant_id(),
            state.artifact_store.as_ref().unwrap().store.as_ref()
        )
        .await
        .unwrap(),
        0
    );
    assert!(restarted.upload_approved(id, &client).await.unwrap() == receipt);
    let recovered_parent = db
        .get_trace_submission(tenant.tenant_id(), envelope.submission_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_parent.submission_score,
        recovered_parent.submission_score
    );
    assert_eq!(
        committed_parent.credit_points_pending,
        recovered_parent.credit_points_pending
    );
    assert_eq!(
        committed_parent.credit_points_final,
        recovered_parent.credit_points_final
    );
    println!(
        "{}",
        serde_json::json!({"fixture":"token_bundle_http_journey","approval_ms":approval_ms,"upload_and_recovery_ms":upload_started.elapsed().as_millis(),"cleanup_ms":cleanup_started.elapsed().as_millis(),"upload_attempts":2,"lost_responses":1,"release_calls":release.0.load(Ordering::SeqCst),"cleanup_pending":restarted.storage_status(Utc::now().timestamp() as u64).unwrap()["cleanup_pending"]})
    );
    server.abort();
}
