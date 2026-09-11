// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::Utc;
use secrecy::SecretString;
use std::collections::BTreeMap;
use trace_commons_protocol::token_distribution::*;
use trace_commons_server::{
    config::{DatabaseConfig, SslMode},
    db::{Database, postgres::PgBackend},
    token_bundle_store::StoredTokenBundle,
    trace_corpus_storage::TraceCorpusStore,
};

#[tokio::test]
async fn bundle_staging_is_immutable_and_owner_scoped() {
    let Ok(url) = std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL") else {
        return;
    };
    let db = PgBackend::new(&DatabaseConfig {
        url: SecretString::from(url.clone()),
        pool_size: 4,
        ssl_mode: SslMode::Prefer,
        login_resolver_url: None,
        gate_driver_url: None,
        pii_backstop_driver_url: None,
        invite_registry_url: None,
    })
    .await
    .unwrap();
    db.run_migrations().await.unwrap();
    let tenant = format!("bundle-test-{}", uuid::Uuid::new_v4());
    let submission = uuid::Uuid::new_v4();
    let (envelope_bytes, token_bytes, event_id) = bundle_payloads(submission);
    let bundle = StoredTokenBundle {
        tenant_id: tenant.clone(),
        submission_id: submission,
        revision: "revision".into(),
        owner_ref: "owner".into(),
        manifest: ContributionBundleManifest {
            version: 1,
            usage_profile: TokenUsageProfile::RestrictedResearch,
            submission_id: submission.to_string(),
            bundle_revision: "revision".into(),
            envelope_digest: ContentDigest::of(&envelope_bytes),
            consent_digest: ContentDigest::of(b"consent"),
            policy_version: "policy".into(),
            attachments: vec![AttachmentDescriptor {
                artifact_id: "tokens".into(),
                event_id,
                content_digest: ContentDigest::of(&token_bytes),
                size_bytes: token_bytes.len() as u64,
            }],
        },
        witness_headers: BTreeMap::new(),
        state: "staging".into(),
        processing_state: "pending".into(),
        processing_summary: None,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        receipt: None,
        attachments: Vec::new(),
    };
    let (first, retry) = tokio::join!(
        db.begin_token_bundle(bundle.clone()),
        db.begin_token_bundle(bundle.clone())
    );
    first.unwrap();
    retry.unwrap();
    // Exercise actual RLS under a non-superuser role, not just application predicates.
    let (mut raw, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let tx = raw.transaction().await.unwrap();
    let role = format!("tc_bundle_test_{}", uuid::Uuid::new_v4().simple());
    tx.batch_execute(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
        GRANT SELECT, INSERT ON trace_token_bundles, trace_token_attachments TO {role};
        SET LOCAL ROLE {role};"
    ))
    .await
    .unwrap();
    let bypass: bool = tx
        .query_one(
            "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!bypass);
    tx.query_one(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    let own: i64 = tx
        .query_one("SELECT count(*) FROM trace_token_bundles", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(own, 1);
    tx.query_one(
        "SELECT set_config('trace_commons.trace_tenant_id', 'other-bundle-tenant', true)",
        &[],
    )
    .await
    .unwrap();
    let other: i64 = tx
        .query_one("SELECT count(*) FROM trace_token_bundles", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(other, 0);
    let error = tx.execute("INSERT INTO trace_token_bundles (tenant_id,submission_id,revision,owner_ref,manifest_digest,witness_headers,manifest,state,expires_at) VALUES ($1,$2,'rls','owner',$3,'{}','{}','staging',NOW())", &[&tenant,&uuid::Uuid::new_v4(),&bundle.manifest.digest().unwrap().as_str()]).await.unwrap_err();
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
    );
    tx.rollback().await.unwrap(); // Also removes the disposable role and grants.

    assert!(
        db.get_token_bundle(&tenant, submission, "revision", "other-owner")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_token_bundle("other-tenant", submission, "revision", "owner")
            .await
            .unwrap()
            .is_none()
    );
    let mut changed = bundle.clone();
    changed.manifest.envelope_digest = ContentDigest::of(b"different");
    assert!(db.begin_token_bundle(changed).await.is_err());
    let receipt = DurableBundleReceipt {
        version: 1,
        server_id: "server".into(),
        tenant_id: tenant.clone(),
        account_id: "owner".into(),
        submission_id: submission.to_string(),
        bundle_revision: "revision".into(),
        manifest_digest: bundle.manifest.digest().unwrap(),
        committed_at_unix: Utc::now().timestamp() as u64,
        retain_until_unix: Utc::now().timestamp() as u64 + 3600,
        retention_policy_version: "policy".into(),
    };
    assert!(
        db.commit_token_bundle(&tenant, submission, "revision", "owner", receipt.clone())
            .await
            .is_err()
    );
    // Quotas also apply before a parent submission is admitted.
    for index in 1..16 {
        let mut next = bundle.clone();
        next.submission_id = uuid::Uuid::new_v4();
        next.manifest.submission_id = next.submission_id.to_string();
        next.revision = format!("revision-{index}");
        next.manifest.bundle_revision = next.revision.clone();
        db.begin_token_bundle(next).await.unwrap();
    }
    let mut excess = bundle.clone();
    excess.submission_id = uuid::Uuid::new_v4();
    excess.manifest.submission_id = excess.submission_id.to_string();
    assert!(db.begin_token_bundle(excess).await.is_err());
    db.begin_token_bundle(bundle.clone()).await.unwrap();
    qualify_publication_commit_and_withdrawal(
        &db,
        &url,
        bundle,
        receipt,
        &envelope_bytes,
        &token_bytes,
    )
    .await;
}

async fn qualify_publication_commit_and_withdrawal(
    db: &PgBackend,
    url: &str,
    bundle: StoredTokenBundle,
    receipt: DurableBundleReceipt,
    envelope_bytes: &[u8],
    token_bytes: &[u8],
) {
    use trace_commons_server::secrets::SecretsCrypto;
    use trace_commons_server::token_bundle_store::StoredTokenObject;
    use trace_commons_server::trace_artifact_store::*;
    use trace_commons_server::trace_corpus_storage::{TraceCorpusStatus, TraceSubmissionWrite};
    let tenant = &bundle.tenant_id;
    let submission = bundle.submission_id;
    db.upsert_trace_submission(TraceSubmissionWrite {
        tenant_id: tenant.clone(),
        submission_id: submission,
        trace_id: uuid::Uuid::new_v4(),
        auth_principal_ref: "owner".into(),
        contributor_pseudonym: None,
        submitted_tenant_scope_ref: Some(tenant.clone()),
        schema_version: "ironclaw.trace_contribution.v1".into(),
        consent_policy_version: "policy".into(),
        consent_scopes: vec!["debugging_evaluation".into()],
        allowed_uses: vec!["debugging".into()],
        retention_policy_id: "private_corpus_revocable".into(),
        status: TraceCorpusStatus::Accepted,
        privacy_risk: "low".into(),
        redaction_pipeline_version: "policy".into(),
        redaction_counts: BTreeMap::new(),
        redaction_hash: "hash".into(),
        canonical_summary_hash: None,
        submission_score: None,
        credit_points_pending: None,
        credit_points_final: None,
        expires_at: None,
        residual_risk_basis: None,
    })
    .await
    .unwrap();
    let crypto = || SecretsCrypto::new(SecretString::from("11".repeat(32))).unwrap();
    let objects = tempfile::tempdir().unwrap();
    let store = ServiceOwnedTraceArtifactStore::new(
        TraceArtifactProviderConfig::service_owned_remote("bundle-test").unwrap(),
        crypto(),
        trace_commons_server::trace_artifact_kek::LocalMasterKeyWrapper::new(crypto(), "test-kek"),
        FileRemoteTraceArtifactProvider::new(objects.path()),
    );
    let scope = TraceArtifactScope {
        tenant_storage_ref: tenant.clone(),
        submission_storage_ref: submission.to_string(),
    };
    for (artifact, kind, bytes) in [
        ("tokens", TraceArtifactKind::TokenDistribution, token_bytes),
        (
            "envelope",
            TraceArtifactKind::ContributionEnvelope,
            envelope_bytes,
        ),
    ] {
        let prepared = store
            .prepare_bundle_bytes(&scope, kind, artifact, bytes)
            .unwrap();
        db.stage_token_object(
            tenant,
            submission,
            "revision",
            "owner",
            StoredTokenObject {
                artifact_id: artifact.into(),
                object_ref: prepared.object_ref.clone(),
                deleted: false,
                ready: false,
                prepared: Some(serde_json::to_vec(&prepared).unwrap()),
            },
        )
        .await
        .unwrap();
        // Crash boundary: ciphertext exists, but no ready marker or receipt.
        store.publish_bundle_bytes(&scope, &prepared).unwrap();
        assert!(
            db.commit_token_bundle(tenant, submission, "revision", "owner", receipt.clone())
                .await
                .is_err()
        );
        db.publish_token_object(tenant, submission, "revision", "owner", artifact, &store)
            .await
            .unwrap();
        db.publish_token_object(tenant, submission, "revision", "owner", artifact, &store)
            .await
            .unwrap();
    }
    let (first, retry) = tokio::join!(
        db.commit_token_bundle(tenant, submission, "revision", "owner", receipt.clone()),
        db.commit_token_bundle(tenant, submission, "revision", "owner", receipt.clone())
    );
    assert_eq!(
        first.unwrap().manifest_digest,
        retry.unwrap().manifest_digest
    );
    assert_eq!(db.process_token_bundles(tenant, &store).await.unwrap(), 1);
    assert_eq!(db.process_token_bundles(tenant, &store).await.unwrap(), 0);
    let query = trace_commons_server::token_bundle_store::TokenBundleQuery {
        model: Some("fixture-model".into()),
        requested_alternatives: Some(5),
        minimum_coverage: Some(1.0),
        ..Default::default()
    };
    let entries = db
        .query_token_bundles(tenant, Some("owner"), &query)
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].summary[0]["mean_chosen_surprisal"], 1.25);
    assert!(
        db.query_token_bundles(tenant, Some("other"), &query)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.query_token_bundles("other-tenant", None, &query)
            .await
            .unwrap()
            .is_empty()
    );
    let stored = db
        .get_token_bundle(tenant, submission, "revision", "owner")
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored
            .attachments
            .iter()
            .all(|a| a.ready && a.prepared.is_none())
    );
    // Parent revocation blocks access before object deletion and prevents a
    // publication retry or a new revision from resurrecting the contribution.
    let (mut client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rescrub = client.transaction().await.unwrap();
    rescrub.execute("UPDATE trace_submissions SET redaction_hash='changed-redaction' WHERE tenant_id=$1 AND submission_id=$2", &[tenant,&submission]).await.unwrap();
    let invalidated = rescrub.query_one("SELECT state,processing_state,processing_summary FROM trace_token_bundles WHERE tenant_id=$1 AND submission_id=$2", &[tenant,&submission]).await.unwrap();
    assert_eq!(invalidated.get::<_, String>(0), "revoked");
    assert_eq!(invalidated.get::<_, String>(1), "revoked");
    assert!(invalidated.get::<_, Option<serde_json::Value>>(2).is_none());
    rescrub.rollback().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.query_one("SELECT submission_id FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 FOR UPDATE", &[tenant, &submission]).await.unwrap();
    let mut racing = bundle.clone();
    racing.revision = "racing-revision".into();
    racing.manifest.bundle_revision = racing.revision.clone();
    let beginning = db.begin_token_bundle(racing);
    tokio::pin!(beginning);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut beginning)
            .await
            .is_err(),
        "begin must wait for the parent lifecycle lock"
    );
    tx.execute("INSERT INTO trace_withdrawals(tenant_id,submission_id,withdrawn_at,prior_status,distribution_reach) VALUES($1,$2,NOW(),'accepted','not_distributed')", &[tenant,&submission]).await.unwrap();
    tx.execute("UPDATE trace_submissions SET status='revoked',withdrawn_at=NOW() WHERE tenant_id=$1 AND submission_id=$2", &[tenant, &submission]).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        beginning.await.is_err(),
        "withdrawal prevents a racing new revision"
    );
    assert_eq!(
        db.get_token_bundle(tenant, submission, "revision", "owner")
            .await
            .unwrap()
            .unwrap()
            .state,
        "revoked"
    );
    // Simulate restoring stale child rows after the parent tombstone. Reads,
    // metadata discovery and processing must still refuse the restored revision.
    client.execute("UPDATE trace_token_bundles SET state='committed',processing_state='ready',processing_summary='[]' WHERE tenant_id=$1 AND submission_id=$2", &[tenant,&submission]).await.unwrap();
    client.execute("UPDATE trace_submissions SET status='accepted',withdrawn_at=NULL WHERE tenant_id=$1 AND submission_id=$2", &[tenant,&submission]).await.unwrap();
    let restored = db
        .get_token_bundle(tenant, submission, "revision", "owner")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.state, "revoked");
    assert!(restored.processing_summary.is_none());
    assert!(
        db.query_token_bundles(tenant, None, &query)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(db.process_token_bundles(tenant, &store).await.unwrap(), 0);
    db.pending_token_bundle_deletions(tenant, Some(submission))
        .await
        .unwrap();
    assert!(
        db.publish_token_object(tenant, submission, "revision", "owner", "tokens", &store)
            .await
            .is_err()
    );
    assert!(
        db.query_token_bundles(tenant, None, &query)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(db.process_token_bundles(tenant, &store).await.unwrap(), 0);
    assert!(db.begin_token_bundle(bundle.clone()).await.is_err());
    assert!(
        db.delete_token_objects(
            tenant,
            submission,
            "revision",
            &["private_corpus_revocable".into()],
            &store
        )
        .await
        .is_err()
    );
    for object in &stored.attachments {
        assert!(store.read_bundle_bytes(&scope, &object.object_ref).is_ok());
    }
    db.delete_token_objects(tenant, submission, "revision", &[], &store)
        .await
        .unwrap();
    db.delete_token_objects(tenant, submission, "revision", &[], &store)
        .await
        .unwrap();
    assert!(
        db.get_token_bundle(tenant, submission, "revision", "owner")
            .await
            .unwrap()
            .unwrap()
            .attachments
            .iter()
            .all(|a| a.deleted && a.prepared.is_none())
    );
    for object in stored.attachments {
        assert!(store.read_bundle_bytes(&scope, &object.object_ref).is_err());
    }
}

fn envelope_with_events(
    events: Vec<trace_commons_protocol::trace_contribution::TraceContributionEvent>,
) -> trace_commons_protocol::trace_contribution::TraceContributionEnvelope {
    use trace_commons_protocol::trace_contribution::*;
    use uuid::Uuid;
    let now = Utc::now();
    TraceContributionEnvelope {
        schema_version: TRACE_CONTRIBUTION_SCHEMA_VERSION.to_string(),
        trace_id: Uuid::new_v4(),
        submission_id: Uuid::new_v4(),
        created_at: now,
        ironclaw: IronclawTraceMetadata {
            version: "1".to_string(),
            engine_version: None,
            feature_flags: BTreeMap::new(),
            channel: TraceChannel::Cli,
            model_name: None,
        },
        consent: ConsentMetadata {
            policy_version: TRACE_CONTRIBUTION_POLICY_VERSION.to_string(),
            scopes: vec![ConsentScope::DebuggingEvaluation],
            message_text_included: false,
            tool_payloads_included: false,
            correction_included: false,
            routing_metadata_included: true,
            revocable: true,
        },
        contributor: ContributorMetadata {
            pseudonymous_contributor_id: None,
            tenant_scope_ref: None,
            credit_account_ref: None,
            revocation_handle: Uuid::new_v4(),
        },
        privacy: PrivacyMetadata {
            redaction_pipeline_version: DETERMINISTIC_REDACTION_PIPELINE_VERSION.to_string(),
            redaction_counts: BTreeMap::new(),
            redaction_distinct_counts: BTreeMap::new(),
            privacy_filter_summary: None,
            pii_labels_present: Vec::new(),
            residual_pii_risk: ResidualPiiRisk::Low,
            redaction_hash: "sha256:placeholder".to_string(),
            warnings: Vec::new(),
        },
        events,
        outcome: OutcomeMetadata::default(),
        replay: ReplayMetadata {
            replayable: false,
            required_tools: Vec::new(),
            tool_manifest_hashes: BTreeMap::new(),
            expected_assertions: Vec::new(),
            replay_notes: Vec::new(),
        },
        embedding_analysis: None,
        value: ValueMetadata::default(),
        conversation_id: None,
        trace_card: TraceCard::default(),
        value_card: TraceValueCard::default(),
        hindsight: None,
        training_dynamics: None,
        process_evaluation: None,
    }
}

fn bundle_payloads(submission: uuid::Uuid) -> (Vec<u8>, Vec<u8>, String) {
    use trace_commons_protocol::trace_contribution::*;
    let event_id = uuid::Uuid::new_v4();
    let event = TraceContributionEvent {
        event_id,
        parent_event_id: None,
        event_type: TraceContributionEventType::AssistantMessage,
        timestamp: Utc::now(),
        redacted_content: Some("blue".into()),
        structured_payload: serde_json::json!({}),
        tool_name: None,
        tool_category: None,
        tool_call_id: None,
        latency_ms: None,
        token_counts: None,
        cost_usd: None,
        success: None,
        failure_modes: vec![],
        side_effect: SideEffectLevel::None,
    };
    let mut envelope = envelope_with_events(vec![event]);
    envelope.submission_id = submission;
    let source = TokenDistribution {
        version: 1,
        capture_store_id: "store".into(),
        exchange_id: "exchange".into(),
        event_id: event_id.to_string(),
        choice: 0,
        segment: 0,
        requested_model: "fixture-model".into(),
        served_model: None,
        tokenizer: None,
        semantics: ProbabilitySemantics::Unknown,
        conditioning: Conditioning::Unknown,
        requested_alternatives: 5,
        response_digest: ContentDigest::of(b"blue"),
        records: vec![TokenRecord {
            index: 0,
            span: ByteSpan { start: 0, end: 4 },
            chosen: TokenValue {
                bytes: b"blue".to_vec(),
                token_id: None,
                logprob: LogProbability::Finite(-1.25),
            },
            alternatives: vec![],
            returned_alternatives: 0,
        }],
    };
    let attachment = filter_with_edits(&source, b"blue", b"blue", &[], "policy", |_, _, _| {
        Some(vec![])
    })
    .unwrap();
    (
        serde_json::to_vec(&envelope).unwrap(),
        serde_json::to_vec(&attachment).unwrap(),
        event_id.to_string(),
    )
}
