// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in bundle transport. Existing transcript-only routes remain unchanged.
use super::*;
use axum::{http::header, response::Response};
use trace_commons_protocol::token_distribution::*;
use trace_commons_server::redaction_witness::request::{CERTIFICATE_HEADER, SIGNATURE_HEADER};
use trace_commons_server::witness_service::token_bundle::TOKEN_BUNDLE_POLICY;
use trace_commons_server::{token_bundle_store::*, trace_artifact_store::TraceArtifactScope};

fn gate(state: &AppState) -> ApiResult<(&ConfiguredTraceArtifactStore, String)> {
    let server = std::env::var("TRACE_COMMONS_BUNDLE_SERVER_ID")
        .ok()
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "token_bundles_disabled"))?;
    let store = state
        .artifact_store
        .as_ref()
        .filter(|s| s.object_primary_eligible() && s.store.supports_bundle_bytes())
        .ok_or_else(|| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "token_bundle_storage_unavailable",
            )
        })?;
    if !account_db(state)?.supports_token_bundles() {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "token_bundle_storage_unavailable",
        ));
    }
    if !state
        .witness_bypass
        .as_ref()
        .is_some_and(|b| b.policy_version_allowed(TOKEN_BUNDLE_POLICY))
    {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "token_bundle_policy_unavailable",
        ));
    }
    Ok((store, server))
}
fn verify_manifest(state: &AppState, headers: &HeaderMap, bytes: &[u8]) -> ApiResult<()> {
    let verified = verified_witness_for_submission(state, headers, bytes)
        .ok_or_else(|| api_error(StatusCode::FORBIDDEN, "token_bundle_witness_required"))?;
    if verified.redaction_policy_version() != TOKEN_BUNDLE_POLICY
        || !state
            .witness_bypass
            .as_ref()
            .is_some_and(|b| b.policy_version_allowed(TOKEN_BUNDLE_POLICY))
    {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "token_bundle_policy_unavailable",
        ));
    }
    Ok(())
}
fn scope(bundle: &StoredTokenBundle) -> TraceArtifactScope {
    TraceArtifactScope {
        tenant_storage_ref: tenant_storage_ref(&bundle.tenant_id),
        submission_storage_ref: bundle.submission_id.to_string(),
    }
}
async fn owned(
    state: &AppState,
    tenant: &TenantCtx,
    submission: Uuid,
    revision: &str,
) -> ApiResult<StoredTokenBundle> {
    account_db(state)?
        .get_token_bundle(
            tenant.tenant_id(),
            submission,
            revision,
            tenant.principal_ref(),
        )
        .await
        .map_err(internal_error)?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "token_bundle_not_found"))
}
fn stored_headers(bundle: &StoredTokenBundle) -> ApiResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    for key in [CERTIFICATE_HEADER, SIGNATURE_HEADER] {
        let value = bundle
            .witness_headers
            .get(key)
            .ok_or_else(|| internal_error("token_bundle_certificate_unavailable"))?;
        headers.insert(
            key,
            value
                .parse()
                .map_err(|_| internal_error("token_bundle_certificate_unavailable"))?,
        );
    }
    Ok(headers)
}
pub(super) async fn begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let (_, server_id) = gate(&state)?;
    let tenant =
        authorize_tenant_access_grant_ctx(&state, authenticate_ctx(&state, &headers)?).await?;
    if body.len() > MAX_ATTACHMENT_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "token_bundle_limit",
        ));
    }
    verify_manifest(&state, &headers, &body)?;
    let manifest = ContributionBundleManifest::decode(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "token_bundle_manifest_invalid"))?;
    let submission = Uuid::parse_str(&manifest.submission_id)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "token_bundle_manifest_invalid"))?;
    cleanup(&state, tenant.tenant_id(), None)
        .await
        .map_err(internal_error)?;
    let mut witness_headers = BTreeMap::new();
    for key in [CERTIFICATE_HEADER, SIGNATURE_HEADER] {
        witness_headers.insert(
            key.into(),
            headers
                .get(key)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    api_error(StatusCode::BAD_REQUEST, "token_bundle_certificate_invalid")
                })?
                .into(),
        );
    }
    let bundle = account_db(&state)?
        .begin_token_bundle(StoredTokenBundle {
            tenant_id: tenant.tenant_id().into(),
            submission_id: submission,
            revision: manifest.bundle_revision.clone(),
            owner_ref: tenant.principal_ref().into(),
            manifest,
            witness_headers,
            state: "staging".into(),
            processing_state: "pending".into(),
            processing_summary: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            receipt: None,
            attachments: Vec::new(),
        })
        .await
        .map_err(internal_error)?;
    Ok(Json(
        serde_json::json!({"server_id":server_id,"tenant_id":tenant.tenant_id(),"account_id":tenant.principal_ref(),"state":bundle.state,"receipt":bundle.receipt,
        "ready":bundle.attachments.iter().filter(|a|a.ready&&!a.deleted).map(|a|&a.artifact_id).collect::<Vec<_>>()}),
    ))
}
pub(super) async fn put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((submission, revision, artifact)): AxumPath<(Uuid, String, String)>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let (store, _) = gate(&state)?;
    let tenant =
        authorize_tenant_access_grant_ctx(&state, authenticate_ctx(&state, &headers)?).await?;
    let bundle = owned(&state, &tenant, submission, &revision).await?;
    verify_manifest(
        &state,
        &stored_headers(&bundle)?,
        &bundle.manifest.canonical_bytes().map_err(internal_error)?,
    )?;
    if bundle.state != "staging" || body.len() > MAX_ATTACHMENT_BYTES {
        return Err(api_error(StatusCode::CONFLICT, "token_bundle_not_staging"));
    }
    if artifact == "envelope" {
        if !bundle.manifest.envelope_digest.matches(&body) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "token_bundle_digest_mismatch",
            ));
        }
    } else {
        bundle
            .manifest
            .verify_attachment(&artifact, &body)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "token_bundle_digest_mismatch"))?;
    }
    let db = account_db(&state)?;
    if !bundle.attachments.iter().any(|o| o.artifact_id == artifact) {
        let kind = if artifact == "envelope" {
            TraceArtifactKind::ContributionEnvelope
        } else {
            TraceArtifactKind::TokenDistribution
        };
        let prepared = store
            .store
            .prepare_bundle_bytes(&scope(&bundle), kind, &Uuid::new_v4().to_string(), &body)
            .map_err(internal_error)?;
        let encoded = serde_json::to_vec(&prepared).map_err(internal_error)?;
        db.stage_token_object(
            tenant.tenant_id(),
            submission,
            &revision,
            tenant.principal_ref(),
            StoredTokenObject {
                artifact_id: artifact.clone(),
                object_ref: prepared.object_ref,
                deleted: false,
                ready: false,
                prepared: Some(encoded),
            },
        )
        .await
        .map_err(internal_error)?;
    }
    db.publish_token_object(
        tenant.tenant_id(),
        submission,
        &revision,
        tenant.principal_ref(),
        &artifact,
        store.store.as_ref(),
    )
    .await
    .map_err(internal_error)?;
    Ok(Json(serde_json::json!({"ready":true})))
}
pub(super) async fn finalize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((submission, revision)): AxumPath<(Uuid, String)>,
    body: SubmitBody,
) -> ApiResult<Json<DurableBundleReceipt>> {
    let (store, server_id) = gate(&state)?;
    let tenant = authenticate_ctx(&state, &headers)?;
    let bundle = owned(&state, &tenant, submission, &revision).await?;
    if bundle.state == "revoked" {
        return Err(api_error(StatusCode::GONE, "token_bundle_revoked"));
    }
    verify_manifest(
        &state,
        &stored_headers(&bundle)?,
        &bundle.manifest.canonical_bytes().map_err(internal_error)?,
    )?;
    if body.envelope.submission_id != submission
        || !bundle.manifest.envelope_digest.matches(&body.raw)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "token_bundle_digest_mismatch",
        ));
    }
    if let Some(receipt) = bundle.receipt {
        return Ok(Json(receipt));
    }
    let consent = serde_json::to_vec(&(
        &body.envelope.consent.scopes,
        &body.envelope.trace_card.allowed_uses,
        TOKEN_BUNDLE_POLICY,
    ))
    .map_err(internal_error)?;
    if !bundle.manifest.consent_digest.matches(&consent) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "token_bundle_consent_mismatch",
        ));
    }
    let mut attachments = Vec::new();
    for descriptor in &bundle.manifest.attachments {
        let object = bundle
            .attachments
            .iter()
            .find(|o| o.artifact_id == descriptor.artifact_id && o.ready && !o.deleted)
            .ok_or_else(|| api_error(StatusCode::CONFLICT, "token_bundle_incomplete"))?;
        let bytes = store
            .store
            .read_bundle_bytes(&scope(&bundle), &object.object_ref)
            .map_err(internal_error)?;
        let text = body
            .envelope
            .events
            .iter()
            .find(|e| e.event_id.to_string() == descriptor.event_id)
            .and_then(|e| e.redacted_content.as_deref())
            .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "token_bundle_event_mismatch"))?;
        bundle
            .manifest
            .verify_sanitized_attachment(&descriptor.artifact_id, &bytes, text.as_bytes())
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "token_bundle_event_mismatch"))?;
        attachments.push((
            descriptor.event_id.clone(),
            ContentDigest::of(text.as_bytes()),
        ));
    }
    let original = bundle
        .attachments
        .iter()
        .find(|o| o.artifact_id == "envelope" && o.ready && !o.deleted)
        .ok_or_else(|| api_error(StatusCode::CONFLICT, "token_bundle_incomplete"))?;
    let original_bytes = store
        .store
        .read_bundle_bytes(&scope(&bundle), &original.object_ref)
        .map_err(internal_error)?;
    if !bundle.manifest.envelope_digest.matches(&original_bytes) {
        return Err(internal_error("token_bundle_digest_mismatch"));
    }
    // Existing admission, tenant scope, witness, PII and consent checks all run.
    // A normal upload status is not the bundle's durable receipt.
    let _ = submit_trace_handler(State(state.clone()), headers, body).await?;
    let record = tenant
        .read_submission_record(&state.root, submission)
        .map_err(internal_error)?
        .ok_or_else(|| internal_error("token_bundle_submission_unavailable"))?;
    let stored = read_envelope_by_record(&state, &record).map_err(internal_error)?;
    for (event, digest) in attachments {
        let text = stored
            .events
            .iter()
            .find(|e| e.event_id.to_string() == event)
            .and_then(|e| e.redacted_content.as_deref())
            .ok_or_else(|| api_error(StatusCode::CONFLICT, "token_bundle_rescrub_changed"))?;
        if !digest.matches(text.as_bytes()) {
            return Err(api_error(
                StatusCode::CONFLICT,
                "token_bundle_rescrub_changed",
            ));
        }
    }
    let now = Utc::now().timestamp() as u64;
    let receipt = DurableBundleReceipt {
        version: SCHEMA_VERSION,
        server_id,
        tenant_id: tenant.tenant_id().into(),
        account_id: tenant.principal_ref().into(),
        submission_id: submission.to_string(),
        bundle_revision: revision.clone(),
        manifest_digest: bundle.manifest.digest().map_err(internal_error)?,
        committed_at_unix: now,
        retain_until_unix: now + 30 * 86400,
        retention_policy_version: "private-revocable-30d-v1".into(),
    };
    let receipt = account_db(&state)?
        .commit_token_bundle(
            tenant.tenant_id(),
            submission,
            &revision,
            tenant.principal_ref(),
            receipt,
        )
        .await
        .map_err(internal_error)?;
    let _ = account_db(&state)?
        .process_token_bundles(tenant.tenant_id(), store.store.as_ref())
        .await;
    Ok(Json(receipt))
}
pub(super) async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((submission, revision)): AxumPath<(Uuid, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let tenant = authenticate_ctx(&state, &headers)?;
    let bundle = owned(&state, &tenant, submission, &revision).await?;
    let held = tenant
        .read_submission_record(&state.root, submission)
        .map_err(internal_error)?
        .is_some_and(|record| {
            state
                .legal_hold_retention_policy_ids
                .contains(&record.retention_policy_id)
        });
    let deletion_state = if bundle.state != "revoked" && bundle.expires_at > Utc::now() {
        "retained"
    } else if bundle.attachments.iter().all(|o| o.deleted) {
        "completed"
    } else if held {
        "held"
    } else {
        "pending"
    };
    Ok(Json(
        serde_json::json!({"deletion_state":deletion_state,"state":bundle.state,"receipt":bundle.receipt,"manifest":bundle.manifest,"processing_state":bundle.processing_state,"processing_summary":bundle.processing_summary,"ready":bundle.attachments.iter().filter(|o|o.ready&&!o.deleted).map(|o|&o.artifact_id).collect::<Vec<_>>()}),
    ))
}
pub(super) async fn cleanup(
    state: &AppState,
    tenant: &str,
    submission: Option<Uuid>,
) -> anyhow::Result<()> {
    let Some(db) = &state.db_mirror else {
        return Ok(());
    };
    if !db.supports_token_bundles() {
        return Ok(());
    }
    if let Some(store) = state.artifact_store.as_ref() {
        // Committed intents remain recoverable if a previous process stopped
        // before producing their metadata. This never evaluates credit.
        let _ = db.process_token_bundles(tenant, store.store.as_ref()).await;
    }
    let pending = db
        .pending_token_bundle_deletions(tenant, submission)
        .await?;
    if pending.is_empty() {
        return Ok(());
    }
    let store = state
        .artifact_store
        .as_ref()
        .context("token_bundle_storage_unavailable")?;
    let held_policies = state
        .legal_hold_retention_policy_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    for bundle in pending {
        let result = db
            .delete_token_objects(
                tenant,
                bundle.submission_id,
                &bundle.revision,
                &held_policies,
                store.store.as_ref(),
            )
            .await;
        match result {
            Err(trace_commons_server::error::DatabaseError::Query(ref tag))
                if tag == "TokenBundleHeld" =>
            {
                continue;
            }
            result => result?,
        }
    }
    Ok(())
}

/// Owner-only research access; attachments never enter public text/vector routes.
pub(super) async fn read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((submission, revision, artifact)): AxumPath<(Uuid, String, String)>,
) -> ApiResult<Response> {
    read_bundle(state, headers, submission, revision, artifact, false).await
}
pub(super) async fn research_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((submission, revision, artifact)): AxumPath<(Uuid, String, String)>,
) -> ApiResult<Response> {
    read_bundle(state, headers, submission, revision, artifact, true).await
}
async fn read_bundle(
    state: Arc<AppState>,
    headers: HeaderMap,
    submission: Uuid,
    revision: String,
    artifact: String,
    research: bool,
) -> ApiResult<Response> {
    let (store, _) = gate(&state)?;
    let tenant =
        authorize_tenant_access_grant_ctx(&state, authenticate_ctx(&state, &headers)?).await?;
    let bundle = if research {
        research_gate(&state, &tenant)?;
        account_db(&state)?
            .get_token_bundle_for_export(tenant.tenant_id(), submission, &revision)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"))?
    } else {
        owned(&state, &tenant, submission, &revision).await?
    };
    if bundle.state != "committed" || bundle.expires_at <= Utc::now() || artifact == "envelope" {
        return Err(api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"));
    }
    let descriptor = bundle
        .manifest
        .attachments
        .iter()
        .find(|a| a.artifact_id == artifact)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"))?;
    let object = bundle
        .attachments
        .iter()
        .find(|a| a.artifact_id == artifact && a.ready && !a.deleted)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"))?;
    let record = tenant
        .read_submission_record(&state.root, submission)
        .map_err(internal_error)?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"))?;
    if research {
        research_record(&state, &tenant, &record).await?;
    }
    let envelope = read_envelope_by_record(&state, &record).map_err(internal_error)?;
    let text = envelope
        .events
        .iter()
        .find(|e| e.event_id.to_string() == descriptor.event_id)
        .and_then(|e| e.redacted_content.as_deref())
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"))?;
    let bytes = store
        .store
        .read_bundle_bytes(&scope(&bundle), &object.object_ref)
        .map_err(internal_error)?;
    bundle
        .manifest
        .verify_sanitized_attachment(&artifact, &bytes, text.as_bytes())
        .map_err(|_| api_error(StatusCode::GONE, "token_bundle_rescrub_changed"))?;
    // Record every restricted download in the ordinary export lineage tables.
    // There is no derived export object: these exact bytes stream to the owner.
    // Parent withdrawal invalidates the manifest through existing export GC.
    let export_id = Uuid::new_v4();
    let manifest_digest = bundle.manifest.digest().map_err(internal_error)?;
    account_db(&state)?
        .upsert_trace_export_manifest_mirror(StorageTraceExportManifestMirrorWrite {
            manifest: StorageTraceExportManifestWrite {
                tenant_id: tenant.tenant_id().into(),
                export_manifest_id: export_id,
                artifact_kind: StorageTraceObjectArtifactKind::ExportArtifact,
                purpose_code: Some("restricted_token_distribution".into()),
                audit_event_id: None,
                source_submission_ids: vec![submission],
                source_submission_ids_hash: source_submission_ids_hash(
                    "restricted_token_distribution",
                    &[submission],
                ),
                item_count: 1,
                generated_at: Utc::now(),
            },
            object_refs: Vec::new(),
            items: vec![StorageTraceExportManifestItemWrite {
                tenant_id: tenant.tenant_id().into(),
                export_manifest_id: export_id,
                submission_id: submission,
                trace_id: envelope.trace_id,
                derived_id: None,
                object_ref_id: None,
                vector_entry_id: None,
                source_status_at_export: storage_corpus_status(record.status),
                source_hash_at_export: manifest_digest.as_str().into(),
            }],
        })
        .await
        .map_err(internal_error)?;
    // Recheck after object I/O: revocation/expiry observed during the read
    // must not return bytes from the earlier snapshot.
    let current = if research {
        account_db(&state)?
            .get_token_bundle_for_export(tenant.tenant_id(), submission, &revision)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| api_error(StatusCode::GONE, "token_bundle_revoked"))?
    } else {
        owned(&state, &tenant, submission, &revision).await?
    };
    if current.state != "committed" || current.expires_at <= Utc::now() {
        return Err(api_error(StatusCode::GONE, "token_bundle_revoked"));
    }
    if research {
        research_gate(&state, &tenant)?;
        let current_record = tenant
            .read_submission_record(&state.root, submission)
            .map_err(internal_error)?
            .ok_or_else(|| api_error(StatusCode::GONE, "token_bundle_revoked"))?;
        research_record(&state, &tenant, &current_record).await?;
        let current_envelope =
            read_envelope_by_record(&state, &current_record).map_err(internal_error)?;
        let current_text = current_envelope
            .events
            .iter()
            .find(|e| e.event_id.to_string() == descriptor.event_id)
            .and_then(|e| e.redacted_content.as_deref())
            .ok_or_else(|| api_error(StatusCode::GONE, "token_bundle_rescrub_changed"))?;
        current
            .manifest
            .verify_sanitized_attachment(&artifact, &bytes, current_text.as_bytes())
            .map_err(|_| api_error(StatusCode::GONE, "token_bundle_rescrub_changed"))?;
    }
    let bytes = if research {
        use base64::Engine;
        let base64 = base64::engine::general_purpose::STANDARD;
        serde_json::to_vec(&serde_json::json!({
            "version":SCHEMA_VERSION,
            "export_id":export_id,
            "artifact_id":artifact,
            "event_id":descriptor.event_id,
            "event_text":text,
            "attachment_base64":base64.encode(&bytes),
            "manifest_base64":base64.encode(bundle.manifest.canonical_bytes().map_err(internal_error)?),
            "manifest_certificate":bundle.witness_headers.get(CERTIFICATE_HEADER),
            "manifest_signature":bundle.witness_headers.get(SIGNATURE_HEADER),
            "processing_summary":current.processing_summary,
        })).map_err(internal_error)?
    } else {
        bytes
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response();
    response.headers_mut().insert(
        "x-trace-export-id",
        export_id.to_string().parse().map_err(internal_error)?,
    );
    response.headers_mut().insert(
        "x-trace-bundle-digest",
        manifest_digest.as_str().parse().map_err(internal_error)?,
    );
    Ok(response)
}

/// Authenticated capability discovery precedes any raw witness request.
pub(super) async fn capabilities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (_, server_id) = gate(&state)?;
    let tenant =
        authorize_tenant_access_grant_ctx(&state, authenticate_ctx(&state, &headers)?).await?;
    Ok(Json(
        serde_json::json!({"version":SCHEMA_VERSION,"server_id":server_id,"tenant_id":tenant.tenant_id(),"account_id":tenant.principal_ref(),"policy":TOKEN_BUNDLE_POLICY,"usage_profile":"restricted_research","max_attachment_bytes":MAX_ATTACHMENT_BYTES}),
    ))
}

fn research_gate(state: &AppState, tenant: &TenantCtx) -> ApiResult<()> {
    if !env_truthy("TRACE_COMMONS_TOKEN_RESEARCH_EXPORTS") {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "token_research_disabled",
        ));
    }
    let _ = gate(state)?;
    require_exporter(tenant.auth())
}
async fn research_record(
    state: &AppState,
    tenant: &TenantCtx,
    record: &TraceCommonsSubmissionRecord,
) -> ApiResult<()> {
    let query = DatasetExportQuery {
        limit: Some(1),
        purpose: Some("restricted_token_distribution".into()),
        status: Some(TraceCorpusStatus::Accepted),
        privacy_risk: Some(ResidualPiiRisk::Low),
        consent_scope: Some("debugging_evaluation".into()),
    };
    let (_, policy, _) = prepare_replay_export_execution(state, tenant.auth(), &query).await?;
    if !record.is_export_eligible()
        || record.privacy_risk != ResidualPiiRisk::Low
        || !record_matches_export_policy_abac(
            record,
            tenant.auth(),
            policy.as_ref(),
            TraceAllowedUse::Evaluation,
        )
    {
        return Err(api_error(StatusCode::NOT_FOUND, "token_bundle_unavailable"));
    }
    ensure_retention_metadata_within_server_policy(record).map_err(internal_error)
}
pub(super) async fn query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(query): Json<TokenBundleQuery>,
) -> ApiResult<Json<Vec<TokenBundleIndexEntry>>> {
    let (_, _) = gate(&state)?;
    let tenant =
        authorize_tenant_access_grant_ctx(&state, authenticate_ctx(&state, &headers)?).await?;
    let entries = account_db(&state)?
        .query_token_bundles(tenant.tenant_id(), Some(tenant.principal_ref()), &query)
        .await
        .map_err(internal_error)?;
    Ok(Json(entries))
}

/// Restricted summaries obey the same current consent and ABAC checks as downloads.
pub(super) async fn research_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(query): Json<TokenBundleQuery>,
) -> ApiResult<Json<Vec<TokenBundleIndexEntry>>> {
    let tenant =
        authorize_tenant_access_grant_ctx(&state, authenticate_ctx(&state, &headers)?).await?;
    research_gate(&state, &tenant)?;
    let entries = account_db(&state)?
        .query_token_bundles(tenant.tenant_id(), None, &query)
        .await
        .map_err(internal_error)?;
    let mut allowed = Vec::new();
    for entry in entries {
        if let Some(record) = tenant
            .read_submission_record(&state.root, entry.submission_id)
            .map_err(internal_error)?
        {
            if research_record(&state, &tenant, &record).await.is_ok() {
                allowed.push(entry);
            }
        }
    }
    Ok(Json(allowed))
}
