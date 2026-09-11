// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::postgres::PgBackend;
use crate::{error::DatabaseError, token_bundle_store::*};
use chrono::{DateTime, Utc};
use trace_commons_protocol::token_distribution::DurableBundleReceipt;
use uuid::Uuid;
type Result<T> = std::result::Result<T, DatabaseError>;
fn invalid() -> DatabaseError {
    DatabaseError::Query("TokenBundleConflict".into())
}
fn encode<T: serde::Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| invalid())
}
async fn row(
    tx: &deadpool_postgres::Transaction<'_>,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    owner: &str,
) -> Result<Option<StoredTokenBundle>> {
    let Some(r)=tx.query_opt("SELECT * FROM trace_token_bundles WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 AND owner_ref=$4",&[&tenant,&submission,&revision,&owner]).await? else {return Ok(None)};
    let mut attachments = Vec::new();
    for a in tx.query("SELECT artifact_id,object_ref,deleted,ready,prepared FROM trace_token_attachments WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 ORDER BY artifact_id",&[&tenant,&submission,&revision]).await? {
        attachments.push(StoredTokenObject{artifact_id:a.get(0),object_ref:decode(a.get(1))?,deleted:a.get(2),ready:a.get(3),prepared:a.get(4)});
    }
    // A restored child row cannot override the surviving parent tombstone.
    let revoked: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 AND (status='revoked' OR withdrawn_at IS NOT NULL OR purged_at IS NOT NULL)) OR EXISTS(SELECT 1 FROM trace_withdrawals WHERE tenant_id=$1 AND submission_id=$2)", &[&tenant,&submission]).await?.get(0);
    Ok(Some(StoredTokenBundle {
        tenant_id: tenant.into(),
        submission_id: submission,
        revision: revision.into(),
        owner_ref: owner.into(),
        manifest: decode(r.get("manifest"))?,
        witness_headers: decode(r.get("witness_headers"))?,
        state: if revoked {
            "revoked".into()
        } else {
            r.get("state")
        },
        processing_state: if revoked {
            "revoked".into()
        } else {
            r.get("processing_state")
        },
        processing_summary: if revoked {
            None
        } else {
            r.get("processing_summary")
        },
        expires_at: r.get("expires_at"),
        receipt: r
            .get::<_, Option<serde_json::Value>>("receipt")
            .map(decode)
            .transpose()?,
        attachments,
    }))
}
async fn lock(
    tx: &deadpool_postgres::Transaction<'_>,
    tenant: &str,
    submission: Uuid,
) -> Result<()> {
    // Shared by every bundle revision and parent withdrawal's row lock.
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 734892))",
        &[&format!("{}:{}:{}", tenant.len(), tenant, submission)],
    )
    .await?;
    Ok(())
}
pub(super) async fn begin_token_bundle(
    db: &PgBackend,
    bundle: StoredTokenBundle,
) -> Result<StoredTokenBundle> {
    bundle.manifest.validate().map_err(|_| invalid())?;
    if bundle.manifest.submission_id != bundle.submission_id.to_string()
        || bundle.manifest.bundle_revision != bundle.revision
        || bundle.state != "staging"
        || !bundle.attachments.is_empty()
        || bundle.receipt.is_some()
    {
        return Err(invalid());
    }
    db.ensure_trace_tenant(&bundle.tenant_id).await?;
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, &bundle.tenant_id).await?;
    // Same parent-before-bundle lock order as finalize and revocation. A
    // begin racing withdrawal must see the committed tombstone, rather than
    // insert a new revision after the withdrawal trigger scanned old rows.
    tx.query_opt("SELECT submission_id FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 FOR UPDATE", &[&bundle.tenant_id, &bundle.submission_id]).await?;
    lock(&tx, &bundle.tenant_id, bundle.submission_id).await?;
    let withdrawn:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM trace_withdrawals WHERE tenant_id=$1 AND submission_id=$2) OR EXISTS(SELECT 1 FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 AND (status='revoked' OR withdrawn_at IS NOT NULL OR purged_at IS NOT NULL))",&[&bundle.tenant_id,&bundle.submission_id]).await?.get(0);
    if withdrawn {
        return Err(invalid());
    }
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 734893))",
        &[&bundle.tenant_id],
    )
    .await?;
    let active: i64 = tx.query_one("SELECT count(*) FROM trace_token_bundles WHERE tenant_id=$1 AND state IN ('staging','committed')", &[&bundle.tenant_id]).await?.get(0);
    if active >= 128
        && row(
            &tx,
            &bundle.tenant_id,
            bundle.submission_id,
            &bundle.revision,
            &bundle.owner_ref,
        )
        .await?
        .is_none()
    {
        return Err(invalid());
    }
    let pending: i64 = tx
        .query_one(
            "SELECT count(*) FROM trace_token_bundles WHERE tenant_id=$1 AND state='staging'",
            &[&bundle.tenant_id],
        )
        .await?
        .get(0);
    if pending >= 16
        && row(
            &tx,
            &bundle.tenant_id,
            bundle.submission_id,
            &bundle.revision,
            &bundle.owner_ref,
        )
        .await?
        .is_none()
    {
        return Err(invalid());
    }
    let digest = bundle.manifest.digest().map_err(|_| invalid())?;
    tx.execute("INSERT INTO trace_token_bundles(tenant_id,submission_id,revision,owner_ref,manifest_digest,manifest,state,expires_at,witness_headers) VALUES($1,$2,$3,$4,$5,$6,'staging',$7,$8) ON CONFLICT DO NOTHING",&[&bundle.tenant_id,&bundle.submission_id,&bundle.revision,&bundle.owner_ref,&digest.as_str(),&encode(&bundle.manifest)?,&bundle.expires_at,&encode(&bundle.witness_headers)?]).await?;
    let stored = row(
        &tx,
        &bundle.tenant_id,
        bundle.submission_id,
        &bundle.revision,
        &bundle.owner_ref,
    )
    .await?
    .ok_or_else(invalid)?;
    if stored.manifest.digest().map_err(|_| invalid())? != digest || stored.state == "revoked" {
        return Err(invalid());
    }
    tx.commit().await?;
    Ok(stored)
}
pub(super) async fn get_token_bundle(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    owner: &str,
) -> Result<Option<StoredTokenBundle>> {
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    let value = row(&tx, tenant, submission, revision, owner).await?;
    tx.commit().await?;
    Ok(value)
}
pub(super) async fn stage_token_object(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    owner: &str,
    object: StoredTokenObject,
) -> Result<()> {
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    lock(&tx, tenant, submission).await?;
    let bundle = row(&tx, tenant, submission, revision, owner)
        .await?
        .ok_or_else(invalid)?;
    if bundle.state != "staging"
        || bundle.expires_at <= Utc::now()
        || (object.artifact_id != "envelope"
            && !bundle
                .manifest
                .attachments
                .iter()
                .any(|a| a.artifact_id == object.artifact_id))
        || object.deleted
        || object.ready
        || object
            .prepared
            .as_ref()
            .is_none_or(|p| p.len() > 12 * 1024 * 1024)
    {
        return Err(invalid());
    }
    let existing=tx.query_opt("SELECT object_ref FROM trace_token_attachments WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 AND artifact_id=$4",&[&tenant,&submission,&revision,&object.artifact_id]).await?;
    if let Some(existing) = existing {
        if existing.get::<_, serde_json::Value>(0) != encode(&object.object_ref)? {
            return Err(invalid());
        }
    } else {
        tx.execute("INSERT INTO trace_token_attachments(tenant_id,submission_id,revision,artifact_id,object_ref,prepared) VALUES($1,$2,$3,$4,$5,$6)",&[&tenant,&submission,&revision,&object.artifact_id,&encode(&object.object_ref)?,&object.prepared]).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub(super) async fn commit_token_bundle(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    owner: &str,
    receipt: DurableBundleReceipt,
) -> Result<DurableBundleReceipt> {
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    // Parent first: revocation's trigger takes the bundle lock in this order.
    let parent=tx.query_opt("SELECT auth_principal_ref,status,withdrawn_at,purged_at FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 FOR UPDATE",&[&tenant,&submission]).await?.ok_or_else(invalid)?;
    if parent.get::<_, String>(0) != owner
        || parent.get::<_, String>(1) == "revoked"
        || parent.get::<_, Option<DateTime<Utc>>>(2).is_some()
        || parent.get::<_, Option<DateTime<Utc>>>(3).is_some()
    {
        return Err(invalid());
    }
    lock(&tx, tenant, submission).await?;
    let bundle = row(&tx, tenant, submission, revision, owner)
        .await?
        .ok_or_else(invalid)?;
    if bundle.state == "revoked" {
        return Err(invalid());
    }
    if let Some(existing) = bundle.receipt {
        tx.commit().await?;
        return Ok(existing);
    }
    if bundle.expires_at <= Utc::now()
        || bundle.attachments.len() != bundle.manifest.attachments.len() + 1
        || bundle.attachments.iter().any(|a| a.deleted || !a.ready)
    {
        return Err(invalid());
    }
    if receipt.submission_id != submission.to_string()
        || receipt.bundle_revision != revision
        || receipt.tenant_id != tenant
        || receipt.account_id != owner
        || receipt.manifest_digest != bundle.manifest.digest().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    receipt
        .matches_bundle(
            &bundle.manifest,
            &receipt.server_id,
            tenant,
            owner,
            Utc::now().timestamp() as u64,
        )
        .map_err(|_| invalid())?;
    let expires = DateTime::from_timestamp(
        i64::try_from(receipt.retain_until_unix).map_err(|_| invalid())?,
        0,
    )
    .ok_or_else(invalid)?;
    tx.execute("UPDATE trace_token_bundles SET state='committed',receipt=$4,expires_at=$5,processing_state='pending' WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3",&[&tenant,&submission,&revision,&encode(&receipt)?,&expires]).await?;
    tx.commit().await?;
    Ok(receipt)
}
pub(super) async fn pending_token_bundle_deletions(
    db: &PgBackend,
    tenant: &str,
    submission: Option<Uuid>,
) -> Result<Vec<StoredTokenBundle>> {
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    tx.execute("UPDATE trace_token_bundles b SET state='revoked',processing_state='revoked',processing_summary=NULL WHERE tenant_id=$1 AND ($2::uuid IS NULL OR submission_id=$2) AND (expires_at<=NOW() OR EXISTS(SELECT 1 FROM trace_withdrawals w WHERE w.tenant_id=b.tenant_id AND w.submission_id=b.submission_id) OR EXISTS(SELECT 1 FROM trace_submissions p WHERE p.tenant_id=b.tenant_id AND p.submission_id=b.submission_id AND (p.status='revoked' OR p.withdrawn_at IS NOT NULL OR p.purged_at IS NOT NULL)))",&[&tenant,&submission]).await?;
    let keys=tx.query("SELECT submission_id,revision,owner_ref FROM trace_token_bundles WHERE tenant_id=$1 AND state='revoked' AND EXISTS(SELECT 1 FROM trace_token_attachments a WHERE a.tenant_id=trace_token_bundles.tenant_id AND a.submission_id=trace_token_bundles.submission_id AND a.revision=trace_token_bundles.revision AND a.deleted=FALSE) AND ($2::uuid IS NULL OR submission_id=$2) ORDER BY created_at LIMIT 128",&[&tenant,&submission]).await?;
    let mut result = Vec::new();
    for key in keys {
        if let Some(value) = row(
            &tx,
            tenant,
            key.get(0),
            key.get::<_, String>(1).as_str(),
            key.get::<_, String>(2).as_str(),
        )
        .await?
        {
            result.push(value);
        }
    }
    tx.commit().await?;
    Ok(result)
}
pub(super) async fn mark_token_object_deleted(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    artifact: &str,
) -> Result<()> {
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    tx.execute("UPDATE trace_token_attachments a SET deleted=TRUE WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 AND artifact_id=$4 AND EXISTS(SELECT 1 FROM trace_token_bundles b WHERE b.tenant_id=a.tenant_id AND b.submission_id=a.submission_id AND b.revision=a.revision AND b.state='revoked')",&[&tenant,&submission,&revision,&artifact]).await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn publish_token_object(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    owner: &str,
    artifact: &str,
    store: &dyn crate::trace_artifact_store::TraceArtifactStore,
) -> Result<()> {
    use crate::trace_artifact_store::{PreparedBundleArtifact, TraceArtifactScope};
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    lock(&tx, tenant, submission).await?;
    tx.query_opt("SELECT revision FROM trace_token_bundles WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 FOR UPDATE",&[&tenant,&submission,&revision]).await?.ok_or_else(invalid)?;
    let bundle = row(&tx, tenant, submission, revision, owner)
        .await?
        .ok_or_else(invalid)?;
    if bundle.state != "staging" || bundle.expires_at <= Utc::now() {
        return Err(invalid());
    }
    let object = bundle
        .attachments
        .iter()
        .find(|o| o.artifact_id == artifact && !o.deleted)
        .ok_or_else(invalid)?;
    if object.ready {
        return Ok(());
    }
    let prepared: PreparedBundleArtifact =
        serde_json::from_slice(object.prepared.as_deref().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    if prepared.object_ref != object.object_ref {
        return Err(invalid());
    }
    let scope = TraceArtifactScope {
        tenant_storage_ref: object.object_ref.tenant_storage_ref.clone(),
        submission_storage_ref: object.object_ref.submission_storage_ref.clone(),
    };
    // Keep the DB row lock through synchronous publication and readback. No
    // detached upload task may survive cancellation and race deletion.
    store
        .publish_bundle_bytes(&scope, &prepared)
        .map_err(|_| invalid())?;
    let bytes = store
        .read_bundle_bytes(&scope, &object.object_ref)
        .map_err(|_| invalid())?;
    if artifact == "envelope" {
        if !bundle.manifest.envelope_digest.matches(&bytes) {
            return Err(invalid());
        }
    } else {
        bundle
            .manifest
            .verify_attachment(artifact, &bytes)
            .map_err(|_| invalid())?;
    }
    tx.execute("UPDATE trace_token_attachments SET ready=TRUE,prepared=NULL WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 AND artifact_id=$4",&[&tenant,&submission,&revision,&artifact]).await?;
    tx.commit().await?;
    Ok(())
}
pub(super) async fn delete_token_objects(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
    held_policies: &[String],
    store: &dyn crate::trace_artifact_store::TraceArtifactStore,
) -> Result<()> {
    use crate::trace_artifact_store::TraceArtifactScope;
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    // Match the parent-before-bundle lifecycle lock order. Holds block
    // physical deletion even after access has been revoked by expiry.
    if let Some(parent) = tx.query_opt("SELECT retention_policy_id FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 FOR UPDATE", &[&tenant,&submission]).await? {
        if held_policies.contains(&parent.get::<_,String>(0)) {
            return Err(DatabaseError::Query("TokenBundleHeld".into()));
        }
    }
    lock(&tx, tenant, submission).await?;
    let Some(record)=tx.query_opt("SELECT owner_ref,state FROM trace_token_bundles WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 FOR UPDATE",&[&tenant,&submission,&revision]).await? else {return Ok(())};
    if record.get::<_, String>(1) != "revoked" {
        return Err(invalid());
    }
    let bundle = row(
        &tx,
        tenant,
        submission,
        revision,
        record.get::<_, String>(0).as_str(),
    )
    .await?
    .ok_or_else(invalid)?;
    for object in bundle.attachments {
        if object.deleted {
            continue;
        }
        let scope = TraceArtifactScope {
            tenant_storage_ref: object.object_ref.tenant_storage_ref.clone(),
            submission_storage_ref: object.object_ref.submission_storage_ref.clone(),
        };
        store
            .delete_bundle_bytes(&scope, &object.object_ref)
            .map_err(|_| invalid())?;
        tx.execute("UPDATE trace_token_attachments SET deleted=TRUE,prepared=NULL WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 AND artifact_id=$4",&[&tenant,&submission,&revision,&object.artifact_id]).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Drain a bounded part of the revision outbox. No vector insertion or credit
/// evaluation is performed here, so retries cannot score against themselves.
pub(super) async fn process_token_bundles(
    db: &PgBackend,
    tenant: &str,
    store: &dyn crate::trace_artifact_store::TraceArtifactStore,
) -> Result<usize> {
    use crate::trace_artifact_store::TraceArtifactScope;
    use trace_commons_protocol::{
        token_distribution::LogProbability, trace_contribution::TraceContributionEnvelope,
    };
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    let keys = tx.query("SELECT submission_id,revision,owner_ref FROM trace_token_bundles WHERE tenant_id=$1 AND state='committed' AND processing_state='pending' AND expires_at>NOW() AND processing_retry_at<=NOW() ORDER BY processing_retry_at,created_at LIMIT 8", &[&tenant]).await?;
    tx.commit().await?;
    let mut completed = 0;
    for key in keys {
        let submission: Uuid = key.get(0);
        let revision: String = key.get(1);
        let owner: String = key.get(2);
        let processed = async {
        let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
        let Some(parent) = tx.query_opt("SELECT status,withdrawn_at,purged_at FROM trace_submissions WHERE tenant_id=$1 AND submission_id=$2 FOR UPDATE", &[&tenant,&submission]).await? else {return Ok(false)};
        if parent.get::<_, String>(0) == "revoked"
            || parent.get::<_, Option<DateTime<Utc>>>(1).is_some()
            || parent.get::<_, Option<DateTime<Utc>>>(2).is_some()
        {
            return Ok(false);
        }
        lock(&tx, tenant, submission).await?;
        let Some(current) = tx.query_opt("SELECT processing_state FROM trace_token_bundles WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 FOR UPDATE", &[&tenant,&submission,&revision]).await? else {return Ok(false)};
        if current.get::<_, String>(0) != "pending" {
            return Ok(false);
        }
        let bundle = row(&tx, tenant, submission, &revision, &owner)
            .await?
            .ok_or_else(invalid)?;
        if bundle.state != "committed" || bundle.expires_at <= Utc::now() {
            return Ok(false);
        }
        let scope = TraceArtifactScope {
            tenant_storage_ref: bundle
                .attachments
                .first()
                .ok_or_else(invalid)?
                .object_ref
                .tenant_storage_ref
                .clone(),
            submission_storage_ref: submission.to_string(),
        };
        let envelope_object = bundle
            .attachments
            .iter()
            .find(|a| a.artifact_id == "envelope" && a.ready && !a.deleted)
            .ok_or_else(invalid)?;
        let bytes = store
            .read_bundle_bytes(&scope, &envelope_object.object_ref)
            .map_err(|_| invalid())?;
        if !bundle.manifest.envelope_digest.matches(&bytes) {
            return Err(invalid());
        }
        let envelope: TraceContributionEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let mut summaries = Vec::new();
        for descriptor in &bundle.manifest.attachments {
            let object = bundle
                .attachments
                .iter()
                .find(|a| a.artifact_id == descriptor.artifact_id && a.ready && !a.deleted)
                .ok_or_else(invalid)?;
            let bytes = store
                .read_bundle_bytes(&scope, &object.object_ref)
                .map_err(|_| invalid())?;
            let text = envelope
                .events
                .iter()
                .find(|e| e.event_id.to_string() == descriptor.event_id)
                .and_then(|e| e.redacted_content.as_deref())
                .ok_or_else(invalid)?;
            let attachment = bundle
                .manifest
                .verify_sanitized_attachment(&descriptor.artifact_id, &bytes, text.as_bytes())
                .map_err(|_| invalid())?;
            let mut sum = 0.0;
            let mut measured = 0u64;
            for record in &attachment.records {
                if let LogProbability::Finite(value) = record.chosen.logprob {
                    sum -= value;
                    measured += 1;
                }
            }
            let retained = attachment.records.len() as u64;
            let total = retained.saturating_add(attachment.omitted_records);
            let mean = if measured > 0 && sum.is_finite() {
                Some(sum / measured as f64)
            } else {
                None
            };
            summaries.push(serde_json::json!({
                "artifact_id":descriptor.artifact_id,"event_id":descriptor.event_id,"attachment_digest":descriptor.content_digest,
                "requested_model":attachment.requested_model,"reported_model":attachment.metadata.reported_model,"served_model":attachment.served_model,
                "tokenizer_available":attachment.tokenizer.is_some(),"semantics":attachment.semantics,"evidence":attachment.metadata.evidence,
                "requested_alternatives":attachment.metadata.requested_alternatives,"retained_records":retained,"omitted_records":attachment.omitted_records,
                "retained_alternatives":attachment.records.iter().map(|r|r.alternatives.len() as u64).sum::<u64>(),
                "coverage":if total>0 {retained as f64 / total as f64} else {0.0},
                "measured_records":measured,"mean_chosen_surprisal":mean,"metadata":attachment.metadata
            }));
        }
        tx.execute("UPDATE trace_token_bundles SET processing_state='ready',processing_policy='chosen-surprisal-v1',processing_summary=$4 WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3", &[&tenant,&submission,&revision,&serde_json::json!(summaries)]).await?;
        tx.commit().await?;
        Ok::<bool, crate::db::DatabaseError>(true)
        }.await;
        match processed {
            Ok(true) => completed += 1,
            Ok(false) => {}
            Err(_) => {
                let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
                tx.execute("UPDATE trace_token_bundles SET processing_retry_at=NOW()+INTERVAL '1 hour' WHERE tenant_id=$1 AND submission_id=$2 AND revision=$3 AND processing_state='pending'", &[&tenant,&submission,&revision]).await?;
                tx.commit().await?;
            }
        }
    }
    Ok(completed)
}

pub(super) async fn query_token_bundles(
    db: &PgBackend,
    tenant: &str,
    owner: Option<&str>,
    query: &TokenBundleQuery,
) -> Result<Vec<TokenBundleIndexEntry>> {
    if query.limit.is_some_and(|v| v == 0 || v > 100)
        || query
            .minimum_coverage
            .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
        || query.requested_alternatives.is_some_and(|v| v > 20)
        || query.after_submission.is_some() != query.after_revision.is_some()
        || [
            &query.model,
            &query.semantics,
            &query.evidence,
            &query.after_revision,
        ]
        .into_iter()
        .flatten()
        .any(|v| v.len() > 256)
    {
        return Err(invalid());
    }
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    let rows = tx.query("SELECT b.submission_id,b.revision,b.manifest_digest,b.processing_policy,b.processing_summary FROM trace_token_bundles b JOIN trace_submissions p USING(tenant_id,submission_id) WHERE b.tenant_id=$1 AND ($2::text IS NULL OR b.owner_ref=$2) AND b.state='committed' AND b.processing_state='ready' AND b.expires_at>NOW() AND p.status='accepted' AND p.withdrawn_at IS NULL AND p.purged_at IS NULL AND NOT EXISTS(SELECT 1 FROM trace_withdrawals w WHERE w.tenant_id=b.tenant_id AND w.submission_id=b.submission_id) AND ($3::uuid IS NULL OR (b.submission_id,b.revision)>($3,$4::text)) AND EXISTS(SELECT 1 FROM jsonb_array_elements(b.processing_summary) s WHERE ($5::text IS NULL OR s->>'requested_model'=$5 OR s->>'reported_model'=$5 OR s->>'served_model'=$5) AND ($6::text IS NULL OR s->>'semantics'=$6) AND ($7::bigint IS NULL OR (s->>'requested_alternatives')::bigint=$7) AND ($8::double precision IS NULL OR (s->>'coverage')::double precision>=$8) AND ($9::boolean IS NULL OR (s->>'tokenizer_available')::boolean=$9) AND ($11::text IS NULL OR s->>'evidence'=$11)) ORDER BY b.submission_id,b.revision LIMIT $10", &[&tenant,&owner,&query.after_submission,&query.after_revision,&query.model,&query.semantics,&query.requested_alternatives.map(i64::from),&query.minimum_coverage,&query.tokenizer_available,&i64::from(query.limit.unwrap_or(50)),&query.evidence]).await?;
    let result = rows
        .into_iter()
        .map(|r| TokenBundleIndexEntry {
            submission_id: r.get(0),
            revision: r.get(1),
            manifest_digest: r.get(2),
            policy_version: r.get(3),
            summary: r.get(4),
        })
        .collect();
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn get_token_bundle_for_export(
    db: &PgBackend,
    tenant: &str,
    submission: Uuid,
    revision: &str,
) -> Result<Option<StoredTokenBundle>> {
    let mut client = db.trace_pool().get().await?;
    let tx = PgBackend::begin_trace_tenant_transaction(&mut client, tenant).await?;
    let Some(owner) = tx.query_opt("SELECT b.owner_ref FROM trace_token_bundles b JOIN trace_submissions p USING(tenant_id,submission_id) WHERE b.tenant_id=$1 AND b.submission_id=$2 AND b.revision=$3 AND b.state='committed' AND b.expires_at>NOW() AND p.status='accepted' AND p.withdrawn_at IS NULL AND p.purged_at IS NULL", &[&tenant,&submission,&revision]).await? else {return Ok(None)};
    let bundle = row(
        &tx,
        tenant,
        submission,
        revision,
        &owner.get::<_, String>(0),
    )
    .await?;
    tx.commit().await?;
    Ok(bundle)
}
