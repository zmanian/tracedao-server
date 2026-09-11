// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bundle persistence contracts. PostgreSQL holds descriptors, receipts, and
//! temporary encrypted publication packets; it never holds plaintext tokens.
use crate::trace_artifact_store::TraceArtifactObjectRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trace_commons_protocol::token_distribution::{
    ContributionBundleManifest, DurableBundleReceipt,
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTokenBundle {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub revision: String,
    pub owner_ref: String,
    pub manifest: ContributionBundleManifest,
    pub witness_headers: std::collections::BTreeMap<String, String>,
    pub state: String,
    pub processing_state: String,
    pub processing_summary: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
    pub receipt: Option<DurableBundleReceipt>,
    pub attachments: Vec<StoredTokenObject>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTokenObject {
    pub artifact_id: String,
    pub object_ref: TraceArtifactObjectRef,
    pub deleted: bool,
    pub ready: bool,
    #[serde(skip)]
    pub prepared: Option<Vec<u8>>,
}

/// Metadata-only immutable revision cursor; never a plaintext-token search.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBundleQuery {
    pub after_submission: Option<Uuid>,
    pub after_revision: Option<String>,
    pub model: Option<String>,
    pub semantics: Option<String>,
    pub evidence: Option<String>,
    pub requested_alternatives: Option<u32>,
    pub minimum_coverage: Option<f64>,
    pub tokenizer_available: Option<bool>,
    pub limit: Option<u32>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenBundleIndexEntry {
    pub submission_id: Uuid,
    pub revision: String,
    pub manifest_digest: String,
    pub policy_version: String,
    pub summary: serde_json::Value,
}
