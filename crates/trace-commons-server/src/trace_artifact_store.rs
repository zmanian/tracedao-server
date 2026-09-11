// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encrypted local artifact storage primitives for Trace Commons.
//!
//! The ingestion MVP currently writes JSON files directly. This module is the
//! storage building block for the production object-store path: serialize a
//! redacted artifact, encrypt it with the existing IronClaw secrets crypto, and
//! persist only ciphertext plus non-sensitive routing metadata.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use crate::secrets::SecretsCrypto;
use crate::trace_artifact_kek::{KekContext, KmsKeyWrapper};

pub const TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_VERSION: &str = "ironclaw.trace_artifact_ciphertext.v1";
/// Envelope schema version for KEK-wrapped per-object DEK records.
pub const TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2: &str = "ironclaw.trace_artifact_ciphertext.v2";

static TRACE_ARTIFACT_WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedTraceArtifactReceipt {
    pub tenant_storage_ref: String,
    pub artifact_kind: TraceArtifactKind,
    pub object_key: String,
    pub ciphertext_sha256: String,
    pub encrypted_at: DateTime<Utc>,
}

impl EncryptedTraceArtifactReceipt {
    /// Compares the identity and integrity fields of two receipts, ignoring
    /// `encrypted_at`.
    ///
    /// Read paths reconstruct the receipt from a persisted object ref whose
    /// `encrypted_at` is derived from the row's audit `created_at` timestamp —
    /// a different instant than the artifact's true encryption time, which is
    /// never persisted alongside it. A full-struct equality therefore never
    /// holds on any real read. Integrity does not depend on `encrypted_at`:
    /// `ciphertext_sha256` binds the bytes and is independently re-verified
    /// against the decoded ciphertext at every read site.
    pub fn matches_identity(&self, other: &Self) -> bool {
        self.tenant_storage_ref == other.tenant_storage_ref
            && self.artifact_kind == other.artifact_kind
            && self.object_key == other.object_key
            && self.ciphertext_sha256 == other.ciphertext_sha256
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceArtifactProviderConfig {
    pub kind: TraceArtifactProviderKind,
    pub object_store: String,
}

impl TraceArtifactProviderConfig {
    pub fn local_encrypted(object_store: impl Into<String>) -> anyhow::Result<Self> {
        Self::new(TraceArtifactProviderKind::LocalEncrypted, object_store)
    }

    pub fn service_owned_remote(object_store: impl Into<String>) -> anyhow::Result<Self> {
        Self::new(TraceArtifactProviderKind::ServiceOwnedRemote, object_store)
    }

    fn new(
        kind: TraceArtifactProviderKind,
        object_store: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let object_store = object_store.into();
        validate_non_empty_ref("trace artifact object store", &object_store)?;
        anyhow::ensure!(
            object_store
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
            "trace artifact object store contains unsupported characters"
        );
        Ok(Self { kind, object_store })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceArtifactProviderKind {
    LocalEncrypted,
    ServiceOwnedRemote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceArtifactScope {
    pub tenant_storage_ref: String,
    pub submission_storage_ref: String,
}

impl TraceArtifactScope {
    pub fn new(
        tenant_storage_ref: impl Into<String>,
        submission_storage_ref: impl Into<String>,
    ) -> Self {
        Self {
            tenant_storage_ref: tenant_storage_ref.into(),
            submission_storage_ref: submission_storage_ref.into(),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        validate_non_empty_ref("tenant storage ref", &self.tenant_storage_ref)?;
        validate_non_empty_ref("submission storage ref", &self.submission_storage_ref)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceArtifactObjectRef {
    pub provider_kind: TraceArtifactProviderKind,
    pub object_store: String,
    pub tenant_storage_ref: String,
    pub submission_storage_ref: String,
    pub artifact_kind: TraceArtifactKind,
    pub object_key: String,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceArtifactPutReceipt {
    pub object_ref: TraceArtifactObjectRef,
    pub encrypted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceArtifactDeleteReceipt {
    pub object_ref: TraceArtifactObjectRef,
    pub deleted: bool,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceArtifactInvalidationReceipt {
    pub object_ref: TraceArtifactObjectRef,
    pub reason: TraceArtifactInvalidationReason,
    pub invalidated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceArtifactInvalidationReason {
    Revoked,
    RetentionExpired,
    Replaced,
    OperatorRequested,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceArtifactKind {
    ContributionEnvelope,
    TokenDistribution,
    ContributionBundleManifest,
    ReplayExportManifest,
    ReplayDatasetExport,
    BenchmarkConversion,
    RankerTrainingExport,
    VectorPayload,
    AuditSnapshot,
    /// A NEAR wallet account name sealed for read-back at pepper-rotation time
    /// (`near_account_identity`). Not an object-store artifact: nothing under
    /// this kind is ever written to the object store, and the segment exists so
    /// the sealed name gets its own `KekContext` binding rather than sharing
    /// one with a real artifact.
    NearAccountName,
    Other,
}

impl TraceArtifactKind {
    /// Stable wire identifier for each variant. Used both for object-store key
    /// paths and (since the KEK module landed) as a hash-stable binding in
    /// `KekContext::canonical_hash`. Stored `context_hash` values depend on
    /// these exact strings — do not rename without a migration.
    pub fn as_path_segment(&self) -> &'static str {
        match self {
            Self::ContributionEnvelope => "contribution_envelope",
            Self::TokenDistribution => "token_distribution",
            Self::ContributionBundleManifest => "contribution_bundle_manifest",
            Self::ReplayExportManifest => "replay_export_manifest",
            Self::ReplayDatasetExport => "replay_dataset_export",
            Self::BenchmarkConversion => "benchmark_conversion",
            Self::RankerTrainingExport => "ranker_training_export",
            Self::VectorPayload => "vector_payload",
            Self::AuditSnapshot => "audit_snapshot",
            Self::NearAccountName => "near_account_name",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTraceArtifact {
    pub schema_version: String,
    pub receipt: EncryptedTraceArtifactReceipt,
    /// Legacy v1 KDF salt. For v2 envelopes, this is always the empty string —
    /// readers MUST NOT use this field to detect schema version. Use
    /// `schema_version` and `wrapped_dek` instead.
    pub salt_base64: String,
    pub ciphertext_base64: String,
    /// Wrapped per-object DEK for v2 envelopes. Authenticated by AES-GCM
    /// inside the wrapper plus the KekContext binding (`context_hash`) — not
    /// by `receipt.ciphertext_sha256`. Legacy v1 records leave this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_dek: Option<crate::trace_artifact_kek::WrappedDek>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedBundleArtifact {
    pub object_ref: TraceArtifactObjectRef,
    pub artifact: EncryptedTraceArtifact,
}

pub trait TraceArtifactStore: Send + Sync {
    /// Binary bundle support is explicit; legacy stores cannot claim it.
    fn supports_bundle_bytes(&self) -> bool {
        false
    }

    fn prepare_bundle_bytes(
        &self,
        _scope: &TraceArtifactScope,
        _kind: TraceArtifactKind,
        _object_id: &str,
        _bytes: &[u8],
    ) -> anyhow::Result<PreparedBundleArtifact> {
        anyhow::bail!("bundle-byte-storage-unavailable")
    }
    fn publish_bundle_bytes(
        &self,
        _scope: &TraceArtifactScope,
        _prepared: &PreparedBundleArtifact,
    ) -> anyhow::Result<()> {
        anyhow::bail!("bundle-byte-storage-unavailable")
    }

    fn put_bundle_bytes(
        &self,
        _scope: &TraceArtifactScope,
        _kind: TraceArtifactKind,
        _object_id: &str,
        _bytes: &[u8],
    ) -> anyhow::Result<TraceArtifactPutReceipt> {
        anyhow::bail!("bundle-byte-storage-unavailable")
    }
    fn read_bundle_bytes(
        &self,
        _scope: &TraceArtifactScope,
        _object: &TraceArtifactObjectRef,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("bundle-byte-storage-unavailable")
    }
    fn delete_bundle_bytes(
        &self,
        _scope: &TraceArtifactScope,
        _object: &TraceArtifactObjectRef,
    ) -> anyhow::Result<bool> {
        anyhow::bail!("bundle-byte-storage-unavailable")
    }

    fn put_serialized_json(
        &self,
        tenant_storage_ref: &str,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<EncryptedTraceArtifactReceipt>;

    fn read_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<EncryptedTraceArtifact>;

    fn read_json(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<serde_json::Value>;

    fn read_json_by_object_key(
        &self,
        expected_tenant_storage_ref: &str,
        expected_artifact_kind: TraceArtifactKind,
        object_key: &str,
        expected_ciphertext_sha256: &str,
    ) -> anyhow::Result<serde_json::Value>;

    fn delete_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<bool>;

    fn restore_deleted_artifact(
        &self,
        _expected_tenant_storage_ref: &str,
        _receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<bool> {
        anyhow::bail!("trace artifact store does not support restore-after-delete")
    }
}

#[derive(Debug, Clone)]
pub struct RemoteTraceArtifactRecord {
    pub object_ref: TraceArtifactObjectRef,
    pub artifact: EncryptedTraceArtifact,
    pub invalidated_at: Option<DateTime<Utc>>,
}

pub trait RemoteTraceArtifactProvider: Send + Sync {
    fn put_encrypted_artifact(
        &self,
        object_ref: TraceArtifactObjectRef,
        artifact: EncryptedTraceArtifact,
    ) -> anyhow::Result<()>;

    fn read_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<RemoteTraceArtifactRecord>;

    fn invalidate_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
        reason: TraceArtifactInvalidationReason,
        invalidated_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;

    fn delete_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
        deleted_at: DateTime<Utc>,
    ) -> anyhow::Result<bool>;

    fn restore_deleted_encrypted_artifact(
        &self,
        _object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<bool> {
        anyhow::bail!("remote trace artifact provider does not support restore-after-delete")
    }
}

#[derive(Debug, Clone)]
pub struct FileRemoteTraceArtifactProvider {
    root: PathBuf,
    versioned_deletes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileRemoteTraceArtifactRecord {
    object_ref: TraceArtifactObjectRef,
    artifact: EncryptedTraceArtifact,
    invalidated_at: Option<DateTime<Utc>>,
    invalidation_reason: Option<TraceArtifactInvalidationReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileRemoteTraceArtifactDeletedVersion {
    record: FileRemoteTraceArtifactRecord,
    deleted_at: DateTime<Utc>,
}

impl FileRemoteTraceArtifactProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            versioned_deletes: false,
        }
    }

    pub fn versioned(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            versioned_deletes: true,
        }
    }

    fn object_path(&self, object_ref: &TraceArtifactObjectRef) -> anyhow::Result<PathBuf> {
        validate_file_remote_object_ref(object_ref)?;
        let store_dir = self.root.join(&object_ref.object_store);
        let path = store_dir.join(&object_ref.object_key);
        anyhow::ensure!(
            path.starts_with(&store_dir),
            "remote trace artifact path escapes object-store directory"
        );
        Ok(path)
    }

    fn deleted_version_path(&self, object_ref: &TraceArtifactObjectRef) -> anyhow::Result<PathBuf> {
        validate_file_remote_object_ref(object_ref)?;
        let store_dir = self.root.join(&object_ref.object_store);
        let version_dir = store_dir.join(".deleted_versions");
        let version_key = sha256_text_hex(
            &serde_json::json!({
                "object_key": object_ref.object_key,
                "ciphertext_sha256": object_ref.ciphertext_sha256,
            })
            .to_string(),
        );
        let path = version_dir.join(format!("{version_key}.json"));
        anyhow::ensure!(
            path.starts_with(&version_dir),
            "remote trace artifact deleted-version path escapes object-store directory"
        );
        Ok(path)
    }

    fn read_record(
        &self,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<FileRemoteTraceArtifactRecord> {
        let path = self.object_path(object_ref)?;
        let record = Self::read_record_at_path(&path)?;
        anyhow::ensure!(
            record.object_ref == *object_ref,
            "remote trace artifact object ref mismatch"
        );
        Ok(record)
    }

    fn read_record_at_path(path: &Path) -> anyhow::Result<FileRemoteTraceArtifactRecord> {
        let body = std::fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read remote trace artifact object {}",
                path.display()
            )
        })?;
        serde_json::from_str(&body).context("failed to parse remote trace artifact record")
    }

    fn write_record(&self, record: &FileRemoteTraceArtifactRecord) -> anyhow::Result<()> {
        let path = self.object_path(&record.object_ref)?;
        if path.exists() {
            let existing = Self::read_record_at_path(&path)?;
            anyhow::ensure!(
                existing.object_ref == record.object_ref,
                "remote trace artifact object key already exists for a different object ref"
            );
        }
        write_json_file(&path, record)
    }

    fn write_deleted_version(
        &self,
        record: FileRemoteTraceArtifactRecord,
        deleted_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let path = self.deleted_version_path(&record.object_ref)?;
        let version = FileRemoteTraceArtifactDeletedVersion { record, deleted_at };
        write_json_file(&path, &version)
    }

    fn read_deleted_version(
        &self,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<Option<FileRemoteTraceArtifactDeletedVersion>> {
        let path = self.deleted_version_path(object_ref)?;
        if !path.exists() {
            return Ok(None);
        }
        let body = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read remote trace artifact deleted version {}",
                path.display()
            )
        })?;
        let version: FileRemoteTraceArtifactDeletedVersion = serde_json::from_str(&body)
            .context("failed to parse remote trace artifact deleted version")?;
        anyhow::ensure!(
            version.record.object_ref == *object_ref,
            "remote trace artifact deleted-version object ref mismatch"
        );
        Ok(Some(version))
    }
}

impl RemoteTraceArtifactProvider for FileRemoteTraceArtifactProvider {
    fn put_encrypted_artifact(
        &self,
        object_ref: TraceArtifactObjectRef,
        artifact: EncryptedTraceArtifact,
    ) -> anyhow::Result<()> {
        validate_file_remote_object_ref(&object_ref)?;
        verify_encrypted_artifact(
            &artifact,
            object_ref.tenant_storage_ref.as_str(),
            &object_ref.artifact_kind,
            object_ref.object_key.as_str(),
            object_ref.ciphertext_sha256.as_str(),
        )?;
        let record = FileRemoteTraceArtifactRecord {
            object_ref,
            artifact,
            invalidated_at: None,
            invalidation_reason: None,
        };
        self.write_record(&record)
    }

    fn read_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<RemoteTraceArtifactRecord> {
        let record = self.read_record(object_ref)?;
        Ok(RemoteTraceArtifactRecord {
            object_ref: record.object_ref,
            artifact: record.artifact,
            invalidated_at: record.invalidated_at,
        })
    }

    fn invalidate_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
        reason: TraceArtifactInvalidationReason,
        invalidated_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut record = self.read_record(object_ref)?;
        record.invalidated_at = Some(invalidated_at);
        record.invalidation_reason = Some(reason);
        self.write_record(&record)
    }

    fn delete_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
        deleted_at: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let path = self.object_path(object_ref)?;
        if !path.exists() {
            return Ok(false);
        }
        if self.versioned_deletes {
            let record = self.read_record(object_ref)?;
            self.write_deleted_version(record, deleted_at)?;
        }
        std::fs::remove_file(&path).with_context(|| {
            format!(
                "failed to delete remote trace artifact object {}",
                path.display()
            )
        })?;
        Ok(true)
    }

    fn restore_deleted_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            self.versioned_deletes,
            "remote trace artifact provider does not support restore-after-delete"
        );
        let path = self.object_path(object_ref)?;
        if path.exists() {
            return Ok(false);
        }
        let Some(version) = self.read_deleted_version(object_ref)? else {
            return Ok(false);
        };
        self.write_record(&version.record)?;
        Ok(true)
    }
}

const TRACE_ARTIFACT_STORE_LEGACY_SUBMISSION_STORAGE_REF: &str = "trace-artifact-store-legacy";

pub struct ServiceOwnedTraceArtifactStore<P, K> {
    config: TraceArtifactProviderConfig,
    crypto: SecretsCrypto,
    kek: K,
    provider: P,
}

impl<P: RemoteTraceArtifactProvider, K: KmsKeyWrapper> ServiceOwnedTraceArtifactStore<P, K> {
    pub fn new(
        config: TraceArtifactProviderConfig,
        crypto: SecretsCrypto,
        kek: K,
        provider: P,
    ) -> Self {
        Self {
            config,
            crypto,
            kek,
            provider,
        }
    }

    pub fn put_scoped_json<T: Serialize>(
        &self,
        scope: &TraceArtifactScope,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        value: &T,
    ) -> anyhow::Result<TraceArtifactPutReceipt> {
        let plaintext = serde_json::to_vec(value).context("failed to serialize trace artifact")?;
        self.put_scoped_serialized_json(scope, artifact_kind, object_id, &plaintext)
    }

    pub fn put_scoped_serialized_json(
        &self,
        scope: &TraceArtifactScope,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<TraceArtifactPutReceipt> {
        serde_json::from_slice::<serde_json::Value>(serialized_json)
            .context("failed to parse serialized trace artifact")?;
        self.put_scoped_bytes(scope, artifact_kind, object_id, serialized_json)
    }

    pub fn put_scoped_bytes(
        &self,
        scope: &TraceArtifactScope,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<TraceArtifactPutReceipt> {
        let prepared =
            self.prepare_scoped_bytes(scope, artifact_kind, object_id, serialized_json)?;
        self.provider
            .put_encrypted_artifact(prepared.object_ref.clone(), prepared.artifact.clone())?;
        Ok(TraceArtifactPutReceipt {
            object_ref: prepared.object_ref,
            encrypted_at: prepared.artifact.receipt.encrypted_at,
        })
    }
    fn prepare_scoped_bytes(
        &self,
        scope: &TraceArtifactScope,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<PreparedBundleArtifact> {
        self.validate_remote_config()?;
        scope.validate()?;
        validate_non_empty_ref("trace artifact object id", object_id)?;
        // v2 envelope: wrap a freshly generated DEK with the configured KEK
        // and AES-256-GCM-encrypt the plaintext directly under that DEK.
        let dek = generate_dek();
        let kek_ctx = KekContext {
            tenant_storage_ref: scope.tenant_storage_ref.clone(),
            artifact_kind: artifact_kind.clone(),
        };
        let wrapped = self
            .kek
            .wrap_dek(&dek, &kek_ctx)
            .context("KekWrapFailed: trace artifact DEK wrap failed")?;
        let ciphertext = aead_encrypt_with_dek(&dek, serialized_json)
            .context("failed to encrypt trace artifact under per-object DEK")?;
        let ciphertext_sha256 = sha256_hex(&ciphertext);
        let object_key = remote_artifact_object_key(&self.config, scope, &artifact_kind, object_id);
        let encrypted_at = Utc::now();
        let legacy_receipt = EncryptedTraceArtifactReceipt {
            tenant_storage_ref: scope.tenant_storage_ref.clone(),
            artifact_kind: artifact_kind.clone(),
            object_key: object_key.clone(),
            ciphertext_sha256: ciphertext_sha256.clone(),
            encrypted_at,
        };
        let artifact = EncryptedTraceArtifact {
            schema_version: TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2.to_string(),
            receipt: legacy_receipt,
            // v2 records use the wrapped DEK + AES-GCM nonce embedded in the
            // ciphertext. The legacy `salt_base64` field is kept as an empty
            // string for serde compatibility with the v1 schema shape.
            salt_base64: String::new(),
            ciphertext_base64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
            wrapped_dek: Some(wrapped),
        };
        let object_ref = TraceArtifactObjectRef {
            provider_kind: self.config.kind,
            object_store: self.config.object_store.clone(),
            tenant_storage_ref: scope.tenant_storage_ref.clone(),
            submission_storage_ref: scope.submission_storage_ref.clone(),
            artifact_kind,
            object_key,
            ciphertext_sha256,
        };
        validate_remote_object_ref(scope, &self.config, &object_ref)?;
        Ok(PreparedBundleArtifact {
            object_ref,
            artifact,
        })
    }

    pub fn read_scoped_artifact(
        &self,
        expected_scope: &TraceArtifactScope,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<EncryptedTraceArtifact> {
        validate_remote_object_ref(expected_scope, &self.config, object_ref)?;
        let record = self.provider.read_encrypted_artifact(object_ref)?;
        anyhow::ensure!(
            record.object_ref == *object_ref,
            "remote trace artifact object ref mismatch"
        );
        anyhow::ensure!(
            record.invalidated_at.is_none(),
            "remote trace artifact object ref invalidated"
        );
        verify_encrypted_artifact(
            &record.artifact,
            expected_scope.tenant_storage_ref.as_str(),
            &object_ref.artifact_kind,
            object_ref.object_key.as_str(),
            object_ref.ciphertext_sha256.as_str(),
        )?;
        Ok(record.artifact)
    }

    pub fn read_scoped_json<T: DeserializeOwned>(
        &self,
        expected_scope: &TraceArtifactScope,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<T> {
        let artifact = self.read_scoped_artifact(expected_scope, object_ref)?;
        decrypt_artifact_json_with_kek(
            &self.crypto,
            &self.kek,
            &artifact,
            &object_ref.artifact_kind,
        )
    }

    pub fn invalidate_scoped_artifact(
        &self,
        expected_scope: &TraceArtifactScope,
        object_ref: &TraceArtifactObjectRef,
        reason: TraceArtifactInvalidationReason,
    ) -> anyhow::Result<TraceArtifactInvalidationReceipt> {
        validate_remote_object_ref(expected_scope, &self.config, object_ref)?;
        let invalidated_at = Utc::now();
        self.provider
            .invalidate_encrypted_artifact(object_ref, reason, invalidated_at)?;
        Ok(TraceArtifactInvalidationReceipt {
            object_ref: object_ref.clone(),
            reason,
            invalidated_at,
        })
    }

    pub fn delete_scoped_artifact(
        &self,
        expected_scope: &TraceArtifactScope,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<TraceArtifactDeleteReceipt> {
        validate_remote_object_ref(expected_scope, &self.config, object_ref)?;
        let deleted_at = Utc::now();
        let deleted = self
            .provider
            .delete_encrypted_artifact(object_ref, deleted_at)?;
        Ok(TraceArtifactDeleteReceipt {
            object_ref: object_ref.clone(),
            deleted,
            deleted_at,
        })
    }

    pub fn restore_deleted_scoped_artifact(
        &self,
        expected_scope: &TraceArtifactScope,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<bool> {
        validate_remote_object_ref(expected_scope, &self.config, object_ref)?;
        self.provider.restore_deleted_encrypted_artifact(object_ref)
    }

    fn validate_remote_config(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.config.kind == TraceArtifactProviderKind::ServiceOwnedRemote,
            "trace artifact provider config is not remote service-owned"
        );
        validate_non_empty_ref("trace artifact object store", &self.config.object_store)
    }
}

impl<P: RemoteTraceArtifactProvider, K: KmsKeyWrapper> TraceArtifactStore
    for ServiceOwnedTraceArtifactStore<P, K>
{
    fn prepare_bundle_bytes(
        &self,
        scope: &TraceArtifactScope,
        kind: TraceArtifactKind,
        object_id: &str,
        bytes: &[u8],
    ) -> anyhow::Result<PreparedBundleArtifact> {
        anyhow::ensure!(
            matches!(
                kind,
                TraceArtifactKind::TokenDistribution
                    | TraceArtifactKind::ContributionBundleManifest
                    | TraceArtifactKind::ContributionEnvelope
            ),
            "invalid-bundle-artifact-kind"
        );
        anyhow::ensure!(bytes.len() <= 8 * 1024 * 1024, "bundle-artifact-limit");
        self.prepare_scoped_bytes(scope, kind, object_id, bytes)
    }
    fn publish_bundle_bytes(
        &self,
        scope: &TraceArtifactScope,
        prepared: &PreparedBundleArtifact,
    ) -> anyhow::Result<()> {
        validate_remote_object_ref(scope, &self.config, &prepared.object_ref)?;
        verify_encrypted_artifact(
            &prepared.artifact,
            &scope.tenant_storage_ref,
            &prepared.object_ref.artifact_kind,
            &prepared.object_ref.object_key,
            &prepared.object_ref.ciphertext_sha256,
        )?;
        self.provider
            .put_encrypted_artifact(prepared.object_ref.clone(), prepared.artifact.clone())
    }
    fn supports_bundle_bytes(&self) -> bool {
        true
    }
    fn put_bundle_bytes(
        &self,
        scope: &TraceArtifactScope,
        kind: TraceArtifactKind,
        object_id: &str,
        bytes: &[u8],
    ) -> anyhow::Result<TraceArtifactPutReceipt> {
        anyhow::ensure!(
            matches!(
                kind,
                TraceArtifactKind::TokenDistribution
                    | TraceArtifactKind::ContributionBundleManifest
                    | TraceArtifactKind::ContributionEnvelope
            ),
            "invalid-bundle-artifact-kind"
        );
        anyhow::ensure!(bytes.len() <= 8 * 1024 * 1024, "bundle-artifact-limit");
        self.put_scoped_bytes(scope, kind, object_id, bytes)
    }
    fn read_bundle_bytes(
        &self,
        scope: &TraceArtifactScope,
        object: &TraceArtifactObjectRef,
    ) -> anyhow::Result<Vec<u8>> {
        let artifact = self.read_scoped_artifact(scope, object)?;
        anyhow::ensure!(
            artifact.schema_version == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2,
            "bundle-v2-encryption-required"
        );
        let wrapped = artifact
            .wrapped_dek
            .as_ref()
            .context("bundle-key-unavailable")?;
        let ctx = KekContext {
            tenant_storage_ref: scope.tenant_storage_ref.clone(),
            artifact_kind: object.artifact_kind.clone(),
        };
        let dek = self.kek.unwrap_dek(wrapped, &ctx)?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(artifact.ciphertext_base64.as_bytes())?;
        let plaintext = aead_decrypt_with_dek(&dek, &ciphertext)?;
        anyhow::ensure!(plaintext.len() <= 8 * 1024 * 1024, "bundle-artifact-limit");
        Ok(plaintext)
    }
    fn delete_bundle_bytes(
        &self,
        scope: &TraceArtifactScope,
        object: &TraceArtifactObjectRef,
    ) -> anyhow::Result<bool> {
        self.delete_scoped_artifact(scope, object)
            .map(|receipt| receipt.deleted)
    }

    fn put_serialized_json(
        &self,
        tenant_storage_ref: &str,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<EncryptedTraceArtifactReceipt> {
        let scope = legacy_trace_artifact_scope(tenant_storage_ref);
        let receipt =
            self.put_scoped_serialized_json(&scope, artifact_kind, object_id, serialized_json)?;
        Ok(EncryptedTraceArtifactReceipt {
            tenant_storage_ref: receipt.object_ref.tenant_storage_ref,
            artifact_kind: receipt.object_ref.artifact_kind,
            object_key: receipt.object_ref.object_key,
            ciphertext_sha256: receipt.object_ref.ciphertext_sha256,
            encrypted_at: receipt.encrypted_at,
        })
    }

    fn read_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<EncryptedTraceArtifact> {
        anyhow::ensure!(
            receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "trace artifact receipt tenant mismatch"
        );
        let scope = legacy_trace_artifact_scope(expected_tenant_storage_ref);
        let object_ref = legacy_remote_object_ref_from_receipt(&self.config, &scope, receipt)?;
        let artifact = self.read_scoped_artifact(&scope, &object_ref)?;
        anyhow::ensure!(
            artifact.receipt.matches_identity(receipt),
            "encrypted trace artifact receipt mismatch"
        );
        Ok(artifact)
    }

    fn read_json(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<serde_json::Value> {
        let artifact =
            TraceArtifactStore::read_artifact(self, expected_tenant_storage_ref, receipt)?;
        decrypt_artifact_json_with_kek(&self.crypto, &self.kek, &artifact, &receipt.artifact_kind)
    }

    fn read_json_by_object_key(
        &self,
        expected_tenant_storage_ref: &str,
        expected_artifact_kind: TraceArtifactKind,
        object_key: &str,
        expected_ciphertext_sha256: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let scope = legacy_trace_artifact_scope(expected_tenant_storage_ref);
        let object_ref = legacy_remote_object_ref_from_object_key(
            &self.config,
            &scope,
            expected_artifact_kind,
            object_key,
            expected_ciphertext_sha256,
        )?;
        self.read_scoped_json(&scope, &object_ref)
    }

    fn delete_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "trace artifact receipt tenant mismatch"
        );
        let scope = legacy_trace_artifact_scope(expected_tenant_storage_ref);
        let object_ref = legacy_remote_object_ref_from_receipt(&self.config, &scope, receipt)?;
        let delete_receipt = self.delete_scoped_artifact(&scope, &object_ref)?;
        Ok(delete_receipt.deleted)
    }

    fn restore_deleted_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "trace artifact receipt tenant mismatch"
        );
        let scope = legacy_trace_artifact_scope(expected_tenant_storage_ref);
        let object_ref = legacy_remote_object_ref_from_receipt(&self.config, &scope, receipt)?;
        self.restore_deleted_scoped_artifact(&scope, &object_ref)
    }
}

pub struct LocalEncryptedTraceArtifactStore {
    root: PathBuf,
    crypto: SecretsCrypto,
}

impl LocalEncryptedTraceArtifactStore {
    pub fn new(root: impl Into<PathBuf>, crypto: SecretsCrypto) -> Self {
        Self {
            root: root.into(),
            crypto,
        }
    }

    pub fn put_json<T: Serialize>(
        &self,
        tenant_storage_ref: &str,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        value: &T,
    ) -> anyhow::Result<EncryptedTraceArtifactReceipt> {
        let plaintext = serde_json::to_vec(value).context("failed to serialize trace artifact")?;
        self.put_serialized_json(tenant_storage_ref, artifact_kind, object_id, &plaintext)
    }

    pub fn put_serialized_json(
        &self,
        tenant_storage_ref: &str,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<EncryptedTraceArtifactReceipt> {
        serde_json::from_slice::<serde_json::Value>(serialized_json)
            .context("failed to parse serialized trace artifact")?;
        let (ciphertext, salt) = self
            .crypto
            .encrypt(serialized_json)
            .context("failed to encrypt trace artifact")?;
        let ciphertext_sha256 = sha256_hex(&ciphertext);
        let object_key = artifact_object_key(tenant_storage_ref, &artifact_kind, object_id);
        let receipt = EncryptedTraceArtifactReceipt {
            tenant_storage_ref: tenant_storage_ref.to_string(),
            artifact_kind,
            object_key,
            ciphertext_sha256,
            encrypted_at: Utc::now(),
        };
        let artifact = EncryptedTraceArtifact {
            schema_version: TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_VERSION.to_string(),
            receipt: receipt.clone(),
            salt_base64: base64::engine::general_purpose::STANDARD.encode(salt),
            ciphertext_base64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
            wrapped_dek: None,
        };
        write_json_file(
            &self.artifact_path(&receipt.tenant_storage_ref, &receipt.object_key)?,
            &artifact,
        )?;
        Ok(receipt)
    }

    pub fn get_json<T: DeserializeOwned>(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<T> {
        let artifact = self.read_artifact(expected_tenant_storage_ref, receipt)?;
        if artifact.schema_version == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2 {
            anyhow::bail!(
                "LocalEncryptedTraceArtifactStore does not support v2 KEK-wrapped artifacts"
            );
        }
        decrypt_artifact_json(&self.crypto, &artifact)
    }

    pub fn get_json_by_object_key<T: DeserializeOwned>(
        &self,
        expected_tenant_storage_ref: &str,
        expected_artifact_kind: TraceArtifactKind,
        object_key: &str,
        expected_ciphertext_sha256: &str,
    ) -> anyhow::Result<T> {
        let artifact = self.read_artifact_by_object_key(
            expected_tenant_storage_ref,
            expected_artifact_kind,
            object_key,
            expected_ciphertext_sha256,
        )?;
        if artifact.schema_version == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2 {
            anyhow::bail!(
                "LocalEncryptedTraceArtifactStore does not support v2 KEK-wrapped artifacts"
            );
        }
        decrypt_artifact_json(&self.crypto, &artifact)
    }

    pub fn read_artifact_by_object_key(
        &self,
        expected_tenant_storage_ref: &str,
        expected_artifact_kind: TraceArtifactKind,
        object_key: &str,
        expected_ciphertext_sha256: &str,
    ) -> anyhow::Result<EncryptedTraceArtifact> {
        let expected_ciphertext_sha256 = expected_ciphertext_sha256
            .strip_prefix("sha256:")
            .unwrap_or(expected_ciphertext_sha256);
        let path = self.artifact_path(expected_tenant_storage_ref, object_key)?;
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read trace artifact {}", path.display()))?;
        let artifact: EncryptedTraceArtifact =
            serde_json::from_str(&body).context("failed to parse encrypted trace artifact")?;
        anyhow::ensure!(
            artifact.receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "encrypted trace artifact tenant mismatch"
        );
        anyhow::ensure!(
            artifact.receipt.artifact_kind == expected_artifact_kind,
            "encrypted trace artifact kind mismatch"
        );
        anyhow::ensure!(
            artifact.receipt.object_key == object_key,
            "encrypted trace artifact object key mismatch"
        );
        anyhow::ensure!(
            artifact.receipt.ciphertext_sha256 == expected_ciphertext_sha256,
            "encrypted trace artifact receipt hash mismatch"
        );
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(artifact.ciphertext_base64.as_bytes())
            .context("failed to decode trace artifact ciphertext for hash check")?;
        anyhow::ensure!(
            sha256_hex(&ciphertext) == expected_ciphertext_sha256,
            "trace artifact ciphertext hash mismatch"
        );
        verify_kek_binding(
            &artifact,
            expected_tenant_storage_ref,
            &expected_artifact_kind,
        )?;
        Ok(artifact)
    }

    pub fn read_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<EncryptedTraceArtifact> {
        anyhow::ensure!(
            receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "trace artifact receipt tenant mismatch"
        );
        let path = self.artifact_path(expected_tenant_storage_ref, &receipt.object_key)?;
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read trace artifact {}", path.display()))?;
        let artifact: EncryptedTraceArtifact =
            serde_json::from_str(&body).context("failed to parse encrypted trace artifact")?;
        anyhow::ensure!(
            artifact.receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "encrypted trace artifact tenant mismatch"
        );
        anyhow::ensure!(
            artifact.receipt.matches_identity(receipt),
            "encrypted trace artifact receipt mismatch"
        );
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(artifact.ciphertext_base64.as_bytes())
            .context("failed to decode trace artifact ciphertext for hash check")?;
        anyhow::ensure!(
            sha256_hex(&ciphertext) == receipt.ciphertext_sha256,
            "trace artifact ciphertext hash mismatch"
        );
        verify_kek_binding(
            &artifact,
            expected_tenant_storage_ref,
            &receipt.artifact_kind,
        )?;
        Ok(artifact)
    }

    pub fn delete_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            receipt.tenant_storage_ref == expected_tenant_storage_ref,
            "trace artifact receipt tenant mismatch"
        );
        let path = self.artifact_path(expected_tenant_storage_ref, &receipt.object_key)?;
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to delete trace artifact {}", path.display()))?;
        Ok(true)
    }

    fn artifact_path(&self, tenant_storage_ref: &str, object_key: &str) -> anyhow::Result<PathBuf> {
        validate_object_key(object_key)?;
        let artifact_dir = self.tenant_artifact_dir(tenant_storage_ref)?;
        let path = artifact_dir.join(format!("{object_key}.json"));
        anyhow::ensure!(
            path.starts_with(&artifact_dir),
            "trace artifact path escapes tenant artifact directory"
        );
        Ok(path)
    }

    fn tenant_artifact_dir(&self, tenant_storage_ref: &str) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            !tenant_storage_ref.trim().is_empty(),
            "tenant storage ref must not be empty"
        );
        Ok(self
            .root
            .join("tenants")
            .join(sha256_text_hex(tenant_storage_ref))
            .join("artifacts"))
    }
}

impl TraceArtifactStore for LocalEncryptedTraceArtifactStore {
    fn put_serialized_json(
        &self,
        tenant_storage_ref: &str,
        artifact_kind: TraceArtifactKind,
        object_id: &str,
        serialized_json: &[u8],
    ) -> anyhow::Result<EncryptedTraceArtifactReceipt> {
        Self::put_serialized_json(
            self,
            tenant_storage_ref,
            artifact_kind,
            object_id,
            serialized_json,
        )
    }

    fn read_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<EncryptedTraceArtifact> {
        Self::read_artifact(self, expected_tenant_storage_ref, receipt)
    }

    fn read_json(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<serde_json::Value> {
        Self::get_json(self, expected_tenant_storage_ref, receipt)
    }

    fn read_json_by_object_key(
        &self,
        expected_tenant_storage_ref: &str,
        expected_artifact_kind: TraceArtifactKind,
        object_key: &str,
        expected_ciphertext_sha256: &str,
    ) -> anyhow::Result<serde_json::Value> {
        Self::get_json_by_object_key(
            self,
            expected_tenant_storage_ref,
            expected_artifact_kind,
            object_key,
            expected_ciphertext_sha256,
        )
    }

    fn delete_artifact(
        &self,
        expected_tenant_storage_ref: &str,
        receipt: &EncryptedTraceArtifactReceipt,
    ) -> anyhow::Result<bool> {
        Self::delete_artifact(self, expected_tenant_storage_ref, receipt)
    }
}

fn decrypt_artifact_json<T: DeserializeOwned>(
    crypto: &SecretsCrypto,
    artifact: &EncryptedTraceArtifact,
) -> anyhow::Result<T> {
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(artifact.ciphertext_base64.as_bytes())
        .context("failed to decode trace artifact ciphertext")?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(artifact.salt_base64.as_bytes())
        .context("failed to decode trace artifact salt")?;
    let decrypted = crypto
        .decrypt(&ciphertext, &salt)
        .context("failed to decrypt trace artifact")?;
    let plaintext = decrypted.expose().as_bytes();
    serde_json::from_slice(plaintext).context("failed to deserialize trace artifact")
}

pub(crate) fn verify_encrypted_artifact(
    artifact: &EncryptedTraceArtifact,
    expected_tenant_storage_ref: &str,
    expected_artifact_kind: &TraceArtifactKind,
    expected_object_key: &str,
    expected_ciphertext_sha256: &str,
) -> anyhow::Result<()> {
    let expected_ciphertext_sha256 = expected_ciphertext_sha256
        .strip_prefix("sha256:")
        .unwrap_or(expected_ciphertext_sha256);
    anyhow::ensure!(
        artifact.receipt.tenant_storage_ref == expected_tenant_storage_ref,
        "encrypted trace artifact tenant mismatch"
    );
    anyhow::ensure!(
        artifact.receipt.artifact_kind == *expected_artifact_kind,
        "encrypted trace artifact kind mismatch"
    );
    anyhow::ensure!(
        artifact.receipt.object_key == expected_object_key,
        "encrypted trace artifact object key mismatch"
    );
    anyhow::ensure!(
        artifact.receipt.ciphertext_sha256 == expected_ciphertext_sha256,
        "encrypted trace artifact receipt hash mismatch"
    );
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(artifact.ciphertext_base64.as_bytes())
        .context("failed to decode trace artifact ciphertext for hash check")?;
    anyhow::ensure!(
        sha256_hex(&ciphertext) == expected_ciphertext_sha256,
        "trace artifact ciphertext hash mismatch"
    );
    verify_kek_binding(
        artifact,
        expected_tenant_storage_ref,
        expected_artifact_kind,
    )?;
    Ok(())
}

/// Shared schema-version / `wrapped_dek` shape gate.
///
/// Refuses any cross-shape envelope to prevent a v1-reader from being used as
/// a downgrade oracle for v2 records (and vice versa).
fn verify_kek_binding(
    artifact: &EncryptedTraceArtifact,
    tenant_storage_ref: &str,
    artifact_kind: &TraceArtifactKind,
) -> anyhow::Result<()> {
    match artifact.schema_version.as_str() {
        v if v == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_VERSION => {
            anyhow::ensure!(
                artifact.wrapped_dek.is_none(),
                "KekDowngradeRejected: v1 record carries wrapped_dek"
            );
            Ok(())
        }
        v if v == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2 => {
            let wrapped = artifact.wrapped_dek.as_ref().ok_or_else(|| {
                anyhow::anyhow!("KekDowngradeRejected: v2 record missing wrapped_dek")
            })?;
            let ctx = KekContext {
                tenant_storage_ref: tenant_storage_ref.to_string(),
                artifact_kind: artifact_kind.clone(),
            };
            anyhow::ensure!(
                wrapped.context_hash == ctx.canonical_hash(),
                "KekContextMismatch: wrapped_dek context_hash does not match expected tenant and artifact kind"
            );
            Ok(())
        }
        _ => anyhow::bail!("KekDowngradeRejected: unknown schema_version"),
    }
}

/// Generate a fresh 256-bit per-object DEK using the OS RNG.
///
/// Returns a `Zeroizing` wrapper so the raw key bytes are cleared from the
/// stack automatically on drop, reducing the window during which plaintext
/// key material could appear in core dumps or stack traces.
/// `pub(crate)` so `near_account_identity` can seal an account name under the
/// same per-row DEK envelope the artifact store uses, rather than growing a
/// second key-generation path.
pub(crate) fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut dek = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, dek.as_mut());
    dek
}

/// AES-256-GCM encrypt `plaintext` under `dek`, returning the
/// `[nonce || aead_ciphertext_with_tag]` packed form used by v2 records.
///
/// `pub(crate)` so the gate-service module can build matching test fixtures
/// (it pairs with the same-visibility `aead_decrypt_with_dek` below).
pub(crate) fn aead_encrypt_with_dek(
    dek: &Zeroizing<[u8; 32]>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, AeadCore, OsRng};
    use aes_gcm::{Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new_from_slice(dek.as_ref())
        .map_err(|e| anyhow::anyhow!("KekDekEncryptFailed: cipher init: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("KekDekEncryptFailed: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM decrypt the `[nonce || aead_ciphertext_with_tag]` packed form
/// produced by `aead_encrypt_with_dek`.
///
/// `pub` so the in-process gate service (`EnclaveGateService`) and the
/// `trace-commons-vector-replay` recovery binary can reuse the same routine to
/// recover plaintext from envelope ciphertext for scoring / re-embedding.
/// JSON-payload callers must continue going through the existing
/// `decrypt_artifact_json*` helpers, which also handle schema-version gating.
pub fn aead_decrypt_with_dek(
    dek: &Zeroizing<[u8; 32]>,
    encrypted: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    anyhow::ensure!(
        encrypted.len() >= NONCE_LEN + TAG_LEN,
        "KekDekDecryptFailed: ciphertext too short"
    );
    let cipher = Aes256Gcm::new_from_slice(dek.as_ref())
        .map_err(|e| anyhow::anyhow!("KekDekDecryptFailed: cipher init: {e}"))?;
    let (nonce_bytes, ct) = encrypted.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("KekDekDecryptFailed: {e}"))
}

/// Decrypt an artifact JSON payload, branching on schema version. v1 uses the
/// legacy `SecretsCrypto` reader path; v2 unwraps the per-object DEK through
/// the configured `KmsKeyWrapper` and AES-256-GCM-decrypts the ciphertext.
fn decrypt_artifact_json_with_kek<T: DeserializeOwned, K: KmsKeyWrapper>(
    crypto: &SecretsCrypto,
    kek: &K,
    artifact: &EncryptedTraceArtifact,
    artifact_kind: &TraceArtifactKind,
) -> anyhow::Result<T> {
    match artifact.schema_version.as_str() {
        v if v == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_VERSION => {
            anyhow::ensure!(
                artifact.wrapped_dek.is_none(),
                "KekDowngradeRejected: v1 record carries wrapped_dek"
            );
            decrypt_artifact_json(crypto, artifact)
        }
        v if v == TRACE_ARTIFACT_CIPHERTEXT_SCHEMA_V2 => {
            let wrapped = artifact.wrapped_dek.as_ref().ok_or_else(|| {
                anyhow::anyhow!("KekDowngradeRejected: v2 record missing wrapped_dek")
            })?;
            let ctx = KekContext {
                tenant_storage_ref: artifact.receipt.tenant_storage_ref.clone(),
                artifact_kind: artifact_kind.clone(),
            };
            let dek = kek
                .unwrap_dek(wrapped, &ctx)
                .context("KekUnwrapFailed: trace artifact DEK unwrap failed")?;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(artifact.ciphertext_base64.as_bytes())
                .context("failed to decode trace artifact ciphertext")?;
            let plaintext = aead_decrypt_with_dek(&dek, &ciphertext)?;
            serde_json::from_slice(&plaintext).context("failed to deserialize trace artifact")
        }
        _ => anyhow::bail!("KekDowngradeRejected: unknown schema_version"),
    }
}

fn validate_remote_object_ref(
    expected_scope: &TraceArtifactScope,
    expected_config: &TraceArtifactProviderConfig,
    object_ref: &TraceArtifactObjectRef,
) -> anyhow::Result<()> {
    expected_scope.validate()?;
    validate_remote_object_key(&object_ref.object_key)?;
    validate_object_hash(&object_ref.ciphertext_sha256)?;
    anyhow::ensure!(
        object_ref.provider_kind == TraceArtifactProviderKind::ServiceOwnedRemote,
        "remote trace artifact provider kind mismatch"
    );
    anyhow::ensure!(
        object_ref.provider_kind == expected_config.kind,
        "remote trace artifact config kind mismatch"
    );
    anyhow::ensure!(
        object_ref.object_store == expected_config.object_store,
        "remote trace artifact object store mismatch"
    );
    anyhow::ensure!(
        object_ref.tenant_storage_ref == expected_scope.tenant_storage_ref,
        "remote trace artifact tenant mismatch"
    );
    anyhow::ensure!(
        object_ref.submission_storage_ref == expected_scope.submission_storage_ref,
        "remote trace artifact submission mismatch"
    );
    validate_remote_object_key_scope(expected_scope, &object_ref.object_key)?;
    Ok(())
}

fn validate_remote_object_key_scope(
    expected_scope: &TraceArtifactScope,
    object_key: &str,
) -> anyhow::Result<()> {
    let segments: Vec<&str> = object_key.split('/').collect();
    anyhow::ensure!(
        segments.len() >= 7
            && segments[0] == "v1"
            && segments[1] == "tenants"
            && segments[3] == "submissions",
        "remote trace artifact object key has unsupported partition layout"
    );
    anyhow::ensure!(
        segments[2] == sha256_text_hex(&expected_scope.tenant_storage_ref),
        "remote trace artifact tenant mismatch: object key partition"
    );
    anyhow::ensure!(
        segments[4] == sha256_text_hex(&expected_scope.submission_storage_ref),
        "remote trace artifact submission mismatch: object key partition"
    );
    Ok(())
}

fn legacy_trace_artifact_scope(tenant_storage_ref: &str) -> TraceArtifactScope {
    TraceArtifactScope::new(
        tenant_storage_ref,
        TRACE_ARTIFACT_STORE_LEGACY_SUBMISSION_STORAGE_REF,
    )
}

fn legacy_remote_object_ref_from_receipt(
    config: &TraceArtifactProviderConfig,
    scope: &TraceArtifactScope,
    receipt: &EncryptedTraceArtifactReceipt,
) -> anyhow::Result<TraceArtifactObjectRef> {
    anyhow::ensure!(
        receipt.tenant_storage_ref == scope.tenant_storage_ref,
        "trace artifact receipt tenant mismatch"
    );
    legacy_remote_object_ref_from_object_key(
        config,
        scope,
        receipt.artifact_kind.clone(),
        &receipt.object_key,
        &receipt.ciphertext_sha256,
    )
}

fn legacy_remote_object_ref_from_object_key(
    config: &TraceArtifactProviderConfig,
    scope: &TraceArtifactScope,
    artifact_kind: TraceArtifactKind,
    object_key: &str,
    ciphertext_sha256: &str,
) -> anyhow::Result<TraceArtifactObjectRef> {
    let object_ref = TraceArtifactObjectRef {
        provider_kind: TraceArtifactProviderKind::ServiceOwnedRemote,
        object_store: config.object_store.clone(),
        tenant_storage_ref: scope.tenant_storage_ref.clone(),
        submission_storage_ref: scope.submission_storage_ref.clone(),
        artifact_kind,
        object_key: object_key.to_string(),
        ciphertext_sha256: ciphertext_sha256
            .strip_prefix("sha256:")
            .unwrap_or(ciphertext_sha256)
            .to_string(),
    };
    validate_remote_object_ref(scope, config, &object_ref)?;
    Ok(object_ref)
}

fn validate_non_empty_ref(label: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!value.trim().is_empty(), "{label} must not be empty");
    anyhow::ensure!(
        !value.bytes().any(|byte| byte.is_ascii_control()),
        "{label} must not contain control characters"
    );
    Ok(())
}

fn validate_object_hash(value: &str) -> anyhow::Result<()> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "trace artifact ciphertext hash must be a 64-character hex digest"
    );
    Ok(())
}

pub(crate) fn validate_file_remote_object_ref(
    object_ref: &TraceArtifactObjectRef,
) -> anyhow::Result<()> {
    validate_non_empty_ref(
        "remote trace artifact object store",
        &object_ref.object_store,
    )?;
    anyhow::ensure!(
        object_ref
            .object_store
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "remote trace artifact object store contains unsupported characters"
    );
    validate_non_empty_ref(
        "remote trace artifact tenant storage ref",
        &object_ref.tenant_storage_ref,
    )?;
    validate_non_empty_ref(
        "remote trace artifact submission storage ref",
        &object_ref.submission_storage_ref,
    )?;
    anyhow::ensure!(
        object_ref.provider_kind == TraceArtifactProviderKind::ServiceOwnedRemote,
        "remote trace artifact provider kind mismatch"
    );
    validate_remote_object_key(&object_ref.object_key)?;
    validate_object_hash(&object_ref.ciphertext_sha256)
}

fn validate_object_key(object_key: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        object_key.len() == 64 && object_key.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "trace artifact object key must be a 64-character hex digest"
    );
    Ok(())
}

fn validate_remote_object_key(object_key: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        object_key.starts_with("v1/tenants/"),
        "remote trace artifact object key must use the v1 tenant partition"
    );
    anyhow::ensure!(
        !object_key
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | "..")),
        "remote trace artifact object key contains unsafe path components"
    );
    anyhow::ensure!(
        object_key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.')
        }),
        "remote trace artifact object key contains unsupported characters"
    );
    Ok(())
}

fn artifact_object_key(
    tenant_storage_ref: &str,
    artifact_kind: &TraceArtifactKind,
    object_id: &str,
) -> String {
    sha256_text_hex(&format!(
        "{}\n{}\n{}",
        tenant_storage_ref,
        artifact_kind.as_path_segment(),
        object_id
    ))
}

fn remote_artifact_object_key(
    config: &TraceArtifactProviderConfig,
    scope: &TraceArtifactScope,
    artifact_kind: &TraceArtifactKind,
    object_id: &str,
) -> String {
    let tenant_partition = sha256_text_hex(scope.tenant_storage_ref.as_str());
    let submission_partition = sha256_text_hex(scope.submission_storage_ref.as_str());
    let object_digest = sha256_text_hex(&format!(
        "{}\n{}\n{}\n{}\n{}",
        config.object_store,
        scope.tenant_storage_ref,
        scope.submission_storage_ref,
        artifact_kind.as_path_segment(),
        object_id
    ));
    format!(
        "v1/tenants/{tenant_partition}/submissions/{submission_partition}/{}/{}.json",
        artifact_kind.as_path_segment(),
        object_digest
    )
}

fn sha256_text_hex(input: &str) -> String {
    sha256_hex(input.as_bytes())
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex::encode(digest)
}

fn write_json_file<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create trace artifact dir {}", parent.display()))?;
    let body =
        serde_json::to_vec_pretty(value).context("failed to serialize encrypted trace artifact")?;
    for _ in 0..32 {
        let temp_path = trace_artifact_temp_path(parent, path)?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                if let Err(error) = file
                    .write_all(&body)
                    .and_then(|()| file.sync_all())
                    .with_context(|| {
                        format!(
                            "failed to write encrypted trace artifact temp file {}",
                            temp_path.display()
                        )
                    })
                {
                    let _ = std::fs::remove_file(&temp_path);
                    return Err(error);
                }
                drop(file);
                if let Err(error) = std::fs::rename(&temp_path, path).with_context(|| {
                    format!(
                        "failed to commit encrypted trace artifact {}",
                        path.display()
                    )
                }) {
                    let _ = std::fs::remove_file(&temp_path);
                    return Err(error);
                }
                sync_trace_artifact_dir(parent)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create encrypted trace artifact temp file {}",
                        temp_path.display()
                    )
                });
            }
        }
    }
    anyhow::bail!(
        "failed to allocate unique encrypted trace artifact temp file for {}",
        path.display()
    )
}

fn trace_artifact_temp_path(parent: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("trace artifact path must include a file name")?;
    let counter = TRACE_ARTIFACT_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temp_file_name = std::ffi::OsString::from(".");
    temp_file_name.push(file_name);
    temp_file_name.push(format!(".{}.{}.tmp", std::process::id(), counter));
    Ok(parent.join(temp_file_name))
}

fn sync_trace_artifact_dir(path: &Path) -> anyhow::Result<()> {
    let dir = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open trace artifact dir {} for sync",
            path.display()
        )
    })?;
    dir.sync_all()
        .with_context(|| format!("failed to sync trace artifact dir {}", path.display()))
}

#[cfg(test)]
#[derive(Default)]
pub struct InMemoryRemoteTraceArtifactProvider {
    objects:
        std::sync::RwLock<std::collections::HashMap<String, InMemoryRemoteTraceArtifactRecord>>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct InMemoryRemoteTraceArtifactRecord {
    object_ref: TraceArtifactObjectRef,
    artifact: EncryptedTraceArtifact,
    invalidated_at: Option<DateTime<Utc>>,
    invalidation_reason: Option<TraceArtifactInvalidationReason>,
}

#[cfg(test)]
impl RemoteTraceArtifactProvider for InMemoryRemoteTraceArtifactProvider {
    fn put_encrypted_artifact(
        &self,
        object_ref: TraceArtifactObjectRef,
        artifact: EncryptedTraceArtifact,
    ) -> anyhow::Result<()> {
        let mut objects = self
            .objects
            .write()
            .map_err(|_| anyhow::anyhow!("remote trace artifact provider lock poisoned"))?;
        objects.insert(
            object_ref.object_key.clone(),
            InMemoryRemoteTraceArtifactRecord {
                object_ref,
                artifact,
                invalidated_at: None,
                invalidation_reason: None,
            },
        );
        Ok(())
    }

    fn read_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
    ) -> anyhow::Result<RemoteTraceArtifactRecord> {
        let objects = self
            .objects
            .read()
            .map_err(|_| anyhow::anyhow!("remote trace artifact provider lock poisoned"))?;
        let record = objects.get(&object_ref.object_key).with_context(|| {
            format!(
                "remote trace artifact object not found: {}",
                object_ref.object_key
            )
        })?;
        anyhow::ensure!(
            record.object_ref == *object_ref,
            "remote trace artifact object ref mismatch"
        );
        let _ = record.invalidation_reason;
        Ok(RemoteTraceArtifactRecord {
            object_ref: record.object_ref.clone(),
            artifact: record.artifact.clone(),
            invalidated_at: record.invalidated_at,
        })
    }

    fn invalidate_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
        reason: TraceArtifactInvalidationReason,
        invalidated_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut objects = self
            .objects
            .write()
            .map_err(|_| anyhow::anyhow!("remote trace artifact provider lock poisoned"))?;
        let record = objects.get_mut(&object_ref.object_key).with_context(|| {
            format!(
                "remote trace artifact object not found: {}",
                object_ref.object_key
            )
        })?;
        anyhow::ensure!(
            record.object_ref == *object_ref,
            "remote trace artifact object ref mismatch"
        );
        record.invalidated_at = Some(invalidated_at);
        record.invalidation_reason = Some(reason);
        Ok(())
    }

    fn delete_encrypted_artifact(
        &self,
        object_ref: &TraceArtifactObjectRef,
        _deleted_at: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let mut objects = self
            .objects
            .write()
            .map_err(|_| anyhow::anyhow!("remote trace artifact provider lock poisoned"))?;
        Ok(objects.remove(&object_ref.object_key).is_some())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use serde_json::json;

    use super::*;

    fn test_store(temp: &tempfile::TempDir) -> LocalEncryptedTraceArtifactStore {
        let key = crate::secrets::keychain::generate_master_key_hex();
        let crypto = SecretsCrypto::new(SecretString::from(key)).expect("test crypto");
        LocalEncryptedTraceArtifactStore::new(temp.path(), crypto)
    }

    fn test_kek(key_hex: &str) -> crate::trace_artifact_kek::LocalMasterKeyWrapper {
        let crypto =
            SecretsCrypto::new(SecretString::from(key_hex.to_string())).expect("kek crypto");
        crate::trace_artifact_kek::LocalMasterKeyWrapper::new(crypto, "trace-commons-test-kek-v1")
    }

    fn test_remote_store() -> ServiceOwnedTraceArtifactStore<
        InMemoryRemoteTraceArtifactProvider,
        crate::trace_artifact_kek::LocalMasterKeyWrapper,
    > {
        let key = crate::secrets::keychain::generate_master_key_hex();
        let crypto = SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto");
        let kek = test_kek(&key);
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        ServiceOwnedTraceArtifactStore::new(
            config,
            crypto,
            kek,
            InMemoryRemoteTraceArtifactProvider::default(),
        )
    }

    #[test]
    fn bundle_bytes_replay_preserves_ciphertext_and_tenant_scope() {
        let store = test_remote_store();
        let scope = TraceArtifactScope {
            tenant_storage_ref: "tenant-a".into(),
            submission_storage_ref: "submission-a".into(),
        };
        let bytes = [0, 255, 128, 13, 10];
        let prepared = store
            .prepare_bundle_bytes(
                &scope,
                TraceArtifactKind::TokenDistribution,
                "tokens",
                &bytes,
            )
            .unwrap();
        let encoded = serde_json::to_vec(&prepared).unwrap();
        let recovered: PreparedBundleArtifact = serde_json::from_slice(&encoded).unwrap();
        store.publish_bundle_bytes(&scope, &prepared).unwrap();
        store.publish_bundle_bytes(&scope, &recovered).unwrap();
        assert_eq!(
            store
                .read_bundle_bytes(&scope, &prepared.object_ref)
                .unwrap(),
            bytes
        );
        let other = TraceArtifactScope {
            tenant_storage_ref: "tenant-b".into(),
            submission_storage_ref: "submission-a".into(),
        };
        assert!(
            store
                .read_bundle_bytes(&other, &prepared.object_ref)
                .is_err()
        );
        assert!(
            store
                .delete_bundle_bytes(&other, &prepared.object_ref)
                .is_err()
        );
        store
            .delete_bundle_bytes(&scope, &prepared.object_ref)
            .unwrap();
        assert!(
            store
                .read_bundle_bytes(&scope, &prepared.object_ref)
                .is_err()
        );
        store
            .delete_bundle_bytes(&scope, &prepared.object_ref)
            .unwrap();
    }

    fn assert_trace_artifact_store_contract(store: &dyn TraceArtifactStore) {
        let payload = json!({"safe": true, "summary": "<redacted>"});
        let serialized_payload = serde_json::to_vec(&payload).expect("payload serializes");
        let receipt = store
            .put_serialized_json(
                "tenant:sha256:trait",
                TraceArtifactKind::ContributionEnvelope,
                "trait-contract",
                &serialized_payload,
            )
            .expect("artifact writes through trait");

        let artifact = store
            .read_artifact("tenant:sha256:trait", &receipt)
            .expect("artifact envelope reads through trait");
        assert_eq!(artifact.receipt, receipt);

        let receipt_round_trip: serde_json::Value = store
            .read_json("tenant:sha256:trait", &receipt)
            .expect("artifact JSON reads by receipt through trait");
        assert_eq!(receipt_round_trip, payload);

        let round_trip: serde_json::Value = store
            .read_json_by_object_key(
                "tenant:sha256:trait",
                TraceArtifactKind::ContributionEnvelope,
                &receipt.object_key,
                &receipt.ciphertext_sha256,
            )
            .expect("artifact JSON reads through trait");
        assert_eq!(round_trip, payload);

        assert!(
            store
                .delete_artifact("tenant:sha256:trait", &receipt)
                .expect("artifact deletes through trait")
        );
    }

    #[test]
    fn encrypted_artifact_round_trips_without_plaintext_on_disk() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({
            "submission_id": "018f2b7b-0c11-72fd-95c4-1f9f98feac01",
            "canonical_summary": "User asked about <PRIVATE_DATE>",
        });

        let receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                "018f2b7b-0c11-72fd-95c4-1f9f98feac01",
                &payload,
            )
            .expect("artifact writes");
        let round_trip: serde_json::Value = store
            .get_json("tenant:sha256:abc123", &receipt)
            .expect("artifact reads");
        assert_eq!(round_trip, payload);

        let artifact = store
            .read_artifact("tenant:sha256:abc123", &receipt)
            .expect("ciphertext reads");
        let serialized = serde_json::to_string(&artifact).expect("artifact serializes");
        assert!(!serialized.contains("plaintext_sha256"));
        assert!(!serialized.contains("<PRIVATE_DATE>"));
        assert!(!serialized.contains("User asked"));
        assert_eq!(artifact.receipt.tenant_storage_ref, "tenant:sha256:abc123");
    }

    #[test]
    fn local_read_tolerates_encrypted_at_drift() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({"canonical_summary": "<redacted>"});

        let receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                "018f2b7b-0c11-72fd-95c4-1f9f98feac01",
                &payload,
            )
            .expect("artifact writes");

        // Reconstructed receipts derive `encrypted_at` from the object-ref
        // audit timestamp (`created_at`), a different instant than the
        // artifact's true encryption time. The read must still succeed on
        // matching identity + integrity fields.
        let mut drifted = receipt.clone();
        drifted.encrypted_at = receipt.encrypted_at + chrono::Duration::seconds(42);

        let artifact = store
            .read_artifact("tenant:sha256:abc123", &drifted)
            .expect("read tolerates encrypted_at drift");
        assert_eq!(artifact.receipt.object_key, receipt.object_key);
    }

    #[test]
    fn local_read_still_rejects_object_key_mismatch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({"canonical_summary": "<redacted>"});

        let receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                "018f2b7b-0c11-72fd-95c4-1f9f98feac01",
                &payload,
            )
            .expect("artifact writes");

        let mut tampered = receipt.clone();
        tampered.ciphertext_sha256 = "0".repeat(64);

        let err = store
            .read_artifact("tenant:sha256:abc123", &tampered)
            .expect_err("integrity mismatch must still fail");
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn remote_read_tolerates_encrypted_at_drift() {
        let store = test_remote_store();
        let payload = json!({"safe": true});
        let serialized_payload = serde_json::to_vec(&payload).expect("payload serializes");
        let receipt = TraceArtifactStore::put_serialized_json(
            &store,
            "tenant:sha256:alpha",
            TraceArtifactKind::AuditSnapshot,
            "legacy-trait-audit",
            &serialized_payload,
        )
        .expect("artifact writes through trait");

        let mut drifted = receipt.clone();
        drifted.encrypted_at = receipt.encrypted_at + chrono::Duration::seconds(42);

        let round_trip: serde_json::Value =
            TraceArtifactStore::read_json(&store, "tenant:sha256:alpha", &drifted)
                .expect("remote read tolerates encrypted_at drift");
        assert_eq!(round_trip, payload);
    }

    #[test]
    fn local_store_satisfies_trace_artifact_store_contract() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);

        assert_trace_artifact_store_contract(&store);
    }

    #[test]
    fn service_owned_remote_store_satisfies_trace_artifact_store_contract() {
        let store = test_remote_store();

        assert_trace_artifact_store_contract(&store);
    }

    #[test]
    fn service_owned_remote_trace_artifact_store_trait_rejects_cross_tenant_access() {
        let store = test_remote_store();
        let payload = json!({"safe": true});
        let serialized_payload = serde_json::to_vec(&payload).expect("payload serializes");
        let receipt = TraceArtifactStore::put_serialized_json(
            &store,
            "tenant:sha256:alpha",
            TraceArtifactKind::AuditSnapshot,
            "legacy-trait-audit",
            &serialized_payload,
        )
        .expect("artifact writes through trait");

        let read_error = TraceArtifactStore::read_json(&store, "tenant:sha256:beta", &receipt)
            .expect_err("cross-tenant remote trait receipt read must fail");
        assert!(read_error.to_string().contains("tenant mismatch"));

        let object_key_error = TraceArtifactStore::read_json_by_object_key(
            &store,
            "tenant:sha256:beta",
            TraceArtifactKind::AuditSnapshot,
            &receipt.object_key,
            &receipt.ciphertext_sha256,
        )
        .expect_err("cross-tenant remote trait object-key read must fail");
        assert!(object_key_error.to_string().contains("tenant mismatch"));

        let delete_error =
            TraceArtifactStore::delete_artifact(&store, "tenant:sha256:beta", &receipt)
                .expect_err("cross-tenant remote trait delete must fail");
        assert!(delete_error.to_string().contains("tenant mismatch"));
    }

    #[test]
    fn service_owned_remote_store_binds_refs_to_tenant_and_submission() {
        let key = crate::secrets::keychain::generate_master_key_hex();
        let crypto = SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto");
        let kek = test_kek(&key);
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let store = ServiceOwnedTraceArtifactStore::new(
            config,
            crypto,
            kek,
            InMemoryRemoteTraceArtifactProvider::default(),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");
        let payload = json!({"safe": true, "summary": "<redacted>"});

        let receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                "submitted-envelope",
                &payload,
            )
            .expect("remote artifact writes");

        assert_eq!(
            receipt.object_ref.provider_kind,
            TraceArtifactProviderKind::ServiceOwnedRemote
        );
        assert_eq!(receipt.object_ref.object_store, "trace-commons-prod");
        assert_eq!(receipt.object_ref.tenant_storage_ref, "tenant:sha256:alpha");
        assert_eq!(
            receipt.object_ref.submission_storage_ref,
            "submission-alpha"
        );
        assert!(
            !receipt
                .object_ref
                .object_key
                .contains("tenant:sha256:alpha")
        );
        assert!(!receipt.object_ref.object_key.contains("submission-alpha"));

        let round_trip: serde_json::Value = store
            .read_scoped_json(&scope, &receipt.object_ref)
            .expect("remote artifact reads with matching scope");
        assert_eq!(round_trip, payload);

        let wrong_tenant = TraceArtifactScope::new("tenant:sha256:beta", "submission-alpha");
        let error = store
            .read_scoped_json::<serde_json::Value>(&wrong_tenant, &receipt.object_ref)
            .expect_err("remote refs must not cross tenants");
        assert!(error.to_string().contains("tenant mismatch"));

        let wrong_submission = TraceArtifactScope::new("tenant:sha256:alpha", "submission-beta");
        let error = store
            .read_scoped_json::<serde_json::Value>(&wrong_submission, &receipt.object_ref)
            .expect_err("remote refs must not cross submissions");
        assert!(error.to_string().contains("submission mismatch"));
    }

    #[test]
    fn service_owned_remote_store_returns_invalidate_and_delete_receipts() {
        let key = crate::secrets::keychain::generate_master_key_hex();
        let crypto = SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto");
        let kek = test_kek(&key);
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let store = ServiceOwnedTraceArtifactStore::new(
            config,
            crypto,
            kek,
            InMemoryRemoteTraceArtifactProvider::default(),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");
        let payload = json!({"safe": true});
        let receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::BenchmarkConversion,
                "conversion-artifact",
                &payload,
            )
            .expect("remote artifact writes");

        let invalidation = store
            .invalidate_scoped_artifact(
                &scope,
                &receipt.object_ref,
                TraceArtifactInvalidationReason::Revoked,
            )
            .expect("remote artifact invalidates");
        assert_eq!(invalidation.object_ref, receipt.object_ref);
        assert_eq!(
            invalidation.reason,
            TraceArtifactInvalidationReason::Revoked
        );

        let error = store
            .read_scoped_json::<serde_json::Value>(&scope, &receipt.object_ref)
            .expect_err("invalidated remote artifact must fail closed");
        assert!(error.to_string().contains("invalidated"));

        let delete_receipt = store
            .delete_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact deletes");
        assert_eq!(delete_receipt.object_ref, receipt.object_ref);
        assert!(delete_receipt.deleted);

        let repeat_delete = store
            .delete_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact delete is idempotent");
        assert_eq!(repeat_delete.object_ref, receipt.object_ref);
        assert!(!repeat_delete.deleted);
    }

    #[test]
    fn file_remote_provider_persists_service_owned_remote_artifacts_across_instances() {
        let temp = tempfile::tempdir().expect("temp dir");
        let key = crate::secrets::keychain::generate_master_key_hex();
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let store = ServiceOwnedTraceArtifactStore::new(
            config.clone(),
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            FileRemoteTraceArtifactProvider::new(temp.path()),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");

        let receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                "submitted-envelope",
                &json!({"stored": "remote"}),
            )
            .expect("remote artifact writes");

        let reopened = ServiceOwnedTraceArtifactStore::new(
            config,
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            FileRemoteTraceArtifactProvider::new(temp.path()),
        );
        let value: serde_json::Value = reopened
            .read_scoped_json(&scope, &receipt.object_ref)
            .expect("remote artifact reads after provider restart");
        assert_eq!(value["stored"], "remote");

        let invalidated = reopened
            .invalidate_scoped_artifact(
                &scope,
                &receipt.object_ref,
                TraceArtifactInvalidationReason::Revoked,
            )
            .expect("remote artifact invalidates");
        assert_eq!(invalidated.object_ref, receipt.object_ref);
        let invalidated_read =
            reopened.read_scoped_json::<serde_json::Value>(&scope, &receipt.object_ref);
        assert!(invalidated_read.is_err());

        let deleted = reopened
            .delete_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact deletes");
        assert!(deleted.deleted);
        let deleted_again = reopened
            .delete_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact delete is idempotent");
        assert!(!deleted_again.deleted);
    }

    #[test]
    fn file_remote_provider_rejects_mismatched_artifact_record_before_write() {
        let temp = tempfile::tempdir().expect("temp dir");
        let key = crate::secrets::keychain::generate_master_key_hex();
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let provider = FileRemoteTraceArtifactProvider::new(temp.path());
        let store = ServiceOwnedTraceArtifactStore::new(
            config,
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            provider.clone(),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");
        let payload = json!({"stored": "remote"});

        let receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                "submitted-envelope",
                &payload,
            )
            .expect("remote artifact writes");
        let mut tampered = store
            .read_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact reads before tamper");
        tampered.receipt.tenant_storage_ref = "tenant:sha256:beta".to_string();

        let write_error = provider
            .put_encrypted_artifact(receipt.object_ref.clone(), tampered)
            .expect_err("provider write must reject artifact/object-ref mismatch");
        assert!(write_error.to_string().contains("tenant mismatch"));

        let round_trip: serde_json::Value = store
            .read_scoped_json(&scope, &receipt.object_ref)
            .expect("failed tamper write must not overwrite original artifact");
        assert_eq!(round_trip, payload);
    }

    #[test]
    fn file_remote_provider_rejects_same_key_different_object_ref_overwrite() {
        let temp = tempfile::tempdir().expect("temp dir");
        let key = crate::secrets::keychain::generate_master_key_hex();
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let store = ServiceOwnedTraceArtifactStore::new(
            config,
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            FileRemoteTraceArtifactProvider::new(temp.path()),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");
        let object_id = "submitted-envelope";
        let first_payload = json!({"stored": "first"});
        let second_payload = json!({"stored": "second"});

        let first_receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                object_id,
                &first_payload,
            )
            .expect("first remote artifact writes");
        let second_error = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                object_id,
                &second_payload,
            )
            .expect_err("same object key with a different object ref must fail closed");
        assert!(
            second_error
                .to_string()
                .contains("already exists for a different object ref")
        );

        let round_trip: serde_json::Value = store
            .read_scoped_json(&scope, &first_receipt.object_ref)
            .expect("failed overwrite must keep first artifact readable");
        assert_eq!(round_trip, first_payload);
    }

    #[cfg(unix)]
    #[test]
    fn file_remote_provider_replaces_object_path_symlink_instead_of_following_it() {
        let temp = tempfile::tempdir().expect("temp dir");
        let key = crate::secrets::keychain::generate_master_key_hex();
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let provider = FileRemoteTraceArtifactProvider::new(temp.path());
        let store = ServiceOwnedTraceArtifactStore::new(
            config,
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            provider.clone(),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");
        let payload = json!({"stored": "remote"});

        let receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                "submitted-envelope",
                &payload,
            )
            .expect("remote artifact writes");
        let artifact = store
            .read_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact reads before symlink swap");
        let object_path = temp
            .path()
            .join(&receipt.object_ref.object_store)
            .join(&receipt.object_ref.object_key);
        let external_path = temp.path().join("external-object-record.json");
        let tampered_record = FileRemoteTraceArtifactRecord {
            object_ref: receipt.object_ref.clone(),
            artifact: artifact.clone(),
            invalidated_at: Some(Utc::now()),
            invalidation_reason: Some(TraceArtifactInvalidationReason::Revoked),
        };
        let external_body =
            serde_json::to_string_pretty(&tampered_record).expect("tampered record serializes");
        std::fs::write(&external_path, &external_body).expect("external record writes");
        std::fs::remove_file(&object_path).expect("object path can be replaced by symlink");
        std::os::unix::fs::symlink(&external_path, &object_path).expect("object symlink writes");

        provider
            .put_encrypted_artifact(receipt.object_ref.clone(), artifact)
            .expect("remote provider rewrites object path");

        let external_after =
            std::fs::read_to_string(&external_path).expect("external record remains readable");
        assert_eq!(external_after, external_body);
        let object_metadata = std::fs::symlink_metadata(&object_path)
            .expect("object path metadata reads after rewrite");
        assert!(!object_metadata.file_type().is_symlink());
        let round_trip: serde_json::Value = store
            .read_scoped_json(&scope, &receipt.object_ref)
            .expect("rewritten object remains readable");
        assert_eq!(round_trip, payload);
    }

    #[test]
    fn file_remote_provider_restores_versioned_delete_across_instances() {
        let temp = tempfile::tempdir().expect("temp dir");
        let key = crate::secrets::keychain::generate_master_key_hex();
        let config = TraceArtifactProviderConfig::service_owned_remote("trace-commons-prod")
            .expect("remote provider config");
        let store = ServiceOwnedTraceArtifactStore::new(
            config.clone(),
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            FileRemoteTraceArtifactProvider::versioned(temp.path()),
        );
        let scope = TraceArtifactScope::new("tenant:sha256:alpha", "submission-alpha");
        let payload = json!({"stored": "versioned-remote"});

        let receipt = store
            .put_scoped_json(
                &scope,
                TraceArtifactKind::ContributionEnvelope,
                "submitted-envelope",
                &payload,
            )
            .expect("remote artifact writes");
        let deleted = store
            .delete_scoped_artifact(&scope, &receipt.object_ref)
            .expect("remote artifact deletes into a recoverable version");
        assert!(deleted.deleted);
        let deleted_read = store.read_scoped_json::<serde_json::Value>(&scope, &receipt.object_ref);
        assert!(deleted_read.is_err());

        let reopened = ServiceOwnedTraceArtifactStore::new(
            config,
            SecretsCrypto::new(SecretString::from(key.clone())).expect("test crypto"),
            test_kek(&key),
            FileRemoteTraceArtifactProvider::versioned(temp.path()),
        );
        assert!(
            reopened
                .restore_deleted_scoped_artifact(&scope, &receipt.object_ref)
                .expect("deleted remote artifact restores")
        );
        let restored: serde_json::Value = reopened
            .read_scoped_json(&scope, &receipt.object_ref)
            .expect("restored remote artifact reads");
        assert_eq!(restored, payload);
        assert!(
            !reopened
                .restore_deleted_scoped_artifact(&scope, &receipt.object_ref)
                .expect("already-restored artifact restore is idempotent")
        );
    }

    #[test]
    fn encrypted_artifact_rejects_cross_tenant_receipts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({"safe": true});
        let receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::BenchmarkConversion,
                "conversion-1",
                &payload,
            )
            .expect("artifact writes");

        let error = store
            .get_json::<serde_json::Value>("tenant:sha256:other", &receipt)
            .expect_err("cross-tenant receipt must fail");
        assert!(error.to_string().contains("tenant mismatch"));
    }

    #[test]
    fn encrypted_artifact_reads_by_object_key_and_hash() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({"safe": true, "summary": "<redacted>"});
        let receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                "object-ref-read",
                &payload,
            )
            .expect("artifact writes");

        let round_trip: serde_json::Value = store
            .get_json_by_object_key(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                &receipt.object_key,
                &format!("sha256:{}", receipt.ciphertext_sha256),
            )
            .expect("artifact reads by object key and hash");
        assert_eq!(round_trip, payload);

        let error = store
            .get_json_by_object_key::<serde_json::Value>(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                &receipt.object_key,
                "sha256:wrong",
            )
            .expect_err("wrong object hash must fail");
        assert!(error.to_string().contains("receipt hash mismatch"));
    }

    #[test]
    fn encrypted_artifact_detects_ciphertext_receipt_tampering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({"safe": true});
        let mut receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::BenchmarkConversion,
                "conversion-1",
                &payload,
            )
            .expect("artifact writes");

        receipt.ciphertext_sha256 = "sha256:wrong".to_string();
        let error = store
            .get_json::<serde_json::Value>("tenant:sha256:abc123", &receipt)
            .expect_err("tampered receipt must fail");
        assert!(error.to_string().contains("receipt mismatch"));
    }

    #[test]
    fn encrypted_artifact_rejects_path_shaped_object_keys() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let receipt = EncryptedTraceArtifactReceipt {
            tenant_storage_ref: "tenant:sha256:abc123".to_string(),
            artifact_kind: TraceArtifactKind::Other,
            object_key: "../escape".to_string(),
            ciphertext_sha256: "sha256:unused".to_string(),
            encrypted_at: Utc::now(),
        };

        let error = store
            .read_artifact("tenant:sha256:abc123", &receipt)
            .expect_err("path-shaped object keys must fail");
        assert!(error.to_string().contains("64-character hex digest"));
    }

    #[test]
    fn encrypted_artifact_delete_removes_ciphertext_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = test_store(&temp);
        let payload = json!({"safe": true});
        let receipt = store
            .put_json(
                "tenant:sha256:abc123",
                TraceArtifactKind::ContributionEnvelope,
                "delete-me",
                &payload,
            )
            .expect("artifact writes");

        assert!(
            store
                .delete_artifact("tenant:sha256:abc123", &receipt)
                .expect("artifact deletes")
        );
        assert!(
            !store
                .delete_artifact("tenant:sha256:abc123", &receipt)
                .expect("missing artifact delete is idempotent")
        );
        let error = store
            .read_artifact("tenant:sha256:abc123", &receipt)
            .expect_err("deleted artifact should not read");
        assert!(error.to_string().contains("failed to read trace artifact"));
    }
}
