//! Durable acknowledgement and lease-release journal for token bundles.
//!
//! Payload ownership remains with Ironwire. A receipt from an authenticated,
//! configured destination must be persisted before this module releases a lease.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use trace_commons_protocol::token_distribution::{
    ContributionBundleManifest, DurableBundleReceipt,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleDestination {
    pub server_id: String,
    pub tenant_id: String,
    pub account_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleLease {
    pub capture_store_id: String,
    pub lease_id: String,
    pub owner: String,
    pub snapshot_digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(default)]
    created_at_unix: u64,
    #[serde(default)]
    expired: bool,
    #[serde(default)]
    approved: bool,
    #[serde(default)]
    renew_after_unix: u64,
    #[serde(default)]
    cleanup_after_unix: u64,
    #[serde(default)]
    lease_expires_at_unix: Option<u64>,
    #[serde(default)]
    renewal_failed: bool,
    manifest: ContributionBundleManifest,
    destination: BundleDestination,
    lease: BundleLease,
    receipt: Option<DurableBundleReceipt>,
    released: bool,
    #[serde(default)]
    approved_payload: Option<CertifiedBundleUpload>,
}

/// Content-free reference included in the ordinary witness approval pin.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBundleReview {
    pub journal_id: uuid::Uuid,
    pub manifest_digest: trace_commons_protocol::token_distribution::ContentDigest,
    pub attachment_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_line: Option<String>,
}
/// Abandon a prepared bundle if a later preview/queue pin fails or is canceled.
pub(crate) struct ReviewPinGuard {
    root: PathBuf,
    id: Option<uuid::Uuid>,
}
impl ReviewPinGuard {
    pub(crate) fn new(state: &Path, review: Option<&TokenBundleReview>) -> Self {
        Self {
            root: state.join("token-bundles"),
            id: review.map(|r| r.journal_id),
        }
    }
    pub(crate) fn disarm(&mut self) {
        self.id = None;
    }
}
impl Drop for ReviewPinGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let _ = BundleJournal::open(&self.root).and_then(|j| j.abandon_review(id));
        }
    }
}

/// Only the caller's immutable lease is released. Implementations must not
/// delete a session directory or release another destination's lease.
#[async_trait::async_trait]
pub trait BundleLeaseReleaser: Send + Sync {
    async fn release(&self, lease: &BundleLease) -> Result<()>;
}

/// Serialize review-store writers across the ordinary approval files and
/// token journal, enforcing one aggregate 256 MiB retained-payload budget.
/// Removal and replacement by smaller data must remain possible at capacity.
pub(crate) fn with_review_budget(
    state: &Path,
    replacing: &Path,
    bytes: u64,
    write: impl FnOnce() -> Result<()>,
) -> Result<()> {
    fs::create_dir_all(state)?;
    let lock_path = state.join("review-budget.lock");
    if fs::symlink_metadata(&lock_path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
        bail!("review-budget-lock");
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.lock()?;
    let mut total = bytes;
    for item in fs::read_dir(state)? {
        let item = item?;
        if item.path() != replacing
            && item
                .file_name()
                .to_string_lossy()
                .trim_start_matches('.')
                .starts_with(crate::config::DAEMON_APPROVED_ENVELOPE_PREFIX)
        {
            total = total.saturating_add(item.metadata()?.len());
        }
    }
    let root = state.join("token-bundles");
    if root.exists() {
        if fs::symlink_metadata(&root)?.file_type().is_symlink() {
            bail!("review-budget-directory");
        }
        for item in fs::read_dir(root)? {
            let item = item?;
            if item.path() != replacing && item.path().extension().is_some_and(|s| s == "json") {
                total = total.saturating_add(item.metadata()?.len());
            }
        }
    }
    let prior = fs::symlink_metadata(replacing)
        .map(|m| m.len())
        .unwrap_or(0);
    if total > 256 * 1024 * 1024 && bytes > prior {
        bail!("review-store-capacity");
    }
    write()
}

pub struct BundleJournal {
    root: PathBuf,
}
impl BundleJournal {
    /// The directory must be inside the contributor's private state directory.
    pub fn open(root: &Path) -> Result<Self> {
        if !root.exists() {
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(root).context("bundle-journal-create")?;
        }
        let metadata = fs::symlink_metadata(root).context("bundle-journal-metadata")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("bundle-journal-directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("bundle-journal-permissions");
            }
        }
        Ok(Self { root: root.into() })
    }
    fn path(&self, id: uuid::Uuid) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
    fn lock(&self) -> Result<File> {
        let path = self.root.join("journal.lock");
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
            bail!("bundle-journal-lock");
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).context("bundle-journal-lock")?;
        file.lock().context("bundle-journal-lock")?;
        Ok(file)
    }
    fn read(&self, id: uuid::Uuid) -> Result<Entry> {
        let path = self.path(id);
        let m = fs::symlink_metadata(&path).context("bundle-journal-read")?;
        if !m.is_file() || m.file_type().is_symlink() || m.len() > 128 * 1024 * 1024 {
            bail!("bundle-journal-invalid");
        }
        serde_json::from_slice(&fs::read(path).context("bundle-journal-read")?)
            .context("bundle-journal-invalid")
    }
    fn write(&self, id: uuid::Uuid, entry: &Entry) -> Result<()> {
        let bytes = serde_json::to_vec(entry).context("bundle-journal-encode")?;
        if bytes.len() > 128 * 1024 * 1024 {
            bail!("bundle-journal-limit");
        }
        let mut total = bytes.len() as u64;
        for item in fs::read_dir(&self.root)? {
            let item = item?;
            if item.path() != self.path(id) && item.path().extension().is_some_and(|s| s == "json")
            {
                total = total.saturating_add(item.metadata()?.len());
            }
        }
        if total > 256 * 1024 * 1024 {
            bail!("bundle-journal-capacity");
        }
        // The production journal lives immediately below the state directory.
        with_review_budget(
            self.root.parent().context("bundle-journal-parent")?,
            &self.path(id),
            bytes.len() as u64,
            || {
                crate::config::write_atomic_0600(&self.root, &self.path(id), &bytes)
                    .context("bundle-journal-write")
            },
        )?;
        #[cfg(unix)]
        File::open(&self.root)?
            .sync_all()
            .context("bundle-journal-sync")?;
        Ok(())
    }
    pub fn validate_review(&self, review: &TokenBundleReview, envelope: &[u8]) -> Result<()> {
        let _lock = self.lock()?;
        let entry = self.read(review.journal_id)?;
        if entry.manifest.digest()? != review.manifest_digest
            || !entry.manifest.envelope_digest.matches(envelope)
        {
            bail!("bundle-review-stale");
        }
        if entry.approved_payload.is_none() && entry.receipt.is_none() {
            bail!("bundle-review-unavailable");
        }
        Ok(())
    }
    /// Call before upload. Retries must reuse the returned journal ID.
    pub fn prepare(
        &self,
        manifest: ContributionBundleManifest,
        destination: BundleDestination,
        lease: BundleLease,
    ) -> Result<uuid::Uuid> {
        manifest.validate().context("bundle-manifest-invalid")?;
        for value in [
            &destination.server_id,
            &destination.tenant_id,
            &destination.account_id,
            &lease.capture_store_id,
            &lease.lease_id,
            &lease.owner,
            &lease.snapshot_digest,
        ] {
            if value.is_empty() || value.len() > 1024 {
                bail!("bundle-binding-invalid");
            }
        }
        let _lock = self.lock()?;
        if fs::read_dir(&self.root)?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|s| s == "json"))
            .count()
            >= 4096
        {
            bail!("bundle-journal-limit");
        }
        let id = uuid::Uuid::new_v4();
        self.write(
            id,
            &Entry {
                created_at_unix: chrono::Utc::now().timestamp().max(0) as u64,
                expired: false,
                approved: false,
                renew_after_unix: 0,
                cleanup_after_unix: 0,
                lease_expires_at_unix: None,
                renewal_failed: false,
                manifest,
                destination,
                lease,
                receipt: None,
                released: false,
                approved_payload: None,
            },
        )?;
        Ok(id)
    }
    /// This method is called only after authentication of the response transport.
    /// An upload status, local JSON file, or transcript receipt is insufficient.
    pub fn acknowledge_authenticated(
        &self,
        id: uuid::Uuid,
        receipt: DurableBundleReceipt,
        now: u64,
    ) -> Result<()> {
        let _lock = self.lock()?;
        let mut entry = self.read(id)?;
        receipt
            .matches_bundle(
                &entry.manifest,
                &entry.destination.server_id,
                &entry.destination.tenant_id,
                &entry.destination.account_id,
                now,
            )
            .context("bundle-receipt-mismatch")?;
        if let Some(existing) = &entry.receipt {
            if existing != &receipt {
                bail!("bundle-receipt-conflict");
            }
            return Ok(());
        }
        entry.receipt = Some(receipt);
        self.write(id, &entry)
    }
    /// Safe to retry after a crash, including a crash after remote release.
    /// Expired receipts remain evidence of an earlier durable commit.
    pub async fn cleanup(&self, id: uuid::Uuid, releaser: &dyn BundleLeaseReleaser) -> Result<()> {
        let lease = {
            let _lock = self.lock()?;
            let entry = self.read(id)?;
            if entry.released {
                return Ok(());
            }
            if entry.receipt.is_none() && !entry.expired {
                bail!("bundle-not-acknowledged");
            }
            entry.lease
        };
        releaser.release(&lease).await?;
        let _lock = self.lock()?;
        let mut entry = self.read(id)?;
        entry.released = true;
        entry.approved_payload = None;
        self.write(id, &entry)
    }
    /// Called from the durable queue's approved/uploading states, never from
    /// merely preparing a review. Approval cannot revive expired payloads.
    pub fn mark_approved(&self, id: uuid::Uuid) -> Result<()> {
        let _lock = self.lock()?;
        let mut entry = self.read(id)?;
        if !entry.approved && !entry.expired && entry.receipt.is_none() {
            entry.approved = true;
            self.write(id, &entry)?;
        }
        Ok(())
    }
    /// Reserve a bounded renewal batch before I/O. Failed attempts back off,
    /// so an unavailable old spool cannot starve other owners indefinitely.
    pub fn due_renewals(&self, now: u64) -> Result<Vec<BundleLease>> {
        let _lock = self.lock()?;
        let mut due = Vec::new();
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let entry = self.read(id)?;
            if entry.approved
                && !entry.expired
                && entry.receipt.is_none()
                && entry.renew_after_unix <= now
            {
                due.push((entry.renew_after_unix, id));
            }
        }
        due.sort_unstable();
        let mut leases = Vec::new();
        for (_, id) in due.into_iter().take(8) {
            let mut entry = self.read(id)?;
            entry.renew_after_unix = now.saturating_add(3600);
            self.write(id, &entry)?;
            leases.push(entry.lease);
        }
        Ok(leases)
    }
    /// Persist the expiry returned by the owning capture store, never an estimate.
    pub fn record_renewal(&self, lease: &BundleLease, expiry: Option<u64>) -> Result<()> {
        let _lock = self.lock()?;
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let mut entry = self.read(id)?;
            if entry.lease.capture_store_id == lease.capture_store_id
                && entry.lease.lease_id == lease.lease_id
                && entry.lease.owner == lease.owner
                && entry.lease.snapshot_digest == lease.snapshot_digest
            {
                entry.renewal_failed = expiry.is_none();
                if let Some(expiry) = expiry {
                    entry.lease_expires_at_unix = Some(expiry);
                }
                self.write(id, &entry)?;
            }
        }
        Ok(())
    }
    /// A revoked or discarded local review no longer owns retained payloads.
    /// This never revokes a server contribution or fabricates a receipt.
    pub fn abandon_review(&self, id: uuid::Uuid) -> Result<()> {
        let _lock = self.lock()?;
        let mut entry = self.read(id)?;
        if entry.receipt.is_none() {
            entry.expired = true;
            entry.approved_payload = None;
            self.write(id, &entry)?;
        }
        Ok(())
    }
    /// Expiration is a separate abandonment reason, never a durable receipt.
    /// Clearing expired review bytes invalidates their approval. Agent source
    /// files are outside this journal and are never touched.
    pub fn expire_reviews(&self, now: u64) -> Result<()> {
        let _lock = self.lock()?;
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let mut entry = self.read(id)?;
            if entry.receipt.is_none()
                && !entry.expired
                && now
                    >= entry.created_at_unix.saturating_add(if entry.approved {
                        7 * 86400
                    } else {
                        3 * 86400
                    })
            {
                entry.expired = true;
                entry.approved_payload = None;
                self.write(id, &entry)?;
            }
        }
        Ok(())
    }
    /// Metadata-only lifecycle status. No token text, paths, or lease handles.
    pub fn storage_status(&self, now: u64) -> Result<serde_json::Value> {
        let _lock = self.lock()?;
        // Settings polling must not repeatedly decode up to 256 MiB of review
        // payloads. Cache only content-free results and invalidate on every
        // journal file's size/mtime, with a one-minute age bound.
        type StatusCache = std::collections::BTreeMap<
            PathBuf,
            (
                u64,
                Vec<(PathBuf, u64, std::time::SystemTime)>,
                serde_json::Value,
            ),
        >;
        static CACHE: std::sync::OnceLock<std::sync::Mutex<StatusCache>> =
            std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(Default::default);
        let mut signature = Vec::new();
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let meta = fs::symlink_metadata(&path)?;
                signature.push((path, meta.len(), meta.modified()?));
            }
        }
        signature.sort();
        if let Some((at, previous, value)) = cache.lock().expect("status cache").get(&self.root) {
            if now >= *at && now - at < 60 && *previous == signature {
                return Ok(value.clone());
            }
        }
        let mut bytes = 0u64;
        let mut pending = 0u64;
        let mut reviews = 0u64;
        let mut oldest = now;
        let mut renewal_failures = 0u64;
        let mut earliest_expiry: Option<u64> = None;
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let entry = self.read(id)?;
            if entry.approved_payload.is_some() {
                bytes = bytes.saturating_add(fs::symlink_metadata(path)?.len());
            }
            if (entry.receipt.is_some() || entry.expired) && !entry.released {
                pending += 1;
                oldest = oldest.min(entry.created_at_unix);
            }
            if entry.receipt.is_none() && !entry.expired {
                reviews += 1;
                renewal_failures += u64::from(entry.renewal_failed);
                if let Some(expiry) = entry.lease_expires_at_unix {
                    earliest_expiry = Some(earliest_expiry.map_or(expiry, |old| old.min(expiry)));
                }
            }
        }
        let expiry_line = match earliest_expiry {
            Some(expiry) if expiry <= now => {
                "A capture lease has expired. Recreate its review before submitting.".to_string()
            }
            Some(expiry) => format!(
                "The earliest confirmed capture lease expires in {} hours.",
                expiry.saturating_sub(now).div_ceil(3600)
            ),
            None if reviews > 0 => {
                "Capture lease expiry has not been confirmed by the owning proxy.".to_string()
            }
            None => String::new(),
        };
        let value = serde_json::json!({"lease_expires_at_unix":earliest_expiry,"renewal_failures":renewal_failures,"retained_bytes":bytes,"cleanup_pending":pending,"unsubmitted_reviews":reviews,"oldest_pending_seconds":if pending>0 {now.saturating_sub(oldest)} else {0},
            "state_line":format!("{bytes} bytes of local review data. {pending} capture releases pending. {reviews} unsubmitted reviews. {renewal_failures} lease renewals need retry. {expiry_line}"),
            "scope_note":"Local cleanup preserves original agent files and server contributions. Withdraw a contribution separately to stop server use.",
            "cleanup_label":"Remove submitted local copies","discard_label":"Discard unsubmitted token reviews",
            "discard_confirmation":"Discard unsubmitted token reviews? Their local approval data will be removed and their capture leases released. Original agent files and submitted contributions are preserved.",
            "cancel_label":"Cancel","confirm_label":"Discard reviews","failure_line":"Cleanup could not complete. Undo approval before discarding an approved review, then try again."});
        let mut cached = cache.lock().expect("status cache");
        if cached.len() >= 16 {
            cached.clear();
        }
        cached.insert(self.root.clone(), (now, signature, value.clone()));
        Ok(value)
    }
    /// A durable receipt already authorizes disposal of these client copies,
    /// independently of whether the owning proxy is available to release raw data.
    pub fn remove_local_copies(&self, discard: bool) -> Result<()> {
        let _lock = self.lock()?;
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let mut entry = self.read(id)?;
            if entry.receipt.is_some() || entry.expired || discard {
                if entry.receipt.is_none() {
                    entry.expired = true;
                }
                entry.approved_payload = None;
                entry.cleanup_after_unix = 0;
                self.write(id, &entry)?;
            }
        }
        Ok(())
    }
    pub(crate) fn owns_lease(&self, lease: &BundleLease) -> Result<bool> {
        let _lock = self.lock()?;
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let entry = self.read(id)?;
            if entry.lease.capture_store_id == lease.capture_store_id
                && entry.lease.lease_id == lease.lease_id
                && entry.lease.snapshot_digest == lease.snapshot_digest
                && entry.lease.owner == lease.owner
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Reserve retries durably before network I/O. A stale store cannot keep
    /// its first directory entry at the head of every maintenance pass.
    pub fn due_cleanup(&self, now: u64) -> Result<Vec<uuid::Uuid>> {
        let ids = self.pending_cleanup()?;
        let _lock = self.lock()?;
        let mut due = Vec::new();
        for id in ids {
            let entry = self.read(id)?;
            if !entry.released && entry.cleanup_after_unix <= now {
                due.push((entry.cleanup_after_unix, id));
            }
        }
        due.sort_unstable();
        let mut batch = Vec::new();
        for (_, id) in due.into_iter().take(8) {
            let mut entry = self.read(id)?;
            entry.cleanup_after_unix = now.saturating_add(3600);
            self.write(id, &entry)?;
            batch.push(id);
        }
        Ok(batch)
    }
    /// Acknowledged or explicitly expired intents are retried at startup.
    pub fn pending_cleanup(&self) -> Result<Vec<uuid::Uuid>> {
        let _lock = self.lock()?;
        let mut pending = Vec::new();
        for item in fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| uuid::Uuid::parse_str(v).ok())
                .context("bundle-journal-invalid")?;
            let entry = self.read(id)?;
            if (entry.receipt.is_some() || entry.expired) && !entry.released {
                pending.push(id);
            }
        }
        Ok(pending)
    }
}

/// Certified bytes are uploaded without reserialization. The journal ID must
/// have been prepared for this destination and immutable capture snapshot.
impl BundleJournal {
    /// Pin a reviewed payload to the already prepared immutable manifest.
    /// Existing approval is never overwritten with newly witnessed bytes.
    pub fn approve_payload(&self, id: uuid::Uuid, payload: CertifiedBundleUpload) -> Result<()> {
        use crate::witness::transport::verify_certificate;
        verify_certificate(&payload.envelope, &payload.pinned_witness_address)
            .context("bundle-envelope-certificate")?;
        verify_certificate(&payload.manifest, &payload.pinned_witness_address)
            .context("bundle-manifest-certificate")?;
        let manifest = ContributionBundleManifest::decode(&payload.manifest.envelope_bytes)?;
        let _lock = self.lock()?;
        let mut entry = self.read(id)?;
        if manifest.digest()? != entry.manifest.digest()?
            || !manifest
                .envelope_digest
                .matches(&payload.envelope.envelope_bytes)
        {
            bail!("bundle-approval-mismatch");
        }
        if entry.expired {
            bail!("bundle-review-expired");
        }
        if entry.approved_payload.is_some() {
            bail!("bundle-already-approved");
        }
        entry.approved_payload = Some(payload);
        self.write(id, &entry)
    }
    /// Upload only the exact bytes persisted during approval, including after
    /// restart. This never calls the witness again to rebuild approved content.
    pub async fn upload_approved(
        &self,
        id: uuid::Uuid,
        client: &trace_commons_operator_client::Client,
    ) -> Result<DurableBundleReceipt> {
        let payload = {
            let _lock = self.lock()?;
            let entry = self.read(id)?;
            // A crash can occur after acknowledgement and cleanup but before
            // the ordinary transcript receipt is written. The authenticated
            // durable receipt remains evidence after payload deletion.
            if let Some(receipt) = entry.receipt {
                return Ok(receipt);
            }
            entry.approved_payload.context("bundle-not-approved")?
        };
        self.upload(id, client, &payload).await
    }
    pub async fn upload(
        &self,
        id: uuid::Uuid,
        client: &trace_commons_operator_client::Client,
        payload: &CertifiedBundleUpload,
    ) -> Result<DurableBundleReceipt> {
        use crate::witness::transport::{
            WITNESS_CERTIFICATE_HEADER, WITNESS_SIGNATURE_HEADER, verify_certificate,
        };
        use reqwest::Method;
        let entry = {
            let _lock = self.lock()?;
            self.read(id)?
        };
        verify_certificate(&payload.envelope, &payload.pinned_witness_address)
            .context("bundle-envelope-certificate")?;
        verify_certificate(&payload.manifest, &payload.pinned_witness_address)
            .context("bundle-manifest-certificate")?;
        let manifest = ContributionBundleManifest::decode(&payload.manifest.envelope_bytes)
            .context("bundle-manifest-invalid")?;
        if manifest.digest()? != entry.manifest.digest()?
            || !manifest
                .envelope_digest
                .matches(&payload.envelope.envelope_bytes)
            || payload.attachments.len() != manifest.attachments.len()
        {
            bail!("bundle-upload-mismatch");
        }
        let envelope: trace_commons_protocol::trace_contribution::TraceContributionEnvelope =
            serde_json::from_slice(&payload.envelope.envelope_bytes)
                .context("bundle-envelope-invalid")?;
        for descriptor in &manifest.attachments {
            let bytes = payload
                .attachments
                .get(&descriptor.artifact_id)
                .context("bundle-attachment-missing")?;
            let text = envelope
                .events
                .iter()
                .find(|e| e.event_id.to_string() == descriptor.event_id)
                .and_then(|e| e.redacted_content.as_deref())
                .context("bundle-event-missing")?;
            manifest
                .verify_sanitized_attachment(&descriptor.artifact_id, bytes, text.as_bytes())
                .context("bundle-attachment-invalid")?;
        }
        // Encode path components independently: identifiers are never URL paths.
        let component = |value: &str| -> Result<String> {
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                bail!("bundle-path-invalid");
            }
            Ok(value.into())
        };
        let base = format!(
            "/v1/token-bundles/{}/{}",
            component(&manifest.submission_id)?,
            component(&manifest.bundle_revision)?
        );
        let witness_headers = |value: &crate::witness::transport::WitnessedEnvelope| {
            vec![
                (
                    WITNESS_CERTIFICATE_HEADER.to_string(),
                    value.certificate_json.clone(),
                ),
                (
                    WITNESS_SIGNATURE_HEADER.to_string(),
                    value.signature_hex.clone(),
                ),
            ]
        };
        let manifest_headers = witness_headers(&payload.manifest);
        let headers: Vec<_> = manifest_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let response = client
            .call_bytes(
                Method::POST,
                "/v1/token-bundles",
                &[],
                &payload.manifest.envelope_bytes,
                &headers,
            )
            .await
            .map_err(|_| anyhow::anyhow!("bundle-upload-unavailable"))?;
        let response: serde_json::Value =
            serde_json::from_str(&response).context("bundle-response-invalid")?;
        if response["server_id"].as_str() != Some(&entry.destination.server_id)
            || response["tenant_id"].as_str() != Some(&entry.destination.tenant_id)
            || response["account_id"].as_str() != Some(&entry.destination.account_id)
        {
            bail!("bundle-destination-mismatch");
        }
        if response["state"].as_str() == Some("committed") {
            let receipt = serde_json::from_value(response["receipt"].clone())
                .context("bundle-receipt-invalid")?;
            self.acknowledge_authenticated(
                id,
                receipt,
                chrono::Utc::now().timestamp().max(0) as u64,
            )?;
            return self.read(id)?.receipt.context("bundle-receipt-missing");
        }
        let ready: Vec<String> =
            serde_json::from_value(response["ready"].clone()).context("bundle-response-invalid")?;
        for (artifact, bytes) in std::iter::once(("envelope", &payload.envelope.envelope_bytes))
            .chain(payload.attachments.iter().map(|(k, v)| (k.as_str(), v)))
        {
            if ready.iter().any(|v| v == artifact) {
                continue;
            }
            client
                .call_bytes(
                    Method::PUT,
                    &format!("{base}/{}", component(artifact)?),
                    &[],
                    bytes,
                    &[],
                )
                .await
                .map_err(|_| anyhow::anyhow!("bundle-upload-unavailable"))?;
        }
        let mut envelope_headers = witness_headers(&payload.envelope);
        if let Some(admission) = &payload.envelope.admission {
            envelope_headers.push((
                "x-trace-admission-evidence".into(),
                admission.evidence_json.clone(),
            ));
            envelope_headers.push((
                "x-trace-admission-signature".into(),
                admission.signature_hex.clone(),
            ));
        }
        let headers: Vec<_> = envelope_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let response = client
            .call_bytes(
                Method::POST,
                &base,
                &[],
                &payload.envelope.envelope_bytes,
                &headers,
            )
            .await
            .map_err(|_| anyhow::anyhow!("bundle-upload-unavailable"))?;
        let receipt = serde_json::from_str(&response).context("bundle-receipt-invalid")?;
        self.acknowledge_authenticated(id, receipt, chrono::Utc::now().timestamp().max(0) as u64)?;
        self.read(id)?.receipt.context("bundle-receipt-missing")
    }
}

/// Contains private content; deliberately does not implement Debug.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedBundleUpload {
    pub pinned_witness_address: String,
    pub envelope: crate::witness::transport::WitnessedEnvelope,
    pub manifest: crate::witness::transport::WitnessedEnvelope,
    pub attachments: std::collections::BTreeMap<String, Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use trace_commons_protocol::token_distribution::*;
    struct Release {
        calls: AtomicUsize,
        fail: bool,
    }
    #[async_trait::async_trait]
    impl BundleLeaseReleaser for Release {
        async fn release(&self, lease: &BundleLease) -> Result<()> {
            assert_eq!(lease.owner, "destination-owner");
            assert_eq!(lease.lease_id, "immutable-lease");
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                bail!("offline");
            }
            Ok(())
        }
    }
    fn fixture() -> (
        ContributionBundleManifest,
        BundleDestination,
        BundleLease,
        DurableBundleReceipt,
    ) {
        let manifest = ContributionBundleManifest {
            version: 1,
            usage_profile: TokenUsageProfile::RestrictedResearch,
            submission_id: uuid::Uuid::new_v4().to_string(),
            bundle_revision: "revision".into(),
            envelope_digest: ContentDigest::of(b"envelope"),
            consent_digest: ContentDigest::of(b"consent"),
            policy_version: "policy".into(),
            attachments: vec![AttachmentDescriptor {
                artifact_id: "tokens".into(),
                event_id: "event".into(),
                content_digest: ContentDigest::of(b"tokens"),
                size_bytes: 6,
            }],
        };
        let destination = BundleDestination {
            server_id: "server".into(),
            tenant_id: "tenant".into(),
            account_id: "account".into(),
        };
        let lease = BundleLease {
            capture_store_id: "store".into(),
            lease_id: "immutable-lease".into(),
            owner: "destination-owner".into(),
            snapshot_digest: "snapshot".into(),
        };
        let receipt = DurableBundleReceipt {
            version: 1,
            server_id: "server".into(),
            tenant_id: "tenant".into(),
            account_id: "account".into(),
            submission_id: manifest.submission_id.clone(),
            bundle_revision: manifest.bundle_revision.clone(),
            manifest_digest: manifest.digest().unwrap(),
            committed_at_unix: 100,
            retain_until_unix: 200,
            retention_policy_version: "policy".into(),
        };
        (manifest, destination, lease, receipt)
    }
    #[tokio::test]
    async fn release_requires_bound_durable_receipt_and_recovers_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("journal");
        let journal = BundleJournal::open(&root).unwrap();
        let (manifest, destination, lease, receipt) = fixture();
        let id = journal.prepare(manifest, destination, lease).unwrap();
        let release = Release {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        assert!(journal.cleanup(id, &release).await.is_err());
        assert_eq!(release.calls.load(Ordering::SeqCst), 0);
        let mut wrong = receipt.clone();
        wrong.account_id = "someone-else".into();
        assert!(journal.acknowledge_authenticated(id, wrong, 101).is_err());
        assert!(journal.pending_cleanup().unwrap().is_empty());
        journal.acknowledge_authenticated(id, receipt, 101).unwrap();
        drop(journal);
        let journal = BundleJournal::open(&root).unwrap();
        assert_eq!(journal.pending_cleanup().unwrap(), vec![id]);
        assert!(
            journal
                .cleanup(
                    id,
                    &Release {
                        calls: AtomicUsize::new(0),
                        fail: true
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(journal.pending_cleanup().unwrap(), vec![id]);
        journal.cleanup(id, &release).await.unwrap();
        journal.cleanup(id, &release).await.unwrap();
        assert_eq!(release.calls.load(Ordering::SeqCst), 1);
        assert!(journal.pending_cleanup().unwrap().is_empty());
    }
    #[test]
    fn ordinary_and_token_reviews_share_one_budget_and_can_shrink_at_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let ordinary = dir.path().join(format!(
            "{}test.json",
            crate::config::DAEMON_APPROVED_ENVELOPE_PREFIX
        ));
        File::create(&ordinary)
            .unwrap()
            .set_len(200 * 1024 * 1024)
            .unwrap();
        let root = dir.path().join("token-bundles");
        fs::create_dir(&root).unwrap();
        File::create(root.join("other.json"))
            .unwrap()
            .set_len(56 * 1024 * 1024)
            .unwrap();
        assert!(with_review_budget(dir.path(), &root.join("new.json"), 1, || Ok(())).is_err());
        assert!(with_review_budget(dir.path(), &ordinary, 100, || Ok(())).is_ok());
    }
    #[test]
    fn approval_extends_review_retention_but_cannot_renew_forever() {
        let dir = tempfile::tempdir().unwrap();
        let journal = BundleJournal::open(&dir.path().join("journal")).unwrap();
        let (manifest, destination, lease, _) = fixture();
        let id = journal.prepare(manifest, destination, lease).unwrap();
        let created = journal.read(id).unwrap().created_at_unix;
        assert!(journal.due_renewals(created).unwrap().is_empty());
        journal.mark_approved(id).unwrap();
        assert_eq!(journal.due_renewals(created).unwrap().len(), 1);
        assert!(journal.due_renewals(created + 1).unwrap().is_empty());
        journal.expire_reviews(created + 3 * 86400).unwrap();
        assert!(journal.pending_cleanup().unwrap().is_empty());
        journal.expire_reviews(created + 7 * 86400).unwrap();
        assert_eq!(journal.pending_cleanup().unwrap(), vec![id]);
        assert!(
            journal
                .due_renewals(created + 7 * 86400)
                .unwrap()
                .is_empty()
        );
        journal.mark_approved(id).unwrap();
        assert!(journal.read(id).unwrap().expired);
    }
    #[tokio::test]
    async fn expired_reviews_release_only_their_lease_without_fabricating_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let journal = BundleJournal::open(&dir.path().join("journal")).unwrap();
        let (manifest, destination, lease, _) = fixture();
        let id = journal.prepare(manifest, destination, lease).unwrap();
        let created = journal.read(id).unwrap().created_at_unix;
        journal.expire_reviews(created + 3 * 86400 - 1).unwrap();
        assert!(journal.pending_cleanup().unwrap().is_empty());
        journal.expire_reviews(created + 3 * 86400).unwrap();
        assert_eq!(journal.pending_cleanup().unwrap(), vec![id]);
        let release = Release {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        journal.cleanup(id, &release).await.unwrap();
        assert!(journal.read(id).unwrap().receipt.is_none());
        assert!(journal.pending_cleanup().unwrap().is_empty());
        assert_eq!(release.calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn durable_receipt_recovers_after_payload_cleanup_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let journal = BundleJournal::open(&dir.path().join("journal")).unwrap();
        let (manifest, destination, lease, receipt) = fixture();
        let id = journal.prepare(manifest, destination, lease).unwrap();
        journal
            .acknowledge_authenticated(id, receipt.clone(), 101)
            .unwrap();
        journal
            .cleanup(
                id,
                &Release {
                    calls: AtomicUsize::new(0),
                    fail: false,
                },
            )
            .await
            .unwrap();
        let client = trace_commons_operator_client::Client::builder("http://127.0.0.1:1", "unused")
            .bearer_token("test")
            .build()
            .unwrap();
        let recovered = journal.upload_approved(id, &client).await.unwrap();
        assert_eq!(recovered.manifest_digest, receipt.manifest_digest);
    }
    #[test]
    fn unavailable_cleanup_is_backed_off_without_starving_other_leases() {
        let dir = tempfile::tempdir().unwrap();
        let journal = BundleJournal::open(&dir.path().join("journal")).unwrap();
        for _ in 0..10 {
            let (manifest, destination, lease, _) = fixture();
            let id = journal.prepare(manifest, destination, lease).unwrap();
            journal.abandon_review(id).unwrap();
        }
        let first = journal.due_cleanup(100).unwrap();
        assert_eq!(first.len(), 8);
        let restarted = BundleJournal::open(&dir.path().join("journal")).unwrap();
        let second = restarted.due_cleanup(101).unwrap();
        assert_eq!(second.len(), 2);
        assert!(second.iter().all(|id| !first.contains(id)));
        assert!(restarted.due_cleanup(102).unwrap().is_empty());
        assert_eq!(restarted.due_cleanup(3700).unwrap().len(), 8);
        let (manifest, destination, lease, _) = fixture();
        let id = restarted.prepare(manifest, destination, lease).unwrap();
        restarted.mark_approved(id).unwrap();
        assert_eq!(restarted.due_renewals(102).unwrap().len(), 1);
    }

    #[test]
    fn canceled_pin_is_abandoned_and_status_tracks_confirmed_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let journal = BundleJournal::open(&dir.path().join("token-bundles")).unwrap();
        let (manifest, destination, lease, _) = fixture();
        let digest = manifest.digest().unwrap();
        let id = journal
            .prepare(manifest, destination, lease.clone())
            .unwrap();
        journal.record_renewal(&lease, Some(500)).unwrap();
        assert_eq!(
            journal.storage_status(100).unwrap()["lease_expires_at_unix"],
            500
        );
        journal.record_renewal(&lease, None).unwrap();
        let status = journal.storage_status(100).unwrap();
        assert_eq!(status["renewal_failures"], 1);
        assert_eq!(status["lease_expires_at_unix"], 500);
        let review = TokenBundleReview {
            journal_id: id,
            manifest_digest: digest,
            attachment_bytes: 0,
            summary_line: None,
        };
        drop(ReviewPinGuard::new(dir.path(), Some(&review)));
        let status = journal.storage_status(101).unwrap();
        assert_eq!(status["unsubmitted_reviews"], 0);
        assert_eq!(status["cleanup_pending"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_journal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(BundleJournal::open(&link).is_err());
    }
}
