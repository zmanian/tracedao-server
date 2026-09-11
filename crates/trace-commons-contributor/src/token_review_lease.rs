//! Durable ownership while a review is being prepared, before a manifest exists.
use crate::token_bundle::{BundleJournal, BundleLease, BundleLeaseReleaser};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Intent {
    lease: BundleLease,
    retry_after: u64,
}
fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}
fn save(path: &Path, intent: &Intent) -> Result<()> {
    crate::config::write_atomic_0600(
        path.parent().context("lease-intent-parent")?,
        path,
        &serde_json::to_vec(intent)?,
    )
}
fn intent_lock(path: &Path) -> Result<std::fs::File> {
    let path = path.with_extension("lease-lock");
    if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
        bail!("lease-lock-invalid");
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
/// Drop marks cancellation synchronously; no network task survives its caller.
/// A crash is recovered after the bounded witness request deadline.
pub struct ReviewLeaseGuard {
    path: PathBuf,
    intent: Intent,
    adopted: bool,
    _lock: std::fs::File,
}
impl ReviewLeaseGuard {
    pub fn new(root: &Path, lease: BundleLease) -> Result<Self> {
        BundleJournal::open(root)?;
        if std::fs::read_dir(root)?.count() >= 8192 {
            bail!("lease-intent-capacity");
        }
        let intent = Intent {
            lease,
            retry_after: now().saturating_add(600),
        };
        let path = root.join(format!("{}.lease", uuid::Uuid::new_v4()));
        let lock = intent_lock(&path)?;
        lock.lock()?;
        save(&path, &intent)?;
        Ok(Self {
            path,
            intent,
            adopted: false,
            _lock: lock,
        })
    }
    pub fn adopted(mut self) -> Result<()> {
        std::fs::remove_file(&self.path)?;
        self.adopted = true;
        Ok(())
    }
}
impl Drop for ReviewLeaseGuard {
    fn drop(&mut self) {
        if !self.adopted {
            self.intent.retry_after = now();
            let _ = save(&self.path, &self.intent);
        } else {
            let _ = self._lock.unlock();
            let _ = std::fs::remove_file(self.path.with_extension("lease-lock"));
        }
    }
}
/// Fair retries; an old capture store cannot block current leases.
pub async fn cleanup(
    root: &Path,
    journal: &BundleJournal,
    releaser: &dyn BundleLeaseReleaser,
    at: u64,
) -> Result<()> {
    let mut due = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().is_none_or(|s| s != "lease") {
            continue;
        }
        let lock = intent_lock(&path)?;
        if lock.try_lock().is_err() {
            continue;
        }
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16384 {
            bail!("lease-intent-invalid");
        }
        let intent: Intent = serde_json::from_slice(&std::fs::read(&path)?)?;
        // A crash between journal publication and guard removal must never
        // release the lease of the now-persisted review.
        if journal.owns_lease(&intent.lease)? {
            std::fs::remove_file(&path)?;
            drop(lock);
            let _ = std::fs::remove_file(path.with_extension("lease-lock"));
        } else if intent.retry_after <= at {
            due.push((intent.retry_after, path, intent, lock));
        }
    }
    due.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    for (_, path, mut intent, _lock) in due.into_iter().take(8) {
        intent.retry_after = at.saturating_add(3600);
        save(&path, &intent)?;
        if releaser.release(&intent.lease).await.is_ok() {
            std::fs::remove_file(&path)?;
            drop(_lock);
            let _ = std::fs::remove_file(path.with_extension("lease-lock"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Release(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl BundleLeaseReleaser for Release {
        async fn release(&self, _: &BundleLease) -> Result<()> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
    #[tokio::test]
    async fn cancellation_is_durable_and_a_crash_has_a_bounded_recovery_delay() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("journal");
        let lease = BundleLease {
            capture_store_id: "store".into(),
            lease_id: "lease".into(),
            owner: "owner".into(),
            snapshot_digest: "digest".into(),
        };
        let guard = ReviewLeaseGuard::new(&root, lease.clone()).unwrap();
        let journal = BundleJournal::open(&root).unwrap();
        let release = Release(std::sync::atomic::AtomicUsize::new(0));
        cleanup(&root, &journal, &release, now() + 3600)
            .await
            .unwrap();
        assert_eq!(release.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(guard);
        cleanup(&root, &journal, &release, now()).await.unwrap();
        assert_eq!(release.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        let guard = ReviewLeaseGuard::new(&root, lease).unwrap();
        // Simulate process exit: release the OS lock without running Drop.
        let guard = std::mem::ManuallyDrop::new(guard);
        guard._lock.unlock().unwrap();
        cleanup(&root, &journal, &release, now() + 601)
            .await
            .unwrap();
        assert_eq!(release.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
