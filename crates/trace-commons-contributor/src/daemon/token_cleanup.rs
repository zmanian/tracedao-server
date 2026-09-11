//! Fair, bounded renewal and cleanup batches, including after restart.
use super::ipc::DaemonShared;
use crate::{token_bundle::BundleJournal, token_capture_client::TokenCaptureClient};

pub(super) async fn pass(shared: &DaemonShared) -> anyhow::Result<()> {
    let root = shared.store.dir().join("token-bundles");
    if !root.exists() {
        return Ok(());
    }
    let journal = BundleJournal::open(&root)?;
    let approved = shared
        .queue
        .lock()
        .expect("queue lock")
        .all()
        .iter()
        .filter(|entry| {
            matches!(
                entry.state,
                super::queue::QueueState::Approved | super::queue::QueueState::Uploading
            )
        })
        .map(|entry| entry.entry_id)
        .collect::<Vec<_>>();
    for entry in approved {
        if let Ok(Some(artifact)) = super::approved_envelope::load_witnessed(&shared.store, entry) {
            if let Some(bundle) = artifact.token_bundle {
                journal.mark_approved(bundle.journal_id)?;
            }
        }
    }
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    journal.expire_reviews(now)?;
    let declaration = shared
        .settings
        .lock()
        .expect("settings lock")
        .ironwire
        .clone();
    let Some(declaration) = declaration else {
        return Ok(());
    };
    let port = declaration
        .port()
        .filter(|port| *port > 0)
        .ok_or_else(|| anyhow::anyhow!("token-cleanup-proxy-unavailable"))?;
    let path = super::settings::ironwire_token_path(declaration.token_dir())
        .ok_or_else(|| anyhow::anyhow!("token-cleanup-proxy-unavailable"))?;
    let metadata = super::ironwire_pointer::trustworthy_file(&path)
        .ok_or_else(|| anyhow::anyhow!("token-cleanup-proxy-untrusted"))?;
    if metadata.len() > 4096 {
        anyhow::bail!("token-cleanup-proxy-untrusted");
    }
    let token = std::fs::read_to_string(path)?;
    let client = TokenCaptureClient::new(&format!("http://127.0.0.1:{port}"), token.trim().into())?;
    for lease in journal.due_renewals(now)? {
        let expiry = client
            .renew_bundle(&lease, 3 * 86400)
            .await
            .ok()
            .and_then(|v| u64::try_from(v).ok());
        journal.record_renewal(&lease, expiry)?;
    }
    for id in journal.due_cleanup(now)? {
        // Failure belongs to this intent, not the rest of the batch. The
        // journal already reserved its backoff before making the request.
        let _ = journal.cleanup(id, &client).await;
    }
    crate::token_review_lease::cleanup(&root, &journal, &client, now).await?;
    Ok(())
}
