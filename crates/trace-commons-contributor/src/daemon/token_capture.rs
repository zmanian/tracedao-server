//! Snapshot selection uses the exact attested request and response digests.
use crate::{
    routing::attested::AttestedCall,
    token_capture_client::{CaptureLease, TokenCaptureClient},
};
use anyhow::{Result, bail};

pub fn client(declaration: &super::settings::IronWireDeclaration) -> Result<TokenCaptureClient> {
    let port = declaration
        .port()
        .filter(|p| *p > 0)
        .ok_or_else(|| anyhow::anyhow!("token-capture-proxy-unavailable"))?;
    let path = super::settings::ironwire_token_path(declaration.token_dir())
        .ok_or_else(|| anyhow::anyhow!("token-capture-proxy-unavailable"))?;
    let metadata = super::ironwire_pointer::trustworthy_file(&path)
        .ok_or_else(|| anyhow::anyhow!("token-capture-proxy-untrusted"))?;
    if metadata.len() > 4096 {
        bail!("token-capture-proxy-untrusted");
    }
    let token = std::fs::read_to_string(path)?;
    TokenCaptureClient::new(&format!("http://127.0.0.1:{port}"), token.trim().into())
}
pub async fn acquire(
    client: &TokenCaptureClient,
    session: &str,
    call: &AttestedCall,
) -> Result<CaptureLease> {
    use sha2::{Digest, Sha256};
    let request = hex::encode(Sha256::digest(call.request_body().as_bytes()));
    let response = hex::encode(Sha256::digest(call.response_body().as_bytes()));
    let matches = client
        .find(session, &request, &response)
        .await?
        .into_iter()
        .filter(|c| {
            c.request_digest == request
                && c.response_digest == response
                && c.protocol == "openai.chat"
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("token-capture-source-unavailable");
    }
    let lease = client
        .acquire(
            session,
            &[matches[0].capture_id.clone()],
            &uuid::Uuid::new_v4().to_string(),
            3 * 86400,
        )
        .await?;
    let result = client.read(&lease, &matches[0]).await;
    match result {
        Ok((request, response))
            if request == call.request_body().as_bytes()
                && response == call.response_body().as_bytes() =>
        {
            Ok(lease)
        }
        _ => {
            use crate::token_bundle::BundleLeaseReleaser;
            if let Ok(binding) = lease.bundle_lease() {
                // Best effort for this caller's lease only; bounded expiry
                // remains the recovery path when the proxy is unavailable.
                let _ = client.release(&binding).await;
            }
            bail!("token-capture-source-mismatch")
        }
    }
}
