//! Authenticated, loopback-only access to Ironwire's private capture spool.
use crate::token_bundle::{BundleLease, BundleLeaseReleaser};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct CaptureDescriptor {
    pub store_id: String,
    pub capture_id: String,
    pub ledger_id: i64,
    pub request_digest: String,
    pub response_digest: String,
    pub protocol: String,
    pub streaming: bool,
}
#[derive(Deserialize)]
pub struct CaptureLease {
    pub lease_id: String,
    pub owner: String,
    pub snapshot_digest: String,
    pub expires_at: i64,
    pub captures: Vec<CaptureDescriptor>,
}
impl CaptureLease {
    /// Bind cleanup to the persistent store that owns every captured exchange.
    pub fn bundle_lease(&self) -> Result<BundleLease> {
        let first = self
            .captures
            .first()
            .ok_or_else(|| anyhow::anyhow!("token-capture-empty"))?;
        if self
            .captures
            .iter()
            .any(|capture| capture.store_id != first.store_id)
        {
            bail!("token-capture-store-mismatch");
        }
        Ok(BundleLease {
            capture_store_id: first.store_id.clone(),
            lease_id: self.lease_id.clone(),
            owner: self.owner.clone(),
            snapshot_digest: self.snapshot_digest.clone(),
        })
    }
}
pub struct TokenCaptureClient {
    http: reqwest::Client,
    endpoint: url::Url,
    token: String,
}
impl TokenCaptureClient {
    pub fn new(endpoint: &str, token: String) -> Result<Self> {
        let mut endpoint = url::Url::parse(endpoint)?;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if endpoint.scheme() != "http"
            || !loopback
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || token.is_empty()
        {
            bail!("token-control-endpoint-invalid");
        }
        endpoint.set_path("/_ironwire/token-captures");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(Self {
            endpoint,
            token,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        body: serde_json::Value,
        limit: usize,
    ) -> Result<T> {
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("token-control-unavailable"))?;
        if !response.status().is_success() {
            bail!("token-control-refused");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("token-control-unavailable"))?
        {
            if bytes.len().saturating_add(chunk.len()) > limit {
                bail!("token-control-limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("token-control-invalid"))
    }
    pub async fn list(&self, session: &str) -> Result<Vec<CaptureDescriptor>> {
        self.request(
            serde_json::json!({"operation":"list","session":session}),
            1024 * 1024,
        )
        .await
    }
    pub async fn find(
        &self,
        session: &str,
        request_digest: &str,
        response_digest: &str,
    ) -> Result<Vec<CaptureDescriptor>> {
        self.request(
            serde_json::json!({"operation":"find", "session":session,
            "request_digest":request_digest,"response_digest":response_digest}),
            16384,
        )
        .await
    }
    pub async fn acquire(
        &self,
        session: &str,
        captures: &[String],
        owner: &str,
        seconds: i64,
    ) -> Result<CaptureLease> {
        self.request(serde_json::json!({"operation":"acquire","session":session,"captures":captures,"owner":owner,"seconds":seconds}),1024*1024).await
    }
    pub async fn renew(&self, lease: &CaptureLease, seconds: i64) -> Result<i64> {
        #[derive(Deserialize)]
        struct Renewed {
            expires_at: i64,
        }
        let value: Renewed = self.request(serde_json::json!({"operation":"renew","lease":lease.lease_id,"owner":lease.owner,"snapshot_digest":lease.snapshot_digest,"seconds":seconds}),4096).await?;
        Ok(value.expires_at)
    }
    pub async fn renew_bundle(&self, lease: &BundleLease, seconds: i64) -> Result<i64> {
        #[derive(Deserialize)]
        struct Renewed {
            expires_at: i64,
        }
        let value: Renewed = self
            .request(
                serde_json::json!({"operation":"renew","lease":lease.lease_id,
            "owner":lease.owner,"snapshot_digest":lease.snapshot_digest,"seconds":seconds}),
                4096,
            )
            .await?;
        Ok(value.expires_at)
    }
    pub async fn read(
        &self,
        lease: &CaptureLease,
        capture: &CaptureDescriptor,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use sha2::{Digest, Sha256};
        #[derive(Deserialize)]
        struct Bodies {
            request: Vec<u8>,
            response: Vec<u8>,
        }
        let bodies: Bodies = self.request(serde_json::json!({"operation":"read","lease":lease.lease_id,"owner":lease.owner,"capture":capture.capture_id}), 256*1024*1024+4096).await?;
        if hex::encode(Sha256::digest(&bodies.request)) != capture.request_digest
            || hex::encode(Sha256::digest(&bodies.response)) != capture.response_digest
        {
            bail!("token-capture-digest-mismatch");
        }
        Ok((bodies.request, bodies.response))
    }
}
#[async_trait::async_trait]
impl BundleLeaseReleaser for TokenCaptureClient {
    async fn release(&self, lease: &BundleLease) -> Result<()> {
        let response: serde_json::Value = self.request(serde_json::json!({"operation":"release","capture_store_id":lease.capture_store_id,"lease":lease.lease_id,"owner":lease.owner,"snapshot_digest":lease.snapshot_digest}),4096).await?;
        if response["released"].as_bool() != Some(true) {
            bail!("token-control-release-unconfirmed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_control_refuses_remote_hosts_and_ambiguous_authority() {
        for endpoint in [
            "https://example.com",
            "http://localhost:1234",
            "http://user@127.0.0.1:1234",
            "http://192.0.2.1:1234",
        ] {
            assert!(TokenCaptureClient::new(endpoint, "secret".into()).is_err());
        }
        assert!(TokenCaptureClient::new("http://127.0.0.1:1234", "secret".into()).is_ok());
    }
    #[tokio::test]
    async fn release_requires_confirmation_and_carries_original_store_identity() {
        use axum::{Json, Router, routing::post};
        let app = Router::new().route(
            "/_ironwire/token-captures",
            post(
                |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| async move {
                    assert_eq!(headers["authorization"], "Bearer secret");
                    assert_eq!(body["capture_store_id"], "original-store");
                    assert_eq!(body["owner"], "original-owner");
                    Json(serde_json::json!({"released":false}))
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            TokenCaptureClient::new(&format!("http://{address}"), "secret".into()).unwrap();
        assert!(
            client
                .release(&BundleLease {
                    capture_store_id: "original-store".into(),
                    lease_id: "lease".into(),
                    owner: "original-owner".into(),
                    snapshot_digest: "digest".into()
                })
                .await
                .is_err()
        );
        task.abort();
    }
}
