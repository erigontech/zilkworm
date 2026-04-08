use base64::{self, Engine};
use reqwest::Client;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
pub struct EthProofsConfig {
    pub endpoint: String,
    pub token: String,
    pub cluster_id: u64,
}

#[derive(Clone, Debug)]
pub struct EthproofsClient {
    cluster_id: u64,
    endpoint: String,
    api_token: String,
    client: Client,
}

impl EthproofsClient {
    pub fn new(config: EthProofsConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            cluster_id: config.cluster_id,
            endpoint: config.endpoint,
            api_token: config.token,
            client,
        }
    }

    async fn post_json(&self, path: &str, json: &serde_json::Value) -> Result<(), String> {
        let url = format!("{}{}", self.endpoint, path);

        // Print the full request JSON (truncate proof field to avoid flooding logs)
        let mut debug_json = json.clone();
        if let Some(obj) = debug_json.as_object_mut() {
            if let Some(proof_val) = obj.get("proof") {
                if let Some(s) = proof_val.as_str() {
                    if s.len() > 100 {
                        obj.insert("proof".to_string(), serde_json::json!(format!("{}...({} chars)", &s[..80], s.len())));
                    }
                }
            }
        }
        info!("ethproofs POST {}\n  {}", url, serde_json::to_string_pretty(&debug_json).unwrap_or_default());

        let response = self.client.post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(json)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            info!("ethproofs {} -> {} {}", path, status, &body);
            Ok(())
        } else {
            let msg = format!("ethproofs {} -> {} {}", path, status, body);
            error!("{}", msg);
            Err(msg)
        }
    }

    pub async fn queued(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        if let Err(e) = self.post_json("/proofs/queued", &json).await {
            warn!("ethproofs queued block={} failed: {}", block_number, e);
        }
    }

    pub async fn proving(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        if let Err(e) = self.post_json("/proofs/proving", &json).await {
            warn!("ethproofs proving block={} failed: {}", block_number, e);
        }
    }

    pub async fn proved(
        &self,
        proof_bytes: &[u8],
        block_number: u64,
        cycle_count: u64,
        proving_millis: u64,
        verifier_id: &str,
    ) {
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof_bytes);
        info!(
            "ethproofs proved block={} cycles={} time={}ms proof_size={} proof_b64_len={}",
            block_number, cycle_count, proving_millis, proof_bytes.len(), proof_b64.len()
        );

        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
            "proving_time": proving_millis,
            "proving_cycles": cycle_count,
            "proof": proof_b64,
            "verifier_id": verifier_id,
        });

        if let Err(e) = self.post_json("/proofs/proved", &json).await {
            error!("ethproofs proved block={} FAILED: {}", block_number, e);
        }
    }
}
