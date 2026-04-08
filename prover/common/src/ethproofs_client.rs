use base64::{self, Engine};
use reqwest::Client;
use std::time::Duration;
use tracing::error;

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
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            cluster_id: config.cluster_id,
            endpoint: config.endpoint,
            api_token: config.token,
            client,
        }
    }

    pub async fn queued(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        let this = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/proofs/queued", this.endpoint);
            tracing::info!("ethproofs queued block={}", block_number);
            let response = this.client.post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send().await;
            match response {
                Ok(resp) => tracing::info!("ethproofs queued response: {}", resp.status()),
                Err(err) => error!("ethproofs queued failed: {}", err),
            }
        });
    }

    pub async fn proving(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        let this = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/proofs/proving", this.endpoint);
            tracing::info!("ethproofs proving block={}", block_number);
            let response = this.client.post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send().await;
            match response {
                Ok(resp) => tracing::info!("ethproofs proving response: {}", resp.status()),
                Err(err) => error!("ethproofs proving failed: {}", err),
            }
        });
    }

    pub async fn proved(
        &self,
        proof_bytes: &[u8],
        block_number: u64,
        cycle_count: u64,
        proving_millis: u64,
        verifier_id: &str,
    ) {
        let json = serde_json::json!({
            "proof": base64::engine::general_purpose::STANDARD.encode(proof_bytes),
            "block_number": block_number,
            "proving_cycles": cycle_count,
            "proving_time": proving_millis,
            "verifier_id": verifier_id,
            "cluster_id": self.cluster_id,
        });
        let this = self.clone();
        tokio::spawn(async move {
            let url = format!("{}/proofs/proved", this.endpoint);
            tracing::info!("ethproofs proved block={}", block_number);
            let response = this.client.post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send().await;
            match response {
                Ok(resp) => tracing::info!("ethproofs proved response: {}", resp.status()),
                Err(err) => error!("ethproofs proved failed: {}", err),
            }
        });
    }
}
