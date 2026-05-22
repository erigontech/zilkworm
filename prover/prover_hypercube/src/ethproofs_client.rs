// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

        // Spawn another task to avoid retries to impact block execution
        tokio::spawn(async move {
            let url = format!("{}/proofs/queued", this.endpoint);
            let request_body =
                serde_json::to_string_pretty(&json).unwrap_or_else(|_| "Invalid JSON".to_string());

            println!("EthProofs queued request:");
            println!("  URL: {}", url);
            println!("  Headers: Content-Type: application/json, Authorization: Bearer [REDACTED]");
            println!("  Body: {}", request_body);

            let response = this
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    println!("EthProofs queued response:");
                    println!("  Status: {}", resp.status());
                    println!("  Headers: {:?}", resp.headers());

                    match resp.text().await {
                        Ok(body) => {
                            println!("  Body: {}", body);
                        }
                        Err(e) => {
                            println!("  Body: Failed to read response body: {}", e);
                        }
                    }
                }
                Err(err) => {
                    error!("Failed to report proof queuing: {}", err)
                }
            }
        });
    }

    pub async fn proving(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        let this = self.clone();

        // Spawn another task to avoid retries to impact block execution
        tokio::spawn(async move {
            let url = format!("{}/proofs/proving", this.endpoint);
            let request_body =
                serde_json::to_string_pretty(&json).unwrap_or_else(|_| "Invalid JSON".to_string());

            println!("EthProofs proving request:");
            println!("  URL: {}", url);
            println!("  Headers: Content-Type: application/json, Authorization: Bearer [REDACTED]");
            println!("  Body: {}", request_body);

            let response = this
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    println!("EthProofs proving response:");
                    println!("  Status: {}", resp.status());
                    println!("  Headers: {:?}", resp.headers());

                    match resp.text().await {
                        Ok(body) => {
                            println!("  Body: {}", body);
                        }
                        Err(e) => {
                            println!("  Body: Failed to read response body: {}", e);
                        }
                    }
                }
                Err(err) => {
                    error!("Failed to report proof proving: {}", err)
                }
            }
        });
    }

    pub async fn proved(
        &self,
        proof_bytes: &[u8],
        block_number: u64,
        cycle_count: u64,
        proving_millis: u64,
        vk: &sp1_sdk::SP1VerifyingKey,
    ) {
        let json = serde_json::json!({
            "proof": base64::engine::general_purpose::STANDARD.encode(proof_bytes),
            "block_number": block_number,
            "proving_cycles": cycle_count,
            "proving_time": proving_millis,
            "verifier_id": sp1_sdk::HashableKey::bytes32(vk),
            "cluster_id": self.cluster_id,
        });

        let this = self.clone();

        // Spawn another task to avoid retries to impact block execution
        tokio::spawn(async move {
            let url = format!("{}/proofs/proved", this.endpoint);
            // let request_body =
            //     serde_json::to_string_pretty(&json).unwrap_or_else(|_| "Invalid JSON".to_string());

            println!("EthProofs proved request:");
            println!("  URL: {}", url);
            println!("  Headers: Content-Type: application/json, Authorization: Bearer [REDACTED]");
            // println!("  Body: {}", request_body);

            let response = this
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    println!("EthProofs proved response:");
                    println!("  Status: {}", resp.status());
                    println!("  Headers: {:?}", resp.headers());

                    match resp.text().await {
                        Ok(body) => {
                            println!("  Body: {}", body);
                        }
                        Err(e) => {
                            println!("  Body: Failed to read response body: {}", e);
                        }
                    }
                }
                Err(err) => {
                    error!("Failed to report proof proved: {}", err)
                }
            }
        });
    }
}
