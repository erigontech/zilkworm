use base64::{self, Engine};
use reqwest::{Client, StatusCode};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
pub struct EthProofsConfig {
    pub endpoint: String,
    pub token: String,
    pub cluster_id: u64,
}

/// Attempts at posting a proof, and the longest wait between two of them.
const PROVED_ATTEMPTS: u32 = 4;
const MAX_RETRY_WAIT: Duration = Duration::from_secs(120);

/// A failed POST: the response status, if there was a response, and `retry_after` when
/// repeating it can succeed (rate limited, server error or no response): the wait the server
/// asked for, or a default.
struct PostError {
    msg: String,
    status: Option<StatusCode>,
    retry_after: Option<Duration>,
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

    async fn post_json(&self, path: &str, json: &serde_json::Value) -> Result<(), PostError> {
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
            .map_err(|e| {
                let msg = format!("request failed: {}", e);
                warn!("ethproofs {} {}", path, msg);
                PostError { msg, status: None, retry_after: Some(Duration::from_secs(10)) }
            })?;

        let status = response.status();
        let header_wait = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            info!("ethproofs {} -> {} {}", path, status, &body);
            Ok(())
        } else {
            let msg = format!("ethproofs {} -> {} {}", path, status, body);
            // Ethproofs answers 429 with {"retryAfter": <seconds>} in the body.
            let retry_after = if status == StatusCode::TOO_MANY_REQUESTS {
                let body_wait = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("retryAfter")?.as_u64());
                Some(Duration::from_secs(body_wait.or(header_wait).unwrap_or(30)))
            } else if status.is_server_error() {
                Some(Duration::from_secs(10))
            } else {
                None
            };
            // Only failures that won't be retried are errors; the caller logs giving up.
            if retry_after.is_some() {
                warn!("{}", msg);
            } else {
                error!("{}", msg);
            }
            Err(PostError { msg, status: Some(status), retry_after })
        }
    }

    pub async fn queued(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        if let Err(e) = self.post_json("/proofs/queued", &json).await {
            warn!("ethproofs queued block={} failed: {}", block_number, e.msg);
        }
    }

    pub async fn proving(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        if let Err(e) = self.post_json("/proofs/proving", &json).await {
            warn!("ethproofs proving block={} failed: {}", block_number, e.msg);
        }
    }

    /// Posts a proof. `proof_bytes` are the prover's proof file (for Airbender, gzip of the
    /// EPROOF01 v2 envelope), sent base64 encoded; `proving_millis` is the proving time the
    /// caller measured; `cycle_count` is the guest's own cycle count. A rate-limited or failed
    /// post is retried (up to `PROVED_ATTEMPTS` posts), so callers run this in the background.
    pub async fn proved(
        &self,
        proof_bytes: &[u8],
        block_number: u64,
        cycle_count: u64,
        proving_millis: u64,
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
        });

        for attempt in 1..=PROVED_ATTEMPTS {
            let Err(e) = self.post_json("/proofs/proved", &json).await else {
                return;
            };
            // An earlier attempt landed though its response was lost.
            if attempt > 1 && e.status == Some(StatusCode::CONFLICT) {
                info!("ethproofs proved block={} already stored by an earlier attempt", block_number);
                return;
            }
            match e.retry_after {
                Some(wait) if attempt < PROVED_ATTEMPTS => {
                    let wait = wait.min(MAX_RETRY_WAIT);
                    warn!(
                        "ethproofs proved block={} attempt {}/{} failed, retrying in {}s: {}",
                        block_number, attempt, PROVED_ATTEMPTS, wait.as_secs(), e.msg
                    );
                    tokio::time::sleep(wait).await;
                }
                _ => {
                    error!("ethproofs proved block={} FAILED: {}", block_number, e.msg);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Reads one HTTP request (headers, then content-length bytes of body).
    async fn read_request(sock: &mut TcpStream) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = sock.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed mid-request");
            buf.extend_from_slice(&chunk[..n]);
            let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
            let headers = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = headers
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse::<usize>().unwrap());
            if buf.len() >= end + 4 + len {
                return;
            }
        }
    }

    /// Answers one request per connection with each (status line, body) in turn; returns the
    /// endpoint and the number of requests served.
    async fn serve(responses: Vec<(&'static str, &'static str)>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let served = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&served);
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                read_request(&mut sock).await;
                counter.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                sock.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (endpoint, served)
    }

    async fn post_proof(responses: Vec<(&'static str, &'static str)>) -> usize {
        let (endpoint, served) = serve(responses).await;
        let client = EthproofsClient::new(EthProofsConfig { endpoint, token: "t".into(), cluster_id: 9 });
        client.proved(&[1, 2, 3], 26191660, 162743337, 3996).await;
        served.load(Ordering::SeqCst)
    }

    const RATE_LIMITED: (&str, &str) = ("429 Too Many Requests", r#"{"error":"Rate limit exceeded","retryAfter":0}"#);

    #[tokio::test]
    async fn proved_retries_after_rate_limit() {
        assert_eq!(post_proof(vec![RATE_LIMITED, ("200 OK", r#"{"proof_id":1}"#)]).await, 2);
    }

    #[tokio::test]
    async fn proved_stops_when_a_retry_finds_the_proof_stored() {
        assert_eq!(post_proof(vec![RATE_LIMITED, ("409 Conflict", "Proof already proved")]).await, 2);
    }

    #[tokio::test]
    async fn proved_does_not_retry_client_errors() {
        assert_eq!(post_proof(vec![("409 Conflict", "Proof already proved")]).await, 1);
    }

    #[tokio::test]
    async fn proved_gives_up_after_its_attempts() {
        assert_eq!(post_proof(vec![RATE_LIMITED; PROVED_ATTEMPTS as usize]).await, PROVED_ATTEMPTS as usize);
    }
}
