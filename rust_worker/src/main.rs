use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

#[derive(Debug, Deserialize)]
struct ScanRequest {
    target: String,
    ports: Vec<u16>,
    timeout_ms: Option<u64>,
    max_concurrency: Option<usize>,
}

#[derive(Debug, Serialize)]
struct PortResult {
    port: u16,
    open: bool,
    latency_ms: f64,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    results: Vec<PortResult>,
}

async fn scan_port(target: &str, port: u16, timeout_ms: u64) -> PortResult {
    let start = Instant::now();
    let addr = format!("{}:{}", target, port);
    let result = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await;
    let open = matches!(result, Ok(Ok(_)));
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    PortResult {
        port,
        open,
        latency_ms,
    }
}

#[tokio::main]
async fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        return;
    }

    let req: ScanRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => return,
    };

    let timeout_ms = req.timeout_ms.unwrap_or(800).clamp(100, 5000);
    let max_concurrency = req.max_concurrency.unwrap_or(256).clamp(1, 4096);
    let sem = Arc::new(Semaphore::new(max_concurrency));

    let mut handles = Vec::with_capacity(req.ports.len());

    for port in req.ports {
        let sem_clone = Arc::clone(&sem);
        let target = req.target.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem_clone.acquire_owned().await.ok();
            scan_port(&target, port, timeout_ms).await
        }));
    }

    let mut out = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            out.push(result);
        }
    }
    out.sort_by_key(|r| r.port);

    let resp = ScanResponse { results: out };
    if let Ok(json) = serde_json::to_string(&resp) {
        println!("{}", json);
    }
}
