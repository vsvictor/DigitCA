use std::env;

use base64::{engine::general_purpose::STANDARD, Engine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_base = env::var("API_BASE").unwrap_or_else(|_| "https://digitca.digit.com".to_string());
    let username = env::var("USERNAME").unwrap_or_else(|_| "admin".to_string());
    let password = env::var("PASSWORD").unwrap_or_else(|_| "secret".to_string());

    let auth = STANDARD.encode(format!("{username}:{password}"));
    let client = reqwest::Client::new();

    let health = client
        .get(format!("{api_base}/health"))
        .send()
        .await?
        .text()
        .await?;
    println!("health: {health}");

    let docs_status = client
        .get(format!("{api_base}/docs"))
        .send()
        .await?
        .status();
    println!("docs status: {docs_status}");

    let certs_status = client
        .get(format!("{api_base}/api/v1/certificates?include_revoked=true&page=1&per_page=5"))
        .header("Authorization", format!("Basic {auth}"))
        .send()
        .await?
        .status();
    println!("certificates status: {certs_status}");

    Ok(())
}

