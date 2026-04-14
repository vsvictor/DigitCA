/// OCSP client example for digitca-ocsp — Rust
///
/// Usage:
///   cargo run -- \
///     --ocsp-base http://localhost:8082 \
///     --request-der ./request.der \
///     --response-der ./response.der
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "OCSP client example for digitca-ocsp")]
struct Args {
    /// OCSP responder base URL
    #[arg(long, env = "OCSP_BASE", default_value = "http://localhost:8082")]
    ocsp_base: String,

    /// Path to the DER-encoded OCSP request file
    #[arg(long, env = "OCSP_REQUEST_DER", default_value = "./request.der")]
    request_der: String,

    /// Path where the DER-encoded OCSP response will be saved
    #[arg(long, env = "OCSP_RESPONSE_DER", default_value = "./response.der")]
    response_der: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let client = reqwest::Client::new();

    // 1) Health check
    println!("[rust] GET {}/health", args.ocsp_base);
    let health = client
        .get(format!("{}/health", args.ocsp_base))
        .send()
        .await?
        .error_for_status()?;
    println!("{}", health.text().await?);

    // 2) Read request DER
    let request_bytes = tokio::fs::read(&args.request_der).await?;
    println!("[rust] POST {}/ocsp  ({} bytes)", args.ocsp_base, request_bytes.len());

    // 3) POST OCSP request
    let response = client
        .post(format!("{}/ocsp", args.ocsp_base))
        .header("Content-Type", "application/ocsp-request")
        .body(request_bytes)
        .send()
        .await?
        .error_for_status()?;

    // 4) Save DER response
    let response_bytes = response.bytes().await?;
    tokio::fs::write(&args.response_der, &response_bytes).await?;
    println!(
        "[rust] OCSP response saved: {}  ({} bytes)",
        args.response_der,
        response_bytes.len()
    );

    Ok(())
}

