#[tokio::main]
async fn main() {
	if let Err(err) = digitca_ocsp::run().await {
		eprintln!("{err}");
		std::process::exit(1);
	}
}

