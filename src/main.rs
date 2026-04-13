use digitca::run;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("Помилка: {err}");
        std::process::exit(1);
    }
}

