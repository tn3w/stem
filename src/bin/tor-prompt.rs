#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = stem::interpreter::run(&arguments).await;
    std::process::exit(status);
}
