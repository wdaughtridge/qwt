mod http1;
mod quic;

use http1::Http1Server;
use quic::QuicServer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = "127.0.0.1:4433".parse().unwrap();

    let http1 = Http1Server::new(addr);
    let http1 = tokio::spawn(async move {
        http1.serve().await;
    });

    let mut quic = QuicServer::new(addr);
    let quic = tokio::spawn(async move {
        quic.serve().await.expect("server failed");
    });

    let (http1, quic) = tokio::join!(http1, quic);

    http1.expect("http1 failed");
    quic.expect("quic failed");
}
