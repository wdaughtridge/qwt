use axum::response::Html;
use axum::{Router, routing::get};
use ring::digest::{SHA256, digest};
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use std::fs;
use std::io::{self, Cursor, Read};
use std::net::SocketAddr;

async fn index() -> Html<&'static str> {
    include_str!("../static/index.html").into()
}

async fn fingerprint() -> String {
    let chain = fs::File::open("certs/cert.crt").expect("failed to open cert file");
    let mut chain = io::BufReader::new(chain);

    let chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut chain)
        .collect::<Result<_, _>>()
        .expect("failed to read certs");

    let mut keys = fs::File::open("certs/cert.key").expect("failed to open key file");

    let mut buf = Vec::new();
    keys.read_to_end(&mut buf).unwrap();

    let key = rustls_pemfile::private_key(&mut Cursor::new(&buf))
        .unwrap()
        .unwrap();
    let key = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();

    let certified = CertifiedKey::new(chain, key);

    let fingerprint = digest(&SHA256, certified.cert[0].as_ref());
    let fingerprint = hex::encode(fingerprint.as_ref());

    fingerprint
}

pub struct Http1Server {
    addr: SocketAddr,
}

impl Http1Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
        }
    }

    pub async fn serve(&self) {
        let app = Router::new()
            .route("/", get(index))
            .route("/fingerprint", get(fingerprint));

        let listener = tokio::net::TcpListener::bind(self.addr).await.unwrap();

        axum::serve(listener, app).await.unwrap();
    }
}
