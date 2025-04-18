use axum::{Router, routing::get};
use futures::StreamExt as _;
use quiche::h3::Header;
use quiche::{Connection, h3};
use ring::digest::{SHA256, digest};
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use std::fs;
use std::io::{self, Cursor, Read};
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::QuicSettings;
use tracing::*;

async fn fingerprint() -> String {
    let chain = fs::File::open("./certs/cert.crt").expect("failed to open cert file");
    let mut chain = io::BufReader::new(chain);

    let chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut chain)
        .collect::<Result<_, _>>()
        .expect("failed to read certs");

    let mut keys = fs::File::open("./certs/cert.key").expect("failed to open key file");

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

#[allow(unused)]
struct WebTransport {
    h3conn: Option<h3::Connection>,
    data_buf: [u8; 4096],
    established: bool,
}

impl WebTransport {
    pub fn new() -> Self {
        WebTransport {
            data_buf: [0; 4096],
            h3conn: None,
            established: false,
        }
    }

    fn process_webtransport_reads(&mut self, qconn: &mut Connection) {
        match qconn.stream_readable_next() {
            Some(stream_id) => {
                while let Ok((read, fin)) = qconn.stream_recv(stream_id, &mut self.data_buf) {
                    debug!("{} received {} bytes", qconn.trace_id(), read);

                    let stream_buf = &self.data_buf[..read];

                    debug!(
                        "{} stream {} has {} bytes (fin? {})",
                        qconn.trace_id(),
                        stream_id,
                        stream_buf.len(),
                        fin
                    );

                    debug!("data {stream_buf:?}");
                }
            }

            None => {}
        }
    }

    fn process_h3_reads(&mut self, qconn: &mut Connection) {
        loop {
            match self.h3conn.as_mut().unwrap().poll(qconn) {
                Ok((stream_id, event)) => {
                    debug!("Got event {event:?} on stream {stream_id}");
                    self.process_h3_event(qconn, event, stream_id);
                }
                Err(h3::Error::Done) => break,
                Err(err) => panic!("Connection closed due to h3 protocol error {err:?}"),
            };
        }
    }

    fn process_h3_event(&mut self, qconn: &mut Connection, event: h3::Event, stream_id: u64) {
        match event {
            h3::Event::Headers { list, .. } => {
                // TODO: check client's headers
                let _list = list;

                // TODO: handle errors here, e.g., non-2XX responses
                let headers_buf = [Header::new(":status".as_bytes(), "200".as_bytes())].to_vec();
                self.h3conn
                    .as_mut()
                    .unwrap()
                    .send_response(qconn, stream_id, &headers_buf, true)
                    .expect("sending HTTP/3 response");

                // We've got liftoff 🚀
                self.established = true;
            }
            h3::Event::Data => loop {
                match self.h3conn.as_mut().unwrap().recv_body(
                    qconn,
                    stream_id,
                    &mut self.data_buf[..],
                ) {
                    Ok(read) => debug!(
                        "{} received {read} bytes on stream {}",
                        qconn.trace_id(),
                        stream_id,
                    ),
                    Err(h3::Error::Done) => break,
                    Err(_) => error!(
                        "{} error reading data from stream {}",
                        qconn.trace_id(),
                        stream_id,
                    ),
                }
            },
            e => {
                warn!("unhandled h3 event {e:?}");
            }
        }
    }
}

const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0xc671706a;

impl ApplicationOverQuic for WebTransport {
    fn on_conn_established(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
        handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> tokio_quiche::QuicResult<()> {
        debug!(
            "{} quic conn established in {} ms",
            qconn.trace_id(),
            handshake_info.elapsed().as_millis()
        );

        let mut config = h3::Config::new().unwrap();
        config.enable_extended_connect(true);
        config
            .set_additional_settings([(SETTINGS_WEBTRANSPORT_MAX_SESSIONS, 1024)].to_vec())
            .unwrap();

        let h3conn = h3::Connection::with_transport(qconn, &config).unwrap();
        self.h3conn = Some(h3conn);

        debug!("{} HTTP/3 conn established", qconn.trace_id());

        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        // TODO: more efficient buffer?
        &mut self.data_buf
    }

    async fn wait_for_data(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        // TODO: handle application logic
        Ok(())
    }

    fn process_reads(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        if self.established {
            self.process_webtransport_reads(qconn);
        } else {
            self.process_h3_reads(qconn);
        }

        Ok(())
    }

    fn process_writes(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = "127.0.0.1:4433";

    // HTTP/1 for the fingerprint route
    // TODO: remove this if we have proper certs
    let app = Router::new().route("/fingerprint", get(fingerprint));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let quic_settings = QuicSettings::default();
    let socket = tokio::net::UdpSocket::bind(addr).await.unwrap();
    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            quic_settings,
            tokio_quiche::settings::TlsCertificatePaths {
                cert: "./certs/cert.crt",
                private_key: "./certs/cert.key",
                kind: tokio_quiche::settings::CertificateKind::X509,
            },
            Default::default(),
        ),
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .unwrap();
    let accept_stream = &mut listeners[0];

    while let Some(conn) = accept_stream.next().await {
        let driver = WebTransport::new();
        conn.unwrap().start(driver);
    }
}
