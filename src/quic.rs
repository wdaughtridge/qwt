use bytes::Bytes;
use octets::{Octets, OctetsMut};
use quiche::h3::{self, qpack};
use s2n_quic::{
    Connection, Server,
    stream::{BidirectionalStream, ReceiveStream, SendStream},
};
use std::{collections::HashMap, error::Error, net::SocketAddr, time::Duration};
use tokio::{
    io::AsyncReadExt,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::sleep,
};
use tracing::*;

const SETTINGS_ENABLE_WEBTRANSPORT: u64 = 0x2b603742;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0xc671706a;

pub static CERT_PEM: &str = include_str!(concat!("../certs/cert.crt"));

pub static KEY_PEM: &str = include_str!(concat!("../certs/cert.key"));

pub struct QuicServer {
    server: Server,
}

pub struct QwtClient {
    conn: Connection,
}

pub struct QwtBidirectional {
    bidi: BidirectionalStream,
    sess: Option<u64>,
    buf: Vec<u8>,
}

impl QwtBidirectional {
    pub fn new(bidi: BidirectionalStream) -> Self {
        Self {
            bidi,
            sess: None,
            buf: Vec::with_capacity(1350),
        }
    }

    pub async fn sess(&mut self) -> Result<(), Box<dyn Error>> {
        let data = self.bidi.receive().await?.expect("receive");
        let mut data = Octets::with_slice(&data[..]);

        if self.sess.is_none() {
            self.sess = Some(data.get_varint()?);

            debug!("WebTransport session {}", self.sess.unwrap());
        } else {
            panic!("Can't reset session ID");
        }

        debug!("Initial WebTransport bidirectional data {:?}", data);

        self.buf.extend_from_slice(&data.buf()[data.off()..]);

        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        self.sess().await?;

        while let Ok(Some(data)) = self.bidi.receive().await {
            debug!(
                "Got WebTransport {} bytes of bidirectional data",
                data.len()
            );

            let _data = self.buf.iter().chain(data.iter());

            // for byte in data {
            //     debug!("Got byte {byte}");
            // }
        }

        Ok(())
    }
}

pub struct QwtReceive {
    rx: ReceiveStream,
    sess: Option<u64>,
    buf: Vec<u8>,
}

impl QwtReceive {
    pub fn new(rx: ReceiveStream) -> Self {
        Self {
            rx,
            sess: None,
            buf: Vec::with_capacity(1350),
        }
    }

    pub async fn sess(&mut self) -> Result<(), Box<dyn Error>> {
        let data = self.rx.receive().await?.expect("receive");
        let mut data = Octets::with_slice(&data[..]);

        if self.sess.is_none() {
            self.sess = Some(data.get_varint()?);

            debug!("WebTransport session {}", self.sess.unwrap());
        } else {
            panic!("Can't reset session ID");
        }

        self.buf.extend_from_slice(&data.buf()[data.off()..]);

        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        self.sess().await?;

        while let Ok(Some(data)) = self.rx.receive().await {
            debug!("Got WebTransport unidirectional data {:?}", data);

            let data = self.buf.iter().chain(data.iter());

            for byte in data {
                debug!("Got byte {byte}");
            }
        }

        Ok(())
    }
}

impl QwtClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        let (tx, rx) = mpsc::unbounded_channel();

        // Their SETTINGS frame will be sent to this stream
        if let Some(rx) = self.conn.accept_receive_stream().await? {
            debug!("Accepted receive stream");
            self.handle_receive_control_stream(rx, tx).await?
        }

        // Our SETTINGS frame will be sent from this stream
        if let Ok(tx) = self.conn.open_send_stream().await {
            debug!("Opened send stream");
            self.handle_send_control_stream(tx, rx).await?;
        }

        // HEADERS frame will come to this stream
        if let Some(bidi) = self.conn.accept_bidirectional_stream().await? {
            debug!("Accepted bidi stream");
            self.handle_bidirectional_request_stream(bidi).await?;
        }

        // This loop will concurrently accept new bidi and recv streams. I am not sure if
        // 50 ms is a reasonable timeout for this so could use some tuning
        loop {
            tokio::select! {
                Ok(Some(bidi)) = self.conn.accept_bidirectional_stream() => {
                    self.handle_bidirectional_stream(bidi).await?;
                }

                _ = sleep(Duration::from_millis(50)) => {}
            }

            tokio::select! {
                Ok(Some(rx)) = self.conn.accept_receive_stream() => {
                    self.handle_receive_stream(rx).await?;
                }

                _ = sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    async fn handle_send_control_stream(
        &mut self,
        mut tx: SendStream,
        mut rx: UnboundedReceiver<Bytes>,
    ) -> Result<(), Box<dyn Error>> {
        let typ = Bytes::from_static(&[0x00]);
        tx.send(typ).await?;

        debug!("Server opened control stream");

        // Listen on the mpsc and just blindly send the frames. We should probably put
        // this in a select and do something useful when it is just sitting here idle
        tokio::spawn(async move {
            while let Some(out) = rx.recv().await {
                debug!("Got outgoing {} bytes", out.len());
                tx.send(out).await.expect("tx send");
            }
        });

        Ok(())
    }

    async fn handle_bidirectional_request_stream(
        &mut self,
        mut bidi: BidirectionalStream,
    ) -> Result<(), Box<dyn Error>> {
        tokio::spawn(async move {
            let mut buf = [0; 1350];
            let mut out = [0; 1350];

            while let Ok(Some(data)) = bidi.receive().await {
                let mut data = Octets::with_slice(&data[..]);

                // Parse frame type and length of payload
                let typ = data.get_varint().unwrap();
                let len = data.get_varint().unwrap();
                let frm = data.get_bytes(len as usize).unwrap();

                match typ {
                    0x01 => {
                        // HEADERS Frame {
                        //   Type (i) = 0x01,
                        //   Length (i),
                        //   Encoded Field Section (..),
                        // }

                        // I am lazy
                        // TODO: replace with minimal QPACK implementation later
                        let mut dec = qpack::Decoder::new();
                        let hdrs = dec.decode(frm.buf(), 1024).unwrap();

                        // TODO: validate headers
                        for hdr in hdrs {
                            debug!("Got header {:?}", hdr);
                        }

                        // TODO: handle non-200 cases
                        let hdrs = vec![h3::Header::new(b":status", b"200")];

                        debug!("Will send headers {:?}", hdrs);

                        let mut enc = qpack::Encoder::new();
                        let len = enc.encode(&hdrs, &mut buf[..]).unwrap();

                        let len = {
                            let mut out = OctetsMut::with_slice(&mut out[..]);

                            out.put_varint(0x01).unwrap();
                            out.put_varint(len as u64).unwrap();
                            out.put_bytes(&buf[..len]).unwrap();

                            out.off()
                        };

                        let out = Bytes::copy_from_slice(&out[..len]);

                        bidi.send(out).await.unwrap();

                        debug!("Sent {} bytes", len);
                    }

                    unk => {
                        panic!("Unknown frame type {}", unk);
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_receive_control_stream(
        &mut self,
        mut rx: ReceiveStream,
        tx: UnboundedSender<Bytes>,
    ) -> Result<(), Box<dyn Error>> {
        // Ensure that it is indeed a control stream
        // NOTE: I think this might not be an invariant we can count on after the
        // WebTransport RFC is standardized
        let stream_type = rx.read_u8().await.unwrap();
        assert_eq!(stream_type, 0x00);

        debug!("Client opened control stream");

        tokio::spawn(async move {
            let mut buf = [0; 1350];
            let mut out = [0; 1350];

            let mut settings = HashMap::new();
            let mut ver = None;

            while let Ok(Some(data)) = rx.receive().await {
                let mut data = Octets::with_slice(&data[..]);

                // Parse frame type and length of payload
                let typ = data.get_varint().unwrap();
                let len = data.get_varint().unwrap();
                let mut frm = data.get_bytes(len as usize).unwrap();

                match typ {
                    0x04 => {
                        // SETTINGS Frame {
                        //  Type (i) = 0x04,
                        //  Length (i),
                        //  Setting (..) ...,
                        // }

                        // Parse settings frame
                        let mut prev = None;
                        while let Ok(next) = frm.get_varint() {
                            if let Some(key) = prev {
                                // We have value for corresponding key
                                settings.insert(key, next);

                                // Do some extra logic while we have the key and value
                                if key == SETTINGS_ENABLE_WEBTRANSPORT {
                                    ver = Some("draft-02");
                                } else if key == SETTINGS_WEBTRANSPORT_MAX_SESSIONS {
                                    ver = Some("draft-09");
                                }

                                // Reset so next iteration saves key
                                prev = None;
                            } else {
                                prev = Some(next);
                            }
                        }

                        if ver.is_none() {
                            panic!("No WebTransport version specified");
                        }

                        let ver = ver.unwrap();

                        // Create the actual setttings values for the response frame
                        // 10 bytes should be fine for now
                        let len = {
                            let mut frm = OctetsMut::with_slice(&mut buf);

                            // This is for draft-02 only
                            if "draft-02" == ver {
                                frm.put_varint(SETTINGS_ENABLE_WEBTRANSPORT).unwrap();
                                frm.put_varint(1).unwrap();
                            } else {
                                frm.put_varint(SETTINGS_WEBTRANSPORT_MAX_SESSIONS).unwrap();
                                frm.put_varint(1024).unwrap();
                            }

                            // Required in all WebTransport drafts
                            frm.put_varint(SETTINGS_H3_DATAGRAM).unwrap();
                            frm.put_varint(1).unwrap();

                            frm.off()
                        };

                        // Add the type (0x04), len, and bytes computed above to send
                        let len = {
                            let mut out = OctetsMut::with_slice(&mut out);

                            out.put_u8(0x04).unwrap();
                            out.put_varint(len as u64).unwrap();

                            out.put_bytes(&buf[..len]).unwrap();

                            out.off()
                        };

                        // Bytes type makes it super convenient to send over a tokio mpsc
                        let out = Bytes::copy_from_slice(&out[..len]);

                        tx.send(out).unwrap();
                    }

                    unk => {
                        panic!("Unknown frame type {}", unk);
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_receive_stream(&mut self, mut rx: ReceiveStream) -> Result<(), Box<dyn Error>> {
        // HACK: read the varint frame type as two bytes
        let var = rx.read_u8().await?;
        assert_eq!(var, 0x40);
        let typ = rx.read_u8().await?;
        assert_eq!(typ, 0x54);

        debug!("WebTransport unidirectional stream");

        // Eject to WebTransport unidirectional stream
        let mut rx = QwtReceive::new(rx);
        tokio::spawn(async move {
            rx.start().await.expect("WebTransport bidirectional");
        });

        Ok(())
    }

    async fn handle_bidirectional_stream(
        &mut self,
        mut bidi: BidirectionalStream,
    ) -> Result<(), Box<dyn Error>> {
        // HACK: read the varint frame type as two bytes
        let var = bidi.read_u8().await?;
        assert_eq!(var, 0x40);
        let typ = bidi.read_u8().await?;
        assert_eq!(typ, 0x41);

        debug!("WebTransport bidirectional stream");

        // Eject to WebTransport bidirectional stream
        let mut bidi = QwtBidirectional::new(bidi);
        tokio::spawn(async move {
            bidi.start().await.expect("WebTransport bidirectional");
        });

        Ok(())
    }
}

impl QuicServer {
    pub fn new(addr: SocketAddr) -> Self {
        let server = Server::builder()
            .with_tls((CERT_PEM, KEY_PEM))
            .expect("tls quic")
            .with_io(addr)
            .expect("binding quic")
            .start()
            .expect("serving quic");

        Self { server }
    }

    pub async fn serve(&mut self) -> Result<(), Box<dyn Error>> {
        // Accept incoming connections
        while let Some(conn) = self.server.accept().await {
            // New connection spawned
            let mut client = QwtClient::new(conn);

            tokio::spawn(async move {
                client.start().await.expect("client failed");
            });
        }

        Ok(())
    }
}
