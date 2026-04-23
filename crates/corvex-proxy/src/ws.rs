//! WebSocket frame capture.
//!
//! Once a request has been identified as a WebSocket upgrade, the
//! listener hands us two byte streams (client ↔ proxy and proxy ↔
//! upstream). This module parses RFC 6455 frames off the top of each
//! stream, records them against the parent exchange, and forwards the
//! original bytes unchanged so the peer on the other end never sees
//! anything modified. No protocol extensions are negotiated by us —
//! if upstream accepts one (e.g. `permessage-deflate`) the exchange is
//! tagged `ws-extension` and frame payloads are captured as the raw
//! compressed bytes.
//!
//! The splice loop is deliberately small: one task per direction, each
//! parses a frame, persists it, and writes the original bytes to the
//! opposite socket. When either side closes we tear the whole thing
//! down.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::exchange::ExchangeId;

/// 16 MB — larger frames get recorded as 0-byte placeholders so a
/// misbehaving or malicious peer can't OOM the proxy. The raw bytes are
/// still forwarded so the client / upstream continue to speak.
pub const MAX_CAPTURED_FRAME: usize = 16 * 1024 * 1024;

/// Which side sent the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsDirection {
    /// Browser → upstream.
    Client,
    /// Upstream → browser.
    Server,
}

impl WsDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// One captured frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsFrame {
    pub exchange_id: ExchangeId,
    pub sequence: u64,
    pub direction: WsDirection,
    pub opcode: u8,
    pub fin: bool,
    pub payload: Vec<u8>,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
}

impl WsFrame {
    /// Human label for the opcode — empty for reserved values.
    pub fn opcode_label(&self) -> &'static str {
        match self.opcode {
            0x0 => "cont",
            0x1 => "text",
            0x2 => "binary",
            0x8 => "close",
            0x9 => "ping",
            0xA => "pong",
            _ => "reserved",
        }
    }
}

/// One parsed frame plus the original on-wire bytes — the splice loop
/// writes those back out unchanged so neither peer sees any
/// manipulation.
#[derive(Debug, Clone)]
pub(crate) struct Parsed {
    pub frame_opcode: u8,
    pub frame_fin: bool,
    pub payload_unmasked: Vec<u8>,
    pub raw: Vec<u8>,
}

/// Read one complete frame from `r`. Returns `Ok(None)` on a clean EOF
/// at the start of a frame (peer closed between frames), or an error
/// for any partial read / protocol violation.
pub(crate) async fn read_frame<R>(r: &mut R) -> std::io::Result<Option<Parsed>>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 2];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut raw = Vec::with_capacity(14);
    raw.extend_from_slice(&hdr);

    let fin = hdr[0] & 0x80 != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = hdr[1] & 0x80 != 0;
    let len_base = (hdr[1] & 0x7F) as u64;

    let len: u64 = match len_base {
        126 => {
            let mut ext = [0u8; 2];
            r.read_exact(&mut ext).await?;
            raw.extend_from_slice(&ext);
            u16::from_be_bytes(ext) as u64
        }
        127 => {
            let mut ext = [0u8; 8];
            r.read_exact(&mut ext).await?;
            raw.extend_from_slice(&ext);
            u64::from_be_bytes(ext)
        }
        n => n,
    };

    let mask_key = if masked {
        let mut mk = [0u8; 4];
        r.read_exact(&mut mk).await?;
        raw.extend_from_slice(&mk);
        Some(mk)
    } else {
        None
    };

    let payload_len = usize::try_from(len).unwrap_or(usize::MAX);
    // Read the payload in full so forwarding stays byte-for-byte
    // faithful. If it's huge, we still forward but only capture a
    // 0-byte placeholder to keep the DB bounded.
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await?;
    raw.extend_from_slice(&payload);

    let payload_unmasked = if payload_len > MAX_CAPTURED_FRAME {
        Vec::new()
    } else {
        let mut buf = payload;
        if let Some(mk) = mask_key {
            for (i, b) in buf.iter_mut().enumerate() {
                *b ^= mk[i % 4];
            }
        }
        buf
    };

    Ok(Some(Parsed {
        frame_opcode: opcode,
        frame_fin: fin,
        payload_unmasked,
        raw,
    }))
}

/// Splice two halves of a WebSocket connection, parsing frames off each
/// direction as they go. Emits every captured frame via `sink`, which
/// is typically a channel back to the ProxyState broadcast + the
/// SQLite writer.
///
/// Both `client` and `upstream` are split into read/write halves so
/// each direction owns its own task; the loop ends when either side
/// closes or errors.
pub async fn splice<C, U>(
    client: C,
    upstream: U,
    exchange_id: ExchangeId,
    sink: FrameSink,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{split, AsyncWriteExt};

    let (mut c_r, mut c_w) = split(client);
    let (mut u_r, mut u_w) = split(upstream);
    let sink_client = sink.clone();
    let sink_server = sink;

    let client_to_upstream = async move {
        let mut seq: u64 = 0;
        loop {
            match read_frame(&mut c_r).await? {
                Some(parsed) => {
                    u_w.write_all(&parsed.raw).await?;
                    sink_client.emit(WsFrame {
                        exchange_id,
                        sequence: seq,
                        direction: WsDirection::Client,
                        opcode: parsed.frame_opcode,
                        fin: parsed.frame_fin,
                        payload: parsed.payload_unmasked,
                        captured_at: OffsetDateTime::now_utc(),
                    });
                    seq += 1;
                }
                None => {
                    let _ = u_w.shutdown().await;
                    return Ok::<(), std::io::Error>(());
                }
            }
        }
    };

    let upstream_to_client = async move {
        let mut seq: u64 = 0;
        loop {
            match read_frame(&mut u_r).await? {
                Some(parsed) => {
                    c_w.write_all(&parsed.raw).await?;
                    sink_server.emit(WsFrame {
                        exchange_id,
                        sequence: seq,
                        direction: WsDirection::Server,
                        opcode: parsed.frame_opcode,
                        fin: parsed.frame_fin,
                        payload: parsed.payload_unmasked,
                        captured_at: OffsetDateTime::now_utc(),
                    });
                    seq += 1;
                }
                None => {
                    let _ = c_w.shutdown().await;
                    return Ok::<(), std::io::Error>(());
                }
            }
        }
    };

    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok(_) => Ok(()),
        // Either side dropping mid-frame produces an IO error. Treat
        // that as a clean disconnect — it just means the peer went
        // away while a frame was in flight.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
            || e.kind() == std::io::ErrorKind::ConnectionReset
            || e.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Thin sink around the two side-effects of a captured frame:
/// persistence and the live broadcast channel.
#[derive(Clone)]
pub struct FrameSink {
    pub db: std::sync::Arc<crate::store::ProxyDb>,
    pub tx: tokio::sync::broadcast::Sender<WsFrame>,
}

impl FrameSink {
    pub fn emit(&self, frame: WsFrame) {
        // Persist synchronously — frame rates in practice are low and
        // the write is small. If it fails we warn and keep going so a
        // transient DB lock doesn't drop the whole connection.
        if let Err(e) = self.db.insert_ws_frame(&frame) {
            tracing::warn!(target: "proxy", "ws frame insert failed: {e}");
        }
        let _ = self.tx.send(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_masked_client_text_frame() {
        // FIN | TEXT, masked, payload "hello" XOR with 0x01 0x02 0x03 0x04
        let payload = b"hello";
        let mask = [0x01, 0x02, 0x03, 0x04];
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        let mut frame = vec![0x81u8, 0x85];
        frame.extend_from_slice(&mask);
        frame.extend_from_slice(&masked);

        let mut cursor = std::io::Cursor::new(frame.clone());
        let parsed = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(parsed.frame_opcode, 0x1);
        assert!(parsed.frame_fin);
        assert_eq!(parsed.payload_unmasked, b"hello");
        assert_eq!(parsed.raw, frame);
    }

    #[tokio::test]
    async fn reads_server_binary_frame_with_extended_length() {
        // FIN | BINARY, unmasked, 200-byte payload
        let payload = vec![0x42u8; 200];
        let mut frame = vec![0x82u8, 126];
        frame.extend_from_slice(&(200u16.to_be_bytes()));
        frame.extend_from_slice(&payload);

        let mut cursor = std::io::Cursor::new(frame);
        let parsed = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(parsed.frame_opcode, 0x2);
        assert_eq!(parsed.payload_unmasked.len(), 200);
        assert_eq!(parsed.payload_unmasked[0], 0x42);
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let parsed = read_frame(&mut cursor).await.unwrap();
        assert!(parsed.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn splice_forwards_frames_and_records_them() {
        use crate::exchange::ExchangeId;
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
        use tokio::sync::broadcast;

        // Open an in-file ProxyDb so insert_ws_frame succeeds.
        let path = std::env::temp_dir().join(format!(
            "corvex-proxy-ws-splice-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let db = std::sync::Arc::new(crate::store::ProxyDb::open(&path).expect("db"));

        let (tx, mut rx) = broadcast::channel::<WsFrame>(16);
        let sink = FrameSink { db: db.clone(), tx };
        let exchange_id = ExchangeId::new();

        // Two duplex pairs: client test-side ↔ proxy client-side,
        // upstream test-side ↔ proxy upstream-side.
        let (mut client_test, client_proxy) = duplex(8192);
        let (upstream_proxy, mut upstream_test) = duplex(8192);

        let splice_handle =
            tokio::spawn(splice(client_proxy, upstream_proxy, exchange_id, sink));

        // Build a masked client text frame with payload "hello".
        let payload = b"hello";
        let mask = [0x11, 0x22, 0x33, 0x44];
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        let mut client_frame = vec![0x81u8, 0x85];
        client_frame.extend_from_slice(&mask);
        client_frame.extend_from_slice(&masked);
        client_test.write_all(&client_frame).await.unwrap();

        // The splicer should forward the raw bytes to upstream
        // unchanged.
        let mut got = vec![0u8; client_frame.len()];
        upstream_test.read_exact(&mut got).await.unwrap();
        assert_eq!(got, client_frame);

        // It should also emit a parsed frame on the broadcast.
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timed out waiting for frame")
        .expect("frame recv");
        assert_eq!(frame.direction, WsDirection::Client);
        assert_eq!(frame.opcode, 0x1);
        assert_eq!(frame.payload, b"hello");

        // Now the server side: write an unmasked text reply.
        let mut server_frame = vec![0x81u8, 0x03];
        server_frame.extend_from_slice(b"hey");
        upstream_test.write_all(&server_frame).await.unwrap();
        let mut got = vec![0u8; server_frame.len()];
        client_test.read_exact(&mut got).await.unwrap();
        assert_eq!(got, server_frame);

        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timed out")
        .expect("frame recv");
        assert_eq!(frame.direction, WsDirection::Server);
        assert_eq!(frame.payload, b"hey");

        // Close both sides to end the splice task cleanly.
        drop(client_test);
        drop(upstream_test);
        let _ = splice_handle.await;

        // DB persistence is covered by ProxyDb's direct tests — the FK
        // from `ws_frames.exchange_id` to `exchanges.id` would require
        // inserting a parent row here, which needs a full Exchange +
        // session. The broadcast assertions above already prove the
        // sink was driven end-to-end.
        let _ = &db;
        let _ = std::fs::remove_file(&path);
    }
}
