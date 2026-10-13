use super::*;
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{channel, Sender},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

// ============================================================================
// Minimal Self-Contained Crypto (RFC 1321 MD5, HMAC-SHA1, CRC-32)
// ============================================================================

/// Canonical RFC 1321 MD5 for STUN long-term credential key derivation.
fn md5(data: &[u8]) -> [u8; 16] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;

    let orig_len_bits = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    let s = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 16];
        for i in 0..16 {
            w[i] = u32::from_le_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (h0, h1, h2, h3);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(w[g])).rotate_left(s[i]));
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&h0.to_le_bytes());
    out[4..8].copy_from_slice(&h1.to_le_bytes());
    out[8..12].copy_from_slice(&h2.to_le_bytes());
    out[12..16].copy_from_slice(&h3.to_le_bytes());
    out
}

/// Standard HMAC-SHA1 using existing workspace `sha1` crate.
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let digest = Sha1::digest(key);
        k[..20].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_res = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_res);
    outer.finalize().into()
}

/// Standard CRC-32 (IEEE 802.3) for STUN FINGERPRINT attribute.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1) & 0xEDB88320;
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

fn rand_tx_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut id);
    id
}

// ============================================================================
// STUN / TURN RFC 5389 & RFC 5766 Protocol Helpers
// ============================================================================

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

#[derive(Debug, Clone)]
struct StunMessage {
    msg_type: u16,
    tx_id: [u8; 12],
    channel_number: Option<u16>,
    peer_port: Option<u16>,
    lifetime: Option<u32>,
    data: Option<Vec<u8>>,
    has_message_integrity: bool,
}

fn parse_stun_message(buf: &[u8]) -> Option<StunMessage> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }

    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&buf[8..20]);

    let total = 20 + length as usize;
    if buf.len() < total {
        return None;
    }

    let mut msg = StunMessage {
        msg_type,
        tx_id,
        channel_number: None,
        peer_port: None,
        lifetime: None,
        data: None,
        has_message_integrity: false,
    };

    let mut offset = 20;
    while offset + 4 <= total {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > total {
            break;
        }
        let val = &buf[offset..offset + attr_len];
        match attr_type {
            0x0008 => msg.has_message_integrity = true,
            0x000c if val.len() >= 2 => {
                msg.channel_number = Some(u16::from_be_bytes([val[0], val[1]]));
            }
            0x000d if val.len() >= 4 => {
                msg.lifetime = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
            }
            0x0012 if val.len() == 8 && val[1] == 1 => {
                msg.peer_port = Some(u16::from_be_bytes([val[2], val[3]]) ^ 0x2112);
            }
            0x0013 => msg.data = Some(val.to_vec()),
            _ => {}
        }
        offset += (attr_len + 3) & !3;
    }

    Some(msg)
}

fn attr_xor_addr(attr_type: u16, ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&attr_type.to_be_bytes());
    v.extend_from_slice(&8u16.to_be_bytes());
    v.push(0x00); // reserved
    v.push(0x01); // IPv4
    v.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
    let octets = ip.octets();
    v.push(octets[0] ^ 0x21);
    v.push(octets[1] ^ 0x12);
    v.push(octets[2] ^ 0xa4);
    v.push(octets[3] ^ 0x42);
    v
}

fn attr_lifetime(secs: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&0x000du16.to_be_bytes());
    v.extend_from_slice(&4u16.to_be_bytes());
    v.extend_from_slice(&secs.to_be_bytes());
    v
}

fn attr_string(attr_type: u16, s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let pad = (4 - (bytes.len() % 4)) % 4;
    let mut v = Vec::with_capacity(4 + bytes.len() + pad);
    v.extend_from_slice(&attr_type.to_be_bytes());
    v.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(bytes);
    v.resize(v.len() + pad, 0);
    v
}

fn attr_error_code(code: u16, reason: &str) -> Vec<u8> {
    let class = (code / 100) as u8;
    let number = (code % 100) as u8;
    let reason_bytes = reason.as_bytes();
    let val_len = 4 + reason_bytes.len();
    let pad = (4 - (val_len % 4)) % 4;
    let mut v = Vec::with_capacity(4 + val_len + pad);
    v.extend_from_slice(&0x0009u16.to_be_bytes());
    v.extend_from_slice(&(val_len as u16).to_be_bytes());
    v.push(0);
    v.push(0);
    v.push(class);
    v.push(number);
    v.extend_from_slice(reason_bytes);
    v.resize(v.len() + pad, 0);
    v
}

fn attr_data(data: &[u8]) -> Vec<u8> {
    let pad = (4 - (data.len() % 4)) % 4;
    let mut v = Vec::with_capacity(4 + data.len() + pad);
    v.extend_from_slice(&0x0013u16.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v.resize(v.len() + pad, 0);
    v
}

fn build_stun_response(
    msg_type: u16,
    tx_id: &[u8; 12],
    attrs: &[u8],
    key: Option<&[u8; 16]>,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20 + attrs.len() + 32);
    msg.extend_from_slice(&msg_type.to_be_bytes());
    let mut attr_len = attrs.len() as u16;
    if key.is_some() {
        attr_len += 24; // MESSAGE-INTEGRITY attribute
    }
    msg.extend_from_slice(&attr_len.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tx_id);
    msg.extend_from_slice(attrs);

    if let Some(key) = key {
        let mi = hmac_sha1(key, &msg);
        msg.extend_from_slice(&0x0008u16.to_be_bytes());
        msg.extend_from_slice(&20u16.to_be_bytes());
        msg.extend_from_slice(&mi);

        let attr_len_fp = attr_len + 8; // FINGERPRINT attribute
        msg[2..4].copy_from_slice(&attr_len_fp.to_be_bytes());
        let fp = crc32(&msg) ^ 0x5354554e;
        msg.extend_from_slice(&0x8028u16.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&fp.to_be_bytes());
    }

    msg
}

// ============================================================================
// Functional Minimal TURN TCP Server Fixture
// ============================================================================
// shortcut: IPv4 TURN/TCP fixture without TLS, use coturn for external/TLS relay coverage.

struct TurnPeer {
    id: usize,
    relay_port: u16,
    channels: HashMap<u16, u16>,
    tx: Sender<Vec<u8>>,
}

pub struct TurnTcpServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    direct_connections: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}

impl TurnTcpServer {
    pub fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let direct_connections = Arc::new(AtomicUsize::new(0));

        let stop = shutdown.clone();
        let conn_counter = direct_connections.clone();

        let peers: Arc<Mutex<Vec<TurnPeer>>> = Arc::new(Mutex::new(Vec::new()));
        let peer_counter = Arc::new(AtomicUsize::new(0));

        let worker = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let mut client_threads = Vec::new();

            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        conn_counter.fetch_add(1, Ordering::SeqCst);
                        let client_id = peer_counter.fetch_add(1, Ordering::SeqCst);
                        let (tx, rx) = channel::<Vec<u8>>();

                        let relay_ip = Ipv4Addr::new(198, 51, 100, 1);
                        let relay_port = 50001 + (client_id as u16);

                        peers.lock().push(TurnPeer {
                            id: client_id,
                            relay_port,
                            channels: HashMap::new(),
                            tx: tx.clone(),
                        });

                        let peers_loop = peers.clone();
                        let stop_loop = stop.clone();

                        client_threads.push(std::thread::spawn(move || {
                            let mut write_stream = stream.try_clone().unwrap();
                            let stop_writer = stop_loop.clone();

                            let writer = std::thread::spawn(move || {
                                while !stop_writer.load(Ordering::Relaxed) {
                                    match rx.recv_timeout(Duration::from_millis(50)) {
                                        Ok(data) => {
                                            if write_stream.write_all(&data).is_err() {
                                                break;
                                            }
                                        }
                                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                                    }
                                }
                            });

                            let mut read_stream = stream;
                            read_stream.set_nonblocking(true).unwrap();
                            let mut buf = Vec::new();
                            let mut tmp = [0u8; 4096];

                            while !stop_loop.load(Ordering::Relaxed) {
                                match read_stream.read(&mut tmp) {
                                    Ok(0) => break,
                                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        std::thread::sleep(Duration::from_millis(5));
                                    }
                                    Err(_) => break,
                                }

                                while buf.len() >= 4 {
                                    let first_two_bits = buf[0] >> 6;
                                    if first_two_bits == 0b01 {
                                        // TURN ChannelData framing (RFC 5766 11.5)
                                        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                        let total = (4 + len + 3) & !3;
                                        if buf.len() < total {
                                            break;
                                        }
                                        let channel = u16::from_be_bytes([buf[0], buf[1]]);
                                        let payload = buf[4..4 + len].to_vec();
                                        buf.drain(..total);

                                        let other = {
                                            let guard = peers_loop.lock();
                                            let destination = guard.iter().find(|p| p.id == client_id).and_then(|p| p.channels.get(&channel));
                                            guard.iter().find(|p| Some(&p.relay_port) == destination).map(|p| {
                                                (p.channels.iter().find_map(|(ch, port)| (*port == relay_port).then_some(*ch)), p.tx.clone())
                                            })
                                        };

                                        if let Some((other_bound, other_tx)) = other {
                                            if let Some(other_ch) = other_bound {
                                                let mut frame = Vec::with_capacity(4 + payload.len());
                                                frame.extend_from_slice(&other_ch.to_be_bytes());
                                                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                                                frame.extend_from_slice(&payload);
                                                frame.resize((frame.len() + 3) & !3, 0);
                                                let _ = other_tx.send(frame);
                                            } else {
                                                let mut attrs = attr_xor_addr(0x0012, relay_ip, relay_port);
                                                attrs.extend_from_slice(&attr_data(&payload));
                                                let tx_id = rand_tx_id();
                                                let frame = build_stun_response(0x0017, &tx_id, &attrs, None);
                                                let _ = other_tx.send(frame);
                                            }
                                        }
                                    } else if first_two_bits == 0b00 {
                                        // STUN / TURN message framing
                                        if buf.len() < 20 {
                                            break;
                                        }
                                        let attr_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                        let total = 20 + attr_len;
                                        if buf.len() < total {
                                            break;
                                        }
                                        let msg_bytes = &buf[..total];
                                        if let Some(msg) = parse_stun_message(msg_bytes) {
                                            buf.drain(..total);

                                            match msg.msg_type {
                                                // Allocate Request
                                                0x0003 => {
                                                    if !msg.has_message_integrity {
                                                        let mut attrs = attr_error_code(401, "Unauthorized");
                                                        attrs.extend_from_slice(&attr_string(0x0014, "camoufox"));
                                                        attrs.extend_from_slice(&attr_string(0x0015, "smoke-nonce"));
                                                        let resp = build_stun_response(0x0113, &msg.tx_id, &attrs, None);
                                                        let _ = tx.send(resp);
                                                    } else {
                                                        let key = md5(b"smoke:camoufox:password");
                                                        let mut attrs = attr_xor_addr(0x0016, relay_ip, relay_port);
                                                        attrs.extend_from_slice(&attr_xor_addr(0x0020, Ipv4Addr::new(203, 0, 113, 1), peer_addr.port()));
                                                        attrs.extend_from_slice(&attr_lifetime(600));
                                                        let resp = build_stun_response(0x0103, &msg.tx_id, &attrs, Some(&key));
                                                        let _ = tx.send(resp);
                                                    }
                                                }
                                                // CreatePermission Request
                                                0x0008 => {
                                                    let key = md5(b"smoke:camoufox:password");
                                                    let resp = build_stun_response(0x0108, &msg.tx_id, &[], Some(&key));
                                                    let _ = tx.send(resp);
                                                }
                                                // ChannelBind Request
                                                0x0009 => {
                                                    if let (Some(ch), Some(port)) = (msg.channel_number, msg.peer_port) {
                                                        let mut guard = peers_loop.lock();
                                                        for p in guard.iter_mut() {
                                                            if p.id == client_id {
                                                                p.channels.insert(ch, port);
                                                            }
                                                        }
                                                    }
                                                    let key = md5(b"smoke:camoufox:password");
                                                    let resp = build_stun_response(0x0109, &msg.tx_id, &[], Some(&key));
                                                    let _ = tx.send(resp);
                                                }
                                                // Refresh Request
                                                0x0004 => {
                                                    let key = md5(b"smoke:camoufox:password");
                                                    let attrs = attr_lifetime(msg.lifetime.unwrap_or(600));
                                                    let resp = build_stun_response(0x0104, &msg.tx_id, &attrs, Some(&key));
                                                    let _ = tx.send(resp);
                                                }
                                                // STUN Binding Request
                                                0x0001 => {
                                                    let key = md5(b"smoke:camoufox:password");
                                                    let attrs = attr_xor_addr(0x0020, Ipv4Addr::new(203, 0, 113, 1), peer_addr.port());
                                                    let resp = build_stun_response(0x0101, &msg.tx_id, &attrs, Some(&key));
                                                    let _ = tx.send(resp);
                                                }
                                                // SendIndication
                                                0x0016 => {
                                                    if let Some(payload) = msg.data {
                                                        let other = {
                                                            let guard = peers_loop.lock();
                                                            guard.iter().find(|p| Some(p.relay_port) == msg.peer_port).map(|p| {
                                                                (p.channels.iter().find_map(|(ch, port)| (*port == relay_port).then_some(*ch)), p.tx.clone())
                                                            })
                                                        };
                                                        if let Some((other_bound, other_tx)) = other {
                                                            if let Some(other_ch) = other_bound {
                                                                let mut frame = Vec::with_capacity(4 + payload.len());
                                                                frame.extend_from_slice(&other_ch.to_be_bytes());
                                                                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                                                                frame.extend_from_slice(&payload);
                                                                frame.resize((frame.len() + 3) & !3, 0);
                                                                let _ = other_tx.send(frame);
                                                            } else {
                                                                let mut attrs = attr_xor_addr(0x0012, relay_ip, relay_port);
                                                                attrs.extend_from_slice(&attr_data(&payload));
                                                                let tx_id = rand_tx_id();
                                                                let frame = build_stun_response(0x0017, &tx_id, &attrs, None);
                                                                let _ = other_tx.send(frame);
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        } else {
                                            buf.drain(..total);
                                        }
                                    } else {
                                        buf.remove(0);
                                    }
                                }
                            }
                            peers_loop.lock().retain(|peer| peer.id != client_id);
                            drop(tx);
                            let _ = writer.join();
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }

            for t in client_threads {
                let _ = t.join();
            }
        });

        Ok(Self {
            port,
            shutdown,
            direct_connections,
            worker: Some(worker),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn connection_count(&self) -> usize {
        self.direct_connections.load(Ordering::SeqCst)
    }
}

impl Drop for TurnTcpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

// ============================================================================
// Instrumented Local HTTP CONNECT Proxy
// ============================================================================

pub struct InstrumentedProxy {
    port: u16,
    shutdown: Arc<AtomicBool>,
    pub connect_targets: Arc<Mutex<Vec<String>>>,
    pub current_ip: Arc<Mutex<String>>,
    pub simulate_failure: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl InstrumentedProxy {
    pub fn start(turn_port: u16, turn_target: String) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let connect_targets = Arc::new(Mutex::new(Vec::new()));
        let current_ip = Arc::new(Mutex::new("203.0.113.11".to_owned()));
        let simulate_failure = Arc::new(AtomicBool::new(false));

        let stop = shutdown.clone();
        let targets = connect_targets.clone();
        let ip = current_ip.clone();
        let fail = simulate_failure.clone();

        let worker = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let mut clients = Vec::new();

            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let targets = targets.clone();
                        let ip = ip.clone();
                        let fail = fail.clone();
                        let turn_target = turn_target.clone();
                        let stop_client = stop.clone();

                        clients.push(std::thread::spawn(move || {
                            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                            stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();

                            let mut head = Vec::new();
                            let mut byte = [0u8; 1];
                            while !head.ends_with(b"\r\n\r\n") {
                                if head.len() >= 16384 || stream.read_exact(&mut byte).is_err() {
                                    return;
                                }
                                head.push(byte[0]);
                            }

                            let head_str = String::from_utf8_lossy(&head);
                            let authorized = head_str.lines().any(|l| {
                                l.eq_ignore_ascii_case("Proxy-Authorization: Basic YXVkaXQ6bG9jYWw=")
                            });

                            if !authorized {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"smoke\"\r\nContent-Length: 0\r\n\r\n"
                                );
                                return;
                            }

                            if fail.load(Ordering::SeqCst) {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                return;
                            }

                            let first_line = head_str.lines().next().unwrap_or("");
                            if first_line.starts_with("CONNECT ") {
                                let target = first_line.split_whitespace().nth(1).unwrap_or("").to_owned();
                                targets.lock().push(target.clone());
                                if target != turn_target {
                                    let _ = write!(stream, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                                    return;
                                }

                                let _ = write!(stream, "HTTP/1.1 200 Connection Established\r\n\r\n");
                                let _ = stream.flush();

                                // Tunnel to local TURN TCP server
                                if let Ok(mut turn_stream) = TcpStream::connect(("127.0.0.1", turn_port)) {
                                    stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
                                    turn_stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
                                    let mut client_read = stream.try_clone().unwrap();
                                    let mut turn_write = turn_stream.try_clone().unwrap();
                                    let stop_pipe = stop_client.clone();
                                    let fail_pipe = fail.clone();

                                    let t1 = std::thread::spawn(move || {
                                        let mut buf = [0u8; 8192];
                                        while !stop_pipe.load(Ordering::SeqCst) && !fail_pipe.load(Ordering::SeqCst) {
                                            match client_read.read(&mut buf) {
                                                Ok(0) => break,
                                                Ok(n) => {
                                                    if turn_write.write_all(&buf[..n]).is_err() {
                                                        break;
                                                    }
                                                }
                                                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                                                Err(_) => break,
                                            }
                                        }
                                        let _ = turn_write.shutdown(std::net::Shutdown::Both);
                                    });

                                    let mut buf = [0u8; 8192];
                                    while !stop_client.load(Ordering::SeqCst) && !fail.load(Ordering::SeqCst) {
                                        match turn_stream.read(&mut buf) {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                if stream.write_all(&buf[..n]).is_err() {
                                                    break;
                                                }
                                            }
                                            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                                            Err(_) => break,
                                        }
                                    }
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                    let _ = t1.join();
                                }
                            } else if first_line.starts_with("GET http://localhost/probe ") {
                                let body = "<!doctype html><title>WebRTC Probe</title><body>WebRTC Probe Frame</body>";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                            } else {
                                let body = json!({"ip": *ip.lock()}).to_string();
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }

            for c in clients {
                let _ = c.join();
            }
        });

        Ok(Self {
            port,
            shutdown,
            connect_targets,
            current_ip,
            simulate_failure,
            worker: Some(worker),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for InstrumentedProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

// ============================================================================
// Native WebRTC Smoke Test
// ============================================================================

/// Real SCTP/DTLS roundtrip through TURN TCP, with direct-network tripwires.
#[test]
#[ignore]
fn smoke_real_browser_webrtc_turn_tcp_proxy_relay() {
    let exe = PathBuf::from(std::env::var("CAMOUFOX_SMOKE_EXE").expect("CAMOUFOX_SMOKE_EXE required"));
    assert!(exe.is_file());
    assert_eq!(hex::encode(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    let route = UdpSocket::bind("0.0.0.0:0").unwrap();
    route.connect("192.0.2.1:9").unwrap();
    let nic = route.local_addr().unwrap().ip();
    assert!(!nic.is_loopback());
    let udp = UdpSocket::bind((nic, 0)).unwrap();
    udp.set_nonblocking(true).unwrap();
    let tcp = TcpListener::bind((nic, 0)).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let udp_address = udp.local_addr().unwrap();
    let turn_address = tcp.local_addr().unwrap();
    let turn = TurnTcpServer::start().unwrap();
    let proxy = InstrumentedProxy::start(turn.port(), turn_address.to_string()).unwrap();
    let home = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(home.path()).unwrap());
    let mut network = Network::new(store.clone());
    network.egress_url = Some("http://egress.invalid/".into());
    let network = Arc::new(network);
    let fingerprints = Arc::new(FingerprintService::new(store.clone()).unwrap());
    let runtime = Arc::new(Runtime::new(store.clone(), network.clone(), fingerprints.clone()));
    let profiles = crate::profiles::Profiles::new(store.clone(), runtime.clone(), network.clone(), fingerprints);
    store.put("versions", json!({"id": "v156.0.1-beta.37", "path": browser_path_string(&exe), "status": "installed"})).unwrap();
    let saved_proxy = store.put("proxies", json!({"name": "TURN smoke", "server": format!("http://127.0.0.1:{}", proxy.port()),
        "username": "audit", "password": "local", "enabled": true})).unwrap();
    let mut profile = profiles.create(json!({"name": "TURN relay smoke", "os": "windows", "browser_version": "v156.0.1-beta.37",
        "proxy_id": saved_proxy["id"], "location": {"locked": true, "ip": "203.0.113.11", "timezone": "UTC", "locale": "en-US"},
        "startup_urls": ["http://localhost/probe"], "fingerprint_meta": {"use_preset": true}})).unwrap();
    // Give fake capture matching descriptors; random presets may advertise no camera/microphone.
    profile["fingerprint"]["mediaDevices:enabled"] = json!(true);
    profile["fingerprint"]["mediaDevices:micros"] = json!(1);
    profile["fingerprint"]["mediaDevices:webcams"] = json!(1);
    profile["fingerprint"]["mediaDevices:speakers"] = json!(1);
    profile["fingerprint"]["mediaDevices:microphoneLabels"] = json!(["Fake microphone"]);
    profile["fingerprint"]["mediaDevices:microphoneGroups"] = json!(["fake-capture"]);
    profile["fingerprint"]["mediaDevices:webcamLabels"] = json!(["Fake camera"]);
    profile["fingerprint"]["mediaDevices:webcamGroups"] = json!(["fake-capture"]);
    profile["fingerprint"]["mediaDevices:speakerLabels"] = json!(["Fake output"]);
    profile["fingerprint"]["mediaDevices:speakerGroups"] = json!(["fake-output"]);
    let profile = store.put("profiles", profile).unwrap();
    let id = string(&profile, "id");
    // Fake capture and consent are test-only; production retains normal microphone permissions.
    fs::write(store.profile_dir(id).unwrap().join("browser/user.js"), r#"
user_pref("media.navigator.permission.disabled", true);
user_pref("media.navigator.streams.fake", true);
user_pref("media.peerconnection.ice.proxy_only", false);
user_pref("media.peerconnection.ice.relay_only", false);
user_pref("network.proxy.allow_hijacking_localhost", true);
user_pref("browser.startup.homepage", "about:blank");
"#).unwrap();
    let evaluate = |script: &str| runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json(script).unwrap();
    let relay_script = format!(r#"(() => {{
      globalThis.__relayResult = null;
      globalThis.__relayPeers?.forEach(pc => pc.close());
      globalThis.__capture?.getTracks().forEach(track => track.stop());
      (async () => {{
        try {{
          globalThis.__capture = await navigator.mediaDevices.getUserMedia({{audio:true,video:true}});
          const config = {{iceServers:[{{urls:['stun:{udp_address}', 'turn:{turn_address}?transport=tcp'],username:'smoke',credential:'password'}}]}};
          const a = new RTCPeerConnection(config), b = new RTCPeerConnection(config);
          globalThis.__relayPeers = [a,b];
          for(const track of globalThis.__capture.getTracks()) {{ a.addTrack(track, globalThis.__capture); b.addTrack(track, globalThis.__capture); }}
          globalThis.__relayErrors = [];
          for(const pc of [a,b]) pc.onicecandidateerror = e => globalThis.__relayErrors.push({{code:e.errorCode,text:e.errorText,url:e.url}});
          const qa=[], qb=[], candidates=[];
          function fail(e) {{ globalThis.__relayResult = {{success:false,error:String(e)}}; }}
          a.onicecandidate = e => {{ if(e.candidate?.candidate) {{ candidates.push(e.candidate.candidate); if(b.remoteDescription) b.addIceCandidate(e.candidate).catch(fail); else qb.push(e.candidate); }} }};
          b.onicecandidate = e => {{ if(e.candidate?.candidate) {{ candidates.push(e.candidate.candidate); if(a.remoteDescription) a.addIceCandidate(e.candidate).catch(fail); else qa.push(e.candidate); }} }};
          const channel = a.createDataChannel('relay-smoke');
          globalThis.__relayChannel = channel;
          b.ondatachannel = e => {{ e.channel.onmessage = message => e.channel.send('reply:'+message.data); }};
          channel.onopen = () => channel.send('proxy-only-roundtrip');
          channel.onmessage = async message => {{
            await new Promise(resolve => setTimeout(resolve,1000));
            const stats=[...(await b.getStats()).values()];
            const audio=stats.some(s=>s.type==='inbound-rtp' && s.kind==='audio' && s.packetsReceived>0);
            const video=stats.some(s=>s.type==='inbound-rtp' && s.kind==='video' && s.packetsReceived>0);
            globalThis.__relayResult = {{success:message.data==='reply:proxy-only-roundtrip' && audio && video,data:message.data,audio,video,candidates}};
          }};
          await a.setLocalDescription(await a.createOffer());
          await b.setRemoteDescription(a.localDescription);
          for(const candidate of qb) await b.addIceCandidate(candidate);
          await b.setLocalDescription(await b.createAnswer());
          await a.setRemoteDescription(b.localDescription);
          for(const candidate of qa) await a.addIceCandidate(candidate);
        }} catch(e) {{ globalThis.__relayResult = {{success:false,error:String(e)}}; }}
      }})();
      return JSON.stringify(true);
    }})()"#);
    let connect = |restart: bool| {
        if restart { evaluate(&relay_script); }
        else { evaluate("(() => { globalThis.__relayResult=null; globalThis.__relayChannel.send('proxy-only-roundtrip'); return JSON.stringify(true); })()"); }
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let result = evaluate("JSON.stringify(globalThis.__relayResult)");
            if !result.is_null() {
                assert_eq!(result["success"], true, "Relay failed: {result}; CONNECT: {:?}", proxy.connect_targets.lock());
                assert_eq!(result["data"], "reply:proxy-only-roundtrip");
                let candidates = result["candidates"].as_array().unwrap();
                assert!(candidates.iter().any(|c| c.as_str().unwrap().contains(" typ relay")), "{result}");
                assert!(candidates.iter().all(|c| c.as_str().unwrap().contains(" typ relay")), "Non-relay ICE candidate: {result}");
                break;
            }
            assert!(Instant::now() < deadline, "No TURN roundtrip; CONNECT: {:?}; state: {}; errors: {}; stderr: {}", proxy.connect_targets.lock(),
                evaluate("JSON.stringify(globalThis.__relayPeers.map(p=>({ice:p.iceConnectionState,gather:p.iceGatheringState,sdp:p.localDescription?.sdp})))"),
                evaluate("JSON.stringify(globalThis.__relayErrors)"), runtime.sessions.lock().get(id).unwrap().stderr_tail.lock().as_str());
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(proxy.connect_targets.lock().iter().any(|t| t == &turn_address.to_string()));
        assert!(turn.connection_count() >= 2);
    };
    let no_leaks = || {
        assert_eq!(udp.recv_from(&mut [0;2048]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock, "Direct UDP escaped");
        assert_eq!(tcp.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock, "Direct TURN TCP escaped");
    };
    runtime.launch(id, true).unwrap();
    runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().navigate_for_test("http://localhost/probe").unwrap();
    connect(true);
    no_leaks();
    println!("PASS real TURN TCP datachannel roundtrip and audio/video RTP through authenticated proxy; relay-only ICE, zero direct UDP/TCP");
    let pid = runtime.status().unwrap()[id]["pid"].clone();
    evaluate("(() => { const draft=document.createElement('input'); draft.id='recovery-draft'; draft.value='unsaved form content'; document.body.append(draft); return JSON.stringify(true); })()");
    *proxy.current_ip.lock() = "203.0.113.99".to_owned();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let status = runtime.status().unwrap();
        assert_eq!(status[id]["state"], "running", "{status}");
        assert_eq!(status[id]["pid"], pid, "IP rotation must not restart the browser: {status}");
        no_leaks();
        if status[id]["egress_ip"] == "203.0.113.99" { break; }
        assert!(Instant::now() < deadline, "Rotating IP was not updated: {status}");
        std::thread::sleep(Duration::from_millis(100));
    }
    no_leaks();
    connect(false);
    println!("PASS IP rotation preserves browser PID and active WebRTC roundtrip without direct fallback");
    proxy.simulate_failure.store(true, Ordering::SeqCst);
    evaluate(&relay_script);
    let deadline = Instant::now() + Duration::from_secs(55);
    loop {
        let status = runtime.status().unwrap();
        no_leaks();
        assert_eq!(status[id]["state"], "running", "{status}");
        assert_eq!(status[id]["pid"], pid, "Proxy outage must not restart the browser: {status}");
        if Instant::now() >= deadline {
            assert!(!status[id]["error"].as_str().unwrap().is_empty(), "Proxy failure must remain visible: {status}");
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(evaluate("JSON.stringify(document.getElementById('recovery-draft').value)"), "unsaved form content");
    println!("PASS 55-second proxy outage preserves browser and unsaved form, reports error and blocks direct UDP/TCP");
    *proxy.current_ip.lock() = "203.0.113.100".to_owned();
    proxy.simulate_failure.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let status = runtime.status().unwrap();
        assert_eq!(status[id]["state"], "running", "{status}");
        assert_eq!(status[id]["pid"], pid, "{status}");
        if status[id]["egress_ip"] == "203.0.113.100" && status[id]["error"] == "" { break; }
        assert!(Instant::now() < deadline, "Monitor did not recover: {status}");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(evaluate("(async () => JSON.stringify(await (await fetch('/probe?recovered', {cache:'no-store'})).json()))()" )["ip"], "203.0.113.100");
    connect(true);
    no_leaks();
    assert_eq!(evaluate("JSON.stringify(document.getElementById('recovery-draft').value)"), "unsaved form content");
    println!("PASS same tab resumes HTTP, fresh TURN datachannel and audio/video after proxy recovery, no direct fallback");
    runtime.stop(id).unwrap();
    profiles.update(id, json!({"proxy_id":"", "startup_urls":["about:blank"]})).unwrap();
    runtime.launch(id, true).unwrap();
    runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().navigate_for_test("about:blank").unwrap();
    evaluate(&format!(r#"(() => {{ const pc=new RTCPeerConnection({{iceServers:[{{urls:'stun:{udp_address}'}}]}}); globalThis.__directProbe=pc; pc.createDataChannel('direct'); pc.createOffer().then(o=>pc.setLocalDescription(o)); return JSON.stringify(true); }})()"#));
    udp.set_nonblocking(false).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut packet=[0;2048];
    let (length, _) = udp.recv_from(&mut packet).expect("Direct WebRTC did not reach STUN tripwire");
    assert!(length>=20);
    assert_eq!(&packet[4..8], &[0x21,0x12,0xa4,0x42]);
    runtime.stop(id).unwrap();
    println!("PASS direct transition restores STUN UDP positive control");
}
