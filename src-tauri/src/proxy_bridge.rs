use anyhow::{anyhow, bail, Result};
use base64::Engine;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Http,
    Https,
    Socks5,
}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub upstream_protocol: UpstreamProtocol,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    #[cfg(test)]
    pub root_store: Option<Arc<rustls::RootCertStore>>,
}

pub struct ProxyBridge {
    port: u16,
    shutdown: Arc<AtomicBool>,
    active_sockets: Arc<Mutex<HashMap<u64, (TcpStream, Option<TcpStream>)>>>,
    listener_thread: Option<JoinHandle<()>>,
}

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

impl ProxyBridge {
    pub fn start(config: BridgeConfig) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_sockets = Arc::new(Mutex::new(HashMap::new()));

        let shutdown_loop = Arc::clone(&shutdown);
        let active_loop = Arc::clone(&active_sockets);
        let config_loop = config.clone();

        let listener_thread = std::thread::Builder::new()
            .name("proxy-bridge-listener".into())
            .spawn(move || {
                Self::accept_loop(listener, config_loop, shutdown_loop, active_loop);
            })?;

        Ok(Self {
            port,
            shutdown,
            active_sockets,
            listener_thread: Some(listener_thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn stop(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }

        // Interrupt all in-flight connections
        let mut conns = self.active_sockets.lock();
        for (_, (client, remote)) in conns.drain() {
            let _ = client.shutdown(Shutdown::Both);
            if let Some(r) = remote {
                let _ = r.shutdown(Shutdown::Both);
            }
        }
        drop(conns);

        // Unblock accept loop by connecting once to loopback listener
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }

    fn accept_loop(
        listener: TcpListener,
        config: BridgeConfig,
        shutdown: Arc<AtomicBool>,
        active_sockets: Arc<Mutex<HashMap<u64, (TcpStream, Option<TcpStream>)>>>,
    ) {
        while !shutdown.load(Ordering::SeqCst) {
            let (client, _) = match listener.accept() {
                Ok(conn) => conn,
                Err(_) => break,
            };

            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
            let client_clone = match client.try_clone() {
                Ok(c) => c,
                Err(_) => continue,
            };

            active_sockets.lock().insert(conn_id, (client_clone, None));

            let shutdown_client = Arc::clone(&shutdown);
            let active_client = Arc::clone(&active_sockets);
            let config_client = config.clone();

            std::thread::Builder::new()
                .name(format!("proxy-bridge-worker-{}", conn_id))
                .spawn(move || {
                    let _ = Self::handle_client(
                        conn_id,
                        client,
                        config_client,
                        shutdown_client,
                        Arc::clone(&active_client),
                    );
                    active_client.lock().remove(&conn_id);
                })
                .ok();
        }
    }

    fn handle_client(
        conn_id: u64,
        mut client: TcpStream,
        config: BridgeConfig,
        shutdown: Arc<AtomicBool>,
        active_sockets: Arc<Mutex<HashMap<u64, (TcpStream, Option<TcpStream>)>>>,
    ) -> Result<()> {
        let timeout = Duration::from_secs(25);
        client.set_read_timeout(Some(timeout))?;
        client.set_write_timeout(Some(timeout))?;
        #[cfg(test)]
        let root_store = config.root_store.clone();
        #[cfg(not(test))]
        let root_store = None;

        let (head, initial_body) = Self::read_http_head(&mut client)?;
        let head_str = String::from_utf8_lossy(&head);
        let first_line = head_str.lines().next().unwrap_or("").trim();
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        if method.is_empty() || target.is_empty() {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return Ok(());
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            let (target_host, target_port) = Self::parse_host_port(target, 443);
            match config.upstream_protocol {
                UpstreamProtocol::Socks5 => {
                    let mut remote_stream = match Self::socks5_connect(
                        &config.upstream_host,
                        config.upstream_port,
                        config.username.as_deref(),
                        config.password.as_deref(),
                        &target_host,
                        target_port,
                        timeout,
                    ) {
                        Ok(r) => r,
                        Err(err) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(err);
                        }
                    };

                    if let Ok(remote_clone) = remote_stream.try_clone() {
                        if let Some(entry) = active_sockets.lock().get_mut(&conn_id) {
                            entry.1 = Some(remote_clone);
                        }
                    }

                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    if !initial_body.is_empty() {
                        remote_stream.write_all(&initial_body)?;
                    }
                    Self::pipe_bidirectional(client, remote_stream, shutdown);
                }
                UpstreamProtocol::Http => {
                    let mut remote_stream = match Self::http_connect(
                        &config.upstream_host,
                        config.upstream_port,
                        config.username.as_deref(),
                        config.password.as_deref(),
                        &target_host,
                        target_port,
                        timeout,
                    ) {
                        Ok(r) => r,
                        Err(err) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(err);
                        }
                    };

                    if let Ok(remote_clone) = remote_stream.try_clone() {
                        if let Some(entry) = active_sockets.lock().get_mut(&conn_id) {
                            entry.1 = Some(remote_clone);
                        }
                    }

                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    if !initial_body.is_empty() {
                        remote_stream.write_all(&initial_body)?;
                    }
                    Self::pipe_bidirectional(client, remote_stream, shutdown);
                }
                UpstreamProtocol::Https => {
                    let mut tls_stream = match Self::https_connect(
                        &config.upstream_host,
                        config.upstream_port,
                        config.username.as_deref(),
                        config.password.as_deref(),
                        &target_host,
                        target_port,
                        timeout,
                        root_store.clone(),
                    ) {
                        Ok(s) => s,
                        Err(err) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(err);
                        }
                    };

                    if !initial_body.is_empty() {
                        tls_stream.write_all(&initial_body)?;
                        let _ = tls_stream.flush();
                    }

                    let (conn, remote_tcp) = tls_stream.into_parts();
                    if let Ok(remote_clone) = remote_tcp.try_clone() {
                        if let Some(entry) = active_sockets.lock().get_mut(&conn_id) {
                            entry.1 = Some(remote_clone);
                        }
                    }

                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    Self::pipe_bidirectional_tls(client, conn, remote_tcp, shutdown);
                }
            }
        } else {
            // Plain HTTP request forwarding
            let (target_host, target_port) = Self::resolve_plain_http_target(target, &head_str)?;
            let modified_head = Self::prepare_plain_http_head(
                &head,
                config.upstream_protocol,
                config.username.as_deref(),
                config.password.as_deref(),
            );
            match config.upstream_protocol {
                UpstreamProtocol::Socks5 => {
                    let mut remote_stream = match Self::socks5_connect(
                        &config.upstream_host,
                        config.upstream_port,
                        config.username.as_deref(),
                        config.password.as_deref(),
                        &target_host,
                        target_port,
                        timeout,
                    ) {
                        Ok(r) => r,
                        Err(err) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(err);
                        }
                    };

                    if let Ok(remote_clone) = remote_stream.try_clone() {
                        if let Some(entry) = active_sockets.lock().get_mut(&conn_id) {
                            entry.1 = Some(remote_clone);
                        }
                    }

                    remote_stream.write_all(&modified_head)?;
                    if !initial_body.is_empty() {
                        remote_stream.write_all(&initial_body)?;
                    }

                    Self::pipe_bidirectional(client, remote_stream, shutdown);
                }
                UpstreamProtocol::Http => {
                    let addrs: Vec<SocketAddr> = match ToSocketAddrs::to_socket_addrs(&(config.upstream_host.as_str(), config.upstream_port)) {
                        Ok(a) => a.collect(),
                        Err(e) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(e.into());
                        }
                    };
                    if addrs.is_empty() {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                        bail!("Failed to resolve upstream HTTP proxy host");
                    }
                    let mut remote_stream = match TcpStream::connect_timeout(&addrs[0], timeout) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(e.into());
                        }
                    };
                    remote_stream.set_read_timeout(Some(timeout))?;
                    remote_stream.set_write_timeout(Some(timeout))?;

                    if let Ok(remote_clone) = remote_stream.try_clone() {
                        if let Some(entry) = active_sockets.lock().get_mut(&conn_id) {
                            entry.1 = Some(remote_clone);
                        }
                    }

                    remote_stream.write_all(&modified_head)?;
                    if !initial_body.is_empty() {
                        remote_stream.write_all(&initial_body)?;
                    }

                    Self::pipe_bidirectional(client, remote_stream, shutdown);
                }
                UpstreamProtocol::Https => {
                    let mut tls_stream = match Self::https_tls_connect(
                        &config.upstream_host,
                        config.upstream_port,
                        timeout,
                        root_store.clone(),
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return Err(e);
                        }
                    };

                    tls_stream.write_all(&modified_head)?;
                    if !initial_body.is_empty() {
                        tls_stream.write_all(&initial_body)?;
                    }
                    let _ = tls_stream.flush();

                    let (conn, remote_tcp) = tls_stream.into_parts();
                    if let Ok(remote_clone) = remote_tcp.try_clone() {
                        if let Some(entry) = active_sockets.lock().get_mut(&conn_id) {
                            entry.1 = Some(remote_clone);
                        }
                    }

                    Self::pipe_bidirectional_tls(client, conn, remote_tcp, shutdown);
                }
            }
        }

        Ok(())
    }

    fn read_http_head<R: Read>(reader: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 1024];
        loop {
            let n = reader.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let body = buf.split_off(pos + 4);
                return Ok((buf, body));
            }
            if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
                let body = buf.split_off(pos + 2);
                return Ok((buf, body));
            }
            if buf.len() > 65536 {
                bail!("HTTP request header exceeded 64KB");
            }
        }
        if buf.is_empty() {
            bail!("Connection closed without request data");
        }
        Ok((buf, Vec::new()))
    }

    pub fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
        let trimmed = target.trim();
        if trimmed.starts_with('[') {
            if let Some(end) = trimmed.find(']') {
                let host = &trimmed[1..end];
                let rest = &trimmed[end + 1..];
                if let Some(colon) = rest.find(':') {
                    if let Ok(p) = rest[colon + 1..].parse::<u16>() {
                        return (host.to_string(), p);
                    }
                }
                return (host.to_string(), default_port);
            }
        }
        if let Some(colon) = trimmed.rfind(':') {
            let host = &trimmed[..colon];
            let port_str = &trimmed[colon + 1..];
            if let Ok(p) = port_str.parse::<u16>() {
                return (host.to_string(), p);
            }
        }
        (trimmed.to_string(), default_port)
    }

    fn resolve_plain_http_target(target: &str, headers: &str) -> Result<(String, u16)> {
        if target.starts_with("http://") || target.starts_with("https://") {
            if let Ok(url) = url::Url::parse(target) {
                let raw_host = url.host_str().unwrap_or("");
                let host = raw_host
                    .strip_prefix('[')
                    .and_then(|h| h.strip_suffix(']'))
                    .unwrap_or(raw_host);
                let port = url.port_or_known_default().unwrap_or(80);
                if !host.is_empty() {
                    return Ok((host.to_string(), port));
                }
            }
        }

        // Inspect Host header
        for line in headers.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("host:") {
                let val = line[5..].trim();
                let (h, p) = Self::parse_host_port(val, 80);
                if !h.is_empty() {
                    return Ok((h, p));
                }
            }
        }

        bail!("Could not resolve target host from HTTP request")
    }

    fn socks5_connect(
        upstream_host: &str,
        upstream_port: u16,
        username: Option<&str>,
        password: Option<&str>,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream> {
        let addrs: Vec<SocketAddr> =
            ToSocketAddrs::to_socket_addrs(&(upstream_host, upstream_port))?.collect();
        if addrs.is_empty() {
            bail!("Failed to resolve upstream SOCKS5 host: {}", upstream_host);
        }
        let mut stream = TcpStream::connect_timeout(&addrs[0], timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // 1. Client greeting
        let has_auth = username.is_some() || password.is_some();
        let greeting = if has_auth {
            vec![0x05, 0x02, 0x00, 0x02] // NO AUTH (0x00), USER/PASS (0x02)
        } else {
            vec![0x05, 0x01, 0x00] // NO AUTH (0x00)
        };
        stream.write_all(&greeting)?;

        // 2. Server method response
        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp)?;
        if method_resp[0] != 0x05 {
            bail!("Invalid SOCKS5 greeting version: {}", method_resp[0]);
        }

        match method_resp[1] {
            0x00 => {
                // No authentication required
            }
            0x02 => {
                // Username/password auth (RFC 1929)
                let u = username.unwrap_or("");
                let p = password.unwrap_or("");
                let u_bytes = u.as_bytes();
                let p_bytes = p.as_bytes();
                if u_bytes.len() > 255 || p_bytes.len() > 255 {
                    bail!("SOCKS5 username or password exceeds 255 bytes");
                }
                let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
                auth_req.push(0x01); // RFC 1929 version 1
                auth_req.push(u_bytes.len() as u8);
                auth_req.extend_from_slice(u_bytes);
                auth_req.push(p_bytes.len() as u8);
                auth_req.extend_from_slice(p_bytes);
                stream.write_all(&auth_req)?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp)?;
                if auth_resp[1] != 0x00 {
                    bail!("SOCKS5 authentication failed (status: {})", auth_resp[1]);
                }
            }
            0xFF => bail!("SOCKS5 server rejected all authentication methods (0xFF)"),
            other => bail!("Unsupported SOCKS5 auth method: {}", other),
        }

        // 3. Send CONNECT command
        let mut cmd = vec![0x05, 0x01, 0x00];
        if let Ok(ipv4) = target_host.parse::<std::net::Ipv4Addr>() {
            cmd.push(0x01);
            cmd.extend_from_slice(&ipv4.octets());
        } else if let Ok(ipv6) = target_host.parse::<std::net::Ipv6Addr>() {
            cmd.push(0x04);
            cmd.extend_from_slice(&ipv6.octets());
        } else {
            let domain_bytes = target_host.as_bytes();
            if domain_bytes.len() > 255 {
                bail!("Target domain name exceeds 255 bytes: {}", target_host);
            }
            cmd.push(0x03);
            cmd.push(domain_bytes.len() as u8);
            cmd.extend_from_slice(domain_bytes);
        }
        cmd.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&cmd)?;

        // 4. Read CONNECT reply
        let mut reply_hdr = [0u8; 4];
        stream.read_exact(&mut reply_hdr)?;
        if reply_hdr[0] != 0x05 {
            bail!("Invalid SOCKS5 reply version: {}", reply_hdr[0]);
        }
        if reply_hdr[1] != 0x00 {
            bail!("SOCKS5 CONNECT failed with code: {}", reply_hdr[1]);
        }

        match reply_hdr[3] {
            0x01 => {
                let mut bnd = [0u8; 6];
                stream.read_exact(&mut bnd)?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                let mut bnd = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut bnd)?;
            }
            0x04 => {
                let mut bnd = [0u8; 18];
                stream.read_exact(&mut bnd)?;
            }
            other => bail!("Unknown address type in SOCKS5 reply: {}", other),
        }

        Ok(stream)
    }

    fn http_connect(
        upstream_host: &str,
        upstream_port: u16,
        username: Option<&str>,
        password: Option<&str>,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream> {
        let addrs: Vec<SocketAddr> =
            ToSocketAddrs::to_socket_addrs(&(upstream_host, upstream_port))?.collect();
        if addrs.is_empty() {
            bail!("Failed to resolve upstream HTTP proxy host: {}", upstream_host);
        }
        let mut stream = TcpStream::connect_timeout(&addrs[0], timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let target_authority = crate::network::format_host_port(target_host, target_port);
        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
            target_authority, target_authority
        );
        if username.is_some() || password.is_some() {
            let cred = format!("{}:{}", username.unwrap_or(""), password.unwrap_or(""));
            let b64 = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes())?;

        let (head, _) = Self::read_http_head(&mut stream)?;
        let head_str = String::from_utf8_lossy(&head);
        let first_line = head_str.lines().next().unwrap_or("").trim();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("Invalid response from upstream HTTP proxy: {}", first_line);
        }
        let code: u16 = parts[1].parse().unwrap_or(0);
        if !(200..=299).contains(&code) {
            bail!("Upstream HTTP proxy rejected CONNECT: {}", first_line);
        }

        Ok(stream)
    }

    fn prepare_plain_http_head(
        raw_head: &[u8],
        protocol: UpstreamProtocol,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Vec<u8> {
        let head_str = String::from_utf8_lossy(raw_head);
        let mut lines = head_str.lines();
        let request_line = lines.next().unwrap_or("").trim_end();
        let mut out = String::with_capacity(raw_head.len() + 128);
        out.push_str(request_line);
        out.push_str("\r\n");

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(colon) = trimmed.find(':') {
                let name = trimmed[..colon].trim().to_ascii_lowercase();
                if name == "connection"
                    || name == "proxy-connection"
                    || name == "keep-alive"
                    || name == "proxy-authorization"
                {
                    continue;
                }
            }
            out.push_str(trimmed);
            out.push_str("\r\n");
        }

        out.push_str("Connection: close\r\n");
        out.push_str("Proxy-Connection: close\r\n");

        if protocol != UpstreamProtocol::Socks5 && (username.is_some() || password.is_some()) {
            let cred = format!("{}:{}", username.unwrap_or(""), password.unwrap_or(""));
            let b64 = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
            out.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
        }

        out.push_str("\r\n");
        out.into_bytes()
    }

    fn pipe_bidirectional(
        client: TcpStream,
        remote: TcpStream,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut client_r = match client.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client_w = client;
        let mut remote_r = match remote.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut remote_w = remote;

        let s1 = Arc::clone(&shutdown);
        let t1 = std::thread::spawn(move || {
            let mut buf = [0u8; 32768];
            while !s1.load(Ordering::Relaxed) {
                match client_r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if remote_w.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = remote_w.shutdown(Shutdown::Write);
        });

        let s2 = Arc::clone(&shutdown);
        let t2 = std::thread::spawn(move || {
            let mut buf = [0u8; 32768];
            while !s2.load(Ordering::Relaxed) {
                match remote_r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if client_w.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = client_w.shutdown(Shutdown::Write);
        });

        let _ = t1.join();
        let _ = t2.join();
    }

    fn build_tls_client_config(
        root_store: Option<Arc<rustls::RootCertStore>>,
    ) -> Result<Arc<rustls::ClientConfig>> {
        let roots = match root_store {
            Some(r) => r,
            None => {
                let mut r = rustls::RootCertStore::empty();
                r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(r)
            }
        };

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("Failed to configure TLS protocol versions: {}", e))?
        .with_root_certificates(roots)
        .with_no_client_auth();

        Ok(Arc::new(config))
    }

    fn https_tls_connect(
        upstream_host: &str,
        upstream_port: u16,
        timeout: Duration,
        root_store: Option<Arc<rustls::RootCertStore>>,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
        let addrs: Vec<SocketAddr> =
            ToSocketAddrs::to_socket_addrs(&(upstream_host, upstream_port))?.collect();
        if addrs.is_empty() {
            bail!("Failed to resolve upstream HTTPS proxy host: {}", upstream_host);
        }
        let mut last_error = None;
        let tcp_stream = addrs.iter().find_map(|addr| match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => Some(stream),
            Err(error) => { last_error = Some(error); None }
        }).ok_or_else(|| anyhow!("Failed to connect to upstream HTTPS proxy: {}", last_error.unwrap()))?;
        tcp_stream.set_read_timeout(Some(timeout))?;
        tcp_stream.set_write_timeout(Some(timeout))?;

        let client_config = Self::build_tls_client_config(root_store)?;
        let trimmed_host = upstream_host.trim().trim_start_matches('[').trim_end_matches(']');
        let server_name = rustls::pki_types::ServerName::try_from(trimmed_host.to_string())
            .map_err(|e| anyhow!("Invalid server name '{}' for TLS: {}", upstream_host, e))?;

        let conn = rustls::ClientConnection::new(client_config, server_name)
            .map_err(|e| anyhow!("Failed to create TLS connection: {}", e))?;

        Ok(rustls::StreamOwned::new(conn, tcp_stream))
    }

    fn https_connect(
        upstream_host: &str,
        upstream_port: u16,
        username: Option<&str>,
        password: Option<&str>,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
        root_store: Option<Arc<rustls::RootCertStore>>,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
        let mut tls_stream = Self::https_tls_connect(upstream_host, upstream_port, timeout, root_store)?;

        let target_authority = crate::network::format_host_port(target_host, target_port);
        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
            target_authority, target_authority
        );
        if username.is_some() || password.is_some() {
            let cred = format!("{}:{}", username.unwrap_or(""), password.unwrap_or(""));
            let b64 = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
        }
        req.push_str("\r\n");

        tls_stream.write_all(req.as_bytes())?;
        tls_stream.flush()?;

        let (head, _) = Self::read_http_head(&mut tls_stream)?;
        let head_str = String::from_utf8_lossy(&head);
        let first_line = head_str.lines().next().unwrap_or("").trim();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("Invalid response from upstream HTTPS proxy: {}", first_line);
        }
        let code: u16 = parts[1].parse().unwrap_or(0);
        if !(200..=299).contains(&code) {
            bail!("Upstream HTTPS proxy rejected CONNECT: {}", first_line);
        }

        Ok(tls_stream)
    }

    fn drain_plaintext_to_client(
        conn: &Arc<Mutex<rustls::ClientConnection>>,
        client_w: &mut TcpStream,
        buf: &mut [u8],
    ) -> Result<()> {
        loop {
            let (n, has_more) = {
                let mut guard = conn.lock();
                let mut reader = guard.reader();
                match reader.read(buf) {
                    Ok(0) => (0, false),
                    Ok(n) => (n, true),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, false),
                    Err(e) => return Err(e.into()),
                }
            };
            if n > 0 {
                client_w.write_all(&buf[..n])?;
            }
            if !has_more {
                break;
            }
        }
        let _ = client_w.flush();
        Ok(())
    }

    fn pipe_bidirectional_tls(
        client: TcpStream,
        conn: rustls::ClientConnection,
        remote_tcp: TcpStream,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut client_r = match client.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client_w = client;

        let conn_arc = Arc::new(Mutex::new(conn));

        let mut remote_tcp_w1 = match remote_tcp.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut remote_tcp_w2 = match remote_tcp.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut remote_tcp_r = remote_tcp;

        let s1 = Arc::clone(&shutdown);
        let conn_c1 = Arc::clone(&conn_arc);
        let t1 = std::thread::spawn(move || {
            let mut buf = [0u8; 32768];
            while !s1.load(Ordering::Relaxed) {
                match client_r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut write_err = false;
                        {
                            let mut guard = conn_c1.lock();
                            if guard.writer().write_all(&buf[..n]).is_err() {
                                write_err = true;
                            } else {
                                while guard.wants_write() {
                                    match guard.write_tls(&mut remote_tcp_w1) {
                                        Ok(0) => break,
                                        Ok(_) => {}
                                        Err(_) => {
                                            write_err = true;
                                            break;
                                        }
                                    }
                                }
                                if remote_tcp_w1.flush().is_err() {
                                    write_err = true;
                                }
                            }
                        }
                        if write_err {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let mut guard = conn_c1.lock();
            guard.send_close_notify();
            while guard.wants_write() {
                if guard.write_tls(&mut remote_tcp_w1).is_err() {
                    break;
                }
            }
            let _ = remote_tcp_w1.flush();
            let _ = remote_tcp_w1.shutdown(Shutdown::Write);
        });

        let s2 = Arc::clone(&shutdown);
        let conn_c2 = Arc::clone(&conn_arc);
        let t2 = std::thread::spawn(move || {
            let mut raw_buf = [0u8; 32768];
            let mut pt_buf = [0u8; 16384];

            // Drain any pending plaintext already buffered in `conn` from the handshake / initial CONNECT reply
            if Self::drain_plaintext_to_client(&conn_c2, &mut client_w, &mut pt_buf).is_err() {
                let _ = client_w.shutdown(Shutdown::Write);
                return;
            }

            'relay: while !s2.load(Ordering::Relaxed) {
                match remote_tcp_r.read(&mut raw_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut cursor = &raw_buf[..n];
                        while !cursor.is_empty() {
                            {
                                let mut guard = conn_c2.lock();
                                match guard.read_tls(&mut cursor) {
                                    Ok(0) | Err(_) => break 'relay,
                                    Ok(_) => {}
                                }
                                if guard.process_new_packets().is_err() { break 'relay; }
                                while guard.wants_write() {
                                    match guard.write_tls(&mut remote_tcp_w2) {
                                        Ok(0) | Err(_) => break 'relay,
                                        Ok(_) => {}
                                    }
                                }
                            }
                            if Self::drain_plaintext_to_client(&conn_c2, &mut client_w, &mut pt_buf).is_err() {
                                break 'relay;
                            }
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = Self::drain_plaintext_to_client(&conn_c2, &mut client_w, &mut pt_buf);
            let _ = client_w.shutdown(Shutdown::Write);
        });

        let _ = t1.join();
        let _ = t2.join();
    }
}

impl Drop for ProxyBridge {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.listener_thread.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            ProxyBridge::parse_host_port("example.com:443", 80),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            ProxyBridge::parse_host_port("[::1]:9000", 80),
            ("::1".to_string(), 9000)
        );
        assert_eq!(
            ProxyBridge::parse_host_port("127.0.0.1:8080", 80),
            ("127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            ProxyBridge::parse_host_port("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            ProxyBridge::parse_host_port("[2001:db8::1]:443", 80),
            ("2001:db8::1".to_string(), 443)
        );
        assert_eq!(
            crate::network::format_host_port("2001:db8::1", 443),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn test_socks5_authenticated_tunnel_roundtrip() {
        // 1. Start a local echo target server
        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_handle = std::thread::spawn(move || {
            let (mut stream, _) = echo_listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });

        // 2. Start a local mock SOCKS5 server requiring user="alice", pass="secret123"
        let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_port = socks_listener.local_addr().unwrap().port();
        let socks_handle = std::thread::spawn(move || {
            let (mut stream, _) = socks_listener.accept().unwrap();
            // Read greeting
            let mut greet = [0u8; 4];
            stream.read_exact(&mut greet).unwrap();
            assert_eq!(greet[0], 0x05);
            // Select user/pass method 0x02
            stream.write_all(&[0x05, 0x02]).unwrap();

            // Read auth request: [0x01, ulen, u..., plen, p...]
            let mut ver_ulen = [0u8; 2];
            stream.read_exact(&mut ver_ulen).unwrap();
            assert_eq!(ver_ulen[0], 0x01);
            let ulen = ver_ulen[1] as usize;
            let mut u = vec![0u8; ulen];
            stream.read_exact(&mut u).unwrap();
            assert_eq!(String::from_utf8(u).unwrap(), "alice");

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut p).unwrap();
            assert_eq!(String::from_utf8(p).unwrap(), "secret123");

            // Success auth reply: [0x01, 0x00]
            stream.write_all(&[0x01, 0x00]).unwrap();

            // Read CONNECT command: [0x05, 0x01, 0x00, 0x01, 4 bytes ipv4, 2 bytes port]
            let mut cmd_hdr = [0u8; 4];
            stream.read_exact(&mut cmd_hdr).unwrap();
            assert_eq!(cmd_hdr[0], 0x05);
            assert_eq!(cmd_hdr[1], 0x01); // CONNECT
            assert_eq!(cmd_hdr[3], 0x01); // IPv4
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port).unwrap();

            // CONNECT reply: [0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();

            // Connect to echo server and relay
            let mut target = TcpStream::connect(("127.0.0.1", echo_port)).unwrap();
            let mut stream_c = stream.try_clone().unwrap();
            let mut target_c = target.try_clone().unwrap();

            let t1 = std::thread::spawn(move || {
                let mut b = [0u8; 1024];
                while let Ok(n) = stream_c.read(&mut b) {
                    if n == 0 || target.write_all(&b[..n]).is_err() {
                        break;
                    }
                }
            });
            let mut b = [0u8; 1024];
            while let Ok(n) = target_c.read(&mut b) {
                if n == 0 || stream.write_all(&b[..n]).is_err() {
                    break;
                }
            }
            let _ = t1.join();
        });

        // 3. Start ProxyBridge pointing to SOCKS5 server
        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Socks5,
            upstream_host: "127.0.0.1".into(),
            upstream_port: socks_port,
            username: Some("alice".into()),
            password: Some("secret123".into()),
            root_store: None,
        })
        .unwrap();

        // 4. Client connects to bridge and requests CONNECT to echo server
        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", echo_port, echo_port);
        client.write_all(req.as_bytes()).unwrap();

        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        // Send payload and verify echo
        client.write_all(b"hello-proxy").unwrap();
        let mut echo_buf = [0u8; 11];
        client.read_exact(&mut echo_buf).unwrap();
        assert_eq!(&echo_buf, b"hello-proxy");

        drop(client);
        drop(bridge);
        let _ = echo_handle.join();
        let _ = socks_handle.join();
    }

    #[test]
    fn test_socks5_invalid_credentials_returns_502() {
        let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_port = socks_listener.local_addr().unwrap().port();
        let socks_handle = std::thread::spawn(move || {
            let (mut stream, _) = socks_listener.accept().unwrap();
            let mut greet = [0u8; 4];
            stream.read_exact(&mut greet).unwrap();
            stream.write_all(&[0x05, 0x02]).unwrap();

            // Read auth request
            let mut ver_ulen = [0u8; 2];
            stream.read_exact(&mut ver_ulen).unwrap();
            let ulen = ver_ulen[1] as usize;
            let mut u = vec![0u8; ulen];
            stream.read_exact(&mut u).unwrap();

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut p).unwrap();

            // Reject authentication: [0x01, 0x01 (failure)]
            stream.write_all(&[0x01, 0x01]).unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Socks5,
            upstream_host: "127.0.0.1".into(),
            upstream_port: socks_port,
            username: Some("bob".into()),
            password: Some("wrongpass".into()),
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n").unwrap();

        let mut resp = [0u8; b"HTTP/1.1 502 Bad Gateway\r\n\r\n".len()];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 502 Bad Gateway\r\n\r\n");

        drop(client);
        drop(bridge);
        let _ = socks_handle.join();
    }

    #[test]
    fn test_http_authenticated_tunnel_roundtrip() {
        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target_handle = std::thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().unwrap();
            let mut buf = [0u8; 32];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });

        // Mock upstream HTTP proxy expecting Basic auth: "user:pass"
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxy_handle = std::thread::spawn(move || {
            let (mut stream, _) = proxy_listener.accept().unwrap();
            let (head, _) = ProxyBridge::read_http_head(&mut stream).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(head_str.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
            assert!(head_str.starts_with("CONNECT 127.0.0.1:"));

            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();

            // Connect to target and relay
            let mut target = TcpStream::connect(("127.0.0.1", target_port)).unwrap();
            let mut stream_c = stream.try_clone().unwrap();
            let mut target_c = target.try_clone().unwrap();

            let t1 = std::thread::spawn(move || {
                let mut b = [0u8; 1024];
                while let Ok(n) = stream_c.read(&mut b) {
                    if n == 0 || target.write_all(&b[..n]).is_err() {
                        break;
                    }
                }
            });
            let mut b = [0u8; 1024];
            while let Ok(n) = target_c.read(&mut b) {
                if n == 0 || stream.write_all(&b[..n]).is_err() {
                    break;
                }
            }
            let _ = t1.join();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Http,
            upstream_host: "127.0.0.1".into(),
            upstream_port: proxy_port,
            username: Some("user".into()),
            password: Some("pass".into()),
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target_port);
        client.write_all(req.as_bytes()).unwrap();

        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"test-http-tunnel").unwrap();
        let mut echo = [0u8; 16];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"test-http-tunnel");

        drop(client);
        drop(bridge);
        let _ = target_handle.join();
        let _ = proxy_handle.join();
    }
    #[test]
    fn test_http_plain_forwarding_roundtrip() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxy_handle = std::thread::spawn(move || {
            let (mut stream, _) = proxy_listener.accept().unwrap();
            let (head, _) = ProxyBridge::read_http_head(&mut stream).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(head_str.contains("Proxy-Authorization: Basic "));
            assert!(head_str.starts_with("GET http://example.com/hello HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld").unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Http,
            upstream_host: "127.0.0.1".into(),
            upstream_port: proxy_port,
            username: Some("proxyuser".into()),
            password: Some("proxypass".into()),
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"GET http://example.com/hello HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();

        let (resp_head, resp_body) = ProxyBridge::read_http_head(&mut client).unwrap();
        let resp_str = String::from_utf8_lossy(&resp_head);
        assert!(resp_str.contains("200 OK"));
        assert_eq!(&resp_body, b"world");

        drop(client);
        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_bridge_drop_terminates_listener_and_connections() {
        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Socks5,
            upstream_host: "127.0.0.1".into(),
            upstream_port: 1080,
            username: None,
            password: None,
            root_store: None,
        })
        .unwrap();

        let port = bridge.port();
        assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());

        drop(bridge);

        // Once dropped, listener is closed and new connections fail immediately
        std::thread::sleep(Duration::from_millis(50));
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }

    const TEST_CERT_HEX: &str = "3082033a30820222a0030201020214200495cefa974dbcd455cd237ff9f14beaf4c285300d06092a864886f70d01010b050030143112301006035504030c096c6f63616c686f73743020170d3236313031313036323130365a180f32303736303132323036323130365a30143112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100c895f53b1b0000e3eff6f337cc64197ad88ca506c4832466912a65c2fd21bed87e201434452d99c9e9983159217a0c39a1bd1c515e25efcd3564bf1a90d8edd8d12a92bdfdf416c1786d639afacf9ca80d4053846e8d56f9edcbaab78a440096e4154abf9be6b5b39b95b87931d137dc28ab52149f7c90ec49ae2336debafacc030b772c2a9b0ba9f564a8daa7f07dcf8cc6814f7cbb0ae11b6c76cd017bd15dc1a0d5f9de92eec0810de810c606920b3fdfac325c377b64b8cedf4a5bb18d5d75471379382ecafe26642baf4fa3d7add7a3e5c7256c67a0c04f70ed3c8c225e30b8ba3f10f56667d89558bbbc3581084b5b180048ac0d18ddc739c0d90f8f150203010001a38181307f301d0603551d0e04160414168b1dca5fa7ac079b8afe6d94341432a925fe94301f0603551d23041830168014168b1dca5fa7ac079b8afe6d94341432a925fe94300c0603551d130101ff04023000301a0603551d110413301182096c6f63616c686f737487047f00000130130603551d25040c300a06082b06010505070301300d06092a864886f70d01010b050003820101006ff93c9d2f84c9706ad1d7a44c4bb799cc7f87172587194892904a79d724be2239a8be72bbc94825eea3d74e41f2bde251e2ad525522daa30808a28b59be508de92f62fac73942d7bef59eedbf119c7251b2197e6a7444f8e04cef996286cd831aadc2660a0dbc4fdd9767009cb73eafee71e24f570206ea1603d8248311c11cf2cfb29c08e3f25076ab542417141aaa543c97b6699fcdb157ed4ca67ef8af84221ce147d49973650fa67e04e1237c56d6e99db96eb3c190f44b07c712f086454e843e02662177a2e7fbcc7c71415cb476ec58bcd454aa3d3a2c869fd8b1bde24b564947cb5a77cb7d6b623cc01ff4e961fcfacbdce605631258b59560804a78";

    const TEST_KEY_HEX: &str = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100c895f53b1b0000e3eff6f337cc64197ad88ca506c4832466912a65c2fd21bed87e201434452d99c9e9983159217a0c39a1bd1c515e25efcd3564bf1a90d8edd8d12a92bdfdf416c1786d639afacf9ca80d4053846e8d56f9edcbaab78a440096e4154abf9be6b5b39b95b87931d137dc28ab52149f7c90ec49ae2336debafacc030b772c2a9b0ba9f564a8daa7f07dcf8cc6814f7cbb0ae11b6c76cd017bd15dc1a0d5f9de92eec0810de810c606920b3fdfac325c377b64b8cedf4a5bb18d5d75471379382ecafe26642baf4fa3d7add7a3e5c7256c67a0c04f70ed3c8c225e30b8ba3f10f56667d89558bbbc3581084b5b180048ac0d18ddc739c0d90f8f15020301000102820100179253c2b1de12bcb686e13715ec4f7839b9716d35aba99bea043ef826921020d5d5843a4e44d9153abfb950dd97bf970834367f335ea6eb0912c148686c2dab348d59b83cff31ab63b10b2afbbd690df09cb613d2800690114b4551134d017ab9ebeca04ebc526efc62204f11b521e8dbd8a2292d42d0af0bcb8c74d6c0c756fb81a4f38e6e8d4c930f1f921859f791f338aa583b093aeb8697a429946836d61810517199d187bfe1e422f087ba04062926b19462e78026ba54483a483f577b51875492831042fb17e4744b2b0195da58a0dadf420c12c44c02eb74da9b16698f3237bd3f91eae56f261877239be96d33a14e4ec7e89b8f81ef4b4d8a8df4f102818100ff8b681c357667bc48f80e0e7a197800dfc88d842e6d6e4ac0ce931627752d8ac923843dacf3664b3e2e3aa54a5f19a912a5666587e1bf10434a577af42a3bf8398803139582701e71c0050c70d413b0f1f7662e4fbb9df893296944daca14bd8acbd063da7771aebf16a81a7b4f068ef5cf69f7f8a4a4f10bc1e569caff735902818100c8f179df9049dc9d91b5878f9168bbeabccb3df92a305c975e0d33e62ab93b5b35924b2c413560c164b632fd8908286b0bc6b0441cda324242b9e999d6a9d051703e9205d0d9fe0e214092d008af97fae3020690be4fc83b5f26bee2bbacc762cd0e8144533081d97da156d2cff2b9ed066ab961927ade345e66aead0d61ae1d02818100b708c608366ed9bc6dd366560e3481d4b674f28ff3a523f35d085927ec192d06942ce1423fc792c4600442b33382cc61625e9fea271a957c7386230489305b05df474154dca8b1dfcc7fc9ddf04ea6cffd6fc37b76569ebe75c19a89dbe0145cf2b62b4bea25d58261923bd3c3f085750e3182e83eeac6cd742b6c438b47cef9028181008e0f0956202fd7a41deaf4176f7957c0b0100f94235b655a2dc7afb53ce70f2b8048189504d4b3be8570b9c3bc28e44a295d2228452d8cf28331e4103a4e7b53d7c2a4813011ad265823caa7003d0378ff1be38058cb1687c2d1258a2d9c0ca9b0c65c64ed5b11b1acbb6f2242991b1092c4c8a24e6846c74725d8bfc70213910281804da7b65b132c81f76f9c0f638c58402fee5e70049627b1403a58662f4f74308398604dc64cd7ca06473744567ac28ac79828e26a132671f456d2be94df322f1e72e280815b0c51c666d119b5c1ebc4b5d4bac43c3ff6c1b27bd341edd50a4a338a7b4e997f1ce60eee481db727b046c7b932d69c2bd98e7aa2db23ec3f1dd3ef";

    fn make_test_tls_server_config() -> Arc<rustls::ServerConfig> {
        let cert_der = hex::decode(TEST_CERT_HEX.trim()).unwrap();
        let key_der = hex::decode(TEST_KEY_HEX.trim()).unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

        Arc::new(config)
    }

    fn make_test_root_store() -> Arc<rustls::RootCertStore> {
        let cert_der = hex::decode(TEST_CERT_HEX.trim()).unwrap();
        let mut store = rustls::RootCertStore::empty();
        store.add(rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        Arc::new(store)
    }

    #[test]
    fn test_https_authenticated_tunnel_roundtrip() {
        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target_handle = std::thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().unwrap();
            let mut buf = [0u8; 32];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();
        let proxy_handle = std::thread::spawn(move || {
            let (tcp_stream, _) = proxy_listener.accept().unwrap();
            let server_conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);

            let (head, _) = ProxyBridge::read_http_head(&mut tls).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(head_str.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
            assert!(head_str.starts_with("CONNECT 127.0.0.1:"));

            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
            tls.flush().unwrap();

            let target = TcpStream::connect(("127.0.0.1", target_port)).unwrap();
            let (conn, raw_tcp) = tls.into_parts();
            let conn_arc = Arc::new(Mutex::new(conn));

            let mut raw_tcp_w = raw_tcp.try_clone().unwrap();
            let mut raw_tcp_r = raw_tcp;
            let mut target_r = target.try_clone().unwrap();
            let mut target_w = target;

            let c1 = Arc::clone(&conn_arc);
            let t1 = std::thread::spawn(move || {
                let mut b = [0u8; 1024];
                while let Ok(n) = target_r.read(&mut b) {
                    if n == 0 { break; }
                    let mut guard = c1.lock();
                    if guard.writer().write_all(&b[..n]).is_err() { break; }
                    while guard.wants_write() {
                        if guard.write_tls(&mut raw_tcp_w).is_err() { break; }
                    }
                    let _ = raw_tcp_w.flush();
                }
            });

            let c2 = Arc::clone(&conn_arc);
            let t2 = std::thread::spawn(move || {
                let mut raw_b = [0u8; 1024];
                while let Ok(n) = raw_tcp_r.read(&mut raw_b) {
                    if n == 0 { break; }
                    let mut cursor = &raw_b[..n];
                    let mut pt = Vec::new();
                    {
                        let mut guard = c2.lock();
                        while !cursor.is_empty() {
                            if guard.read_tls(&mut cursor).is_err() { break; }
                        }
                        if guard.process_new_packets().is_err() { break; }
                        let mut reader = guard.reader();
                        let mut chunk = [0u8; 1024];
                        loop {
                            match reader.read(&mut chunk) {
                                Ok(0) => break,
                                Ok(cn) => pt.extend_from_slice(&chunk[..cn]),
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => break,
                            }
                        }
                    }
                    if !pt.is_empty() {
                        if target_w.write_all(&pt).is_err() { break; }
                    }
                }
            });

            let _ = t1.join();
            let _ = t2.join();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "localhost".into(),
            upstream_port: proxy_port,
            username: Some("user".into()),
            password: Some("pass".into()),
            root_store: Some(make_test_root_store()),
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target_port);
        client.write_all(req.as_bytes()).unwrap();

        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"test-https-tunnel").unwrap();
        let mut echo = [0u8; 17];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"test-https-tunnel");

        drop(client);
        drop(bridge);
        let _ = target_handle.join();
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_https_plain_forwarding_roundtrip() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();
        let proxy_handle = std::thread::spawn(move || {
            let (tcp_stream, _) = proxy_listener.accept().unwrap();
            let server_conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);

            let (head, _) = ProxyBridge::read_http_head(&mut tls).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(head_str.contains("Proxy-Authorization: Basic "));
            assert!(head_str.starts_with("GET http://example.com/hello HTTP/1.1"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld").unwrap();
            tls.flush().unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "localhost".into(),
            upstream_port: proxy_port,
            username: Some("proxyuser".into()),
            password: Some("proxypass".into()),
            root_store: Some(make_test_root_store()),
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"GET http://example.com/hello HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();

        let (resp_head, resp_body) = ProxyBridge::read_http_head(&mut client).unwrap();
        let resp_str = String::from_utf8_lossy(&resp_head);
        assert!(resp_str.contains("200 OK"));
        assert_eq!(&resp_body, b"world");

        drop(client);
        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_https_unauthenticated_tunnel_roundtrip() {
        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target_handle = std::thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();
        let proxy_handle = std::thread::spawn(move || {
            let (tcp_stream, _) = proxy_listener.accept().unwrap();
            let server_conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);

            let (head, _) = ProxyBridge::read_http_head(&mut tls).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(!head_str.contains("Proxy-Authorization:"));
            assert!(head_str.starts_with("CONNECT 127.0.0.1:"));

            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
            tls.flush().unwrap();

            let target = TcpStream::connect(("127.0.0.1", target_port)).unwrap();
            let (conn, raw_tcp) = tls.into_parts();
            let conn_arc = Arc::new(Mutex::new(conn));

            let mut raw_tcp_w = raw_tcp.try_clone().unwrap();
            let mut raw_tcp_r = raw_tcp;
            let mut target_r = target.try_clone().unwrap();
            let mut target_w = target;

            let c1 = Arc::clone(&conn_arc);
            let t1 = std::thread::spawn(move || {
                let mut b = [0u8; 512];
                while let Ok(n) = target_r.read(&mut b) {
                    if n == 0 { break; }
                    let mut guard = c1.lock();
                    if guard.writer().write_all(&b[..n]).is_err() { break; }
                    while guard.wants_write() {
                        if guard.write_tls(&mut raw_tcp_w).is_err() { break; }
                    }
                    let _ = raw_tcp_w.flush();
                }
            });

            let c2 = Arc::clone(&conn_arc);
            let t2 = std::thread::spawn(move || {
                let mut raw_b = [0u8; 512];
                while let Ok(n) = raw_tcp_r.read(&mut raw_b) {
                    if n == 0 { break; }
                    let mut cursor = &raw_b[..n];
                    let mut pt = Vec::new();
                    {
                        let mut guard = c2.lock();
                        while !cursor.is_empty() {
                            if guard.read_tls(&mut cursor).is_err() { break; }
                        }
                        if guard.process_new_packets().is_err() { break; }
                        let mut reader = guard.reader();
                        let mut chunk = [0u8; 512];
                        loop {
                            match reader.read(&mut chunk) {
                                Ok(0) => break,
                                Ok(cn) => pt.extend_from_slice(&chunk[..cn]),
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => break,
                            }
                        }
                    }
                    if !pt.is_empty() {
                        if target_w.write_all(&pt).is_err() { break; }
                    }
                }
            });

            let _ = t1.join();
            let _ = t2.join();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "localhost".into(),
            upstream_port: proxy_port,
            username: None,
            password: None,
            root_store: Some(make_test_root_store()),
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target_port);
        client.write_all(req.as_bytes()).unwrap();

        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"no-auth-https").unwrap();
        let mut echo = [0u8; 13];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"no-auth-https");

        drop(client);
        drop(bridge);
        let _ = target_handle.join();
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_https_certificate_rejection_fails_closed() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();
        let proxy_handle = std::thread::spawn(move || {
            if let Ok((tcp_stream, _)) = proxy_listener.accept() {
                if let Ok(server_conn) = rustls::ServerConnection::new(server_config) {
                    let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);
                    let mut buf = [0u8; 128];
                    let _ = tls.read(&mut buf);
                }
            }
        });

        // root_store: None uses standard webpki-roots which does not trust test self-signed cert
        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "localhost".into(),
            upstream_port: proxy_port,
            username: Some("secret_user".into()),
            password: Some("secret_pass".into()),
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n").unwrap();

        let (resp_head, _) = ProxyBridge::read_http_head(&mut client).unwrap();
        let resp_str = String::from_utf8_lossy(&resp_head);
        assert!(resp_str.contains("502 Bad Gateway"));

        drop(client);
        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_https_hostname_mismatch_fails_closed() {
        let proxy_listener = TcpListener::bind("127.0.0.2:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();
        let proxy_handle = std::thread::spawn(move || {
            if let Ok((tcp_stream, _)) = proxy_listener.accept() {
                if let Ok(server_conn) = rustls::ServerConnection::new(server_config) {
                    let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);
                    let mut buf = [0u8; 128];
                    let _ = tls.read(&mut buf);
                }
            }
        });

        // Root store trusts cert, but hostname does not match SAN ("localhost", "127.0.0.1")
        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "127.0.0.2".into(),
            upstream_port: proxy_port,
            username: Some("secret_user".into()),
            password: Some("secret_pass".into()),
            root_store: Some(make_test_root_store()),
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n").unwrap();

        let (resp_head, _) = ProxyBridge::read_http_head(&mut client).unwrap();
        let resp_str = String::from_utf8_lossy(&resp_head);
        assert!(resp_str.contains("502 Bad Gateway"));

        drop(client);
        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_https_tunnel_large_payload_half_close() {
        let payload_size = 131_072; // 128 KB
        let client_bytes = vec![0x5Au8; payload_size];
        let server_bytes = vec![0xA5u8; payload_size];

        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let srv_data = server_bytes.clone();
        let expected_client_data = client_bytes.clone();

        let target_handle = std::thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().unwrap();
            let mut received = Vec::with_capacity(payload_size);
            let mut chunk = [0u8; 16384];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(received.len(), payload_size);
            assert_eq!(received, expected_client_data);

            stream.write_all(&srv_data).unwrap();
            stream.flush().unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();

        let proxy_handle = std::thread::spawn(move || {
            let (tcp_stream, _) = proxy_listener.accept().unwrap();
            let server_conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);

            let (head, _) = ProxyBridge::read_http_head(&mut tls).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(head_str.starts_with("CONNECT 127.0.0.1:"));

            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
            tls.flush().unwrap();

            let mut target = TcpStream::connect(("127.0.0.1", target_port)).unwrap();
            let mut request_body = Vec::new();
            tls.read_to_end(&mut request_body).unwrap();
            target.write_all(&request_body).unwrap();
            target.shutdown(Shutdown::Write).unwrap();
            let mut response_body = Vec::new();
            target.read_to_end(&mut response_body).unwrap();
            tls.write_all(&response_body).unwrap();
            tls.flush().unwrap();
            tls.conn.send_close_notify();
            tls.flush().unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "localhost".into(),
            upstream_port: proxy_port,
            username: None,
            password: None,
            root_store: Some(make_test_root_store()),
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target_port);
        client.write_all(req.as_bytes()).unwrap();

        let mut resp_hdr = [0u8; 39];
        client.read_exact(&mut resp_hdr).unwrap();
        assert_eq!(&resp_hdr, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        // Send full 128 KB payload
        client.write_all(&client_bytes).unwrap();
        client.flush().unwrap();

        // Half-close write side
        client.shutdown(Shutdown::Write).unwrap();

        // Read full 128 KB response
        let mut response_data = Vec::with_capacity(payload_size);
        let mut read_buf = [0u8; 16384];
        loop {
            let n = client.read(&mut read_buf).unwrap();
            if n == 0 {
                break;
            }
            response_data.extend_from_slice(&read_buf[..n]);
        }

        assert_eq!(response_data.len(), payload_size);
        assert_eq!(response_data, server_bytes);

        drop(client);
        drop(bridge);
        let _ = target_handle.join();
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_http_plain_forwarding_two_requests_auth_and_keepalive_override() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxy_handle = std::thread::spawn(move || {
            // First request from bridge
            let (mut stream1, _) = proxy_listener.accept().unwrap();
            let (head1, _) = ProxyBridge::read_http_head(&mut stream1).unwrap();
            let head1_str = String::from_utf8_lossy(&head1);
            assert!(head1_str.starts_with("GET http://example.com/first HTTP/1.1"));
            assert!(head1_str.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
            assert!(head1_str.contains("Connection: close"));
            assert!(head1_str.contains("Proxy-Connection: close"));
            assert!(!head1_str.to_ascii_lowercase().contains("keep-alive"));
            stream1.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst").unwrap();
            drop(stream1);

            // Second request from bridge (via fresh browser connection)
            let (mut stream2, _) = proxy_listener.accept().unwrap();
            let (head2, _) = ProxyBridge::read_http_head(&mut stream2).unwrap();
            let head2_str = String::from_utf8_lossy(&head2);
            assert!(head2_str.starts_with("GET http://example.com/second HTTP/1.1"));
            assert!(head2_str.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
            assert!(head2_str.contains("Connection: close"));
            assert!(head2_str.contains("Proxy-Connection: close"));
            assert!(!head2_str.to_ascii_lowercase().contains("keep-alive"));
            stream2.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond").unwrap();
            drop(stream2);
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Http,
            upstream_host: "127.0.0.1".into(),
            upstream_port: proxy_port,
            username: Some("user".into()),
            password: Some("pass".into()),
            root_store: None,
        })
        .unwrap();

        // Browser connection 1 with mixed-case preexisting keepalive headers
        let mut client1 = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client1.write_all(
            b"GET http://example.com/first HTTP/1.1\r\nHost: example.com\r\nCoNnEcTiOn: KeEp-AlIvE\r\nPrOxY-cOnNeCtIoN: KeEp-AlIvE\r\nKeEp-AlIvE: timeout=5\r\n\r\n"
        ).unwrap();
        let (resp1_head, resp1_body) = ProxyBridge::read_http_head(&mut client1).unwrap();
        assert!(String::from_utf8_lossy(&resp1_head).contains("200 OK"));
        assert_eq!(&resp1_body, b"first");
        drop(client1);

        // Browser connection 2: fresh connection after connection 1 closed
        let mut client2 = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client2.write_all(
            b"GET http://example.com/second HTTP/1.1\r\nHost: example.com\r\nCoNnEcTiOn: KeEp-AlIvE\r\n\r\n"
        ).unwrap();
        let (resp2_head, resp2_body) = ProxyBridge::read_http_head(&mut client2).unwrap();
        assert!(String::from_utf8_lossy(&resp2_head).contains("200 OK"));
        assert_eq!(&resp2_body, b"second");
        drop(client2);

        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_socks5_plain_forwarding_does_not_leak_proxy_auth() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_handle = std::thread::spawn(move || {
            let (mut stream, _) = echo_listener.accept().unwrap();
            let (head, _) = ProxyBridge::read_http_head(&mut stream).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            // Verify origin server does not receive proxy authorization and gets Connection: close
            assert!(!head_str.to_ascii_lowercase().contains("proxy-authorization"));
            assert!(head_str.contains("Connection: close"));
            assert!(head_str.contains("Proxy-Connection: close"));
            assert!(!head_str.to_ascii_lowercase().contains("keep-alive"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
        });

        // Mock SOCKS5 server with no auth
        let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_port = socks_listener.local_addr().unwrap().port();
        let socks_handle = std::thread::spawn(move || {
            let (mut stream, _) = socks_listener.accept().unwrap();
            let mut greet = [0u8; 3];
            stream.read_exact(&mut greet).unwrap();
            stream.write_all(&[0x05, 0x00]).unwrap(); // No auth

            let mut cmd_hdr = [0u8; 4];
            stream.read_exact(&mut cmd_hdr).unwrap();
            assert_eq!(cmd_hdr[1], 0x01); // CONNECT
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port).unwrap();
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();

            // Connect to echo server and relay
            let mut target = TcpStream::connect(("127.0.0.1", echo_port)).unwrap();
            let mut stream_c = stream.try_clone().unwrap();
            let mut target_c = target.try_clone().unwrap();

            let t1 = std::thread::spawn(move || {
                let mut b = [0u8; 1024];
                while let Ok(n) = stream_c.read(&mut b) {
                    if n == 0 || target.write_all(&b[..n]).is_err() { break; }
                }
            });
            let mut b = [0u8; 1024];
            while let Ok(n) = target_c.read(&mut b) {
                if n == 0 || stream.write_all(&b[..n]).is_err() { break; }
            }
            let _ = t1.join();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Socks5,
            upstream_host: "127.0.0.1".into(),
            upstream_port: socks_port,
            username: None,
            password: None,
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic leaked_secret\r\nCoNnEcTiOn: KeEp-AlIvE\r\n\r\n",
            echo_port, echo_port
        );
        client.write_all(req.as_bytes()).unwrap();

        let (resp_head, resp_body) = ProxyBridge::read_http_head(&mut client).unwrap();
        assert!(String::from_utf8_lossy(&resp_head).contains("200 OK"));
        assert_eq!(&resp_body, b"ok");

        drop(client);
        drop(bridge);
        let _ = echo_handle.join();
        let _ = socks_handle.join();
    }

    #[test]
    fn test_http_connect_ipv6_target_authority_bracketed() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxy_handle = std::thread::spawn(move || {
            let (mut stream, _) = proxy_listener.accept().unwrap();
            let (head, _) = ProxyBridge::read_http_head(&mut stream).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            // Verify IPv6 target authority is bracketed in CONNECT and Host
            assert!(head_str.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1"));
            assert!(head_str.contains("Host: [2001:db8::1]:443"));

            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();

            // Echo payload
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Http,
            upstream_host: "127.0.0.1".into(),
            upstream_port: proxy_port,
            username: None,
            password: None,
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n").unwrap();

        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"ipv6-connect-ok!").unwrap();
        let mut echo = [0u8; 16];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ipv6-connect-ok!");

        drop(client);
        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_https_connect_ipv6_target_authority_bracketed() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let server_config = make_test_tls_server_config();
        let proxy_handle = std::thread::spawn(move || {
            let (tcp_stream, _) = proxy_listener.accept().unwrap();
            let server_conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(server_conn, tcp_stream);

            let (head, _) = ProxyBridge::read_http_head(&mut tls).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            // Verify IPv6 target authority is bracketed in CONNECT and Host over TLS
            assert!(head_str.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1"));
            assert!(head_str.contains("Host: [2001:db8::1]:443"));

            tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
            tls.flush().unwrap();

            let mut buf = [0u8; 16];
            let n = tls.read(&mut buf).unwrap();
            tls.write_all(&buf[..n]).unwrap();
            tls.flush().unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Https,
            upstream_host: "localhost".into(),
            upstream_port: proxy_port,
            username: None,
            password: None,
            root_store: Some(make_test_root_store()),
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n").unwrap();

        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"ipv6-tls-conn-ok").unwrap();
        let mut echo = [0u8; 16];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ipv6-tls-conn-ok");

        drop(client);
        drop(bridge);
        let _ = proxy_handle.join();
    }

    #[test]
    fn test_prepare_plain_http_head_enforces_close_and_strips_keepalive() {
        let input = b"GET http://example.com/api HTTP/1.1\r\nHost: example.com\r\nCoNnEcTiOn: KeEp-AlIvE\r\nPrOxY-cOnNeCtIoN: KeEp-AlIvE\r\nKeEp-AlIvE: timeout=5\r\nProxy-Authorization: Basic client_stale\r\nCustom-Header: value\r\n\r\n";

        // HTTP upstream with credentials
        let out_http = ProxyBridge::prepare_plain_http_head(input, UpstreamProtocol::Http, Some("usr"), Some("pwd"));
        let s_http = String::from_utf8_lossy(&out_http);
        assert!(s_http.starts_with("GET http://example.com/api HTTP/1.1\r\n"));
        assert!(s_http.contains("Custom-Header: value\r\n"));
        assert!(s_http.contains("Connection: close\r\n"));
        assert!(s_http.contains("Proxy-Connection: close\r\n"));
        assert!(s_http.contains("Proxy-Authorization: Basic dXNyOnB3ZA==\r\n"));
        assert!(!s_http.to_ascii_lowercase().contains("keep-alive"));
        assert!(!s_http.contains("client_stale"));

        // SOCKS5 upstream: must not include Proxy-Authorization
        let out_socks = ProxyBridge::prepare_plain_http_head(input, UpstreamProtocol::Socks5, Some("usr"), Some("pwd"));
        let s_socks = String::from_utf8_lossy(&out_socks);
        assert!(s_socks.contains("Connection: close\r\n"));
        assert!(s_socks.contains("Proxy-Connection: close\r\n"));
        assert!(!s_socks.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!s_socks.to_ascii_lowercase().contains("keep-alive"));
    }

    #[test]
    fn test_resolve_plain_http_target_ipv6() {
        assert_eq!(
            ProxyBridge::resolve_plain_http_target("http://[::1]/path", "").unwrap(),
            ("::1".to_string(), 80)
        );
        assert_eq!(
            ProxyBridge::resolve_plain_http_target("http://[2001:db8::1]:8080/path", "").unwrap(),
            ("2001:db8::1".to_string(), 8080)
        );
        assert_eq!(
            ProxyBridge::resolve_plain_http_target("/path", "Host: [::1]:9000\r\n").unwrap(),
            ("::1".to_string(), 9000)
        );
    }

    #[test]
    fn test_socks5_plain_http_ipv6_target_sends_atyp4() {
        let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_port = socks_listener.local_addr().unwrap().port();
        let socks_handle = std::thread::spawn(move || {
            let (mut stream, _) = socks_listener.accept().unwrap();
            let mut greet = [0u8; 3];
            stream.read_exact(&mut greet).unwrap();
            assert_eq!(&greet, &[0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).unwrap();

            let mut cmd_hdr = [0u8; 4];
            stream.read_exact(&mut cmd_hdr).unwrap();
            assert_eq!(cmd_hdr[0], 0x05);
            assert_eq!(cmd_hdr[1], 0x01); // CONNECT
            assert_eq!(cmd_hdr[2], 0x00);
            assert_eq!(cmd_hdr[3], 0x04); // ATYP IPv6 (4)

            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port).unwrap();
            assert_eq!(&addr_port[..16], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            assert_eq!(&addr_port[16..18], &80u16.to_be_bytes());

            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();

            let (head, _) = ProxyBridge::read_http_head(&mut stream).unwrap();
            let head_str = String::from_utf8_lossy(&head);
            assert!(head_str.starts_with("GET http://[::1]/ HTTP/1.1"));
            assert!(head_str.contains("Host: [::1]"));

            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
        });

        let bridge = ProxyBridge::start(BridgeConfig {
            upstream_protocol: UpstreamProtocol::Socks5,
            upstream_host: "127.0.0.1".into(),
            upstream_port: socks_port,
            username: None,
            password: None,
            root_store: None,
        })
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", bridge.port())).unwrap();
        client.write_all(b"GET http://[::1]/ HTTP/1.1\r\nHost: [::1]\r\n\r\n").unwrap();

        let (resp_head, resp_body) = ProxyBridge::read_http_head(&mut client).unwrap();
        assert!(String::from_utf8_lossy(&resp_head).contains("200 OK"));
        assert_eq!(&resp_body, b"ok");

        drop(client);
        drop(bridge);
        let _ = socks_handle.join();
    }
}
