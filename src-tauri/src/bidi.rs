use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::{net::{SocketAddr, TcpStream}, time::{Duration, Instant}};
use tungstenite::{client::client_with_config, protocol::WebSocketConfig, Message, WebSocket};

pub(crate) struct BrowserSession {
    socket: WebSocket<TcpStream>,
    next_id: u64,
}

impl BrowserSession {
    pub(crate) fn endpoint(line: &str) -> Option<url::Url> {
        let endpoint = url::Url::parse(line.strip_prefix("WebDriver BiDi listening on ")?).ok()?;
        (endpoint.scheme() == "ws"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost"))
            && endpoint.path() == "/"
            && endpoint.port().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none())
            .then_some(endpoint)
    }
    pub(crate) fn connect(endpoint: &url::Url, owned_pids: &[u32]) -> Result<Self> {
        let address = SocketAddr::from(([127,0,0,1],endpoint.port().context("Thiếu cổng phiên native")?));
        let stream = TcpStream::connect_timeout(&address,Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(64 * 1024);
        config.max_frame_size = Some(64 * 1024);
        let (socket, _) = client_with_config(endpoint.join("session")?.as_str(),stream,Some(config))
            .map_err(|error| anyhow!("Không kết nối được phiên trình duyệt native: {error}"))?;
        let mut session = Self { socket, next_id:0 };
        let result = session.call("session.new",json!({"capabilities":{}}))?;
        let pid = result.pointer("/capabilities/moz:processID").and_then(Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok()).context("Trình duyệt không trả PID phiên native")?;
        if !owned_pids.contains(&pid) {
            let _ = session.call("session.end",json!({}));
            bail!("Phiên native không thuộc tiến trình hồ sơ được quản lý");
        }
        Ok(session)
    }
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        self.socket.send(Message::Text(serde_json::to_string(&json!({"id":id,"method":method,"params":params}))?.into()))?;
        let timeout = Duration::from_secs(3);
        #[cfg(test)]
        let timeout = self.socket.get_ref().read_timeout()?.unwrap_or(timeout).max(timeout);
        let deadline = Instant::now() + timeout;
        for _ in 0..32 {
            if Instant::now() >= deadline { bail!("Phiên native không phản hồi: {method}"); }
            match self.socket.read()? {
                Message::Text(text) => {
                    let mut frame: Value = serde_json::from_str(&text)?;
                    if frame["id"].as_u64() != Some(id) { continue; }
                    if frame["type"] == "error" { bail!("Lỗi phiên native: {}",frame["message"]); }
                    return Ok(frame["result"].take());
                },
                Message::Close(_) => bail!("Phiên trình duyệt đã đóng trước khi hoàn tất {method}"),
                Message::Ping(_) | Message::Pong(_) => {},
                _ => bail!("Dữ liệu phiên native không hợp lệ"),
            }
        }
        bail!("Phiên native trả quá nhiều thông báo không liên quan")
    }
    pub(crate) fn close(mut self) -> Result<()> { self.call("browser.close",json!({})).map(|_| ()) }
    #[cfg(test)]
    pub(crate) fn navigate_for_test(&mut self, url: &str) -> Result<()> {
        self.socket.get_mut().set_read_timeout(Some(Duration::from_secs(15)))?;
        let result = (|| {
            let tree = self.call("browsingContext.getTree", json!({})).context("Native context discovery failed")?;
            let context = tree["contexts"][0]["context"].as_str().context("Không có tab để kiểm tra native")?;
            self.call("browsingContext.navigate", json!({"context": context, "url": url, "wait": "complete"}))
                .context("Native full-page navigation failed")?;
            Ok(())
        })();
        self.socket.get_mut().set_read_timeout(Some(Duration::from_secs(2)))?;
        result
    }
    #[cfg(test)]
    pub(crate) fn evaluate_json(&mut self, expression: &str) -> Result<Value> {
        let tree = self.call("browsingContext.getTree", json!({}))?;
        let context = tree["contexts"][0]["context"].as_str().context("Không có tab để kiểm tra native")?;
        let result = self.call("script.evaluate", json!({"expression": expression, "target": {"context": context}, "awaitPromise": true}))?;
        if result["type"] != "success" { bail!("Native probe failed: {result}"); }
        serde_json::from_str(result["result"]["value"].as_str().context("Native probe did not return JSON")?).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn endpoint_accepts_loopback_hosts_and_rejects_remote_or_decorated_urls() {
        for host in ["127.0.0.1", "localhost"] {
            let endpoint = BrowserSession::endpoint(&format!("WebDriver BiDi listening on ws://{host}:9222")).unwrap();
            assert_eq!(endpoint.host_str(), Some(host));
            assert_eq!(endpoint.join("session").unwrap().as_str(), format!("ws://{host}:9222/session"));
        }
        for address in ["ws://example.com:9222", "ws://127.0.0.2:9222", "wss://localhost:9222", "ws://localhost", "ws://localhost:9222/session", "ws://user@localhost:9222", "ws://localhost:9222/?x=1", "ws://localhost:9222/#x"] {
            assert!(BrowserSession::endpoint(&format!("WebDriver BiDi listening on {address}")).is_none(), "{address}");
        }
    }

    #[test]
    fn rejects_unowned_browser_without_closing_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            let request: Value = serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(request["method"],"session.new");
            socket.send(Message::Text(json!({"type":"success","id":request["id"],"result":{"capabilities":{"moz:processID":999}}}).to_string().into())).unwrap();
            let request: Value = serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(request["method"],"session.end");
            socket.send(Message::Text(json!({"type":"success","id":request["id"],"result":{}}).to_string().into())).unwrap();
        });
        let endpoint = BrowserSession::endpoint(&format!("WebDriver BiDi listening on ws://127.0.0.1:{port}")).unwrap();
        let error = BrowserSession::connect(&endpoint,&[123]).err().expect("Unowned process must be rejected");
        assert!(error.to_string().contains("không thuộc tiến trình"));
        server.join().unwrap();
    }
}
