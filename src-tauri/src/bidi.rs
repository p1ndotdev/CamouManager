use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::{net::{SocketAddr, TcpStream}, time::{Duration, Instant}};
use tungstenite::{client::client_with_config, protocol::WebSocketConfig, Message, WebSocket};

pub(crate) struct BrowserSession {
    socket: WebSocket<TcpStream>,
    next_id: u64,
}

impl BrowserSession {
    pub(crate) fn connect(port: u16, owned_pids: &[u32]) -> Result<Self> {
        let address = SocketAddr::from(([127,0,0,1],port));
        let stream = TcpStream::connect_timeout(&address,Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(64 * 1024);
        config.max_frame_size = Some(64 * 1024);
        let (socket, _) = client_with_config(format!("ws://127.0.0.1:{port}/session"),stream,Some(config))
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
        let deadline = Instant::now() + Duration::from_secs(3);
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
        let error = BrowserSession::connect(port,&[123]).err().expect("Unowned process must be rejected");
        assert!(error.to_string().contains("không thuộc tiến trình"));
        server.join().unwrap();
    }
}
