pub use crate::proxy_bridge::{BridgeConfig, ProxyBridge, UpstreamProtocol};

use crate::store::{redact, string, utcnow, Store};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

pub const ALLOWED_SCHEMES: &[&str] = &["http", "https", "socks5", "socks5h"];

pub fn format_host_port(host: &str, port: u16) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') && !h.ends_with(']') {
        format!("[{}]:{}", h, port)
    } else {
        format!("{}:{}", h, port)
    }
}

pub fn percent_encode_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.' || byte == b'~' {
            out.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{:02X}", byte);
        }
    }
    out
}

pub fn percent_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                let hex_str = [h1, h2];
                if let Ok(s) = std::str::from_utf8(&hex_str) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        bytes.push(val);
                        continue;
                    }
                }
                bytes.push(b'%');
                bytes.push(h1);
                bytes.push(h2);
            } else {
                bytes.push(b'%');
            }
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn parse_proxy_line(line: &str) -> Result<Value> {
    let mut clean = line.trim().to_string();
    if clean.is_empty() {
        bail!("Dòng proxy trống");
    }

    // Normalize unbracketed IPv6 in URLs before parsing
    if clean.contains("://") {
        if let Some((s_part, r_part)) = clean.split_once("://") {
            let (auth, hp_part) = if let Some((a, hp)) = r_part.rsplit_once('@') {
                (format!("{}@", a), hp)
            } else {
                (String::new(), r_part)
            };
            if !hp_part.starts_with('[') && hp_part.contains(':') {
                if let Some((h_cand, p_cand)) = hp_part.rsplit_once(':') {
                    if h_cand.parse::<std::net::Ipv6Addr>().is_ok() {
                        clean = format!("{}://{}[{}]:{}", s_part, auth, h_cand, p_cand);
                    }
                }
            }
        }
    }

    let mut scheme = "http".to_string();
    let mut username = String::new();
    let mut password = String::new();
    let host;
    let port;

    if clean.contains("://") {
        let parsed = url::Url::parse(&clean).map_err(|e| anyhow!("URL proxy không hợp lệ: {}", e))?;
        let s_raw = parsed.scheme().to_ascii_lowercase();
        if !ALLOWED_SCHEMES.contains(&s_raw.as_str()) {
            bail!(
                "Giao thức proxy không được hỗ trợ '{}'. Chỉ hỗ trợ http, https, socks5, socks5h",
                s_raw
            );
        }
        scheme = s_raw;
        host = parsed.host_str().unwrap_or("").to_string();
        port = parsed.port_or_known_default().ok_or_else(|| anyhow!("Thiếu cổng proxy"))?;
        if !parsed.username().is_empty() {
            username = percent_decode(parsed.username());
        }
        if let Some(p) = parsed.password() {
            password = percent_decode(p);
        }
    } else if clean.contains('@') {
        let (auth_part, host_part) = clean
            .split_once('@')
            .ok_or_else(|| anyhow!("Định dạng auth proxy không hợp lệ"))?;
        if let Some((u, p)) = auth_part.split_once(':') {
            username = percent_decode(u);
            password = percent_decode(p);
        } else {
            username = percent_decode(auth_part);
        }

        let (h_cand, p_cand) = ProxyBridge::parse_host_port(host_part, 0);
        if p_cand == 0 {
            bail!("Thiếu cổng proxy trong phần host: {}", host_part);
        }
        host = h_cand;
        port = p_cand;
    } else {
        let parts: Vec<&str> = clean.split(':').collect();
        if parts.len() == 4 && parts[1].parse::<u16>().is_ok_and(|port| port > 0) {
            // host:port:username:password
            host = parts[0].to_string();
            port = parts[1].parse::<u16>().map_err(|_| anyhow!("Cổng không hợp lệ"))?;
            username = parts[2].to_string();
            password = parts[3].to_string();
        } else if parts.len() == 4 && parts[3].chars().all(|c| c.is_ascii_digit()) {
            // username:password:host:port
            username = parts[0].to_string();
            password = parts[1].to_string();
            host = parts[2].to_string();
            port = parts[3].parse::<u16>().map_err(|_| anyhow!("Cổng không hợp lệ"))?;
        } else if parts.len() == 2 && parts[1].chars().all(|c| c.is_ascii_digit()) {
            // host:port
            host = parts[0].to_string();
            port = parts[1].parse::<u16>().map_err(|_| anyhow!("Cổng không hợp lệ"))?;
        } else if clean.contains(':') {
            let (h_cand, p_cand) = clean
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("Không nhận dạng được định dạng proxy: '{}'", clean))?;
            if p_cand.chars().all(|c| c.is_ascii_digit())
                && h_cand.trim_matches(|c| c == '[' || c == ']').parse::<std::net::Ipv6Addr>().is_ok()
            {
                host = h_cand.to_string();
                port = p_cand.parse::<u16>().map_err(|_| anyhow!("Cổng không hợp lệ"))?;
            } else {
                bail!("Không nhận dạng được định dạng proxy: '{}'", clean);
            }
        } else {
            bail!("Không nhận dạng được định dạng proxy: '{}'", clean);
        }
    }

    if host.is_empty() || port == 0 {
        bail!("Host hoặc cổng proxy không hợp lệ: '{}'", clean);
    }

    let host_port = format_host_port(&host, port);
    let server = format!("{}://{}", scheme, host_port);

    Ok(json!({
        "name": host_port,
        "server": server,
        "username": username,
        "password": password,
        "enabled": true,
        "last_check": {}
    }))
}

fn proxy_credentials<'a>(proxy: &'a Value, parsed: &'a Value, stored: Option<&'a Value>) -> Result<(&'a str, &'a str)> {
    let embedded = !string(parsed, "username").is_empty() || !string(parsed, "password").is_empty();
    let fallback = if embedded { parsed } else { stored.unwrap_or(parsed) };
    let credential = |key| {
        proxy.get(key).filter(|value| !value.is_null()).map_or_else(
            || Ok(string(fallback, key)),
            |value| value.as_str().ok_or_else(|| anyhow!("'{key}' phải là chuỗi")),
        )
    };
    Ok((credential("username")?, credential("password")?))
}

pub fn to_proxy_url(proxy: &Value) -> Result<String> {
    let parsed = parse_proxy_line(string(proxy, "server"))?;
    let server = string(&parsed, "server");
    let (scheme, host_port) = server.split_once("://").ok_or_else(|| anyhow!("Proxy server không hợp lệ"))?;
    let (username, password) = proxy_credentials(proxy, &parsed, None)?;
    let effective_scheme = if scheme == "socks5" { "socks5h" } else { scheme };
    if username.is_empty() {
        Ok(format!("{effective_scheme}://{host_port}"))
    } else {
        let username = percent_encode_userinfo(username);
        let auth = if password.is_empty() { username } else { format!("{username}:{}", percent_encode_userinfo(password)) };
        Ok(format!("{effective_scheme}://{auth}@{host_port}"))
    }
}

pub fn summary(proxy: &Value) -> Value {
    let mut clean = proxy.clone();
    let has_pwd = if let Some(map) = clean.as_object_mut() {
        let pwd_val = map.remove("password").unwrap_or(Value::Null);
        let p_str = pwd_val.as_str().unwrap_or("");
        !p_str.is_empty()
    } else {
        false
    };

    let u_str = string(&clean, "username").to_string();
    let has_credentials = has_pwd || !u_str.is_empty();

    if let Some(map) = clean.as_object_mut() {
        map.insert("username".into(), Value::String(u_str));
        map.insert("has_password".into(), Value::Bool(has_pwd));
        map.insert("has_credentials".into(), Value::Bool(has_credentials));
    }
    clean
}

pub fn client_for(proxy: Option<&Value>) -> Result<reqwest::blocking::Client> {
    let timeout = Duration::from_secs(15);
    match proxy {
        None => {
            // Direct network with NO ambient proxy bypass
            reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(timeout)
                .build()
                .map_err(|e| anyhow!("Failed to build direct HTTP client: {}", e))
        }
        Some(px) => {
            if px.get("enabled").and_then(Value::as_bool) == Some(false) {
                bail!("Proxy is disabled");
            }

            let srv = string(px, "server").trim();
            if srv.is_empty() {
                bail!("Proxy server cannot be empty");
            }

            let proxy_url_str = to_proxy_url(px)?;
            let req_proxy = reqwest::Proxy::all(&proxy_url_str)
                .map_err(|e| anyhow!("Invalid reqwest proxy URL: {}", e))?;

            reqwest::blocking::Client::builder()
                .proxy(req_proxy)
                .timeout(timeout)
                .build()
                .map_err(|e| anyhow!("Failed to build proxied HTTP client: {}", e))
        }
    }
}

pub fn country_to_locale(country: &str) -> String {
    let upper = country.trim().to_ascii_uppercase();
    match upper.as_str() {
        "VN" => "vi-VN",
        "US" => "en-US",
        "GB" | "UK" => "en-GB",
        "AU" => "en-AU",
        "CA" => "en-CA",
        "JP" => "ja-JP",
        "KR" => "ko-KR",
        "CN" => "zh-CN",
        "TW" => "zh-TW",
        "DE" => "de-DE",
        "FR" => "fr-FR",
        "IT" => "it-IT",
        "ES" => "es-ES",
        "BR" | "PT" => "pt-BR",
        "RU" => "ru-RU",
        "UA" => "uk-UA",
        "PL" => "pl-PL",
        "NL" => "nl-NL",
        "TR" => "tr-TR",
        "IN" => "hi-IN",
        "ID" => "id-ID",
        "TH" => "th-TH",
        "PH" => "en-PH",
        "MY" => "ms-MY",
        "SG" => "en-SG",
        "MX" => "es-MX",
        "AR" => "es-AR",
        "SA" | "AE" | "EG" => "ar-SA",
        "IL" => "he-IL",
        "SE" => "sv-SE",
        "NO" => "nb-NO",
        "FI" => "fi-FI",
        "DK" => "da-DK",
        "CZ" => "cs-CZ",
        "RO" => "ro-RO",
        "HU" => "hu-HU",
        "GR" => "el-GR",
        other => return {
            if other.len() == 2 && other.chars().all(|c| c.is_ascii_alphabetic()) {
                format!("en-{}", other)
            } else {
                "en-US".to_string()
            }
        }
    }.to_owned()
}

pub struct BrowserProxy {
    pub prefs: Value,
    pub bridge: Option<ProxyBridge>,
}

pub struct Network {
    store: Arc<Store>,
    #[cfg(test)]
    pub(crate) egress_url: Option<String>,
}

impl Network {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store, #[cfg(test)] egress_url: None }
    }

    pub(crate) fn egress_url(&self) -> &str {
        #[cfg(test)]
        if let Some(url) = &self.egress_url { return url; }
        "https://api.ipify.org?format=json"
    }

    pub fn summary(&self, proxy: &Value) -> Value {
        summary(proxy)
    }

    pub fn client_for(&self, proxy: Option<&Value>) -> Result<reqwest::blocking::Client> {
        client_for(proxy)
    }

    fn resolve_proxy(&self, proxy: &Value) -> Result<Value> {
        let stored = if string(proxy, "id").is_empty() { None } else { self.store.get("proxies", string(proxy, "id"))? };
        let server = string(proxy, "server").trim();
        let server = if server.is_empty() { stored.as_ref().map_or("", |value| string(value, "server")) } else { server };
        let parsed = parse_proxy_line(server)?;
        let (username, password) = proxy_credentials(proxy, &parsed, stored.as_ref())?;
        let mut resolved = proxy.clone();
        let map = resolved.as_object_mut().ok_or_else(|| anyhow!("Proxy phải là object"))?;
        map.insert("server".into(), parsed["server"].clone());
        map.insert("username".into(), json!(username));
        map.insert("password".into(), json!(password));
        if map.get("name").and_then(Value::as_str).unwrap_or("").trim().is_empty() {
            let name = stored.as_ref().map_or("", |value| string(value, "name"));
            map.insert("name".into(), if name.is_empty() { parsed["name"].clone() } else { json!(name) });
        }
        map.entry("enabled").or_insert_with(|| stored.as_ref().and_then(|value| value.get("enabled")).cloned().unwrap_or_else(|| json!(true)));
        map.entry("last_check").or_insert_with(|| stored.as_ref().and_then(|value| value.get("last_check")).cloned().unwrap_or_else(|| json!({})));
        Ok(resolved)
    }

    pub fn save(&self, data: Value) -> Result<Value> {
        let _guard = self.store.operation.lock();
        let record = self.resolve_proxy(&data)?;
        let saved = self.store.put("proxies", record)?;
        let saved_id = string(&saved, "id");
        let saved_name = string(&saved, "name");
        self.store.log("INFO", &format!("Saved proxy {} ({})", saved_id, saved_name), "")?;
        Ok(saved)
    }

    pub fn import_text(&self, text: &str) -> Result<Vec<Value>> {
        let lines: Vec<&str> = text.lines().collect();
        let mut parsed_items = Vec::new();

        for (idx, raw_line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let stripped = raw_line.trim();
            if stripped.is_empty() || stripped.starts_with('#') {
                continue;
            }
            match parse_proxy_line(stripped) {
                Ok(item) => parsed_items.push(item),
                Err(e) => bail!("Line {} invalid proxy: {}", line_num, e),
            }
        }

        let _guard = self.store.operation.lock();
        let mut imported = Vec::with_capacity(parsed_items.len());
        for item in parsed_items {
            let saved = self.save(item)?;
            imported.push(saved);
        }

        self.store.log("INFO", &format!("Imported {} proxies from text", imported.len()), "")?;
        Ok(imported)
    }

    pub fn delete(&self, id: &str, profiles: &crate::profiles::Profiles) -> Result<()> {
        let _guard = self.store.operation.lock();
        let proxy = match self.store.get("proxies", id)? {
            Some(p) => p,
            None => return Ok(()),
        };

        // Clean default proxy in settings if configured
        let mut settings = self.store.settings()?;
        if string(&settings, "default_proxy_id") == id {
            if let Some(map) = settings.as_object_mut() {
                map.insert("default_proxy_id".into(), Value::String(String::new()));
            }
            self.store.save_settings(settings)?;
        }

        let assigned_ids = self.store.list("profiles")?.iter()
            .filter(|profile| string(profile, "proxy_id") == id)
            .map(|profile| string(profile, "id").to_owned()).collect::<Vec<_>>();
        profiles.set_many(&assigned_ids, "proxy_id", json!(""))?;

        self.store.delete("proxies", id)?;
        self.store.log("INFO", &format!("Deleted proxy {} ({})", id, string(&proxy, "name")), "")?;
        Ok(())
    }

    pub fn check(&self, proxy: &Value) -> Result<Value> {
        let resolved = self.resolve_proxy(proxy)?;
        let proxy_id = string(&resolved, "id").to_string();

        let mut last_check = json!({
            "ok": false,
            "latency_ms": 0,
            "ip": "",
            "country": "",
            "checked_at": utcnow(),
            "error": ""
        });

        let t0 = Instant::now();
        match self.client_for(Some(&resolved)) {
            Err(e) => {
                if let Some(map) = last_check.as_object_mut() {
                    map.insert("error".into(), Value::String(redact(&e.to_string())));
                }
            }
            Ok(client) => {
                match client.get(self.egress_url()).send() {
                    Ok(resp) => {
                        let elapsed = t0.elapsed();
                        let status = resp.status();
                        if status.is_success() {
                            if let Ok(data) = resp.json::<Value>() {
                                let raw_ip = string(&data, "ip").trim();
                                match raw_ip.parse::<IpAddr>() {
                                    Ok(parsed_ip) => {
                                        let ip = parsed_ip.to_string();
                                        let latency = (elapsed.as_millis() as u64).max(1);

                                        let mut country = String::new();
                                        if !ip.is_empty() {
                                            let geo_url = format!("https://ipwho.is/{}", ip);
                                            if let Ok(g_resp) = client.get(&geo_url).send() {
                                                if g_resp.status().is_success() {
                                                    if let Ok(g_data) = g_resp.json::<Value>() {
                                                        let c_code = string(&g_data, "country_code");
                                                        country = if !c_code.is_empty() {
                                                            c_code.to_string()
                                                        } else {
                                                            string(&g_data, "country").to_string()
                                                        };
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(map) = last_check.as_object_mut() {
                                            map.insert("ok".into(), Value::Bool(true));
                                            map.insert("latency_ms".into(), json!(latency));
                                            map.insert("ip".into(), Value::String(ip));
                                            map.insert("country".into(), Value::String(country));
                                        }
                                    }
                                    Err(_) => {
                                        if let Some(map) = last_check.as_object_mut() {
                                            let err = if raw_ip.is_empty() {
                                                "Proxy check returned missing IP address".to_string()
                                            } else {
                                                format!("Proxy check returned invalid IP address: '{}'", redact(raw_ip))
                                            };
                                            map.insert("error".into(), Value::String(err));
                                        }
                                    }
                                }
                            } else if let Some(map) = last_check.as_object_mut() {
                                map.insert("error".into(), Value::String("Phản hồi JSON không hợp lệ".into()));
                            }
                        } else if let Some(map) = last_check.as_object_mut() {
                            map.insert("error".into(), Value::String(format!("HTTP {}", status)));
                        }
                    }
                    Err(e) => {
                        if let Some(map) = last_check.as_object_mut() {
                            map.insert("error".into(), Value::String(redact(&e.to_string())));
                        }
                    }
                }
            }
        }

        // Persist last_check on saved proxy
        if !proxy_id.is_empty() {
            let _guard = self.store.operation.lock();
            if let Some(mut stored) = self.store.get("proxies", &proxy_id)? {
                if let Some(map) = stored.as_object_mut() {
                    map.insert("last_check".into(), last_check.clone());
                }
                self.store.put("proxies", stored)?;
            }
        }

        let is_ok = last_check.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let log_level = if is_ok { "INFO" } else { "WARNING" };
        let px_name = string(&resolved, "name");
        let msg = if is_ok {
            format!(
                "Proxy check for {}: OK ({}ms, IP: {})",
                px_name,
                last_check.get("latency_ms").unwrap_or(&json!(0)),
                string(&last_check, "ip")
            )
        } else {
            format!("Proxy check for {}: FAILED ({})", px_name, string(&last_check, "error"))
        };
        self.store.log(log_level, &msg, "")?;

        Ok(last_check)
    }

    pub fn check_all(&self) -> Result<Vec<Value>> {
        let proxies = self.store.list("proxies")?;
        let mut results = Vec::with_capacity(proxies.len());
        for px in proxies {
            let chk = self.check(&px)?;
            results.push(json!({
                "id": string(&px, "id"),
                "result": chk
            }));
        }
        Ok(results)
    }

    pub fn detect(&self, proxy: Option<&Value>) -> Result<Value> {
        let resolved = match proxy {
            Some(px) => Some(self.resolve_proxy(px)?),
            None => None,
        };
        let client = self.client_for(resolved.as_ref())?;
        // Step 1: Egress IP verification over HTTPS
        let ip;
        let ip_res1 = client
            .get(self.egress_url())
            .send()
            .and_then(|r| r.json::<Value>());
        match ip_res1 {
            Ok(data) => {
                ip = string(&data, "ip").trim().to_string();
            }
            Err(_) => {
                let ip_res2 = client
                    .get("https://icanhazip.com")
                    .send()
                    .and_then(|r| r.text());
                match ip_res2 {
                    Ok(txt) => ip = txt.trim().to_string(),
                    Err(e) => {
                        let err_msg = redact(&e.to_string());
                        self.store.log("ERROR", &format!("Egress IP detection failed: {}", err_msg), "")?;
                        bail!("Egress IP detection failed: {}", err_msg);
                    }
                }
            }
        }

        // Validate IP payload before proceeding
        if ip.is_empty() || ip.parse::<IpAddr>().is_err() {
            bail!("Egress IP detection returned invalid IP address: '{}'", redact(&ip));
        }

        // Step 2: Geolocation lookup for validated egress IP
        let mut country = String::new();
        let mut timezone = "UTC".to_string();
        let mut lat = 0.0f64;
        let mut lon = 0.0f64;

        let geo_res = client
            .get(&format!("https://ipwho.is/{}", ip))
            .send()
            .and_then(|r| r.json::<Value>());

        let mut geo_success = false;
        if let Ok(data) = geo_res {
            if data.get("success").and_then(Value::as_bool) == Some(true) {
                country = {
                    let code = string(&data, "country_code");
                    if !code.is_empty() {
                        code.to_string()
                    } else {
                        string(&data, "country").to_string()
                    }
                };
                if let Some(tz_obj) = data.get("timezone") {
                    if let Some(tz_id) = tz_obj.get("id").and_then(Value::as_str) {
                        timezone = tz_id.to_string();
                    }
                }
                lat = data.get("latitude").and_then(Value::as_f64).unwrap_or(0.0);
                lon = data.get("longitude").and_then(Value::as_f64).unwrap_or(0.0);
                geo_success = true;
            }
        }

        if !geo_success {
            // Secondary fallback endpoint
            let fallback_url = format!(
                "http://ip-api.com/json/{}?fields=status,message,country,countryCode,timezone,lat,lon",
                ip
            );
            let fb_res = client
                .get(&fallback_url)
                .send()
                .and_then(|r| r.json::<Value>());
            match fb_res {
                Ok(data) if string(&data, "status") == "success" => {
                    let code = string(&data, "countryCode");
                    country = if !code.is_empty() {
                        code.to_string()
                    } else {
                        string(&data, "country").to_string()
                    };
                    timezone = {
                        let tz = string(&data, "timezone");
                        if !tz.is_empty() {
                            tz.to_string()
                        } else {
                            "UTC".to_string()
                        }
                    };
                    lat = data.get("lat").and_then(Value::as_f64).unwrap_or(0.0);
                    lon = data.get("lon").and_then(Value::as_f64).unwrap_or(0.0);
                }
                Ok(data) => {
                    let msg = string(&data, "message");
                    bail!("Geolocation lookup failed for egress IP {}: {}", ip, msg);
                }
                Err(e) => {
                    let err_msg = redact(&e.to_string());
                    self.store.log(
                        "ERROR",
                        &format!("Geolocation lookup failed for egress IP {}: {}", ip, err_msg),
                        "",
                    )?;
                    bail!("Geolocation lookup failed for egress IP {}: {}", ip, err_msg);
                }
            }
        }

        let locale = country_to_locale(&country);

        let loc_result = json!({
            "ip": ip,
            "country": country,
            "timezone": timezone,
            "locale": locale,
            "latitude": lat,
            "longitude": lon,
            "locked": false
        });

        self.store.log(
            "INFO",
            &format!("Detected egress location: {} ({}, {}, {})", ip, country, timezone, locale),
            "",
        )?;

        Ok(loc_result)
    }

    pub fn browser_proxy(&self, proxy: &Value) -> Result<BrowserProxy> {
        let resolved = self.resolve_proxy(proxy)?;
        if resolved.get("enabled").and_then(Value::as_bool) == Some(false) {
            bail!("Proxy '{}' is disabled", string(&resolved, "name"));
        }

        let server_str = string(&resolved, "server").trim();
        if server_str.is_empty() {
            bail!("Proxy server cannot be empty");
        }

        let parsed = url::Url::parse(server_str).map_err(|e| anyhow!("Invalid proxy server URL: {}", e))?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().ok_or_else(|| anyhow!("Proxy host missing"))?;
        let port = parsed.port_or_known_default().ok_or_else(|| anyhow!("Proxy port missing"))?;

        let username = string(&resolved, "username").to_string();
        let password = if username.is_empty() { String::new() } else { string(&resolved, "password").to_string() };
        let has_auth = !username.is_empty() || !password.is_empty();

        let is_socks = scheme == "socks5" || scheme == "socks5h";
        let is_https = scheme == "https";

        if has_auth || is_https {
            // Authenticated proxy or HTTPS proxy: start loopback HTTP CONNECT bridge to avoid Firefox auth popups and handle TLS to proxy
            let upstream_protocol = if is_socks {
                UpstreamProtocol::Socks5
            } else if is_https {
                UpstreamProtocol::Https
            } else {
                UpstreamProtocol::Http
            };

            let bridge_config = BridgeConfig {
                upstream_protocol,
                upstream_host: host.to_string(),
                upstream_port: port,
                username: if username.is_empty() { None } else { Some(username) },
                password: if password.is_empty() { None } else { Some(password) },
                #[cfg(test)]
                root_store: None,
            };

            let bridge = ProxyBridge::start(bridge_config)?;
            let local_port = bridge.port();

            let prefs = json!({
                "network.proxy.type": 1,
                "network.proxy.http": "127.0.0.1",
                "network.proxy.http_port": local_port,
                "network.proxy.ssl": "127.0.0.1",
                "network.proxy.ssl_port": local_port,
                "network.proxy.share_proxy_settings": true,
                "network.proxy.socks": "",
                "network.proxy.socks_port": 0,
                "network.proxy.socks_version": 5,
                "network.proxy.socks_remote_dns": true,
                "network.proxy.no_proxies_on": ""
            });

            Ok(BrowserProxy {
                prefs,
                bridge: Some(bridge),
            })
        } else if is_socks {
            // Unauthenticated SOCKS5 proxy: native Firefox prefs directly
            let prefs = json!({
                "network.proxy.type": 1,
                "network.proxy.http": "",
                "network.proxy.http_port": 0,
                "network.proxy.ssl": "",
                "network.proxy.ssl_port": 0,
                "network.proxy.share_proxy_settings": false,
                "network.proxy.socks": host,
                "network.proxy.socks_port": port,
                "network.proxy.socks_version": 5,
                "network.proxy.socks_remote_dns": true,
                "network.proxy.no_proxies_on": ""
            });

            Ok(BrowserProxy { prefs, bridge: None })
        } else {
            // Unauthenticated HTTP proxy: native Firefox prefs directly
            let prefs = json!({
                "network.proxy.type": 1,
                "network.proxy.http": host,
                "network.proxy.http_port": port,
                "network.proxy.ssl": host,
                "network.proxy.ssl_port": port,
                "network.proxy.share_proxy_settings": true,
                "network.proxy.socks": "",
                "network.proxy.socks_port": 0,
                "network.proxy.socks_version": 5,
                "network.proxy.socks_remote_dns": true,
                "network.proxy.no_proxies_on": ""
            });

            Ok(BrowserProxy { prefs, bridge: None })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_line_all_formats() {
        // Percent-encoded URL credentials
        let res1 = parse_proxy_line("http://user%40name:pass%2Fword%3Aextra@127.0.0.1:8123").unwrap();
        assert_eq!(res1["server"], "http://127.0.0.1:8123");
        assert_eq!(res1["username"], "user@name");
        assert_eq!(res1["password"], "pass/word:extra");
        assert_eq!(to_proxy_url(&res1).unwrap(), "http://user%40name:pass%2Fword%3Aextra@127.0.0.1:8123");

        // user:pass@host:port
        let res2 = parse_proxy_line("user:secret@192.168.1.1:8080").unwrap();
        assert_eq!(res2["server"], "http://192.168.1.1:8080");
        assert_eq!(res2["username"], "user");
        assert_eq!(res2["password"], "secret");

        // host:port:user:pass
        let res3 = parse_proxy_line("127.0.0.1:9000:alice:bobpass").unwrap();
        assert_eq!(res3["server"], "http://127.0.0.1:9000");
        assert_eq!(res3["username"], "alice");
        assert_eq!(res3["password"], "bobpass");

        // user:pass:host:port
        let res4 = parse_proxy_line("admin:123456:10.0.0.1:3128").unwrap();
        assert_eq!(res4["server"], "http://10.0.0.1:3128");
        assert_eq!(res4["username"], "admin");
        assert_eq!(res4["password"], "123456");

        // host:port
        let res5 = parse_proxy_line("10.0.0.5:8888").unwrap();
        assert_eq!(res5["server"], "http://10.0.0.5:8888");
        assert_eq!(res5["username"], "");
        assert_eq!(res5["password"], "");

        // IPv6 bracketed
        let res6 = parse_proxy_line("http://[::1]:9000").unwrap();
        assert_eq!(res6["server"], "http://[::1]:9000");

        // SOCKS5 scheme
        let res7 = parse_proxy_line("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(res7["server"], "socks5://127.0.0.1:1080");
        assert_eq!(res7["username"], "user");
        assert_eq!(res7["password"], "pass");
        // to_proxy_url maps socks5 to socks5h for remote DNS
        assert_eq!(to_proxy_url(&res7).unwrap(), "socks5h://user:pass@127.0.0.1:1080");
    }

    #[test]
    fn default_http_ports_survive_import_save_and_browser_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let net = Network::new(Arc::new(Store::open(temp.path()).unwrap()));
        for server in ["http://127.0.0.1:80", "https://127.0.0.1:443"] {
            let imported = parse_proxy_line(server).unwrap();
            let saved = net.save(imported).unwrap();
            assert_eq!(to_proxy_url(&saved).unwrap(),server);
            assert!(net.browser_proxy(&saved).is_ok());
        }
        assert!(parse_proxy_line("socks5://127.0.0.1").is_err());
    }

    #[test]
    fn cleared_username_does_not_test_using_saved_authentication() {
        use std::{io::{BufRead, BufReader, Write}, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = format!("http://127.0.0.1:{}",listener.local_addr().unwrap().port());
        let capture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" { break; }
                headers.push_str(&line);
            }
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            headers
        });
        let temp = tempfile::tempdir().unwrap();
        let net = Network::new(Arc::new(Store::open(temp.path()).unwrap()));
        let saved = net.save(json!({"server":server,"username":"stored-user","password":"secret"})).unwrap();
        let checked = net.check(&json!({"id":saved["id"],"username":""})).unwrap();
        assert_eq!(checked["ok"],false);
        assert!(!capture.join().unwrap().to_ascii_lowercase().contains("proxy-authorization:"));
    }

    #[test]
    fn test_parse_proxy_line_invalid_scheme() {
        assert!(parse_proxy_line("ftp://127.0.0.1:21").is_err());
        assert!(parse_proxy_line("").is_err());
        assert!(parse_proxy_line("invalid-format-without-port").is_err());
    }

    #[test]
    fn test_summary_redacts_password_and_sets_flags() {
        let px = json!({
            "id": "px1",
            "name": "Live Proxy",
            "server": "http://127.0.0.1:8080",
            "username": "tester",
            "password": "super-secret-password",
            "enabled": true
        });

        let sum = summary(&px);
        assert!(sum.get("password").is_none());
        assert_eq!(sum["username"], "tester");
        assert_eq!(sum["has_password"], true);
        assert_eq!(sum["has_credentials"], true);

        // Proxy without password
        let px_no_pass = json!({
            "id": "px2",
            "server": "http://127.0.0.1:8080",
            "username": "",
            "password": ""
        });
        let sum2 = summary(&px_no_pass);
        assert_eq!(sum2["has_password"], false);
        assert_eq!(sum2["has_credentials"], false);
    }

    #[test]
    fn test_disabled_proxy_fails_closed() {
        let disabled = json!({
            "id": "disabled-1",
            "name": "Off",
            "server": "http://127.0.0.1:8080",
            "enabled": false
        });

        let client_res = client_for(Some(&disabled));
        assert!(client_res.is_err());
    }

    #[test]
    fn test_country_to_locale_mapping() {
        assert_eq!(country_to_locale("VN"), "vi-VN");
        assert_eq!(country_to_locale("US"), "en-US");
        assert_eq!(country_to_locale("JP"), "ja-JP");
        assert_eq!(country_to_locale("DE"), "de-DE");
        assert_eq!(country_to_locale("FR"), "fr-FR");
        assert_eq!(country_to_locale("ZZ"), "en-ZZ");
        assert_eq!(country_to_locale(""), "en-US");
    }

    #[test]
    fn test_network_save_credential_preservation_and_import() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let net = Network::new(store.clone());

        // Save initial proxy
        let p1 = net
            .save(json!({
                "name": "Proxy 1",
                "server": "http://127.0.0.1:8080",
                "username": "user1",
                "password": "initial-secret"
            }))
            .unwrap();
        let id = string(&p1, "id").to_string();
        assert_eq!(p1["username"], "user1");
        assert_eq!(p1["password"], "initial-secret");

        // Edit without password field preserves existing password
        let p1_edit = net
            .save(json!({
                "id": id,
                "name": "Proxy 1 Renamed"
            }))
            .unwrap();
        assert_eq!(p1_edit["name"], "Proxy 1 Renamed");
        assert_eq!(p1_edit["password"], "initial-secret");

        // Explicit clear password
        let p1_cleared = net
            .save(json!({
                "id": id,
                "password": ""
            }))
            .unwrap();
        assert_eq!(p1_cleared["password"], "");

        // Import text with one invalid line does not commit anything
        let err_import = net.import_text("127.0.0.1:8080\nftp://127.0.0.1:21");
        assert!(err_import.is_err());

        // Valid import
        let imported = net
            .import_text("127.0.0.1:9090:admin:pass\nsocks5://127.0.0.1:1080")
            .unwrap();
        assert_eq!(imported.len(), 2);
    }

    #[test]
    fn test_browser_proxy_prefs_zeros_unused_keys() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let net = Network::new(store);

        // Authenticated HTTP proxy uses bridge and clears socks
        let auth_http = json!({
            "name": "Auth HTTP",
            "server": "http://1.2.3.4:8080",
            "username": "user",
            "password": "pass",
            "enabled": true
        });
        let bp1 = net.browser_proxy(&auth_http).unwrap();
        assert!(bp1.bridge.is_some());
        assert_eq!(bp1.prefs["network.proxy.type"], 1);
        assert_eq!(bp1.prefs["network.proxy.http"], "127.0.0.1");
        assert_eq!(bp1.prefs["network.proxy.socks"], "");
        assert_eq!(bp1.prefs["network.proxy.socks_port"], 0);

        // Direct SOCKS5 without auth sets socks and clears http/ssl
        let direct_socks = json!({
            "name": "Direct SOCKS",
            "server": "socks5://1.2.3.4:1080",
            "username": "",
            "password": "",
            "enabled": true
        });
        let bp2 = net.browser_proxy(&direct_socks).unwrap();
        assert!(bp2.bridge.is_none());
        assert_eq!(bp2.prefs["network.proxy.type"], 1);
        assert_eq!(bp2.prefs["network.proxy.socks"], "1.2.3.4");
        assert_eq!(bp2.prefs["network.proxy.socks_port"], 1080);
        assert_eq!(bp2.prefs["network.proxy.http"], "");
        assert_eq!(bp2.prefs["network.proxy.http_port"], 0);
        assert_eq!(bp2.prefs["network.proxy.ssl"], "");
        assert_eq!(bp2.prefs["network.proxy.ssl_port"], 0);
    }

    #[test]
    fn test_client_for_empty_server_fails_closed() {
        assert!(client_for(Some(&json!({"server": ""}))).is_err());
        assert!(client_for(Some(&json!({}))).is_err());
        assert!(client_for(None).is_ok());
    }

    #[test]
    fn saved_proxy_credentials_preserve_omissions_and_clear_explicit_fields() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let net = Network::new(store);

        let saved = net
            .save(json!({
                "server": "http://127.0.0.1:8080",
                "username": "saved-user",
                "password": "saved-pass"
            }))
            .unwrap();
        let id = string(&saved, "id");

        // Resolving with only id recovers server and credentials
        let res1 = net.resolve_proxy(&json!({ "id": id })).unwrap();
        assert_eq!(res1["server"], "http://127.0.0.1:8080");
        assert_eq!(res1["username"], "saved-user");
        assert_eq!(res1["password"], "saved-pass");
        assert_eq!(to_proxy_url(&res1).unwrap(), "http://saved-user:saved-pass@127.0.0.1:8080");

        // Explicit empty username stays cleared
        let res2 = net.resolve_proxy(&json!({ "id": id, "username": "" })).unwrap();
        assert_eq!(res2["username"], "");
        assert_eq!(res2["password"], "saved-pass");
        assert_eq!(to_proxy_url(&res2).unwrap(), "http://127.0.0.1:8080");
        assert!(net.browser_proxy(&res2).unwrap().bridge.is_none());

        // Explicit empty password stays cleared
        let res3 = net.resolve_proxy(&json!({ "id": id, "password": "" })).unwrap();
        assert_eq!(res3["username"], "saved-user");
        assert_eq!(res3["password"], "");
        assert_eq!(to_proxy_url(&res3).unwrap(), "http://saved-user@127.0.0.1:8080");
    }

    #[test]
    fn test_normalization_bare_host_port_and_embedded_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let net = Network::new(store);

        // Bare host:port normalization
        let norm_bare = net.resolve_proxy(&json!({ "server": "127.0.0.1:9090" })).unwrap();
        assert_eq!(norm_bare["server"], "http://127.0.0.1:9090");
        assert_eq!(to_proxy_url(&json!({ "server": "127.0.0.1:9090" })).unwrap(), "http://127.0.0.1:9090");

        let embedded = json!({"server": "http://alice:secret@127.0.0.1:9090"});
        let saved = net.save(embedded.clone()).unwrap();
        assert_eq!(saved["server"], "http://127.0.0.1:9090");
        assert_eq!(saved["username"], "alice");
        assert_eq!(saved["password"], "secret");
        assert_eq!(to_proxy_url(&embedded).unwrap(), to_proxy_url(&saved).unwrap());
        let cleared = json!({"server": "http://alice:secret@127.0.0.1:9090", "username": "", "password": ""});
        let saved_clear = net.save(cleared.clone()).unwrap();
        assert_eq!(saved_clear["username"], "");
        assert_eq!(saved_clear["password"], "");
        assert_eq!(to_proxy_url(&cleared).unwrap(), "http://127.0.0.1:9090");
        assert_eq!(to_proxy_url(&cleared).unwrap(), to_proxy_url(&saved_clear).unwrap());

    }
    #[test]
    fn check_all_continues_when_proxy_returns_invalid_or_missing_ip() {
        use std::{io::{BufRead, BufReader, Write}, net::TcpListener};

        fn spawn_mock(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let server = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    drop(listener);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
            });
            (server, handle)
        }

        let (srv1, h1) = spawn_mock(r#"{"ip":"http://user:secret@not-an-ip"}"#);
        let (srv2, h2) = spawn_mock(r#"{"other":"missing-ip"}"#);
        let (srv3, h3) = spawn_mock(r#"{"ip":"198.51.100.42"}"#);

        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let mut net = Network::new(store.clone());
        net.egress_url = Some("http://egress.local/".into());

        let p1 = net.save(json!({"name": "Proxy 1", "server": srv1})).unwrap();
        let p2 = net.save(json!({"name": "Proxy 2", "server": srv2})).unwrap();
        let p3 = net.save(json!({"name": "Proxy 3", "server": srv3})).unwrap();

        let id1 = string(&p1, "id").to_string();
        let id2 = string(&p2, "id").to_string();
        let id3 = string(&p3, "id").to_string();

        let results = net.check_all().unwrap();
        assert_eq!(results.len(), 3);

        // Proxy 1 (invalid IP with credentials redacted)
        assert_eq!(results[0]["id"], id1);
        assert_eq!(results[0]["result"]["ok"], false);
        let err1 = string(&results[0]["result"], "error");
        assert!(err1.contains("invalid IP address"));
        assert!(!err1.contains("secret"));
        assert!(err1.contains("***"));

        // Proxy 2 (missing IP)
        assert_eq!(results[1]["id"], id2);
        assert_eq!(results[1]["result"]["ok"], false);
        let err2 = string(&results[1]["result"], "error");
        assert!(err2.contains("missing IP address"));

        // Proxy 3 (valid IP unaffected)
        assert_eq!(results[2]["id"], id3);
        assert_eq!(results[2]["result"]["ok"], true);
        assert_eq!(results[2]["result"]["ip"], "198.51.100.42");

        // Verify persistence in store for all entries
        let stored1 = net.store.get("proxies", &id1).unwrap().unwrap();
        assert_eq!(stored1["last_check"]["ok"], false);
        assert!(string(&stored1["last_check"], "error").contains("invalid IP address"));

        let stored2 = net.store.get("proxies", &id2).unwrap().unwrap();
        assert_eq!(stored2["last_check"]["ok"], false);
        assert!(string(&stored2["last_check"], "error").contains("missing IP address"));

        let stored3 = net.store.get("proxies", &id3).unwrap().unwrap();
        assert_eq!(stored3["last_check"]["ok"], true);
        assert_eq!(stored3["last_check"]["ip"], "198.51.100.42");

        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();

        // Direct check on a single proxy also returns ok: false instead of Err
        let (srv_single, h_single) = spawn_mock(r#"{"ip":"invalid-single"}"#);
        let p_single = net.save(json!({"name": "Proxy Single", "server": srv_single})).unwrap();
        let chk_single = net.check(&p_single).unwrap();
        assert_eq!(chk_single["ok"], false);
        assert!(string(&chk_single, "error").contains("invalid IP address"));
        h_single.join().unwrap();
    }
}
