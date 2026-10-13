use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::{fs, net::IpAddr, path::{Path, PathBuf}, time::{Duration, Instant}};
use crate::{files::reject_link, store::{new_id, string}};

pub(crate) struct IpSync {
    pub addon_dir: PathBuf,
    state_path: PathBuf,
    token: String,
    sequence: u64,
    last_progress: Instant,
}

impl IpSync {
    pub(crate) fn prepare(profile_dir: &Path, endpoint: &str, proxy_prefs: &Value) -> Result<Self> {
        let manager_dir = profile_dir.join("manager-addons");
        let addon_dir = manager_dir.join("ip-sync");
        for path in [profile_dir, &manager_dir, &addon_dir] { reject_link(path)?; }
        fs::create_dir_all(&addon_dir)?;
        let token = new_id();
        let state_path = addon_dir.join("state.json");
        let state_tmp = addon_dir.join("state.json.tmp");
        let manifest = json!({
            "manifest_version": 2,
            "name": "CamouManager Proxy IP Monitor",
            "version": "1.0.0",
            "browser_specific_settings": {"gecko": {"id": "camoumanager-ip-sync@local.invalid"}},
            "permissions": [url::Url::parse(endpoint)?.join("/")?.as_str().to_owned() + "*"],
            "background": {"scripts": ["settings.js", "background.js"]},
            "experiment_apis": {"ipSync": {"schema": "schema.json", "parent": {
                "scopes": ["addon_parent"], "paths": [["ipSync"]], "script": "api.js"
            }}}
        });
        let schema = json!([{"namespace": "ipSync", "functions": [
            {"name": "confirm", "type": "function", "async": true, "parameters": [{"name": "ip", "type": "string"}]},
            {"name": "fail", "type": "function", "async": true, "parameters": [{"name": "message", "type": "string"}]}
        ]}]);
        let settings = json!({"endpoint": endpoint});
        let native_settings = json!({"token": token, "statePath": state_path, "tmpPath": state_tmp, "proxyPrefs": proxy_prefs});
        let files = [
            ("manifest.json", serde_json::to_string(&manifest)?),
            ("schema.json", serde_json::to_string(&schema)?),
            ("settings.js", format!("const IP_SYNC_SETTINGS = {settings};\n")),
            ("background.js", include_str!("ip_sync.js").to_owned()),
            ("api.js", format!("const IP_SYNC_NATIVE = {native_settings};\n{}", include_str!("ip_sync_api.js"))),
            ("state.json", json!({"token": token, "sequence": 0, "ip": "", "error": ""}).to_string()),
        ];
        for (name, contents) in files {
            let path = addon_dir.join(name);
            reject_link(&path)?;
            fs::write(path, contents)?;
        }
        reject_link(&state_tmp)?;
        // Session-specific addon settings must not reuse Gecko's cached extension startup data.
        let browser_dir = profile_dir.join("browser");
        let cache_dir = browser_dir.join("startupCache");
        let cache_path = cache_dir.join("webext.sc.lz4");
        for path in [&browser_dir, &cache_dir, &cache_path] { reject_link(path)?; }
        match fs::remove_file(&cache_path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
        Ok(Self { addon_dir, state_path, token, sequence: 0, last_progress: Instant::now() })
    }

    pub(crate) fn poll(&mut self) -> Result<Option<String>> {
        reject_link(&self.state_path)?;
        if fs::metadata(&self.state_path)?.len() > 16 * 1024 { bail!("Trạng thái đồng bộ IP vượt giới hạn"); }
        let state: Value = serde_json::from_slice(&fs::read(&self.state_path)?)?;
        if string(&state, "token") != self.token { bail!("Trạng thái đồng bộ IP không thuộc phiên hiện tại"); }
        let error = string(&state, "error");
        if !error.is_empty() { bail!("Đồng bộ IP thất bại: {error}"); }
        let sequence = state["sequence"].as_u64().ok_or_else(|| anyhow!("Trạng thái đồng bộ IP không hợp lệ"))?;
        let mut ip = None;
        if sequence != self.sequence {
            let observed: IpAddr = string(&state, "ip").parse()?;
            ip = Some(observed.to_string());
            self.sequence = sequence;
            self.last_progress = Instant::now();
        }
        if self.last_progress.elapsed() > Duration::from_secs(45) { bail!("Đồng bộ IP không phản hồi trong 45 giây"); }
        Ok(ip)
    }

    pub(crate) fn is_ready(&self) -> bool { self.sequence != 0 }
}

pub(crate) fn update_profile_ip(profile: &mut Value, ip: &str) -> Result<bool> {
    let ip: IpAddr = ip.parse()?;
    let ip = ip.to_string();
    let (key, other) = if ip.contains(':') { ("webrtc:ipv6", "webrtc:ipv4") } else { ("webrtc:ipv4", "webrtc:ipv6") };
    let fp = profile.get("fingerprint").and_then(Value::as_object).ok_or_else(|| anyhow!("Fingerprint không hợp lệ"))?;
    if !profile["location"].is_object() { bail!("Vị trí hồ sơ không hợp lệ"); }
    if string(&profile["location"], "ip") == ip && fp.get(key).and_then(Value::as_str) == Some(ip.as_str()) && !fp.contains_key(other) {
        return Ok(false);
    }
    profile["location"]["ip"] = json!(ip);
    let fp = profile["fingerprint"].as_object_mut().unwrap();
    fp.remove(other);
    fp.insert(key.into(), json!(ip));
    Ok(true)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_invalidates_extension_cache_without_deleting_browser_data() {
        let home = tempfile::tempdir().unwrap();
        let browser = home.path().join("browser");
        let cache = browser.join("startupCache");
        fs::create_dir_all(&cache).unwrap();
        let cached_extensions = cache.join("webext.sc.lz4");
        let preserved = [browser.join("cookies.sqlite"), browser.join("sessionstore.jsonlz4"), cache.join("startupCache.8.little")];
        for path in &preserved { fs::write(path, b"existing data").unwrap(); }
        for _ in 0..2 {
            fs::write(&cached_extensions, b"stale extension startup data").unwrap();
            IpSync::prepare(home.path(), "https://api.ipify.org?format=json", &Value::Null).unwrap();
            assert!(!cached_extensions.exists());
            for path in &preserved { assert_eq!(fs::read(path).unwrap(), b"existing data"); }
        }
        IpSync::prepare(home.path(), "https://api.ipify.org?format=json", &Value::Null).unwrap();
        fs::create_dir(&cached_extensions).unwrap();
        assert!(IpSync::prepare(home.path(), "https://api.ipify.org?format=json", &Value::Null).is_err());
        assert!(cached_extensions.is_dir());
    }


    #[test]
    fn observed_proxy_ip_wins_over_locked_location_and_preserves_identity() {
        let mut profile = json!({"location": {"ip": "198.51.100.9", "locked": true, "timezone": "Asia/Ho_Chi_Minh"},
            "fingerprint": {"webrtc:ipv4": "198.51.100.9", "webrtc:ipv6": "2001:db8::9", "audio:seed": 7, "fonts": ["Arial"]}});
        assert!(update_profile_ip(&mut profile, "203.0.113.2").unwrap());
        assert_eq!(profile["location"]["ip"], "203.0.113.2");
        assert_eq!(profile["fingerprint"]["webrtc:ipv4"], "203.0.113.2");
        assert!(profile["fingerprint"].get("webrtc:ipv6").is_none());
        assert_eq!(profile["location"]["timezone"], "Asia/Ho_Chi_Minh");
        assert_eq!(profile["fingerprint"]["audio:seed"], 7);
        assert_eq!(profile["fingerprint"]["fonts"], json!(["Arial"]));
        assert!(!update_profile_ip(&mut profile, "203.0.113.2").unwrap());
        assert!(update_profile_ip(&mut profile, "2001:db8::2").unwrap());
        assert_eq!(profile["fingerprint"]["webrtc:ipv6"], "2001:db8::2");
        assert!(profile["fingerprint"].get("webrtc:ipv4").is_none());
        let before = profile.clone();
        assert!(update_profile_ip(&mut profile, "bad-ip").is_err());
        assert_eq!(profile, before);
    }

    #[test]
    fn synchronization_rejects_stale_sessions_bad_ips_and_lost_heartbeat() {
        let home = tempfile::tempdir().unwrap();
        let mut sync = IpSync::prepare(home.path(), "https://api.ipify.org?format=json", &Value::Null).unwrap();
        let state = |sync: &IpSync, ip: &str, token: &str, sequence: u64, error: &str| {
            fs::write(&sync.state_path, json!({"token": token, "sequence": sequence, "ip": ip, "error": error}).to_string()).unwrap();
        };
        assert_eq!(sync.poll().unwrap(), None);
        state(&sync, "203.0.113.1", &sync.token, 1, "");
        assert_eq!(sync.poll().unwrap().as_deref(), Some("203.0.113.1"));
        assert!(sync.is_ready());
        assert_eq!(sync.poll().unwrap(), None);
        state(&sync, "2001:db8::1", &sync.token, 2, "");
        assert_eq!(sync.poll().unwrap().as_deref(), Some("2001:db8::1"));
        state(&sync, "203.0.113.1", "old-session", 3, "");
        assert!(sync.poll().is_err());
        state(&sync, "bad-ip", &sync.token, 3, "");
        assert!(sync.poll().is_err());
        state(&sync, "2001:db8::1", &sync.token, 2, "");
        sync.last_progress = Instant::now() - Duration::from_secs(46);
        assert!(sync.poll().is_err());
        state(&sync, "2001:db8::1", &sync.token, 3, "native update failed");
        assert!(sync.poll().unwrap_err().to_string().contains("native update failed"));
        state(&sync, "203.0.113.2", &sync.token, 4, "");
        assert_eq!(sync.poll().unwrap().as_deref(), Some("203.0.113.2"));
    }
}
