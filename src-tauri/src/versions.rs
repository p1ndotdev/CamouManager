use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use parking_lot::{Condvar, Mutex};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const GITHUB_RELEASES_URL: &str = "https://api.github.com/repos/daijro/camoufox/releases";
const MAX_UNCOMPRESSED_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB safe limit

/// Check if asset name corresponds to Windows x86_64 build.
pub fn is_win_x86_64_asset(asset_name: &str) -> bool {
    let lower = asset_name.to_lowercase();
    if !lower.ends_with(".zip") {
        return false;
    }
    if !lower.contains("win") && !lower.contains("windows") {
        return false;
    }
    if lower.contains("i686") || lower.contains("x86.") || lower.contains("win32") {
        return false;
    }
    if lower.contains("font") {
        return false;
    }
    lower.contains("x86_64") || lower.contains("x64") || lower.contains("amd64") || lower.contains("win64")
}

/// Check if a release tag and name correspond to a browser release rather than font/auxiliary bundle.
pub fn is_browser_release(tag: &str, name: &str) -> bool {
    let tag_lower = tag.to_lowercase();
    let name_lower = name.to_lowercase();
    if tag_lower.starts_with("font") || tag_lower.contains("fonts") {
        return false;
    }
    if name_lower.starts_with("font") || name_lower.contains("fonts") {
        return false;
    }
    let clean = tag.trim().trim_start_matches(['v', 'V']);
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^\d+\.\d+").unwrap());
    RE.is_match(clean)
}

/// Parse tag like 'v156.0.1-beta.36' into (version, build).
pub fn parse_tag_version(tag: &str) -> (String, String) {
    let clean = tag.trim().trim_start_matches(['v', 'V']);
    let clean = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^(\d+\.\d+(?:\.\d+)?)(?:-([a-zA-Z0-9.]+))?$").unwrap()
    });
    if let Some(caps) = RE.captures(clean) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or(clean).to_string();
        let build = caps.get(2).map(|m| m.as_str()).unwrap_or(&ver).to_string();
        (ver, build)
    } else {
        (clean.to_string(), clean.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrereleaseToken {
    Numeric(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReleaseStage {
    Prerelease(Vec<PrereleaseToken>),
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionSortKey {
    pub release: Vec<u64>,
    pub stage: ReleaseStage,
}

pub fn parse_version_key(tag: &str) -> VersionSortKey {
    let mut clean = tag.trim();
    if let Some(stripped) = clean.strip_prefix("Camoufox") {
        clean = stripped.trim();
    }
    clean = clean.trim_start_matches(['v', 'V']).trim();

    if clean.is_empty() {
        return VersionSortKey {
            release: vec![0, 0, 0],
            stage: ReleaseStage::Prerelease(Vec::new()),
        };
    }

    // Build metadata is separated by '+' and must be ignored in version precedence.
    let clean_no_build = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);

    let (rel_str, pre_str) = match clean_no_build.split_once('-') {
        Some((rel, pre)) => (rel, Some(pre)),
        None => (clean_no_build, None),
    };

    let mut release: Vec<u64> = rel_str
        .split('.')
        .filter_map(|part| part.trim().parse::<u64>().ok())
        .collect();

    if release.is_empty() {
        release = vec![0, 0, 0];
    } else {
        while release.len() < 3 {
            release.push(0);
        }
    }

    // shortcut: simple semver prerelease tokenizer, upgrade to semver crate if complex build expressions are needed.
    let stage = match pre_str {
        None => ReleaseStage::Final,
        Some(pre) => {
            let pre = pre.trim();
            if pre.is_empty() {
                ReleaseStage::Prerelease(Vec::new())
            } else {
                let mut tokens = Vec::new();
                for chunk in pre.split('.') {
                    let chunk = chunk.trim();
                    if chunk.is_empty() {
                        continue;
                    }
                    if let Ok(num) = chunk.parse::<u64>() {
                        tokens.push(PrereleaseToken::Numeric(num));
                    } else if let Some(idx) = chunk.find(|c: char| c.is_ascii_digit()) {
                        if idx > 0 && chunk[idx..].chars().all(|c| c.is_ascii_digit()) {
                            tokens.push(PrereleaseToken::Text(chunk[..idx].to_ascii_lowercase()));
                            if let Ok(num) = chunk[idx..].parse::<u64>() {
                                tokens.push(PrereleaseToken::Numeric(num));
                            }
                        } else {
                            tokens.push(PrereleaseToken::Text(chunk.to_ascii_lowercase()));
                        }
                    } else {
                        tokens.push(PrereleaseToken::Text(chunk.to_ascii_lowercase()));
                    }
                }
                ReleaseStage::Prerelease(tokens)
            }
        }
    };

    VersionSortKey { release, stage }
}

/// Sort key for sorting versions newest semantic release first.
pub fn version_sort_key(record: &Value) -> VersionSortKey {
    if let Some(s) = record.as_str() {
        return parse_version_key(s);
    }
    let tag = record
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| record.get("tag_name").and_then(Value::as_str))
        .or_else(|| record.get("name").and_then(Value::as_str))
        .unwrap_or("");
    if tag.is_empty() {
        if let Some(v) = record.get("version").and_then(Value::as_str) {
            if let Some(b) = record.get("build").and_then(Value::as_str) {
                if !b.is_empty() && b != v {
                    return parse_version_key(&format!("{v}-{b}"));
                }
            }
            return parse_version_key(v);
        }
    }
    parse_version_key(tag)
}

/// Validate version identifier is a single safe path component.
pub fn validate_safe_version_id(version_id: &str) -> Result<()> {
    if version_id.is_empty() {
        return Err(anyhow!("Invalid version identifier ''"));
    }
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z0-9_.-]+$").unwrap());
    if !RE.is_match(version_id) {
        return Err(anyhow!("Invalid version identifier '{}'", version_id));
    }
    if version_id == "." || version_id == ".." || version_id.contains("..") || version_id.contains('/') || version_id.contains('\\') {
        return Err(anyhow!("Directory traversal detected in version identifier '{}'", version_id));
    }
    crate::store::safe_component(version_id)
}

/// HTTP request descriptor for transport execution.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name_lower))
            .map(|(_, v)| v.as_str())
    }
}

/// HTTP response descriptor containing status code, headers, and readable body stream.
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read + Send>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name_lower))
            .map(|(_, v)| v.as_str())
    }
}

/// Transport abstraction allowing real reqwest calls or deterministic mock streams.
pub trait Transport: Send + Sync {
    fn execute(&self, req: HttpRequest) -> Result<HttpResponse>;
}

/// Default production transport backed by reqwest blocking client.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { client }
    }
}

impl Transport for ReqwestTransport {
    fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
        let mut builder = self.client.get(&req.url);
        for (k, v) in req.headers {
            builder = builder.header(&k, &v);
        }
        let resp = builder.send().context("HTTP request failed")?;
        let status = resp.status().as_u16();
        let mut headers = Vec::new();
        for (k, v) in resp.headers() {
            if let Ok(v_str) = v.to_str() {
                headers.push((k.as_str().to_lowercase(), v_str.to_string()));
            }
        }
        Ok(HttpResponse {
            status,
            headers,
            body: Box::new(resp),
        })
    }
}

#[derive(Debug, Clone)]
struct InstallStatus {
    version_id: String,
    name: String,
    state: String,
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
    error: String,
}

/// RAII admission guard ensuring independent worker ownership through full cleanup.
struct ActiveGuard {
    active_worker: Arc<AtomicBool>,
    staging_dir: Arc<Mutex<Option<PathBuf>>>,
    #[cfg(test)]
    cleanup_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(hook) = &self.cleanup_hook {
            hook();
        }
        if let Some(dir) = self.staging_dir.lock().take() {
            let _ = fs::remove_dir_all(&dir);
        }
        self.active_worker.store(false, Ordering::SeqCst);
    }
}

/// Versions service managing Camoufox installations, updates, discovery, and deletion.
pub struct Versions {
    store: Arc<crate::store::Store>,
    transport: Arc<dyn Transport>,
    status: Mutex<InstallStatus>,
    active_worker: Arc<AtomicBool>,
    pause_requested: Arc<AtomicBool>,
    pause_epoch: AtomicU64,
    cancel_requested: Arc<AtomicBool>,
    wake_cond: Arc<(Mutex<()>, Condvar)>,
    #[cfg(test)]
    cleanup_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Versions {
    pub fn new(store: Arc<crate::store::Store>) -> Self {
        Self::with_transport(store, Arc::new(ReqwestTransport::default()))
    }

    pub fn with_transport(store: Arc<crate::store::Store>, transport: Arc<dyn Transport>) -> Self {
        Self {
            store,
            transport,
            status: Mutex::new(InstallStatus {
                version_id: String::new(),
                name: String::new(),
                state: "idle".to_string(),
                downloaded_bytes: 0,
                total_bytes: None,
                error: String::new(),
            }),
            active_worker: Arc::new(AtomicBool::new(false)),
            pause_requested: Arc::new(AtomicBool::new(false)),
            pause_epoch: AtomicU64::new(0),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            wake_cond: Arc::new((Mutex::new(()), Condvar::new())),
            #[cfg(test)]
            cleanup_hook: None,
        }
    }

    #[cfg(test)]
    pub fn set_cleanup_hook(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.cleanup_hook = Some(hook);
    }

    /// Return the current installation status matching the frontend contract.
    pub fn status(&self) -> Value {
        let st = self.status.lock();
        json!({
            "version_id": st.version_id,
            "name": st.name,
            "state": st.state,
            "downloaded_bytes": st.downloaded_bytes,
            "total_bytes": st.total_bytes,
            "error": st.error,
        })
    }

    /// Check if an installation worker is currently active.
    pub fn is_active(&self) -> bool {
        if self.active_worker.load(Ordering::SeqCst) {
            return true;
        }
        let st = self.status.lock();
        matches!(
            st.state.as_str(),
            "downloading" | "paused" | "verifying" | "extracting" | "installing"
        )
    }

    /// Cooperatively control an active installation ('pause', 'resume', 'cancel').
    pub fn control(&self, version_id: &str, action: &str) -> Result<Value> {
        if !matches!(action, "pause" | "resume" | "cancel") {
            return Err(anyhow!("Unsupported action '{}'", action));
        }

        let mut st = self.status.lock();
        let current_id = &st.version_id;
        let current_state = &st.state;

        if matches!(current_state.as_str(), "idle" | "completed" | "cancelled" | "error")
            || current_id != version_id
        {
            return Err(anyhow!("No active installation matching id '{}'", version_id));
        }

        match action {
            "pause" => {
                if current_state != "downloading" {
                    return Err(anyhow!("Cannot pause installation in '{}' state", current_state));
                }
                self.pause_requested.store(true, Ordering::SeqCst);
                self.pause_epoch.fetch_add(1,Ordering::SeqCst);
                st.state = "paused".to_string();
            }
            "resume" => {
                if current_state != "paused" {
                    return Err(anyhow!("Cannot resume installation in '{}' state", current_state));
                }
                self.pause_requested.store(false, Ordering::SeqCst);
                st.state = "downloading".to_string();
                self.wake_cond.1.notify_all();
            }
            "cancel" => {
                if !matches!(
                    current_state.as_str(),
                    "downloading" | "paused" | "verifying" | "extracting"
                ) {
                    return Err(anyhow!("Cannot cancel installation in '{}' state", current_state));
                }
                self.cancel_requested.store(true, Ordering::SeqCst);
                st.state = "cancelled".to_string();
                self.wake_cond.1.notify_all();
            }
            _ => unreachable!(),
        }

        Ok(json!({
            "version_id": st.version_id,
            "name": st.name,
            "state": st.state,
            "downloaded_bytes": st.downloaded_bytes,
            "total_bytes": st.total_bytes,
            "error": st.error,
        }))
    }

    /// Fetch available official GitHub releases for Windows x86_64 Camoufox.
    pub fn available(&self) -> Result<Vec<Value>> {
        let mut headers = vec![
            ("User-Agent".to_string(), "CamouManager".to_string()),
            ("Accept".to_string(), "application/vnd.github.v3+json".to_string()),
        ];

        // Credential token only sent to exact api.github.com host
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if !token.is_empty() {
                headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
            }
        }

        let resp = self
            .transport
            .execute(HttpRequest {
                url: GITHUB_RELEASES_URL.to_string(),
                headers,
            })
            .context("Network error querying GitHub releases")?;

        if resp.status != 200 {
            return Err(anyhow!("GitHub releases query failed with status {}", resp.status));
        }

        let mut body_str = String::new();
        let mut reader = resp.body;
        reader.read_to_string(&mut body_str)?;

        let releases_data: Value = serde_json::from_str(&body_str)
            .context("Failed to parse GitHub releases JSON")?;

        let releases_arr = match releases_data.as_array() {
            Some(arr) => arr,
            None => return Ok(Vec::new()),
        };

        let mut results = Vec::new();
        for rel in releases_arr {
            let tag_name = rel.get("tag_name").and_then(Value::as_str).unwrap_or("");
            let rel_name = rel.get("name").and_then(Value::as_str).unwrap_or(tag_name);

            // Reject font bundles or non-browser auxiliary releases
            if !is_browser_release(tag_name, rel_name) {
                continue;
            }

            let assets = match rel.get("assets").and_then(Value::as_array) {
                Some(a) => a,
                None => continue,
            };

            // Find Windows x86_64 browser asset
            let target_asset = assets
                .iter()
                .find(|a| {
                    let name = a.get("name").and_then(Value::as_str).unwrap_or("");
                    is_win_x86_64_asset(name)
                });

            let target_asset = match target_asset {
                Some(a) => a,
                None => continue,
            };

            let asset_name = target_asset.get("name").and_then(Value::as_str).unwrap_or("");
            let asset_url = target_asset
                .get("browser_download_url")
                .and_then(Value::as_str)
                .unwrap_or("");
            let asset_size = target_asset.get("size").and_then(Value::as_u64).unwrap_or(0);

            // Extract expected SHA256 from digest field if available
            let mut expected_sha256 = String::new();
            if let Some(digest_field) = target_asset.get("digest").and_then(Value::as_str) {
                if digest_field.to_lowercase().starts_with("sha256:") {
                    expected_sha256 = digest_field[7..].trim().to_lowercase();
                }
            }

            // If digest field is not present, check companion .sha256 asset
            if expected_sha256.is_empty() {
                let companion_name = format!("{}.sha256", asset_name);
                if let Some(comp_asset) = assets.iter().find(|a| {
                    a.get("name")
                        .and_then(Value::as_str)
                        .map(|n| n.eq_ignore_ascii_case(&companion_name))
                        .unwrap_or(false)
                }) {
                    if let Some(c_url) = comp_asset.get("browser_download_url").and_then(Value::as_str) {
                        if let Ok(c_resp) = self.transport.execute(HttpRequest {
                            url: c_url.to_string(),
                            headers: vec![("User-Agent".to_string(), "CamouManager".to_string())],
                        }) {
                            if c_resp.status == 200 {
                                let mut c_text = String::new();
                                let mut c_reader = c_resp.body;
                                if c_reader.read_to_string(&mut c_text).is_ok() {
                                    static SHA_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)\b[a-f0-9]{64}\b").unwrap());
                                    if let Some(m) = SHA_RE.find(&c_text) {
                                        expected_sha256 = m.as_str().to_lowercase();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let (ver, build) = parse_tag_version(tag_name);
            results.push(json!({
                "id": tag_name,
                "name": rel_name,
                "tag_name": tag_name,
                "version": ver,
                "build": build,
                "release_url": rel.get("html_url").and_then(Value::as_str).unwrap_or(""),
                "asset_name": asset_name,
                "asset_url": asset_url,
                "asset_size": asset_size,
                "size": asset_size, // Frontend size field
                "prerelease": rel.get("prerelease").and_then(Value::as_bool).unwrap_or(false),
                "draft": rel.get("draft").and_then(Value::as_bool).unwrap_or(false),
                "created_at": rel.get("created_at").and_then(Value::as_str).unwrap_or(""),
                "sha256": expected_sha256,
            }));
        }

        self.store.log(
            "INFO",
            &format!("Found {} available Windows x86_64 releases", results.len()),
            "",
        )?;
        Ok(results)
    }

    /// List all currently installed Camoufox browser versions, newest semantic release first.
    pub fn installed(&self) -> Result<Vec<Value>> {
        let _op = self.store.operation.lock();
        self.sync_disk_versions()?;
        let records = self.store.list("versions")?;
        let mut valid: Vec<Value> = records
            .into_iter()
            .filter(|r| {
                let p = r.get("path").and_then(Value::as_str).unwrap_or("");
                Path::new(p).is_file()
            })
            .collect();

        valid.sort_by(|a, b| version_sort_key(b).cmp(&version_sort_key(a)));
        Ok(valid)
    }

    /// Discover valid Camoufox installations in versions_dir, skipping staging/norm directories.
    fn sync_disk_versions(&self) -> Result<()> {
        if !self.store.versions_dir.exists() {
            return Ok(());
        }

        let existing_list = self.store.list("versions")?;
        let existing_map: HashMap<String, Value> = existing_list
            .into_iter()
            .filter_map(|r| {
                let id = r.get("id").and_then(Value::as_str)?.to_owned();
                Some((id, r))
            })
            .collect();

        let entries = match fs::read_dir(&self.store.versions_dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let child = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if !child.is_dir() || name.starts_with('.') {
                continue;
            }

            if crate::files::reject_link(&child).is_err() {
                continue;
            }

            let exe_path = if child.join("camoufox.exe").is_file() {
                child.join("camoufox.exe")
            } else if let Some(p) = find_camoufox_exe(&child) {
                p
            } else {
                continue;
            };

            if let Some(existing) = existing_map.get(&name) {
                let p_str = existing.get("path").and_then(Value::as_str).unwrap_or("");
                if Path::new(p_str).is_file() {
                    continue;
                }
            }

            let mut ver_info = serde_json::Map::new();
            let ver_file = exe_path.parent().unwrap_or(&child).join("version.json");
            if ver_file.is_file() {
                if let Ok(content) = fs::read_to_string(&ver_file) {
                    if let Ok(Value::Object(map)) = serde_json::from_str(&content) {
                        ver_info = map;
                    }
                }
            }

            let ver_name = ver_info
                .get("build")
                .and_then(Value::as_str)
                .or_else(|| ver_info.get("version").and_then(Value::as_str))
                .unwrap_or(&name);

            let record = json!({
                "id": name,
                "name": format!("Camoufox {}", ver_name),
                "path": exe_path.to_string_lossy(),
                "release_url": "",
                "installed_at": crate::store::utcnow(),
                "status": "installed",
            });
            let _ = self.store.put("versions", record);
        }

        Ok(())
    }

    /// Safely delete an installed version, verifying pinned status, junction escapes, and managed roots.
    pub fn delete(&self, version_id: &str) -> Result<()> {
        validate_safe_version_id(version_id)?;

        if self.is_active() {
            return Err(anyhow!("Hãy hoàn tất hoặc hủy tải trước khi xóa phiên bản"));
        }

        let _op = self.store.operation.lock();

        let profiles = self.store.list("profiles")?;
        let users: Vec<String> = profiles
            .iter()
            .filter(|p| p.get("browser_version").and_then(Value::as_str) == Some(version_id))
            .map(|p| {
                p.get("name")
                    .and_then(Value::as_str)
                    .or_else(|| p.get("id").and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        if !users.is_empty() {
            return Err(anyhow!(
                "Phiên bản đang được hồ sơ sử dụng: {}. Hãy đổi phiên bản của hồ sơ trước.",
                users.join(", ")
            ));
        }

        let target = self.store.versions_dir.join(version_id);
        crate::files::reject_link(&target)?;

        let versions_dir_canon = self
            .store
            .versions_dir
            .canonicalize()
            .unwrap_or_else(|_| self.store.versions_dir.clone());

        if target.exists() {
            let target_canon = target
                .canonicalize()
                .context("Failed to canonicalize target version path")?;
            if !target_canon.starts_with(&versions_dir_canon)
                || target_canon == versions_dir_canon
                || target_canon.parent() != Some(&versions_dir_canon)
            {
                return Err(anyhow!("Chỉ được xóa thư mục phiên bản được quản lý"));
            }
        }

        let record = self.store.get("versions", version_id)?;
        if let Some(rec) = &record {
            let rec_path_str = rec.get("path").and_then(Value::as_str).unwrap_or("");
            let rec_path = PathBuf::from(rec_path_str);
            if rec_path.exists() {
                let rec_canon = rec_path
                    .canonicalize()
                    .unwrap_or_else(|_| rec_path.clone());
                let expected_parent = versions_dir_canon.join(version_id);
                if !rec_canon.starts_with(&expected_parent) {
                    return Err(anyhow!(
                        "Đường dẫn trình duyệt nằm ngoài thư mục phiên bản được quản lý"
                    ));
                }
            }
        }

        if record.is_none() && !target.exists() {
            return Err(anyhow!("Không tìm thấy phiên bản đã cài"));
        }

        if target.exists() {
            fs::remove_dir_all(&target)?;
        }

        self.store.delete("versions", version_id)?;
        self.store.log("INFO", &format!("Deleted Camoufox {}", version_id), "")?;
        Ok(())
    }

    /// Download, verify SHA256, safely extract, and atomically register an official release.
    /// Resolves official release metadata internally; returns Ok(None) on cancellation.
    pub fn install(&self, id: &str) -> Result<Option<Value>> {
        validate_safe_version_id(id)?;

        // Return immediately if already installed without claiming active worker slot
        let target_dir = self.store.versions_dir.join(id);
        let exe_path = target_dir.join("camoufox.exe");
        if exe_path.exists() {
            let _op = self.store.operation.lock();
            if let Some(existing) = self.store.get("versions", id)? {
                return Ok(Some(existing));
            }
            let record = json!({
                "id": id,
                "name": format!("Camoufox {}", id),
                "path": exe_path.to_string_lossy(),
                "release_url": "",
                "installed_at": crate::store::utcnow(),
                "status": "installed",
            });
            let saved = self.store.put("versions", record)?;
            return Ok(Some(saved));
        }

        // Claim independent active worker ownership
        {
            let mut st = self.status.lock();
            if self.active_worker.load(Ordering::SeqCst)
                || matches!(
                    st.state.as_str(),
                    "downloading" | "paused" | "verifying" | "extracting" | "installing"
                )
            {
                return Err(anyhow!("An installation is already in progress"));
            }
            self.active_worker.store(true, Ordering::SeqCst);
            st.version_id = id.to_string();
            st.name = format!("Camoufox {}", id);
            st.state = "downloading".to_string();
            st.downloaded_bytes = 0;
            st.total_bytes = None;
            st.error.clear();
            self.pause_requested.store(false, Ordering::SeqCst);
            self.cancel_requested.store(false, Ordering::SeqCst);
        }

        let cleanup_staging = Arc::new(Mutex::new(None::<PathBuf>));
        let _guard = ActiveGuard {
            active_worker: self.active_worker.clone(),
            staging_dir: cleanup_staging.clone(),
            #[cfg(test)]
            cleanup_hook: self.cleanup_hook.clone(),
        };

        let run_result = self.run_install(id, &cleanup_staging);
        match run_result {
            Ok(Some(saved)) => Ok(Some(saved)),
            Ok(None) => {
                let mut st = self.status.lock();
                st.state = "cancelled".to_string();
                Ok(None)
            }
            Err(e) => {
                let mut st = self.status.lock();
                if st.state != "cancelled" {
                    st.state = "error".to_string();
                    st.error = e.to_string();
                }
                Err(e)
            }
        }
    }

    fn run_install(
        &self,
        id: &str,
        cleanup_staging: &Arc<Mutex<Option<PathBuf>>>,
    ) -> Result<Option<Value>> {
        if self.cancel_requested.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Resolve official release metadata internally
        let available_releases = self.available()?;
        if self.cancel_requested.load(Ordering::SeqCst) {
            return Ok(None);
        }

        let matched = available_releases
            .into_iter()
            .find(|r| {
                r.get("id").and_then(Value::as_str) == Some(id)
                    || r.get("tag_name").and_then(Value::as_str) == Some(id)
            })
            .ok_or_else(|| anyhow!("No available download found for version '{}'", id))?;

        let asset_url = matched
            .get("asset_url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Asset URL missing for version '{}'", id))?
            .to_string();

        let expected_sha256 = matched
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "Mã kiểm tra SHA256 của phiên bản '{}' bị thiếu hoặc không hợp lệ (cần 64 ký tự hex). Vui lòng kiểm tra lại bản phát hành.",
                id
            ));
        }

        let release_name = matched
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string();

        let release_url = matched
            .get("release_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let asset_size = matched.get("asset_size").and_then(Value::as_u64);
        {
            let mut st = self.status.lock();
            st.name = release_name.clone();
            st.total_bytes = asset_size;
        }

        if self.cancel_requested.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Verify download URL is HTTPS (test suite permits configured mock/local fixtures)
        let parsed_url = Url::parse(&asset_url).context("Invalid release asset URL")?;
        let is_https = parsed_url.scheme() == "https";
        let is_test_allowed = cfg!(test)
            && matches!(
                parsed_url.host_str(),
                Some("127.0.0.1" | "localhost" | "example.com")
            );

        if !is_https && !is_test_allowed {
            return Err(anyhow!("Only HTTPS release download URLs are permitted"));
        }

        // Create staging directory inside managed versions_dir
        let staging_id = format!(
            ".staging_{}_{}",
            id,
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let mut staging_dir = self.store.versions_dir.join(&staging_id);
        fs::create_dir_all(&staging_dir)?;
        *cleanup_staging.lock() = Some(staging_dir.clone());

        let temp_dl_dir = tempfile::Builder::new()
            .prefix("camou_dl_")
            .tempdir()
            .context("Failed to create temporary download directory")?;
        let temp_zip = temp_dl_dir.path().join("camoufox.zip");

        // Download loop with pause, resume (Range), invalid 206 discard, and server ignored range handling
        let mut downloaded_bytes: u64 = 0;
        loop {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Ok(None);
            }

            // A quick resume must still close the response interrupted by pause.
            let pause_epoch = self.pause_epoch.load(Ordering::SeqCst);
            let mut req_headers = vec![("User-Agent".to_string(), "CamouManager".to_string())];
            if parsed_url.host_str() == Some("api.github.com") {
                if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                    if !token.is_empty() {
                        req_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
                    }
                }
            }

            if downloaded_bytes > 0 {
                req_headers.push(("Range".to_string(), format!("bytes={}-", downloaded_bytes)));
            }

            let req = HttpRequest {
                url: asset_url.clone(),
                headers: req_headers,
            };

            let resp = match self.transport.execute(req) {
                Ok(r) => r,
                Err(e) => {
                    if self.cancel_requested.load(Ordering::SeqCst) {
                        return Ok(None);
                    }
                    if self.pause_requested.load(Ordering::SeqCst) {
                        // Connection interrupted while pausing; proceed to pause barrier
                        self.wait_pause_resume();
                        if self.cancel_requested.load(Ordering::SeqCst) {
                            return Ok(None);
                        }
                        continue;
                    }
                    return Err(anyhow!("Failed to download release asset: connection error: {}", e));
                }
            };

            let mut mode_append = false;
            if downloaded_bytes > 0 {
                if resp.status == 206 {
                    let content_range = resp.header("content-range").unwrap_or("");
                    let mut range_valid = false;
                    if content_range.starts_with("bytes ") {
                        let spec = content_range[6..].trim();
                        let mut parts = spec.split('/');
                        let range_part = parts.next().unwrap_or("");
                        let total_part = parts.next().unwrap_or("");
                        let start_str = range_part.split('-').next().unwrap_or("");
                        if let Ok(start_val) = start_str.parse::<u64>() {
                            if start_val == downloaded_bytes {
                                range_valid = true;
                            }
                        }
                        if let Ok(total_val) = total_part.parse::<u64>() {
                            let mut st = self.status.lock();
                            st.total_bytes = Some(total_val);
                        }
                    }

                    if range_valid {
                        mode_append = true;
                    } else {
                        // Invalid 206 range response: discard and refetch from byte 0
                        drop(resp);
                        downloaded_bytes = 0;
                        self.status.lock().downloaded_bytes = 0;
                        let _ = fs::remove_file(&temp_zip);
                        continue;
                    }
                } else if resp.status == 200 {
                    // Server ignored Range header: restart safely from byte 0 without duplicate bytes
                    downloaded_bytes = 0;
                    self.status.lock().downloaded_bytes = 0;
                    if let Some(cl) = resp.header("content-length").and_then(|s| s.parse::<u64>().ok()) {
                        self.status.lock().total_bytes = Some(cl);
                    }
                } else if resp.status == 416 {
                    // Range not satisfiable: restart safely
                    downloaded_bytes = 0;
                    self.status.lock().downloaded_bytes = 0;
                    let _ = fs::remove_file(&temp_zip);
                    continue;
                } else {
                    return Err(anyhow!("Failed to download release asset: HTTP status {}", resp.status));
                }
            } else {
                if resp.status != 200 {
                    return Err(anyhow!("Failed to download release asset: HTTP status {}", resp.status));
                }
                if let Some(cl) = resp.header("content-length").and_then(|s| s.parse::<u64>().ok()) {
                    self.status.lock().total_bytes = Some(cl);
                }
            }

            let mut file = if mode_append {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&temp_zip)?
            } else {
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&temp_zip)?
            };

            let mut stream = resp.body;
            let mut buffer = [0u8; 64 * 1024];
            let mut eof_reached = false;

            loop {
                if self.cancel_requested.load(Ordering::SeqCst)
                    || self.pause_requested.load(Ordering::SeqCst)
                    || self.pause_epoch.load(Ordering::SeqCst) != pause_epoch
                {
                    break;
                }

                let read = stream.read(&mut buffer);
                if self.cancel_requested.load(Ordering::SeqCst) || self.pause_epoch.load(Ordering::SeqCst) != pause_epoch { break; }
                match read {
                    Ok(0) => {
                        eof_reached = true;
                        break;
                    }
                    Ok(n) => {
                        file.write_all(&buffer[..n])?;
                        downloaded_bytes += n as u64;
                        self.status.lock().downloaded_bytes = downloaded_bytes;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        if self.cancel_requested.load(Ordering::SeqCst)
                            || self.pause_requested.load(Ordering::SeqCst)
                        {
                            break;
                        }
                        return Err(anyhow!("Failed to read release stream: {}", e));
                    }
                }
            }

            // Closing stream and file releases socket connection immediately on pause/break
            drop(stream);
            drop(file);

            if self.cancel_requested.load(Ordering::SeqCst) {
                return Ok(None);
            }

            // Wait cooperatively if paused
            if self.pause_requested.load(Ordering::SeqCst) {
                self.wait_pause_resume();
            }

            if self.cancel_requested.load(Ordering::SeqCst) {
                return Ok(None);
            }

            if !self.pause_requested.load(Ordering::SeqCst) && eof_reached {
                let total = self.status.lock().total_bytes;
                if total.map_or(true, |tot| downloaded_bytes >= tot) {
                    break;
                }
            }
        }

        if self.cancel_requested.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Verification phase
        {
            let mut st = self.status.lock();
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Ok(None);
            }
            st.state = "verifying".to_string();
        }

        let calculated_sha256 = {
            let mut hasher = Sha256::new();
            let mut file = File::open(&temp_zip)?;
            let mut buf = [0u8; 1024 * 1024]; // 1 MiB chunks
            loop {
                if self.cancel_requested.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            hex::encode(hasher.finalize()).to_lowercase()
        };

        if calculated_sha256 != expected_sha256 {
            return Err(anyhow!(
                "SHA256 mismatch for {}: expected {}, got {}",
                id,
                expected_sha256,
                calculated_sha256
            ));
        }

        // Extraction phase with cooperative cancellation checkpoints
        {
            let mut st = self.status.lock();
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Ok(None);
            }
            st.state = "extracting".to_string();
        }

        let cancel_fn = || self.cancel_requested.load(Ordering::SeqCst);
        let extracted = crate::files::extract_zip(
            &temp_zip,
            &staging_dir,
            MAX_UNCOMPRESSED_ARCHIVE_BYTES,
            Some(&cancel_fn),
        )?;

        if !extracted || self.cancel_requested.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Drop temporary download directory
        drop(temp_dl_dir);

        // Verify executable is present in extracted archive
        let staged_exe = find_camoufox_exe(&staging_dir)
            .ok_or_else(|| anyhow!("camoufox.exe missing in extracted archive for {}", id))?;

        // Ensure version.json metadata is present
        let ver_file = staged_exe.parent().unwrap_or(&staging_dir).join("version.json");
        if !ver_file.exists() {
            let (ver_str, build_str) = parse_tag_version(id);
            let metadata = json!({
                "version": ver_str,
                "build": build_str,
                "prerelease": matched.get("prerelease").and_then(Value::as_bool).unwrap_or(false),
                "sha256": calculated_sha256,
                "created_at": crate::store::utcnow(),
            });
            fs::write(&ver_file, serde_json::to_string_pretty(&metadata)?)?;
        }

        // Transition to installing / promotion phase
        {
            let mut st = self.status.lock();
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Ok(None);
            }
            st.state = "installing".to_string();
        }

        // Normalize layout so staging contains browser root directly
        let root_source = staged_exe.parent().unwrap().to_path_buf();
        if root_source != staging_dir {
            let norm_id = format!(
                ".norm_{}_{}",
                id,
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let temp_norm = self.store.versions_dir.join(&norm_id);
            fs::rename(&root_source, &temp_norm)?;
            let _ = fs::remove_dir_all(&staging_dir);
            staging_dir = temp_norm;
            *cleanup_staging.lock() = Some(staging_dir.clone());
        }

        // Atomic promote to final version path under store operation lock
        let saved = {
            let _op = self.store.operation.lock();
            let final_target = self.store.versions_dir.join(id);
            if final_target.exists() {
                fs::remove_dir_all(&final_target)?;
            }
            fs::rename(&staging_dir, &final_target)?;
            // Promoted successfully: clear staging from cleanup guard
            cleanup_staging.lock().take();

            let final_exe = final_target.join("camoufox.exe");
            let record = json!({
                "id": id,
                "name": release_name,
                "path": final_exe.to_string_lossy(),
                "release_url": release_url,
                "installed_at": crate::store::utcnow(),
                "status": "installed",
            });
            self.store.put("versions", record)?
        };

        {
            let mut st = self.status.lock();
            st.state = "completed".to_string();
            st.error.clear();
        }

        self.store.log(
            "INFO",
            &format!("Successfully installed and registered Camoufox {}", id),
            "",
        )?;
        Ok(Some(saved))
    }

    fn wait_pause_resume(&self) {
        let (lock, cvar) = &*self.wake_cond;
        let mut guard = lock.lock();
        while self.pause_requested.load(Ordering::SeqCst)
            && !self.cancel_requested.load(Ordering::SeqCst)
        {
            cvar.wait(&mut guard);
        }
    }

    /// Check if newer releases are available compared to installed versions.
    /// Filters for stable non-draft releases for automatic updates; obeys settings and cancel.
    pub fn check_updates(&self) -> Result<Value> {
        let installed_list = self.installed()?;
        let current_id = installed_list
            .first()
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let available_list = match self.available() {
            Ok(list) => list,
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self.store.log(
                    "WARNING",
                    &format!("Failed to check for updates: {}", err_msg),
                    "",
                );
                return Ok(json!({
                    "has_update": false,
                    "latest_version": Value::Null,
                    "current_version": current_id,
                    "error": err_msg,
                }));
            }
        };

        let non_draft: Vec<Value> = available_list
            .into_iter()
            .filter(|a| !a.get("draft").and_then(Value::as_bool).unwrap_or(false))
            .collect();

        let stable_available: Vec<Value> = non_draft
            .iter()
            .filter(|a| !a.get("prerelease").and_then(Value::as_bool).unwrap_or(false))
            .cloned()
            .collect();

        let mut target_available = if !stable_available.is_empty() {
            stable_available
        } else {
            non_draft
        };

        if target_available.is_empty() {
            return Ok(json!({
                "has_update": false,
                "latest_version": Value::Null,
                "current_version": current_id,
            }));
        }

        target_available.sort_by(|a, b| version_sort_key(b).cmp(&version_sort_key(a)));

        let latest_available = &target_available[0];
        let latest_id = latest_available
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("");

        let installed_ids: std::collections::HashSet<&str> = installed_list
            .iter()
            .filter_map(|v| v.get("id").and_then(Value::as_str))
            .collect();

        let has_update = !latest_id.is_empty()
            && !installed_ids.contains(latest_id)
            && installed_list
                .first()
                .map(|current| version_sort_key(latest_available) > version_sort_key(current))
                .unwrap_or(true);
        let mut result = json!({
            "has_update": has_update,
            "latest_version": if has_update { latest_available.clone() } else { Value::Null },
            "current_version": current_id,
        });

        // Auto-download if enabled in settings
        let settings = self.store.settings().unwrap_or(json!({}));
        if has_update
            && settings
                .get("auto_download_updates")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            match self.install(latest_id) {
                Ok(Some(_installed_rec)) => {
                    result["has_update"] = json!(false);
                    result["current_version"] = json!(latest_id);
                }
                Ok(None) => {
                    // Cancelled: do not mark installed or record error
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let _ = self.store.log(
                        "WARNING",
                        &format!("Auto-download update failed: {}", err_msg),
                        "",
                    );
                    result["error"] = json!(err_msg);
                }
            }
        }

        Ok(result)
    }
}

/// Recursively locate camoufox.exe inside a directory.
fn find_camoufox_exe(root: &Path) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && entry.file_name() == "camoufox.exe" {
                return Some(path);
            } else if path.is_dir() && !entry.file_name().to_string_lossy().starts_with('.') {
                if let Some(found) = find_camoufox_exe(&path) {
                    return Some(found);
                }
            }
        }
    }
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use zip::write::SimpleFileOptions;

    /// Helper creating a valid zip archive containing camoufox.exe and version.json.
    pub fn make_camoufox_zip(marker: &[u8]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("camoufox.exe", options).unwrap();
            zip.write_all(marker).unwrap();
            zip.start_file("version.json", options).unwrap();
            zip.write_all(br#"{"version":"135.0.0","build":"135.0.0","prerelease":false}"#)
                .unwrap();
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    /// Deterministic chunked read stream with index-based gate synchronization.
    pub struct DeterministicStream {
        data: Vec<u8>,
        cursor: usize,
        chunk_size: usize,
        chunk_index: usize,
        on_chunk: Option<Arc<dyn Fn(usize, &[u8]) + Send + Sync>>,
        gates: Arc<Mutex<HashMap<usize, Arc<AtomicBool>>>>,
    }

    impl DeterministicStream {
        pub fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                cursor: 0,
                chunk_size: 64 * 1024,
                chunk_index: 0,
                on_chunk: None,
                gates: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        pub fn with_options(
            data: Vec<u8>,
            on_chunk: Option<Arc<dyn Fn(usize, &[u8]) + Send + Sync>>,
            gates: HashMap<usize, Arc<AtomicBool>>,
        ) -> Self {
            Self {
                data,
                cursor: 0,
                chunk_size: 64 * 1024,
                chunk_index: 0,
                on_chunk,
                gates: Arc::new(Mutex::new(gates)),
            }
        }
    }

    impl Read for DeterministicStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.cursor >= self.data.len() {
                return Ok(0);
            }

            let gate = self.gates.lock().get(&self.chunk_index).cloned();
            if let Some(g) = gate {
                while !g.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            let remaining = self.data.len() - self.cursor;
            let to_read = remaining.min(self.chunk_size).min(buf.len());
            let slice = &self.data[self.cursor..self.cursor + to_read];
            buf[..to_read].copy_from_slice(slice);

            if let Some(cb) = &self.on_chunk {
                cb(self.chunk_index, slice);
            }

            self.cursor += to_read;
            self.chunk_index += 1;
            Ok(to_read)
        }
    }

    /// Injectable mock transport matching closures.
    pub struct MockTransport<F>
    where
        F: Fn(&HttpRequest) -> Result<HttpResponse> + Send + Sync,
    {
        handler: F,
    }

    impl<F> MockTransport<F>
    where
        F: Fn(&HttpRequest) -> Result<HttpResponse> + Send + Sync,
    {
        pub fn new(handler: F) -> Self {
            Self { handler }
        }
    }

    impl<F> Transport for MockTransport<F>
    where
        F: Fn(&HttpRequest) -> Result<HttpResponse> + Send + Sync,
    {
        fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
            (self.handler)(&req)
        }
    }

    pub fn wait_for_status<F>(versions: &Versions, pred: F, timeout_secs: f32) -> Value
    where
        F: Fn(&Value) -> bool,
    {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs_f32(timeout_secs);
        loop {
            let st = versions.status();
            if pred(&st) {
                return st;
            }
            if start.elapsed() > timeout {
                panic!("Status condition not met in {:?}: {:?}", timeout, st);
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    }

    #[test]
    fn test_release_metadata_filtering() {
        assert!(is_win_x86_64_asset("camoufox-135.0.0-windows-x86_64.zip"));
        assert!(is_win_x86_64_asset("camoufox-135.0.0-win64.zip"));
        assert!(!is_win_x86_64_asset("camoufox-135.0.0-win32.zip"));
        assert!(!is_win_x86_64_asset("camoufox-fonts-win-x64.zip"));
        assert!(!is_win_x86_64_asset("camoufox-135.0.0-linux-x86_64.zip"));

        assert!(is_browser_release("v135.0.0-beta.1", "Camoufox v135.0.0-beta.1"));
        assert!(is_browser_release("135.0.0", "Camoufox 135.0.0"));
        assert!(!is_browser_release("font-bundle-v1", "Font Bundle v1"));
        assert!(!is_browser_release("fonts-v2", "Fonts Release"));

        let (ver, build) = parse_tag_version("v156.0.1-beta.36");
        assert_eq!(ver, "156.0.1");
        assert_eq!(build, "beta.36");

        let (ver2, build2) = parse_tag_version("v135.0.0");
        assert_eq!(ver2, "135.0.0");
        assert_eq!(build2, "135.0.0");
    }

    #[test]
    fn test_version_sort_key() {
        let r1 = json!({"id": "v135.0.0-beta.1"});
        let r2 = json!({"id": "v135.0.0-beta.10"});
        let r3 = json!({"id": "v156.0.0"});

        let k1 = version_sort_key(&r1);
        let k2 = version_sort_key(&r2);
        let k3 = version_sort_key(&r3);

        assert!(k3 > k2);
        assert!(k2 > k1);

        // Equal version final > prerelease
        assert!(version_sort_key(&json!({"id": "v156.0.1"})) > version_sort_key(&json!({"id": "v156.0.1-beta.37"})));

        // Numeric prerelease parts (beta.10 > beta.2)
        assert!(version_sort_key(&json!({"id": "v156.0.1-beta.10"})) > version_sort_key(&json!({"id": "v156.0.1-beta.2"})));

        // Alpha < beta < rc < final ordering
        let k_alpha = version_sort_key(&json!({"id": "v156.0.1-alpha.1"}));
        let k_beta = version_sort_key(&json!({"id": "v156.0.1-beta.1"}));
        let k_rc1 = version_sort_key(&json!({"id": "v156.0.1-rc.1"}));
        let k_rc2 = version_sort_key(&json!({"id": "v156.0.1-rc.2"}));
        let k_final = version_sort_key(&json!({"id": "v156.0.1"}));
        assert!(k_alpha < k_beta);
        assert!(k_beta < k_rc1);
        assert!(k_rc1 < k_rc2);
        assert!(k_rc2 < k_final);

        // Ignore build metadata
        let k_meta1 = version_sort_key(&json!({"id": "v156.0.1-beta.37+build.1"}));
        let k_meta2 = version_sort_key(&json!({"id": "v156.0.1-beta.37+build.2"}));
        assert_eq!(k_meta1, k_meta2);
        let k_final_meta = version_sort_key(&json!({"id": "v156.0.1+sha.abcdef"}));
        assert_eq!(k_final, k_final_meta);

        // Newer major/minor/patch prerelease > older stable
        assert!(version_sort_key(&json!({"id": "v157.0.0-alpha.1"})) > k_final);
        assert!(version_sort_key(&json!({"id": "v156.1.0-alpha.1"})) > k_final);
        assert!(version_sort_key(&json!({"id": "v156.0.2-alpha.1"})) > k_final);

        // Upstream tag forms
        assert_eq!(version_sort_key(&json!({"id": "v135.0.0"})), version_sort_key(&json!({"id": "135.0.0"})));
        assert_eq!(version_sort_key(&json!({"id": "v135.0"})), version_sort_key(&json!({"id": "135.0.0"})));
        assert!(version_sort_key(&json!({"id": "v135.0.1"})) > version_sort_key(&json!({"id": "135.0"})));
    }

    #[test]
    fn test_validate_safe_version_id() {
        assert!(validate_safe_version_id("v135.0.0").is_ok());
        assert!(validate_safe_version_id("v135.0.0-beta.1").is_ok());
        assert!(validate_safe_version_id(".").is_err());
        assert!(validate_safe_version_id("..").is_err());
        assert!(validate_safe_version_id("../outside").is_err());
        assert!(validate_safe_version_id("foo/bar").is_err());
        assert!(validate_safe_version_id("foo\\bar").is_err());
    }

    #[test]
    fn test_pause_and_resume_download() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'X'; 192 * 1024]);
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let expected_hash = hex::encode(hasher.finalize()).to_lowercase();

        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let pause_gate = Arc::new(AtomicBool::new(false));
        let requests_received = Arc::new(Mutex::new(Vec::<HttpRequest>::new()));
        let reqs_c = requests_received.clone();
        let zip_bytes_c = zip_bytes.clone();
        let pause_gate_c = pause_gate.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            reqs_c.lock().push(req.clone());
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-beta.1",
                    "name": "Camoufox v135.0.0-beta.1",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", expected_hash),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            if let Some(range_header) = req.header("range") {
                let start: usize = range_header
                    .strip_prefix("bytes=")
                    .unwrap_or("0")
                    .trim_end_matches('-')
                    .parse()
                    .unwrap();
                let remaining = zip_bytes_c[start..].to_vec();
                let end = zip_bytes_c.len() - 1;
                let cr = format!("bytes {}-{}/{}", start, end, zip_bytes_c.len());
                return Ok(HttpResponse {
                    status: 206,
                    headers: vec![("content-range".to_string(), cr)],
                    body: Box::new(DeterministicStream::new(remaining)),
                });
            }

            let mut gates = HashMap::new();
            gates.insert(1, pause_gate_c.clone());
            let chunk0_c = chunk0_c.clone();
            let stream = DeterministicStream::with_options(
                zip_bytes_c.clone(),
                Some(Arc::new(move |idx, _| {
                    if idx == 0 {
                        chunk0_c.store(true, Ordering::SeqCst);
                    }
                })),
                gates,
            );

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(stream),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-beta.1"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        wait_for_status(&versions, |s| s["downloaded_bytes"].as_u64().unwrap_or(0) >= 64 * 1024, 3.0);
        let paused_status = versions.control("v135.0.0-beta.1", "pause")?;
        assert_eq!(paused_status["state"], "paused");
        let downloaded_before = paused_status["downloaded_bytes"].as_u64().unwrap();
        assert!(downloaded_before >= 64 * 1024);

        pause_gate.store(true, Ordering::SeqCst);

        let stable = versions.status();
        assert_eq!(stable["state"], "paused");
        assert_eq!(stable["downloaded_bytes"].as_u64().unwrap(), downloaded_before);

        let resumed = versions.control("v135.0.0-beta.1", "resume")?;
        assert_eq!(resumed["state"], "downloading");

        let res = handle.join().unwrap()?;
        assert!(res.is_some());
        let rec = res.unwrap();
        assert_eq!(rec["id"], "v135.0.0-beta.1");
        assert!(store.versions_dir.join("v135.0.0-beta.1").join("camoufox.exe").exists());
        assert_eq!(versions.status()["state"], "completed");

        let had_range = requests_received.lock().iter().any(|r| r.header("range").is_some());
        assert!(had_range);
        Ok(())
    }

    #[test]
    fn test_ignored_range_restarts_safely() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'Y'; 192 * 1024]);
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let expected_hash = hex::encode(hasher.finalize()).to_lowercase();

        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let pause_gate = Arc::new(AtomicBool::new(false));
        let pause_gate_c = pause_gate.clone();
        let req_count = Arc::new(AtomicUsize::new(0));
        let req_count_c = req_count.clone();
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-beta.2",
                    "name": "Camoufox v135.0.0-beta.2",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", expected_hash),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            let count = req_count_c.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                let mut gates = HashMap::new();
                gates.insert(1, pause_gate_c.clone());
                let chunk0_c = chunk0_c.clone();
                let stream = DeterministicStream::with_options(
                    zip_bytes_c.clone(),
                    Some(Arc::new(move |idx, _| {
                        if idx == 0 {
                            chunk0_c.store(true, Ordering::SeqCst);
                        }
                    })),
                    gates,
                );
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                    body: Box::new(stream),
                });
            }

            // Server ignores range and returns 200 with full stream
            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(DeterministicStream::new(zip_bytes_c.clone())),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-beta.2"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        wait_for_status(&versions, |s| s["downloaded_bytes"].as_u64().unwrap_or(0) >= 64 * 1024, 3.0);
        versions.control("v135.0.0-beta.2", "pause")?;
        pause_gate.store(true, Ordering::SeqCst);
        versions.control("v135.0.0-beta.2", "resume")?;

        let res = handle.join().unwrap()?;
        assert!(res.is_some());
        let exe = store.versions_dir.join("v135.0.0-beta.2").join("camoufox.exe");
        assert!(exe.exists());
        Ok(())
    }

    #[test]
    fn test_invalid_206_range_discards_and_refetches() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'K'; 192 * 1024]);
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let expected_hash = hex::encode(hasher.finalize()).to_lowercase();

        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let pause_gate = Arc::new(AtomicBool::new(false));
        let pause_gate_c = pause_gate.clone();
        let req_count = Arc::new(AtomicUsize::new(0));
        let req_count_c = req_count.clone();
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-badrange",
                    "name": "Camoufox v135.0.0-badrange",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", expected_hash),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            let count = req_count_c.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                let mut gates = HashMap::new();
                gates.insert(1, pause_gate_c.clone());
                let chunk0_c = chunk0_c.clone();
                let stream = DeterministicStream::with_options(
                    zip_bytes_c.clone(),
                    Some(Arc::new(move |idx, _| {
                        if idx == 0 {
                            chunk0_c.store(true, Ordering::SeqCst);
                        }
                    })),
                    gates,
                );
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                    body: Box::new(stream),
                });
            }

            if count == 1 {
                assert!(req.header("range").is_some());
                // Return invalid Content-Range start
                return Ok(HttpResponse {
                    status: 206,
                    headers: vec![(
                        "content-range".to_string(),
                        format!("bytes 999999-9999999/{}", zip_bytes_c.len()),
                    )],
                    body: Box::new(DeterministicStream::new(b"corrupt slice".to_vec())),
                });
            }

            // Third request: clean GET from 0 without Range header
            assert!(req.header("range").is_none());
            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(DeterministicStream::new(zip_bytes_c.clone())),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-badrange"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        wait_for_status(&versions, |s| s["downloaded_bytes"].as_u64().unwrap_or(0) >= 64 * 1024, 3.0);
        versions.control("v135.0.0-badrange", "pause")?;
        pause_gate.store(true, Ordering::SeqCst);
        wait_for_status(&versions, |s| s["state"] == "paused", 3.0);
        versions.control("v135.0.0-badrange", "resume")?;

        let res = handle.join().unwrap()?;
        assert!(res.is_some());
        let exe = store.versions_dir.join("v135.0.0-badrange").join("camoufox.exe");
        assert!(exe.exists());
        Ok(())
    }

    #[test]
    fn test_unknown_content_length_pause_and_resume() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'W'; 192 * 1024]);
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let expected_hash = hex::encode(hasher.finalize()).to_lowercase();

        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let pause_gate = Arc::new(AtomicBool::new(false));
        let pause_gate_c = pause_gate.clone();
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-chunked",
                    "name": "Camoufox v135.0.0-chunked",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "digest": format!("sha256:{}", expected_hash),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            if let Some(range_header) = req.header("range") {
                let start: usize = range_header
                    .strip_prefix("bytes=")
                    .unwrap_or("0")
                    .trim_end_matches('-')
                    .parse()
                    .unwrap();
                let remaining = zip_bytes_c[start..].to_vec();
                let end = zip_bytes_c.len() - 1;
                let cr = format!("bytes {}-{}/{}", start, end, zip_bytes_c.len());
                return Ok(HttpResponse {
                    status: 206,
                    headers: vec![("content-range".to_string(), cr)],
                    body: Box::new(DeterministicStream::new(remaining)),
                });
            }

            let mut gates = HashMap::new();
            gates.insert(1, pause_gate_c.clone());
            let chunk0_c = chunk0_c.clone();
            let stream = DeterministicStream::with_options(
                zip_bytes_c.clone(),
                Some(Arc::new(move |idx, _| {
                    if idx == 0 {
                        chunk0_c.store(true, Ordering::SeqCst);
                    }
                })),
                gates,
            );

            // Genuinely omit Content-Length header
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Box::new(stream),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-chunked"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        wait_for_status(&versions, |s| s["downloaded_bytes"].as_u64().unwrap_or(0) >= 64 * 1024, 3.0);
        let paused = versions.control("v135.0.0-chunked", "pause")?;
        assert_eq!(paused["state"], "paused");
        pause_gate.store(true, Ordering::SeqCst);

        wait_for_status(&versions, |s| s["state"] == "paused", 3.0);
        let resumed = versions.control("v135.0.0-chunked", "resume")?;
        assert_eq!(resumed["state"], "downloading");

        let res = handle.join().unwrap()?;
        assert!(res.is_some());
        assert!(store.versions_dir.join("v135.0.0-chunked").join("camoufox.exe").exists());
        Ok(())
    }

    #[test]
    fn test_cancel_during_download_cleans_up_and_releases() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'C'; 192 * 1024]);
        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let hold_gate = Arc::new(AtomicBool::new(false));
        let hold_gate_c = hold_gate.clone();
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-beta.3",
                    "name": "Camoufox v135.0.0-beta.3",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", hex::encode(Sha256::digest(&zip_bytes_c))),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            let mut gates = HashMap::new();
            gates.insert(1, hold_gate_c.clone());
            let chunk0_c = chunk0_c.clone();
            let stream = DeterministicStream::with_options(
                zip_bytes_c.clone(),
                Some(Arc::new(move |idx, _| {
                    if idx == 0 {
                        chunk0_c.store(true, Ordering::SeqCst);
                    }
                })),
                gates,
            );

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(stream),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-beta.3"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        let st_cancel = versions.control("v135.0.0-beta.3", "cancel")?;
        assert_eq!(st_cancel["state"], "cancelled");
        hold_gate.store(true, Ordering::SeqCst);

        let res = handle.join().unwrap()?;
        assert!(res.is_none());

        let staged_count = fs::read_dir(&store.versions_dir)?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".staging_"))
            .count();
        assert_eq!(staged_count, 0);
        assert_eq!(versions.status()["state"], "cancelled");
        assert!(!versions.is_active());
        Ok(())
    }

    #[test]
    fn test_cancel_while_paused_wakes_immediately() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'P'; 192 * 1024]);
        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let zip_bytes_c = zip_bytes.clone();
        let transfer_gate = Arc::new(AtomicBool::new(false));
        let transfer_gate_c = transfer_gate.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-pausedcancel",
                    "name": "Camoufox v135.0.0-pausedcancel",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", hex::encode(Sha256::digest(&zip_bytes_c))),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            let chunk0_c = chunk0_c.clone();
            let stream = DeterministicStream::with_options(
                zip_bytes_c.clone(),
                Some(Arc::new(move |idx, _| {
                    if idx == 0 {
                        chunk0_c.store(true, Ordering::SeqCst);
                    }
                })),
                HashMap::from([(1, transfer_gate_c.clone())]),
            );

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(stream),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-pausedcancel"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        wait_for_status(&versions, |s| s["downloaded_bytes"].as_u64().unwrap_or(0) >= 64 * 1024, 3.0);
        versions.control("v135.0.0-pausedcancel", "pause")?;
        transfer_gate.store(true,Ordering::SeqCst);
        wait_for_status(&versions, |s| s["state"] == "paused", 3.0);

        // Cancel while paused immediately wakes worker
        let cancelled = versions.control("v135.0.0-pausedcancel", "cancel")?;
        assert_eq!(cancelled["state"], "cancelled");

        let res = handle.join().unwrap()?;
        assert!(res.is_none());
        assert_eq!(versions.status()["state"], "cancelled");
        Ok(())
    }

    #[test]
    fn test_stale_and_unsupported_controls() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        let versions = Versions::new(store);

        assert!(versions.control("v1.0.0", "fly").is_err());
        assert!(versions.control("v1.0.0", "pause").is_err());
        assert!(versions.control("v1.0.0", "resume").is_err());
        assert!(versions.control("v1.0.0", "cancel").is_err());
        Ok(())
    }

    #[test]
    fn test_concurrent_installs_rejected() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'Q'; 192 * 1024]);
        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let hold_gate = Arc::new(AtomicBool::new(false));
        let hold_gate_c = hold_gate.clone();
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-concurrent",
                    "name": "Camoufox v135.0.0-concurrent",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", hex::encode(Sha256::digest(&zip_bytes_c))),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            let mut gates = HashMap::new();
            gates.insert(1, hold_gate_c.clone());
            let chunk0_c = chunk0_c.clone();
            let stream = DeterministicStream::with_options(
                zip_bytes_c.clone(),
                Some(Arc::new(move |idx, _| {
                    if idx == 0 {
                        chunk0_c.store(true, Ordering::SeqCst);
                    }
                })),
                gates,
            );

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(stream),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-concurrent"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        let concurrent_err = versions.install("v135.0.0-concurrent");
        assert!(concurrent_err.is_err());
        assert!(concurrent_err
            .unwrap_err()
            .to_string()
            .contains("An installation is already in progress"));

        hold_gate.store(true, Ordering::SeqCst);
        let _ = handle.join().unwrap();
        Ok(())
    }

    #[test]
    fn test_cancel_cleanup_admission_race() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'R'; 192 * 1024]);
        let chunk0_consumed = Arc::new(AtomicBool::new(false));
        let chunk0_c = chunk0_consumed.clone();
        let zip_bytes_c = zip_bytes.clone();
        let transfer_gate = Arc::new(AtomicBool::new(false));
        let transfer_gate_c = transfer_gate.clone();

        let cleanup_blocking = Arc::new(AtomicBool::new(false));
        let cleanup_release = Arc::new(AtomicBool::new(false));
        let cleanup_blocking_c = cleanup_blocking.clone();
        let cleanup_release_c = cleanup_release.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-race",
                    "name": "Camoufox v135.0.0-race",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", hex::encode(Sha256::digest(&zip_bytes_c))),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            let chunk0_c = chunk0_c.clone();
            let stream = DeterministicStream::with_options(
                zip_bytes_c.clone(),
                Some(Arc::new(move |idx, _| {
                    if idx == 0 {
                        chunk0_c.store(true, Ordering::SeqCst);
                    }
                })),
                HashMap::from([(1, transfer_gate_c.clone())]),
            );

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(stream),
            })
        }));

        let mut versions = Versions::with_transport(store.clone(), transport);
        versions.set_cleanup_hook(Arc::new(move || {
            cleanup_blocking_c.store(true, Ordering::SeqCst);
            while !cleanup_release_c.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }));

        let versions = Arc::new(versions);
        let versions_c = versions.clone();
        let handle = std::thread::spawn(move || versions_c.install("v135.0.0-race"));

        while !chunk0_consumed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        versions.control("v135.0.0-race", "cancel")?;
        transfer_gate.store(true, Ordering::SeqCst);
        while !cleanup_blocking.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(versions.status()["state"], "cancelled");
        let second_attempt = versions.install("v135.0.0-race");
        assert!(second_attempt.is_err());

        cleanup_release.store(true, Ordering::SeqCst);
        let res = handle.join().unwrap()?;
        assert!(res.is_none());
        Ok(())
    }

    #[test]
    fn test_sha256_integrity_rejection() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'I'; 100 * 1024]);
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-badsha",
                    "name": "Camoufox v135.0.0-badsha",
                    "html_url": "https://example.com/rel",
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(DeterministicStream::new(zip_bytes_c.clone())),
            })
        }));

        let versions = Versions::with_transport(store.clone(), transport);
        let res = versions.install("v135.0.0-badsha");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("SHA256 mismatch"));

        let staged = fs::read_dir(&store.versions_dir)?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".staging_"))
            .count();
        assert_eq!(staged, 0);
        Ok(())
    }

    #[test]
    fn test_sha256_missing_and_malformed_checksum_rejected() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'Z'; 50 * 1024]);
        let zip_bytes_c = zip_bytes.clone();
        let requested_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let requested_urls_c = requested_urls.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            requested_urls_c.lock().push(req.url.clone());
            if req.url == GITHUB_RELEASES_URL {
                let releases = json!([
                    {
                        "tag_name": "v135.0.0-absent",
                        "name": "Camoufox v135.0.0-absent",
                        "assets": [
                            {
                                "name": "camoufox-win-x64.zip",
                                "browser_download_url": "https://example.com/camoufox-absent.zip",
                                "size": zip_bytes_c.len(),
                            },
                            {
                                "name": "camoufox-win-x64.zip.sha256",
                                "browser_download_url": "https://example.com/camoufox-absent.zip.sha256",
                            }
                        ]
                    },
                    {
                        "tag_name": "v135.0.0-malformed",
                        "name": "Camoufox v135.0.0-malformed",
                        "assets": [
                            {
                                "name": "camoufox-win-x64.zip",
                                "browser_download_url": "https://example.com/camoufox-malformed.zip",
                                "size": zip_bytes_c.len(),
                                "digest": format!("sha256:{}g", "0".repeat(63)),
                            }
                        ]
                    }
                ]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&releases)?)),
                });
            }

            if req.url == "https://example.com/camoufox-absent.zip.sha256" {
                return Ok(HttpResponse {
                    status: 404,
                    headers: vec![],
                    body: Box::new(std::io::Cursor::new(Vec::new())),
                });
            }

            if req.url == "https://example.com/camoufox-absent.zip"
                || req.url == "https://example.com/camoufox-malformed.zip"
            {
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                    body: Box::new(DeterministicStream::new(zip_bytes_c.clone())),
                });
            }

            Err(anyhow!("Unexpected request to {}", req.url))
        }));

        let versions = Versions::with_transport(store.clone(), transport);

        // Verify available() still lists releases even if digest is absent
        let avail = versions.available()?;
        assert_eq!(avail.len(), 2);
        assert_eq!(avail[0]["sha256"], "");

        // 1. Absent digest + companion failure must fail early
        let res_absent = versions.install("v135.0.0-absent");
        assert!(res_absent.is_err());
        let st_absent = versions.status();
        assert_eq!(st_absent["state"], "error");
        assert!(!versions.is_active());
        assert!(!requested_urls.lock().contains(&"https://example.com/camoufox-absent.zip".to_string()));
        assert!(!store.versions_dir.join("v135.0.0-absent").exists());
        assert!(store.get("versions", "v135.0.0-absent")?.is_none());

        // 2. Malformed digest must fail early
        let res_malformed = versions.install("v135.0.0-malformed");
        assert!(res_malformed.is_err());
        let st_malformed = versions.status();
        assert_eq!(st_malformed["state"], "error");
        assert!(!versions.is_active());
        assert!(!requested_urls.lock().contains(&"https://example.com/camoufox-malformed.zip".to_string()));
        assert!(!store.versions_dir.join("v135.0.0-malformed").exists());
        assert!(store.get("versions", "v135.0.0-malformed")?.is_none());

        let staged = fs::read_dir(&store.versions_dir)?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".staging_"))
            .count();
        assert_eq!(staged, 0);

        Ok(())
    }

    #[test]
    fn test_valid_companion_checksum_install() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let zip_bytes = make_camoufox_zip(&vec![b'C'; 60 * 1024]);
        let zip_bytes_c = zip_bytes.clone();
        let expected_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&zip_bytes);
            hex::encode(hasher.finalize()).to_lowercase()
        };
        let expected_hash_c = expected_hash.clone();
        let requested_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let requested_urls_c = requested_urls.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            requested_urls_c.lock().push(req.url.clone());
            if req.url == GITHUB_RELEASES_URL {
                let releases = json!([
                    {
                        "tag_name": "v135.0.0-companion",
                        "name": "Camoufox v135.0.0-companion",
                        "assets": [
                            {
                                "name": "camoufox-win-x64.zip",
                                "browser_download_url": "https://example.com/camoufox-companion.zip",
                                "size": zip_bytes_c.len(),
                            },
                            {
                                "name": "camoufox-win-x64.zip.sha256",
                                "browser_download_url": "https://example.com/camoufox-companion.zip.sha256",
                            }
                        ]
                    }
                ]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&releases)?)),
                });
            }

            if req.url == "https://example.com/camoufox-companion.zip.sha256" {
                let content = format!("{}  camoufox-win-x64.zip\n", expected_hash_c);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "text/plain".to_string())],
                    body: Box::new(std::io::Cursor::new(content.into_bytes())),
                });
            }

            if req.url == "https://example.com/camoufox-companion.zip" {
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                    body: Box::new(DeterministicStream::new(zip_bytes_c.clone())),
                });
            }

            Err(anyhow!("Unexpected request to {}", req.url))
        }));

        let versions = Versions::with_transport(store.clone(), transport);

        let avail = versions.available()?;
        assert_eq!(avail.len(), 1);
        assert_eq!(avail[0]["sha256"], expected_hash);

        let res = versions.install("v135.0.0-companion")?;
        assert!(res.is_some());
        assert!(!versions.is_active());
        assert!(requested_urls.lock().contains(&"https://example.com/camoufox-companion.zip".to_string()));
        assert!(store.versions_dir.join("v135.0.0-companion").join("camoufox.exe").exists());
        assert!(store.get("versions", "v135.0.0-companion")?.is_some());

        Ok(())
    }

    #[test]
    fn test_auto_update_cancellation_does_not_mark_installed() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        store.save_settings(json!({"auto_download_updates": true}))?;

        let zip_bytes = make_camoufox_zip(&vec![b'A'; 100 * 1024]);
        let zip_bytes_c = zip_bytes.clone();
        let transfer_gate = Arc::new(AtomicBool::new(false));
        let transfer_gate_c = transfer_gate.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([{
                    "tag_name": "v135.0.0-autoupdate",
                    "name": "Camoufox v135.0.0-autoupdate",
                    "html_url": "https://example.com/rel",
                    "prerelease": false,
                    "draft": false,
                    "assets": [{
                        "name": "camoufox-win-x64.zip",
                        "browser_download_url": "https://example.com/camoufox.zip",
                        "size": zip_bytes_c.len(),
                        "digest": format!("sha256:{}", hex::encode(Sha256::digest(&zip_bytes_c))),
                    }],
                }]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }

            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(DeterministicStream::with_options(zip_bytes_c.clone(),None,HashMap::from([(1,transfer_gate_c.clone())]))),
            })
        }));

        let versions = Arc::new(Versions::with_transport(store.clone(), transport));
        let worker = versions.clone();
        let handle = std::thread::spawn(move || worker.check_updates());
        wait_for_status(&versions,|s| s["downloaded_bytes"].as_u64().unwrap_or(0) >= 64 * 1024,3.0);
        versions.control("v135.0.0-autoupdate","cancel")?;
        transfer_gate.store(true,Ordering::SeqCst);
        let res = handle.join().unwrap()?;
        assert!(res.get("error").is_none());
        assert_eq!(res["has_update"], true);
        assert_eq!(res["current_version"], "");
        assert!(store.list("versions")?.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_updates_ordering_backports_equal_and_newer() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let v135_dir = store.versions_dir.join("v135.0.0");
        fs::create_dir_all(&v135_dir)?;
        fs::write(v135_dir.join("camoufox.exe"), b"browser-135")?;
        let pinned_profile = store.put(
            "profiles",
            json!({"name": "PinnedProfile", "browser_version": "v135.0.0"}),
        )?;

        let zip_bytes = make_camoufox_zip(b"browser-136");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let expected_hash = hex::encode(hasher.finalize()).to_lowercase();

        let releases_state = Arc::new(Mutex::new(json!([])));
        let releases_c = releases_state.clone();
        let downloaded_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let downloaded_c = downloaded_urls.clone();
        let zip_bytes_c = zip_bytes.clone();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = releases_c.lock().clone();
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }
            downloaded_c.lock().push(req.url.clone());
            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes_c.len().to_string())],
                body: Box::new(DeterministicStream::new(zip_bytes_c.clone())),
            })
        }));

        let versions = Versions::with_transport(store.clone(), transport);
        store.save_settings(json!({"auto_download_updates": true}))?;

        // 1. Older backport missing locally must not be treated as an update or auto-downloaded
        *releases_state.lock() = json!([
            {
                "tag_name": "v134.0.9",
                "name": "Camoufox v134.0.9",
                "html_url": "https://example.com/rel/134",
                "prerelease": false,
                "draft": false,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-134.zip",
                    "size": zip_bytes.len(),
                    "digest": format!("sha256:{}", expected_hash),
                }],
            }
        ]);
        let backport_res = versions.check_updates()?;
        assert_eq!(backport_res["has_update"], false);
        assert!(backport_res["latest_version"].is_null());
        assert_eq!(backport_res["current_version"], "v135.0.0");
        assert!(downloaded_urls.lock().is_empty());
        assert!(!store.versions_dir.join("v134.0.9").exists());

        // 2. Equal semantic version (even with unprefixed tag missing from installed_ids) + older backport first
        *releases_state.lock() = json!([
            {
                "tag_name": "v134.0.9",
                "name": "Camoufox v134.0.9",
                "html_url": "https://example.com/rel/134",
                "prerelease": false,
                "draft": false,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-134.zip",
                    "size": zip_bytes.len(),
                }],
            },
            {
                "tag_name": "135.0.0",
                "name": "Camoufox 135.0.0",
                "html_url": "https://example.com/rel/135",
                "prerelease": false,
                "draft": false,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-135.zip",
                    "size": zip_bytes.len(),
                }],
            }
        ]);
        let equal_res = versions.check_updates()?;
        assert_eq!(equal_res["has_update"], false);
        assert!(equal_res["latest_version"].is_null());
        assert_eq!(equal_res["current_version"], "v135.0.0");
        assert!(downloaded_urls.lock().is_empty());

        // 3. Out-of-order releases: older backport listed before newer stable, plus newer draft/prerelease
        *releases_state.lock() = json!([
            {
                "tag_name": "v134.0.9",
                "name": "Camoufox v134.0.9",
                "html_url": "https://example.com/rel/134",
                "prerelease": false,
                "draft": false,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-134.zip",
                    "size": zip_bytes.len(),
                    "digest": format!("sha256:{}", expected_hash),
                }],
            },
            {
                "tag_name": "v137.0.0",
                "name": "Camoufox v137.0.0 Draft",
                "html_url": "https://example.com/rel/137",
                "prerelease": false,
                "draft": true,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-137.zip",
                    "size": zip_bytes.len(),
                }],
            },
            {
                "tag_name": "v136.0.0",
                "name": "Camoufox v136.0.0",
                "html_url": "https://example.com/rel/136",
                "prerelease": false,
                "draft": false,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-136.zip",
                    "size": zip_bytes.len(),
                    "digest": format!("sha256:{}", expected_hash),
                }],
            },
            {
                "tag_name": "v138.0.0-beta.1",
                "name": "Camoufox v138.0.0-beta.1",
                "html_url": "https://example.com/rel/138b1",
                "prerelease": true,
                "draft": false,
                "assets": [{
                    "name": "camoufox-win-x64.zip",
                    "browser_download_url": "https://example.com/camoufox-138b1.zip",
                    "size": zip_bytes.len(),
                }],
            }
        ]);

        store.save_settings(json!({"auto_download_updates": false}))?;
        let check_only = versions.check_updates()?;
        assert_eq!(check_only["has_update"], true);
        assert_eq!(check_only["latest_version"]["id"], "v136.0.0");
        assert_eq!(check_only["current_version"], "v135.0.0");
        assert!(downloaded_urls.lock().is_empty());

        store.save_settings(json!({"auto_download_updates": true}))?;
        let auto_res = versions.check_updates()?;
        assert_eq!(auto_res["has_update"], false);
        assert_eq!(auto_res["latest_version"]["id"], "v136.0.0");
        assert_eq!(auto_res["current_version"], "v136.0.0");
        assert_eq!(
            *downloaded_urls.lock(),
            vec!["https://example.com/camoufox-136.zip".to_string()]
        );
        assert!(store.versions_dir.join("v136.0.0").join("camoufox.exe").exists());
        assert!(store.versions_dir.join("v135.0.0").join("camoufox.exe").exists());
        let saved_profile = store
            .get("profiles", pinned_profile["id"].as_str().unwrap())?
            .unwrap();
        assert_eq!(saved_profile["browser_version"], "v135.0.0");
        Ok(())
    }

    #[test]
    fn test_check_updates_detects_stable_update_from_prerelease() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);

        let v156_beta_dir = store.versions_dir.join("v156.0.1-beta.37");
        fs::create_dir_all(&v156_beta_dir)?;
        fs::write(v156_beta_dir.join("camoufox.exe"), b"browser-156-beta")?;

        let zip_bytes = make_camoufox_zip(b"browser-156-stable");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let expected_hash = hex::encode(hasher.finalize()).to_lowercase();

        let transport = Arc::new(MockTransport::new(move |req| {
            if req.url == GITHUB_RELEASES_URL {
                let rel = json!([
                    {
                        "tag_name": "v156.0.1",
                        "name": "Camoufox v156.0.1",
                        "html_url": "https://example.com/rel/156-stable",
                        "prerelease": false,
                        "draft": false,
                        "assets": [{
                            "name": "camoufox-win-x64.zip",
                            "browser_download_url": "https://example.com/camoufox-156.zip",
                            "size": zip_bytes.len(),
                            "digest": format!("sha256:{}", expected_hash),
                        }],
                    }
                ]);
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: Box::new(std::io::Cursor::new(serde_json::to_vec(&rel)?)),
                });
            }
            Ok(HttpResponse {
                status: 200,
                headers: vec![("content-length".to_string(), zip_bytes.len().to_string())],
                body: Box::new(DeterministicStream::new(zip_bytes.clone())),
            })
        }));

        let versions = Versions::with_transport(store.clone(), transport);
        let update_res = versions.check_updates()?;

        assert_eq!(update_res["has_update"], true);
        assert_eq!(update_res["latest_version"]["id"], "v156.0.1");
        assert_eq!(update_res["current_version"], "v156.0.1-beta.37");
        Ok(())
    }

    #[test]
    fn test_installed_versions_orders_stable_over_prerelease() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        let versions = Versions::new(store.clone());

        let beta_dir = store.versions_dir.join("v156.0.1-beta.37");
        fs::create_dir_all(&beta_dir)?;
        fs::write(beta_dir.join("camoufox.exe"), b"mock-beta")?;

        let stable_dir = store.versions_dir.join("v156.0.1");
        fs::create_dir_all(&stable_dir)?;
        fs::write(stable_dir.join("camoufox.exe"), b"mock-stable")?;

        let installed = versions.installed()?;
        assert_eq!(installed.len(), 2);
        assert_eq!(installed[0]["id"], "v156.0.1");
        assert_eq!(installed[1]["id"], "v156.0.1-beta.37");
        Ok(())
    }

    #[test]
    fn test_delete_unused_version_preserves_profile_data() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        let versions = Versions::new(store.clone());

        let dir = store.versions_dir.join("v135.0.0");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("camoufox.exe"), b"browser")?;

        let _ = versions.installed()?;
        let profile = store.put(
            "profiles",
            json!({"name": "Keep", "browser_version": "", "fingerprint": {"identity": "keep"}}),
        )?;
        let cookie_file = store.root.join("keep.cookie");
        fs::write(&cookie_file, b"cookie")?;

        versions.delete("v135.0.0")?;
        assert!(!dir.exists());
        assert!(store.get("versions", "v135.0.0")?.is_none());
        assert_eq!(versions.installed()?.len(), 0);
        assert_eq!(store.get("profiles", profile["id"].as_str().unwrap())?, Some(profile));
        assert_eq!(fs::read(&cookie_file)?, b"cookie");
        Ok(())
    }

    #[test]
    fn test_delete_pinned_version_preserves_installation() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        let versions = Versions::new(store.clone());

        let dir = store.versions_dir.join("v135.0.0");
        fs::create_dir_all(&dir)?;
        let exe = dir.join("camoufox.exe");
        fs::write(&exe, b"browser")?;

        let rec = versions.installed()?[0].clone();
        store.put(
            "profiles",
            json!({"name": "Pinned", "browser_version": rec["id"]}),
        )?;

        let del_res = versions.delete(rec["id"].as_str().unwrap());
        assert!(del_res.is_err());
        assert_eq!(fs::read(&exe)?, b"browser");
        assert_eq!(store.get("versions", rec["id"].as_str().unwrap())?, Some(rec));
        Ok(())
    }

    #[test]
    fn test_delete_rejects_escape_and_versions_root() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        let versions = Versions::new(store.clone());

        let marker = store.versions_dir.join("keep");
        fs::write(&marker, b"keep")?;

        assert!(versions.delete(".").is_err());
        assert!(versions.delete("../outside").is_err());
        assert_eq!(fs::read(&marker)?, b"keep");
        Ok(())
    }

    #[test]
    fn test_delete_rejects_external_executable_path() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let store = Arc::new(crate::store::Store::open(temp_dir.path())?);
        let versions = Versions::new(store.clone());

        let external = temp_dir.path().join("external.exe");
        fs::write(&external, b"keep")?;

        let rec = store.put(
            "versions",
            json!({"id": "v135.0.0", "path": external.to_string_lossy()}),
        )?;

        let res = versions.delete("v135.0.0");
        assert!(res.is_err());
        assert_eq!(fs::read(&external)?, b"keep");
        assert_eq!(store.get("versions", "v135.0.0")?, Some(rec));
        Ok(())
    }
}
