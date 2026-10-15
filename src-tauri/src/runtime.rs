use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::{
    collections::HashMap,
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use crate::{
    bidi::BrowserSession,
    files::reject_link,
    fingerprints::FingerprintService,
    ip_sync::{update_profile_ip, IpSync},
    network::{BrowserProxy, Network},
    store::{redact, safe_component, string, utcnow, Store},
    versions::version_sort_key,
};

#[cfg(test)]
#[path = "webrtc_smoke.rs"]
mod webrtc_smoke;

const WINDOWS_11_MARKER_FONTS: &[&str] = &[
    "Sans Serif Collection",
    "Segoe Fluent Icons",
    "Segoe UI Variable",
    "Segoe UI Variable Display",
    "Segoe UI Variable Small",
    "Segoe UI Variable Text",
];

const VOICE_FIELDS: &[&str] = &["lang", "name", "voiceUri", "isDefault", "isLocalService"];

const CAMOU_CHUNK_SIZE: usize = if cfg!(windows) { 2047 } else { 32767 };


/// Strip Windows extended-length `\\?\` prefix for Gecko `nsIFile` / `-profile` CLI arguments.
pub fn browser_path_string(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        raw.into_owned()
    }
}

/// Normalize and validate a startup or bookmark URL, rejecting CLI option prefixes and unsupported schemes.
pub fn normalize_and_validate_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("URL cannot be empty");
    }
    if trimmed.starts_with('-') {
        bail!("URL cannot start with '-'");
    }
    let candidate = if !trimmed.contains("://")
        && !["about:", "data:", "blob:", "file:"]
            .iter()
            .any(|p| trimmed.starts_with(p))
    {
        format!("https://{trimmed}")
    } else {
        trimmed.to_owned()
    };
    let parsed = url::Url::parse(&candidate).with_context(|| format!("Invalid URL '{trimmed}'"))?;
    if !["http", "https", "about", "file", "ws", "wss", "data", "blob"].contains(&parsed.scheme()) {
        bail!("Unsupported URL scheme '{}'", parsed.scheme());
    }
    Ok(parsed.into())
}

/// Query the host OS display work area dimensions (width, height in pixels).
/// On Windows, queries SPI_GETWORKAREA, falling back to screen metrics minus taskbar.
/// On non-Windows platforms, defaults to (1920, 1040).
pub fn host_work_area() -> (i64, i64) {
    #[cfg(windows)]
    {
        use std::mem::MaybeUninit;
        use windows_sys::Win32::{
            Foundation::RECT,
            UI::WindowsAndMessaging::{
                GetSystemMetrics, SystemParametersInfoW, SM_CXSCREEN, SM_CYSCREEN, SPI_GETWORKAREA,
            },
        };

        let mut rect = MaybeUninit::<RECT>::uninit();
        let ok = unsafe {
            SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                rect.as_mut_ptr() as *mut _,
                0,
            )
        };
        if ok != 0 {
            let r = unsafe { rect.assume_init() };
            let w = (r.right - r.left) as i64;
            let h = (r.bottom - r.top) as i64;
            if w > 0 && h > 0 {
                return (w, h);
            }
        }

        let cx = unsafe { GetSystemMetrics(SM_CXSCREEN) } as i64;
        let cy = unsafe { GetSystemMetrics(SM_CYSCREEN) } as i64;
        if cx > 0 && cy > 0 {
            return (cx, (cy - 40).max(0));
        }
    }

    (1920, 1040)
}

/// Adjust spoofed window dimensions if screen exceeds host work area,
/// and remove innerWidth/innerHeight to let Gecko reflow responsively.
pub fn adapt_window_to_host(config_map: &mut Map<String, Value>, host_w: i64, host_h: i64) {
    let screen_w = config_map
        .get("screen.width")
        .and_then(Value::as_i64)
        .unwrap_or(1920);
    let avail_h = config_map
        .get("screen.availHeight")
        .and_then(Value::as_i64)
        .or_else(|| config_map.get("screen.height").and_then(Value::as_i64))
        .unwrap_or(1040);

    if screen_w > host_w || avail_h > host_h {
        let launch_w = (host_w - 40).min(screen_w).max(800);
        let launch_h = (host_h - 60).min(avail_h).max(600);
        config_map.insert("window.outerWidth".into(), json!(launch_w));
        config_map.insert("window.outerHeight".into(), json!(launch_h));
        config_map.insert("window.screenX".into(), json!(((screen_w - launch_w) / 2).max(0)));
        config_map.insert("window.screenY".into(), json!(((avail_h - launch_h) / 2).max(0)));
    }

    // Remove window.innerWidth and window.innerHeight from config_map:
    // By removing them from config_map before encoding CAMOU_CONFIG, Camoufox does NOT lock
    // the DOM viewport to a fixed size, allowing Gecko to dynamically calculate innerWidth/innerHeight
    // so responsive web layouts naturally reflow and adapt when the user drags/resizes the window.
    config_map.remove("window.innerWidth");
    config_map.remove("window.innerHeight");
}

/// Serialize a JSON value to compact ASCII-only JSON (`\uXXXX` for non-ASCII).
/// Guarantees 1 byte per character so chunking never splits UTF-8 codepoints and
/// Windows ANSI `getenv()` in `camoufox.cfg` / `MaskConfig` never corrupts non-ASCII text.
pub fn to_ascii_json(value: &Value) -> Result<String> {
    let raw = serde_json::to_string(value)?;
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    Ok(out)
}

fn chunk_env_vars(prefix: &str, data: &str) -> Vec<(String, String)> {
    if data.is_empty() {
        return Vec::new();
    }
    data.as_bytes()
        .chunks(CAMOU_CHUNK_SIZE)
        .enumerate()
        .map(|(idx, chunk)| {
            let key = format!("{prefix}_{}", idx + 1);
            let val = std::str::from_utf8(chunk).expect("ASCII JSON chunk").to_owned();
            (key, val)
        })
        .collect()
}

/// Encode `CAMOU_CONFIG_1..N` environment variable chunks from a Camoufox config map.
pub fn encode_camou_config_env(config: &Map<String, Value>) -> Result<Vec<(String, String)>> {
    let serialized = to_ascii_json(&Value::Object(config.clone()))?;
    Ok(chunk_env_vars("CAMOU_CONFIG", &serialized))
}

/// Encode `CAMOU_PREFS_1..N` environment variable chunks from a Firefox user prefs map.
pub fn encode_camou_prefs_env(prefs: &Map<String, Value>) -> Result<Vec<(String, String)>> {
    if prefs.is_empty() {
        return Ok(Vec::new());
    }
    let serialized = to_ascii_json(&Value::Object(prefs.clone()))?;
    Ok(chunk_env_vars("CAMOU_PREFS", &serialized))
}

fn check_property_type(value: &Value, expected: &str) -> bool {
    match expected {
        "str" => value.is_string(),
        "int" => {
            value.is_i64()
                || value.is_u64()
                || value
                    .as_f64()
                    .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
        }
        "uint" => {
            value.is_u64()
                || value.as_i64().is_some_and(|i| i >= 0)
                || value
                    .as_f64()
                    .is_some_and(|f| f.is_finite() && f >= 0.0 && f.fract() == 0.0)
        }
        "double" => value.is_number(),
        "bool" => value.is_boolean(),
        "array" => value.is_array(),
        "dict" => value.is_object(),
        _ => false,
    }
}

fn validate_voices_array(voices: &Value) -> Result<()> {
    let arr = voices
        .as_array()
        .ok_or_else(|| anyhow!("Invalid type for property 'voices': expected array"))?;
    for (idx, entry) in arr.iter().enumerate() {
        let obj = entry.as_object().ok_or_else(|| {
            anyhow!(
                "Invalid voices[{idx}]: expected object with {{{}}}",
                VOICE_FIELDS.join(", ")
            )
        })?;
        let missing: Vec<&str> = VOICE_FIELDS
            .iter()
            .copied()
            .filter(|field| !obj.contains_key(*field))
            .collect();
        if !missing.is_empty() {
            bail!(
                "Invalid voices[{idx}]: missing required fields: {}",
                missing.join(", ")
            );
        }
    }
    Ok(())
}

fn find_properties_json(executable_path: &Path) -> Option<PathBuf> {
    let parent = executable_path.parent()?;
    let direct = parent.join("properties.json");
    if direct.is_file() {
        return Some(direct);
    }
    let bundled = parent.parent()?.join("Resources").join("properties.json");
    if bundled.is_file() {
        return Some(bundled);
    }
    None
}

/// Validate and filter a Camoufox config map against the browser bundle's `properties.json`.
/// Strips unknown or removed keys (returning warnings) and fails closed on invalid types or malformed voices.
pub fn validate_and_filter_config(
    config: &mut Map<String, Value>,
    executable_path: &Path,
) -> Result<Vec<String>> {
    let prop_path = find_properties_json(executable_path).ok_or_else(|| {
        anyhow!(
            "Missing Camoufox properties.json beside executable '{}'",
            executable_path.display()
        )
    })?;
    reject_link(&prop_path)?;
    let raw = fs::read(&prop_path)
        .with_context(|| format!("Failed to read '{}'", prop_path.display()))?;
    let prop_list: Vec<Value> = serde_json::from_slice(&raw)
        .with_context(|| format!("Invalid JSON in '{}'", prop_path.display()))?;

    let mut schema: HashMap<String, (String, Option<String>)> =
        HashMap::with_capacity(prop_list.len());
    for item in prop_list {
        if let Some(name) = item.get("property").and_then(Value::as_str) {
            let ty = item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("str")
                .to_owned();
            let removed = item
                .get("removed")
                .and_then(Value::as_str)
                .map(str::to_owned);
            schema.insert(name.to_owned(), (ty, removed));
        }
    }

    let mut warnings = Vec::new();
    let keys: Vec<String> = config.keys().cloned().collect();
    for key in keys {
        match schema.get(&key) {
            None => {
                config.remove(&key);
                warnings.push(format!("Skipped unsupported Camoufox property '{key}'"));
            }
            Some((_, Some(removed_ver))) => {
                config.remove(&key);
                warnings.push(format!(
                    "Skipped deprecated Camoufox property '{key}' (removed in {removed_ver})"
                ));
            }
            Some((expected_type, None)) => {
                let val = &config[&key];
                if !check_property_type(val, expected_type) {
                    bail!("Invalid type for property '{key}': expected {expected_type}");
                }
                if key == "voices" {
                    validate_voices_array(val)?;
                }
            }
        }
    }
    Ok(warnings)
}

fn infer_target_os(config: &Map<String, Value>) -> &'static str {
    let ua = config
        .get("navigator.userAgent")
        .and_then(Value::as_str)
        .unwrap_or("");
    let platform = config
        .get("navigator.platform")
        .and_then(Value::as_str)
        .unwrap_or("");
    let combined = format!("{ua} {platform}").to_ascii_lowercase();
    if combined.contains("mac") || combined.contains("darwin") {
        "mac"
    } else if combined.contains("linux") || combined.contains("x11") {
        "lin"
    } else {
        "win"
    }
}

/// Build default startup Firefox preferences (`CAMOU_PREFS_1..N`) matching upstream Camoufox `launch_options`.
pub fn build_default_prefs(
    config: &Map<String, Value>,
    proxy_prefs: Option<&Value>,
    has_bookmarks: bool,
    search_engine: Option<&str>,
    startup_homepage: Option<&str>,
) -> Map<String, Value> {
    let mut prefs = Map::new();
    let target_os = infer_target_os(config);

    // Overlay scrollbars match claimed OS & Windows 11 font set
    let overlay_scrollbars = if target_os == "win" {
        let fonts = config.get("fonts").and_then(Value::as_array);
        let is_win11 = match fonts {
            None => true,
            Some(list) if list.is_empty() => true,
            Some(list) => list
                .iter()
                .filter_map(Value::as_str)
                .any(|f| WINDOWS_11_MARKER_FONTS.contains(&f)),
        };
        if is_win11 { 1 } else { 0 }
    } else {
        1
    };
    prefs.insert("ui.useOverlayScrollbars".into(), json!(overlay_scrollbars));

    if target_os == "lin" {
        prefs.insert("gfx.font_rendering.fallback.async".into(), json!(false));
    }

    prefs.insert(
        "dom.quotaManager.temporaryStorage.fixedLimit".into(),
        json!(i32::MAX),
    );

    let dnt_enabled = config
        .get("navigator.doNotTrack")
        .and_then(Value::as_str)
        .is_some_and(|v| v == "1");
    prefs.insert("privacy.donottrackheader.enabled".into(), json!(dnt_enabled));

    let gpc_enabled = config
        .get("navigator.globalPrivacyControl")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    prefs.insert(
        "privacy.globalprivacycontrol.enabled".into(),
        json!(gpc_enabled),
    );

    prefs.insert("network.dns.disableIPv6".into(), json!(proxy_prefs.is_none() && config.contains_key("webrtc:ipv4")));

    if config.contains_key("geolocation:latitude") && config.contains_key("geolocation:longitude") {
        prefs.insert("permissions.default.geo".into(), json!(1));
    }

    let requested_locale = match config
        .get("locale:language")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(lang) => {
            let script = config
                .get("locale:script")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let region = config
                .get("locale:region")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let mut parts = vec![lang];
            if let Some(sc) = script {
                parts.push(sc);
            }
            if let Some(reg) = region {
                parts.push(reg);
            }
            parts.join("-")
        }
        None => "en-US".to_owned(),
    };
    prefs.insert("intl.locale.requested".into(), json!(requested_locale));
    let accept_langs = config
        .get("headers.Accept-Language")
        .and_then(Value::as_str)
        .unwrap_or("en-US,en;q=0.5");
    prefs.insert("intl.accept_languages".into(), json!(accept_langs));

    prefs.insert("permissions.default.image".into(), json!(1));
    // Force proxy routing even on about:blank; relay candidates must be real, not spoofed.
    prefs.insert("media.peerconnection.enabled".into(), json!(true));
    prefs.insert("media.peerconnection.ice.proxy_only".into(), json!(proxy_prefs.is_some()));
    prefs.insert("media.peerconnection.ice.relay_only".into(), json!(proxy_prefs.is_some()));
    prefs.insert("media.peerconnection.ice.default_address_only".into(), json!(proxy_prefs.is_none()));
    prefs.insert("network.proxy.failover_direct".into(), json!(proxy_prefs.is_none()));
    prefs.insert("network.proxy.allow_bypass".into(), json!(proxy_prefs.is_none()));
    prefs.insert("network.proxy.socks5_remote_dns".into(), json!(true));
    prefs.insert("media.webrtc.tls_tunnel_for_all_proxy".into(), json!(true));
    if proxy_prefs.is_some() {
        prefs.insert("extensions.experiments.enabled".into(), json!(true));
    }
    prefs.insert(
        "browser.tabs.remote.useCrossOriginOpenerPolicy".into(),
        json!(true),
    );
    prefs.insert("webgl.force-enabled".into(), json!(true));
    prefs.insert("webgl.enable-webgl2".into(), json!(true));

    // Clean non-interactive window close without confirmation prompts
    prefs.insert("browser.warnOnQuit".into(), json!(false));
    prefs.insert("browser.warnOnQuitShortcut".into(), json!(false));
    prefs.insert("browser.tabs.warnOnClose".into(), json!(false));
    prefs.insert("browser.tabs.warnOnCloseOtherTabs".into(), json!(false));
    prefs.insert("browser.shell.checkDefaultBrowser".into(), json!(false));

    if has_bookmarks {
        prefs.insert("browser.toolbars.bookmarks.visibility".into(), json!("always"));
    }

    // Apply proxy preferences or explicitly reset to direct connection
    if let Some(Value::Object(proxy_map)) = proxy_prefs {
        for (k, v) in proxy_map {
            prefs.insert(k.clone(), v.clone());
        }
    } else {
        prefs.insert("network.proxy.type".into(), json!(0));
        prefs.insert("network.proxy.http".into(), json!(""));
        prefs.insert("network.proxy.http_port".into(), json!(0));
        prefs.insert("network.proxy.ssl".into(), json!(""));
        prefs.insert("network.proxy.ssl_port".into(), json!(0));
        prefs.insert("network.proxy.socks".into(), json!(""));
        prefs.insert("network.proxy.socks_port".into(), json!(0));
    }

    let _ = search_engine;
    let startup_homepage = startup_homepage
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("https://duckduckgo.com");

    prefs.insert("browser.search.suggest.enabled".into(), json!(true));
    prefs.insert("browser.startup.homepage".into(), json!(startup_homepage));

    prefs
}

pub fn resolve_search_engine(profile: Option<&Value>, settings: Option<&Value>) -> String {
    profile
        .and_then(|p| p.get("search_engine"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            settings
                .and_then(|s| s.get("default_search_engine"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("DuckDuckGo")
        .to_string()
}

pub fn resolve_default_startup_url(profile: Option<&Value>, settings: Option<&Value>) -> String {
    fn check_url(candidate: &str) -> Option<&str> {
        match normalize_and_validate_url(candidate) {
            Ok(_) => Some(candidate),
            Err(e) => {
                eprintln!("Warning: Invalid default startup URL '{candidate}': {e}; falling back to https://duckduckgo.com");
                None
            }
        }
    }

    profile
        .and_then(|p| p.get("default_startup_url").or_else(|| p.get("startup_url")))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(check_url)
        .or_else(|| {
            settings
                .and_then(|s| s.get("default_startup_url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(check_url)
        })
        .unwrap_or("https://duckduckgo.com")
        .to_string()
}

pub fn resolve_launch_args(valid_urls: &[String], default_startup_url: &str) -> Vec<String> {
    if valid_urls.is_empty() {
        vec!["-url".to_string(), default_startup_url.to_string()]
    } else {
        let mut args = Vec::with_capacity(valid_urls.len() * 2);
        for u in valid_urls {
            args.push("-url".to_string());
            args.push(u.clone());
        }
        args
    }
}

/// Prepare or update `<browser_dir>/xulstore.json` so Firefox reads initial window
/// dimensions and position on startup without unsupported CLI flags (`-width`, `-height`).
pub fn prepare_xulstore_window(browser_dir: &Path, w: i64, h: i64, x: i64, y: i64) -> Result<()> {
    if !browser_dir.exists() {
        fs::create_dir_all(browser_dir)?;
    }
    let path = browser_dir.join("xulstore.json");
    reject_link(&path)?;

    let mut root: Value = if path.exists() {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }

    let root_obj = root.as_object_mut().expect("root must be object");
    let chrome_key = "chrome://browser/content/browser.xhtml";
    let chrome_val = root_obj
        .entry(chrome_key.to_string())
        .or_insert_with(|| json!({}));

    if !chrome_val.is_object() {
        *chrome_val = json!({});
    }

    let chrome_obj = chrome_val.as_object_mut().expect("chrome must be object");
    let main_window_val = chrome_obj
        .entry("main-window".to_string())
        .or_insert_with(|| json!({}));

    if !main_window_val.is_object() {
        *main_window_val = json!({});
    }

    let main_window_obj = main_window_val.as_object_mut().expect("main-window must be object");
    main_window_obj.insert("width".to_string(), json!(w.to_string()));
    main_window_obj.insert("height".to_string(), json!(h.to_string()));
    main_window_obj.insert("screenX".to_string(), json!(x.to_string()));
    main_window_obj.insert("screenY".to_string(), json!(y.to_string()));
    main_window_obj.insert("sizemode".to_string(), json!("normal"));

    fs::write(&path, serde_json::to_string_pretty(&root)?)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    Ok(())
}

const MANAGED_CHROME_CSS: &str = ":root[remotecontrol] #remote-control-box { display: none !important; }\n:root[remotecontrol] .urlbar-background { background-image: none !important; }\n";

pub fn prepare_browser_chrome_css(executable_path: &Path) -> Result<()> {
    use std::io::{Read, Write};

    let parent = executable_path
        .parent()
        .ok_or_else(|| anyhow!("Browser executable has no parent directory"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    reject_link(parent)?;
    let path = parent.join("chrome.css");
    reject_link(&path)?;

    let old = match fs::File::open(&path) {
        Ok(file) => {
            let mut text = String::new();
            file.take(4 * 1024 * 1024 + 1).read_to_string(&mut text)?;
            if text.len() > 4 * 1024 * 1024 {
                bail!("chrome.css exceeds 4 MiB");
            }
            text
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };

    if old.contains(MANAGED_CHROME_CSS) {
        return Ok(());
    }

    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(old.as_bytes())?;
    if !old.is_empty() && !old.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.write_all(MANAGED_CHROME_CSS.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(&path)?;
    Ok(())
}

pub fn ensure_distribution_policies(exe_path: &Path, search_engine: &str) -> Result<()> {
    let Some(exe_dir) = exe_path.parent() else {
        return Ok(());
    };
    let dist_dir = exe_dir.join("distribution");
    let policy_path = dist_dir.join("policies.json");
    if !dist_dir.exists() {
        fs::create_dir_all(&dist_dir)?;
    }
    let mut root: Value = if policy_path.exists() {
        let content = fs::read_to_string(&policy_path).unwrap_or_else(|_| "{}".to_string());
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !root.is_object() {
        root = json!({});
    }
    let root_map = root.as_object_mut().unwrap();
    let policies = root_map.entry("policies".to_string()).or_insert_with(|| json!({}));
    if !policies.is_object() {
        *policies = json!({});
    }
    let p_obj = policies.as_object_mut().unwrap();

    let default_engine = if search_engine.trim().is_empty() {
        "DuckDuckGo"
    } else {
        search_engine.trim()
    };

    let search_engines = json!({
        "PreventInstalls": false,
        "Default": default_engine,
        "Add": [
            {
                "Name": "DuckDuckGo",
                "URLTemplate": "https://duckduckgo.com/?q={searchTerms}",
                "Method": "GET",
                "Alias": "@ddg",
                "Description": "DuckDuckGo Search"
            },
            {
                "Name": "Google",
                "URLTemplate": "https://www.google.com/search?q={searchTerms}",
                "Method": "GET",
                "Alias": "@google",
                "Description": "Google Search"
            },
            {
                "Name": "Bing",
                "URLTemplate": "https://www.bing.com/search?q={searchTerms}",
                "Method": "GET",
                "Alias": "@bing",
                "Description": "Bing Search"
            }
        ]
    });

    p_obj.insert("SearchEngines".into(), search_engines);

    if let Some(exts) = p_obj.get_mut("Extensions").and_then(Value::as_object_mut) {
        if let Some(un) = exts.get_mut("Uninstall").and_then(Value::as_array_mut) {
            un.retain(|v| !v.as_str().is_some_and(|s| s.ends_with("@search.mozilla.org")));
        }
    }

    let _ = fs::write(&policy_path, serde_json::to_string_pretty(&root)?);
    Ok(())
}

fn prepare_webrtc_pref(browser_dir: &Path, prefs: &Map<String, Value>) -> Result<()> {
    use std::io::{Read, Write};
    let path = browser_dir.join("user.js");
    reject_link(&path)?;
    let old = match fs::File::open(&path) {
        Ok(file) => {
            let mut text = String::new();
            file.take(4 * 1024 * 1024 + 1).read_to_string(&mut text)?;
            if text.len() > 4 * 1024 * 1024 { bail!("Profile user.js exceeds 4 MiB"); }
            text
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let mut file = tempfile::NamedTempFile::new_in(browser_dir)?;
    let mut ends_with_newline = true;
    for line in old.split_inclusive('\n') {
        if !line.trim_end().ends_with(" // CamouManager WebRTC") {
            file.write_all(line.as_bytes())?;
            ends_with_newline = line.ends_with('\n');
        }
    }
    // User-branch prefs override CAMOU_PREFS; enforce this before any startup URL can run.
    if !ends_with_newline { writeln!(file)?; }
    for (key, value) in prefs {
        if key.starts_with("media.peerconnection.")
            || key.starts_with("network.proxy.")
            || key.starts_with("media.webrtc.")
        {
            writeln!(file, "user_pref({}, {}); // CamouManager WebRTC", serde_json::to_string(key)?, value)?;
        }
    }
    file.as_file().sync_all()?;
    file.persist(&path)?;
    Ok(())
}


fn clean_managed_bookmarks(bookmarks: &[Value]) -> Result<Vec<Value>> {
    let mut clean_bms = Vec::new();
    for item in bookmarks {
        if let Some(obj) = item.as_object() {
            let raw_url = obj.get("url").and_then(Value::as_str).unwrap_or("").trim();
            if !raw_url.is_empty() {
                let url = normalize_and_validate_url(raw_url)?;
                let raw_title = obj.get("title").and_then(Value::as_str).unwrap_or("").trim();
                let title = if raw_title.is_empty() {
                    url.clone()
                } else {
                    raw_title.to_owned()
                };
                clean_bms.push(json!({ "title": title, "url": url }));
            }
        }
    }
    Ok(clean_bms)
}

/// Generate an unpacked Firefox WebExtension under `profile_dir/manager-addons/bookmarks`
/// with stable Gecko ID `camoumanager-bookmarks@local.invalid` to synchronize managed bookmarks natively.
pub fn prepare_bookmark_addon(profile_dir: &Path, bookmarks: &[Value]) -> Result<PathBuf> {
    reject_link(profile_dir)?;
    let manager_addons = profile_dir.join("manager-addons");
    reject_link(&manager_addons)?;
    let addon_dir = manager_addons.join("bookmarks");
    reject_link(&addon_dir)?;
    fs::create_dir_all(&addon_dir)?;

    let clean_bms = clean_managed_bookmarks(bookmarks)?;

    let manifest = json!({
        "manifest_version": 2,
        "name": "CamouManager Bookmarks Synchronizer",
        "version": "1.0.0",
        "description": "Internal manager service for native profile bookmarks synchronization",
        "browser_specific_settings": {
            "gecko": {
                "id": "camoumanager-bookmarks@local.invalid"
            }
        },
        "permissions": [
            "bookmarks",
            "storage"
        ],
        "background": {
            "scripts": ["background.js"]
        }
    });

    fs::write(
        addon_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    fs::write(
        addon_dir.join("bookmarks.json"),
        serde_json::to_string_pretty(&clean_bms)?,
    )?;

    let embedded_json = serde_json::to_string(&clean_bms)?;
    let background_js = format!(
        r#"// CamouManager Native Bookmarks Synchronizer Background Service
(async () => {{
  const TARGET_BOOKMARKS = {embedded_json};
  const STORAGE_KEY = 'camoumanager_managed_folder_id';

  try {{
    const storageData = await browser.storage.local.get(STORAGE_KEY);
    let managedFolderId = storageData[STORAGE_KEY];

    let folderExists = false;
    if (managedFolderId) {{
      try {{
        const results = await browser.bookmarks.get(managedFolderId);
        if (results && results.length > 0) {{
          folderExists = true;
        }}
      }} catch (e) {{
        folderExists = false;
      }}
    }}

    if (TARGET_BOOKMARKS.length === 0) {{
      if (folderExists) {{
        await browser.bookmarks.removeTree(managedFolderId);
        await browser.storage.local.remove(STORAGE_KEY);
      }}
      await browser.storage.local.set({{ sync_completed: true, sync_count: 0 }});
      return;
    }}

    if (!folderExists) {{
      const newFolder = await browser.bookmarks.create({{
        parentId: 'toolbar_____',
        title: 'CamouManager'
      }});
      managedFolderId = newFolder.id;
      await browser.storage.local.set({{ [STORAGE_KEY]: managedFolderId }});
    }}

    const children = await browser.bookmarks.getChildren(managedFolderId);

    for (let i = 0; i < TARGET_BOOKMARKS.length; i++) {{
      const target = TARGET_BOOKMARKS[i];
      if (i < children.length) {{
        const child = children[i];
        if (child.title !== target.title || child.url !== target.url) {{
          await browser.bookmarks.update(child.id, {{
            title: target.title,
            url: target.url
          }});
        }}
      }} else {{
        await browser.bookmarks.create({{
          parentId: managedFolderId,
          index: i,
          title: target.title,
          url: target.url
        }});
      }}
    }}

    if (children.length > TARGET_BOOKMARKS.length) {{
      for (let i = TARGET_BOOKMARKS.length; i < children.length; i++) {{
        await browser.bookmarks.remove(children[i].id);
      }}
    }}

    await browser.storage.local.set({{ sync_completed: true, sync_count: TARGET_BOOKMARKS.length }});
  }} catch (err) {{
    console.error('[CamouManager] Native bookmarks synchronization error:', err);
  }}
}})();
"#
    );

    fs::write(addon_dir.join("background.js"), background_js)?;
    Ok(addon_dir)
}

/// Check if places.sqlite has committed the managed bookmarks folder and its children under the toolbar.
fn verify_bookmark_sync_state(places_path: &Path, expected_bookmarks: &[Value]) -> bool {
    if !places_path.is_file() {
        return false;
    }

    let conn = match rusqlite::Connection::open_with_flags(
        places_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let _ = conn.busy_timeout(Duration::from_millis(150));

    // Toolbar folder with guid = 'toolbar_____' must exist in moz_bookmarks for schema readiness
    let toolbar_id: i64 = match conn.query_row(
        "SELECT id FROM moz_bookmarks WHERE guid = 'toolbar_____' LIMIT 1",
        [],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return false,
    };

    let managed_folder_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM moz_bookmarks WHERE parent = ?1 AND title = 'CamouManager' AND type = 2 LIMIT 1",
            [toolbar_id],
            |row| row.get(0),
        )
        .ok();

    if expected_bookmarks.is_empty() {
        match managed_folder_id {
            None => true,
            Some(folder_id) => {
                let count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM moz_bookmarks WHERE parent = ?1",
                        [folder_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(1);
                count == 0
            }
        }
    } else {
        let folder_id = match managed_folder_id {
            Some(id) => id,
            None => return false,
        };

        let total_children: usize = match conn.query_row(
            "SELECT COUNT(*) FROM moz_bookmarks WHERE parent = ?1",
            [folder_id],
            |row| row.get(0),
        ) {
            Ok(c) => c,
            Err(_) => return false,
        };

        if total_children != expected_bookmarks.len() {
            return false;
        }

        let mut stmt = match conn.prepare(
            "SELECT child.type, child.title, p.url \
             FROM moz_bookmarks child \
             LEFT JOIN moz_places p ON child.fk = p.id \
             WHERE child.parent = ?1 \
             ORDER BY child.position ASC",
        ) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let rows: Vec<(i64, Option<String>, Option<String>)> = match stmt.query_map([folder_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        }) {
            Ok(mapped) => mapped.filter_map(Result::ok).collect(),
            Err(_) => return false,
        };

        if rows.len() != expected_bookmarks.len() {
            return false;
        }

        for (idx, (item_type, title, url)) in rows.iter().enumerate() {
            if *item_type != 1 {
                return false;
            }
            let exp_obj = match expected_bookmarks[idx].as_object() {
                Some(o) => o,
                None => return false,
            };
            let exp_title = exp_obj.get("title").and_then(Value::as_str).unwrap_or("");
            let exp_url = exp_obj.get("url").and_then(Value::as_str).unwrap_or("");
            if title.as_deref().unwrap_or("") != exp_title || url.as_deref().unwrap_or("") != exp_url {
                return false;
            }
        }

        true
    }
}

/// Resolve the Firefox major version from `version.json`, `application.ini`, or fallback version tag.
pub fn resolve_browser_major(executable_path: &Path, fallback_id: &str) -> u32 {
    static NUM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+").expect("static regex"));
    if let Some(parent) = executable_path.parent() {
        let ver_json = parent.join("version.json");
        if let Ok(raw) = fs::read_to_string(&ver_json) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                if let Some(ver) = val.get("version").and_then(Value::as_str) {
                    if let Some(m) = NUM_RE.find(ver) {
                        if let Ok(major) = m.as_str().parse::<u32>() {
                            return major;
                        }
                    }
                }
            }
        }
        let app_ini = parent.join("application.ini");
        if let Ok(raw) = fs::read_to_string(&app_ini) {
            for line in raw.lines() {
                if let Some(ver) = line.strip_prefix("Version=") {
                    if let Some(m) = NUM_RE.find(ver.trim()) {
                        if let Ok(major) = m.as_str().parse::<u32>() {
                            return major;
                        }
                    }
                }
            }
        }
    }
    NUM_RE
        .find(fallback_id)
        .and_then(|m| m.as_str().parse::<u32>().ok())
        .unwrap_or(135)
}

fn extract_ua_major(config: &Map<String, Value>) -> Option<u32> {
    static FF_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"Firefox/(\d+)").expect("static regex"));
    let ua = config.get("navigator.userAgent")?.as_str()?;
    let caps = FF_RE.captures(ua)?;
    caps.get(1)?.as_str().parse::<u32>().ok()
}

fn validate_executable_bundle(exe_path: &Path) -> Result<PathBuf> {
    reject_link(exe_path)?;
    if !exe_path.is_file() {
        bail!("Browser executable '{}' does not exist", exe_path.display());
    }
    let parent = exe_path
        .parent()
        .ok_or_else(|| anyhow!("Browser executable has no parent directory"))?;
    reject_link(parent)?;
    if find_properties_json(exe_path).is_none() {
        bail!(
            "Browser bundle at '{}' is missing properties.json",
            parent.display()
        );
    }
    Ok(exe_path.canonicalize()?)
}

fn find_exe_in_dir(dir: &Path) -> Option<PathBuf> {
    let direct = dir.join("camoufox.exe");
    if direct.is_file() {
        return Some(direct);
    }
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let nested = path.join("camoufox.exe");
            if nested.is_file() {
                return Some(nested);
            }
        }
    }
    None
}

fn discover_installed_versions(store: &Store) -> Result<Vec<Value>> {
    if store.versions_dir.exists() {
        let existing: HashMap<String, Value> = store
            .list("versions")?
            .into_iter()
            .filter_map(|v| {
                let id = string(&v, "id").to_owned();
                if id.is_empty() { None } else { Some((id, v)) }
            })
            .collect();

        if let Ok(entries) = fs::read_dir(&store.versions_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || reject_link(&path).is_err() || !path.is_dir() {
                    continue;
                }
                if safe_component(&name).is_err() {
                    continue;
                }
                if let Some(record) = existing.get(&name) {
                    if Path::new(string(record, "path")).is_file() {
                        continue;
                    }
                }
                if let Some(exe_path) = find_exe_in_dir(&path) {
                    if validate_executable_bundle(&exe_path).is_ok() {
                        let ver_file = exe_path.parent().unwrap_or(&path).join("version.json");
                        let ver_info: Value = fs::read_to_string(&ver_file)
                            .ok()
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_else(|| json!({}));
                        let ver_label = ver_info
                            .get("build")
                            .and_then(Value::as_str)
                            .or_else(|| ver_info.get("version").and_then(Value::as_str))
                            .unwrap_or(&name);
                        let record = json!({
                            "id": name,
                            "name": format!("Camoufox {ver_label}"),
                            "path": browser_path_string(&exe_path),
                            "release_url": "",
                            "installed_at": utcnow(),
                            "status": "installed"
                        });
                        let _ = store.put("versions", record);
                    }
                }
            }
        }
    }

    let mut valid: Vec<Value> = store
        .list("versions")?
        .into_iter()
        .filter(|r| {
            let p = Path::new(string(r, "path"));
            validate_executable_bundle(p).is_ok()
        })
        .collect();
    valid.sort_by(|a, b| version_sort_key(b).cmp(&version_sort_key(a)));
    Ok(valid)
}

#[cfg(windows)]
pub(crate) struct ProcessJob(isize);

#[cfg(windows)]
impl ProcessJob {
    pub(crate) fn attach(pid: u32) -> std::io::Result<Self> {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::{
                JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                },
                Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE},
            },
        };
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                let err = std::io::Error::last_os_error();
                CloseHandle(handle);
                return Err(err);
            }
            let process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if process.is_null() {
                let err = std::io::Error::last_os_error();
                CloseHandle(handle);
                return Err(err);
            }
            let assigned = AssignProcessToJobObject(handle, process);
            let err = std::io::Error::last_os_error();
            CloseHandle(process);
            if assigned == 0 {
                CloseHandle(handle);
                return Err(err);
            }
            Ok(Self(handle as isize))
        }
    }

    pub(crate) fn accounting(
        &self,
    ) -> Option<windows_sys::Win32::System::JobObjects::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>
    {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        unsafe {
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
            let ok = QueryInformationJobObject(
                self.0 as _,
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            );
            if ok != 0 { Some(info) } else { None }
        }
    }

    pub(crate) fn active_processes(&self) -> u32 {
        self.accounting().map(|a| a.ActiveProcesses).unwrap_or(0)
    }

    pub(crate) fn total_cpu_ticks(&self) -> i64 {
        self.accounting()
            .map(|a| a.TotalUserTime.saturating_add(a.TotalKernelTime))
            .unwrap_or(0)
    }

    pub(crate) fn pids(&self) -> Vec<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicProcessIdList, QueryInformationJobObject,
            JOBOBJECT_BASIC_PROCESS_ID_LIST,
        };
        #[repr(C)]
        struct PidListBuffer {
            header: JOBOBJECT_BASIC_PROCESS_ID_LIST,
            extra: [usize; 255],
        }
        unsafe {
            let mut buf: PidListBuffer = std::mem::zeroed();
            let ok = QueryInformationJobObject(
                self.0 as _,
                JobObjectBasicProcessIdList,
                &mut buf as *mut _ as *mut _,
                std::mem::size_of_val(&buf) as u32,
                std::ptr::null_mut(),
            );
            if ok == 0 {
                return Vec::new();
            }
            let count = (buf.header.NumberOfProcessIdsInList as usize).min(256);
            let ptr = std::ptr::addr_of!(buf.header.ProcessIdList[0]);
            std::slice::from_raw_parts(ptr, count)
                .iter()
                .filter_map(|&pid| u32::try_from(pid).ok())
                .filter(|&pid| pid != 0)
                .collect()
        }
    }

    pub(crate) fn sample_memory_mb(&self, fallback_pid: u32) -> f64 {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::{
                ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
                Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
            },
        };
        let mut pids = self.pids();
        if pids.is_empty() && fallback_pid != 0 {
            pids.push(fallback_pid);
        }
        let mut total_bytes: u64 = 0;
        unsafe {
            for pid in pids {
                let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if proc_handle.is_null() {
                    continue;
                }
                let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                if K32GetProcessMemoryInfo(proc_handle, &mut counters, counters.cb) != 0 {
                    total_bytes = total_bytes.saturating_add(counters.WorkingSetSize as u64);
                }
                CloseHandle(proc_handle);
            }
        }
        let mb = (total_bytes as f64) / (1024.0 * 1024.0);
        (mb * 10.0).round() / 10.0
    }

    pub(crate) fn request_graceful_close(&self, fallback_pid: u32) -> usize {
        use windows_sys::Win32::{
            Foundation::{HWND, LPARAM},
            UI::WindowsAndMessaging::{
                EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
            },
        };
        let mut pids = self.pids();
        if !pids.contains(&fallback_pid) && fallback_pid != 0 {
            pids.push(fallback_pid);
        }
        if pids.is_empty() {
            return 0;
        }
        struct CloseCtx {
            pids: Vec<u32>,
            closed: usize,
        }
        unsafe extern "system" fn enum_window_cb(hwnd: HWND, lparam: LPARAM) -> windows_sys::core::BOOL {
            let ctx = &mut *(lparam as *mut CloseCtx);
            let mut win_pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut win_pid);
            if win_pid != 0 && ctx.pids.contains(&win_pid) {
                if PostMessageW(hwnd, WM_CLOSE, 0, 0) != 0 {
                    ctx.closed += 1;
                }
            }
            1
        }
        let mut ctx = CloseCtx { pids, closed: 0 };
        unsafe {
            EnumWindows(Some(enum_window_cb), &mut ctx as *mut CloseCtx as LPARAM);
        }
        ctx.closed
    }

    pub(crate) fn terminate(&self, exit_code: u32) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0 as _, exit_code);
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0 as _);
        }
    }
}

struct ProfileSession {
    child: Option<Child>,
    #[cfg(windows)]
    job: Option<ProcessJob>,
    bridge: Option<BrowserProxy>,
    driver: Option<BrowserSession>,
    ip_sync: Option<IpSync>,
    pid: Option<u32>,
    state: String,
    error: String,
    stopping: bool,
    stderr_tail: Arc<Mutex<String>>,
    last_cpu_sample: Option<(Instant, i64)>,
    last_cpu_percent: f64,
}

impl ProfileSession {
    fn new_error(error: String) -> Self {
        Self {
            child: None,
            #[cfg(windows)]
            job: None,
            bridge: None,
            driver: None,
            ip_sync: None,
            pid: None,
            state: "error".into(),
            error,
            stopping: false,
            stderr_tail: Arc::new(Mutex::new(String::new())),
            last_cpu_sample: None,
            last_cpu_percent: 0.0,
        }
    }
    fn new_starting() -> Self {
        Self {
            child: None,
            #[cfg(windows)]
            job: None,
            bridge: None,
            driver: None,
            ip_sync: None,
            pid: None,
            state: "starting".into(),
            error: String::new(),
            stopping: false,
            stderr_tail: Arc::new(Mutex::new(String::new())),
            last_cpu_sample: None,
            last_cpu_percent: 0.0,
        }
    }


    fn is_alive(&mut self) -> bool {
        let mut child_alive = false;
        let mut exit_code: Option<i32> = None;

        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(None) => child_alive = true,
                Ok(Some(status)) => {
                    exit_code = status.code();
                }
                Err(_) => {}
            }
        }

        #[cfg(windows)]
        let job_alive = self
            .job
            .as_ref()
            .is_some_and(|job| job.active_processes() > 0);
        #[cfg(not(windows))]
        let job_alive = false;

        if child_alive || job_alive {
            #[cfg(windows)]
            if !child_alive {
                if let Some(job) = self.job.as_ref() {
                    if let Some(&first_pid) = job.pids().first() {
                        self.pid = Some(first_pid);
                    }
                }
            }
            return true;
        }
        if self.child.is_none() && self.state == "starting" && !self.stopping {
            return true;
        }


        if !self.stopping && self.state != "starting" {
            if let Some(sync) = self.ip_sync.as_mut() {
                if let Err(error) = sync.poll() {
                    self.state = "error".into();
                    self.error = format!("{error:#}");
                }
            }
        }
        // Process tree has completely exited; release any proxy bridge immediately.
        self.bridge = None;
        self.driver = None;
        self.ip_sync = None;
        self.pid = None;
        self.last_cpu_sample = None;
        self.last_cpu_percent = 0.0;

        if self.state == "running" || self.state == "starting" || self.state == "stopping" {
            if !self.stopping && (self.state == "starting" || exit_code.is_some_and(|code| code != 0)) {
                let tail = self.stderr_tail.lock().trim().to_owned();
                self.state = "error".into();
                self.error = if !tail.is_empty() {
                    redact(&tail)
                } else if !self.error.is_empty() {
                    self.error.clone()
                } else if self.state == "starting" {
                    "Browser exited unexpectedly during startup".to_owned()
                } else {
                    format!(
                        "Browser exited unexpectedly (code {})",
                        exit_code.unwrap_or(-1)
                    )
                };
            } else if self.state != "error" {
                self.state = "stopped".into();
            }
        }
        false
    }

    fn sample_metrics(&mut self) -> (f64, f64) {
        let pid = self.pid.unwrap_or(0);
        #[cfg(windows)]
        if let Some(job) = self.job.as_ref() {
            let mem_mb = job.sample_memory_mb(pid);
            let now = Instant::now();
            let ticks = job.total_cpu_ticks();
            let cpu = if let Some((prev_time, prev_ticks)) = self.last_cpu_sample {
                let dt_ns = now.duration_since(prev_time).as_nanos() as f64;
                if dt_ns >= 5_000_000.0 {
                    let d_cpu_ns = ((ticks.saturating_sub(prev_ticks).max(0)) as f64) * 100.0;
                    let cores = std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1) as f64;
                    let raw = (d_cpu_ns / (dt_ns * cores)) * 100.0;
                    let rounded = ((raw.clamp(0.0, 100.0)) * 10.0).round() / 10.0;
                    self.last_cpu_sample = Some((now, ticks));
                    self.last_cpu_percent = rounded;
                    rounded
                } else {
                    self.last_cpu_percent
                }
            } else {
                self.last_cpu_sample = Some((now, ticks));
                self.last_cpu_percent
            };
            return (cpu, mem_mb);
        }

        #[cfg(not(windows))]
        {
            let _ = pid;
            (0.0, 0.0)
        }
        #[cfg(windows)]
        (0.0, 0.0)
    }

    fn begin_graceful_stop(&mut self) -> Duration {
        self.stopping = true;
        self.state = "stopping".into();
        if let Some(driver) = self.driver.take() {
            match driver.close() {
                Ok(()) => return Duration::from_secs(3),
                Err(error) => self.error = format!("Native graceful shutdown failed: {error:#}"),
            }
        }
        let fallback_pid = self.pid.unwrap_or(0);
        #[cfg(windows)]
        let windows_notified = self
            .job
            .as_ref()
            .map(|j| j.request_graceful_close(fallback_pid))
            .unwrap_or(0);
        #[cfg(not(windows))]
        let windows_notified = 0usize;

        if windows_notified > 0 {
            Duration::from_millis(3000)
        } else {
            Duration::from_millis(350)
        }
    }

    fn finish_stop(&mut self) {
        if self.is_alive() {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
            }
            #[cfg(windows)]
            if let Some(job) = self.job.as_ref() {
                job.terminate(0);
            }
            if let Some(child) = self.child.as_mut() {
                let _ = child.wait();
            }
        }

        self.bridge = None;
        self.driver = None;
        self.ip_sync = None;
        self.child = None;
        #[cfg(windows)]
        {
            self.job = None;
        }
        self.pid = None;
        self.last_cpu_sample = None;
        self.last_cpu_percent = 0.0;
        self.state = "stopped".into();
        self.error.clear();
    }

    fn refresh_proxy_ip(&mut self) -> Result<Option<String>> {
        let Some(sync) = self.ip_sync.as_mut() else { return Ok(None); };
        match sync.poll() {
            Ok(ip) => { self.error.clear(); Ok(ip) },
            Err(error) => {
                let message = format!("{error:#}");
                if self.error == message { return Ok(None); }
                self.error = message;
                Err(error)
            }
        }
    }
}

pub struct Runtime {
    store: Arc<Store>,
    network: Arc<Network>,
    fingerprints: Arc<FingerprintService>,
    sessions: Mutex<HashMap<String, ProfileSession>>,
}

impl Runtime {
    #[cfg(test)]
    pub(crate) fn mark_starting_for_test(&self, id: &str) {
        self.sessions.lock().insert(id.to_owned(), ProfileSession::new_starting());
    }

    pub fn new(
        store: Arc<Store>,
        network: Arc<Network>,
        fingerprints: Arc<FingerprintService>,
    ) -> Self {
        Self {
            store,
            network,
            fingerprints,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_running(&self, id: &str) -> bool {
        let mut sessions = self.sessions.lock();
        sessions.get_mut(id).is_some_and(ProfileSession::is_alive)
    }

    fn record_launch_failure(&self, id: &str, err: anyhow::Error) -> anyhow::Error {
        let clean = self.store.redact_text(&err.to_string());
        let mut sessions = self.sessions.lock();
        if let Some(session) = sessions.get_mut(id) {
            if session.stopping && session.error.is_empty() {
                session.finish_stop();
                session.stopping = false;
                return anyhow!("Launch cancelled: profile was stopped");
            }
            session.finish_stop();
        }
        let _ = self.store.log("ERROR", &format!("Launch failed: {clean}"), id);
        sessions.insert(id.to_owned(), ProfileSession::new_error(clean.clone()));
        anyhow!(clean)
    }

    pub fn launch(&self, id: &str, headless: bool) -> Result<Value> {
        let _op = self.store.operation.lock();

        let mut profile = self
            .store
            .get("profiles", id)?
            .ok_or_else(|| anyhow!("Profile '{id}' not found"))?;
        let profile_name = string(&profile, "name").to_owned();

        // Duplicate launch guard (must not overwrite active running session)
        if self.is_running(id) {
            bail!("Profile '{profile_name}' is already running");
        }

        let attempt = (|| -> Result<Value> {
            // 1. Enforce max_running concurrency limit
            let settings = self.store.settings()?;
            let max_running = settings
                .get("max_running")
                .and_then(Value::as_u64)
                .unwrap_or(4) as usize;
            {
                let mut sessions = self.sessions.lock();
                let active_count = sessions
                    .values_mut()
                    .map(|s| usize::from(s.is_alive()))
                    .sum::<usize>();
                if active_count >= max_running {
                    bail!("Maximum running profiles limit ({max_running}) reached");
                }
                sessions.insert(id.to_owned(), ProfileSession::new_starting());
            }

            // 2. Resolve and permanently pin Camoufox browser version
            let installed = discover_installed_versions(&self.store)?;
            let mut version_id = string(&profile, "browser_version").trim().to_owned();
            let mut profile_dirty = false;

            let exe_path = if !version_id.is_empty() {
                safe_component(&version_id)?;
                let ver_record = self
                    .store
                    .get("versions", &version_id)?
                    .or_else(|| {
                        installed
                            .iter()
                            .find(|v| string(v, "id") == version_id)
                            .cloned()
                    })
                    .ok_or_else(|| {
                        anyhow!("Pinned browser version '{version_id}' is not installed")
                    })?;
                let candidate = PathBuf::from(string(&ver_record, "path"));
                validate_executable_bundle(&candidate).with_context(|| {
                    format!("Pinned browser version '{version_id}' is not installed")
                })?
            } else {
                let chosen = installed.first().ok_or_else(|| {
                    anyhow!("No Camoufox browser version found. Please install a version first.")
                })?;
                version_id = string(chosen, "id").to_owned();
                let candidate = PathBuf::from(string(chosen, "path"));
                let validated = validate_executable_bundle(&candidate)?;
                profile["browser_version"] = Value::String(version_id.clone());
                profile_dirty = true;
                let _ = self.store.log(
                    "INFO",
                    &format!("Pinned profile '{profile_name}' to browser version {version_id}"),
                    id,
                );
                validated
            };

            let actual_major = resolve_browser_major(&exe_path, &version_id);

            // 3. Ensure persistent fingerprint exists and aligns with pinned browser major
            if profile
                .get("fingerprint")
                .and_then(Value::as_object)
                .is_none_or(|m| m.is_empty())
            {
                profile["fingerprint"] = self.fingerprints.generate(&profile)?;
                profile_dirty = true;
            }
            if let Some(fp_obj) = profile.get("fingerprint").and_then(Value::as_object) {
                if extract_ua_major(fp_obj) != Some(actual_major) {
                    self.fingerprints
                        .retarget_version(&mut profile["fingerprint"], actual_major)?;
                    profile_dirty = true;
                }
            }
            if let Some(fp_obj) = profile.get_mut("fingerprint").and_then(Value::as_object_mut) {
                if !fp_obj.contains_key("window.outerWidth") || !fp_obj.contains_key("window.outerHeight") {
                    crate::fingerprints::ensure_window_dimensions(fp_obj);
                    profile_dirty = true;
                }
                if !fp_obj.contains_key("headers.User-Agent") {
                    if let Some(ua) = fp_obj.get("navigator.userAgent").and_then(Value::as_str) {
                        fp_obj.insert("headers.User-Agent".into(), json!(ua));
                        profile_dirty = true;
                    }
                }
            }

            // 4. Proxy preflight check (fail closed) and proxy bridge acquisition
            let proxy_id = string(&profile, "proxy_id").trim().to_owned();
            let mut browser_proxy: Option<BrowserProxy> = None;

            if !proxy_id.is_empty() {
                let proxy = self
                    .store
                    .get("proxies", &proxy_id)?
                    .ok_or_else(|| anyhow!("Assigned proxy '{proxy_id}' not found"))?;
                if !proxy.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
                    bail!(
                        "Assigned proxy '{}' is disabled",
                        string(&proxy, "name")
                    );
                }
                let preflight_ip;
                let mut location = if profile["location"]["locked"].as_bool().unwrap_or(false) {
                    let check = self.network.check(&proxy)?;
                    if !check["ok"].as_bool().unwrap_or(false) {
                        bail!("Preflight proxy check failed: {}", string(&check, "error"));
                    }
                    preflight_ip = string(&check, "ip").to_owned();
                    profile["location"].clone()
                } else {
                    let detected = self.network.detect(Some(&proxy)).context("Preflight proxy location check failed")?;
                    preflight_ip = string(&detected, "ip").to_owned();
                    detected
                };
                location["ip"] = json!(preflight_ip);
                if location != profile["location"] {
                    self.fingerprints.apply_location(&mut profile["fingerprint"], &location)?;
                    profile["location"] = location;
                    profile_dirty = true;
                }
                profile_dirty |= update_profile_ip(&mut profile, &preflight_ip)?;
                browser_proxy = Some(self.network.browser_proxy(&proxy)?);
            }

            if profile_dirty {
                profile = self.store.put("profiles", profile)?;
                profile_dirty = false;
            }
            {
                let mut sessions = self.sessions.lock();
                if let Some(session) = sessions.get_mut(id) {
                    if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                        session.finish_stop();
                        session.stopping = false;
                        bail!("Launch cancelled: profile was stopped");
                    }
                }
            }


            // 5. Prepare persistent profile directories and clean stale crash locks
            let profile_dir = self.store.profile_dir(id)?;
            reject_link(&profile_dir)?;
            let browser_dir = profile_dir.join("browser");
            let addons_dir = profile_dir.join("addons");
            reject_link(&browser_dir)?;
            reject_link(&addons_dir)?;
            fs::create_dir_all(&browser_dir)?;
            fs::create_dir_all(&addons_dir)?;

            for stale_lock in ["parent.lock", "lock", ".parentlock", ".startup-incomplete"] {
                let lock_path = browser_dir.join(stale_lock);
                if lock_path.exists() {
                    let _ = fs::remove_file(&lock_path);
                }
            }

            // 6. Validate and resolve managed extensions & bookmark synchronizer WebExtension
            let mut warnings: Vec<String> = Vec::new();
            let mut addon_paths: Vec<String> = Vec::new();
            let addons_canonical = addons_dir.canonicalize()?;

            if let Some(ext_list) = profile.get("extensions").and_then(Value::as_array) {
                for ext_val in ext_list {
                    let ext_raw = ext_val.as_str().unwrap_or("").trim();
                    if ext_raw.is_empty() {
                        continue;
                    }
                    let rel = ext_raw.strip_prefix("addons/").unwrap_or(ext_raw);
                    if let Err(e) = safe_component(rel) {
                        let msg = format!("Invalid managed extension '{ext_raw}': {e}");
                        let _ = self.store.log("WARNING", &msg, id);
                        warnings.push(msg);
                        continue;
                    }
                    let ext_dir = addons_dir.join(rel);
                    if let Err(e) = reject_link(&ext_dir) {
                        let msg = format!("Rejected extension link '{ext_raw}': {e}");
                        let _ = self.store.log("WARNING", &msg, id);
                        warnings.push(msg);
                        continue;
                    }
                    let manifest_path = ext_dir.join("manifest.json");
                    if !ext_dir.is_dir()
                        || !manifest_path.is_file()
                        || reject_link(&manifest_path).is_err()
                    {
                        let msg = format!(
                            "Managed extension '{ext_raw}' not found or missing manifest.json"
                        );
                        let _ = self.store.log("WARNING", &msg, id);
                        warnings.push(msg);
                        continue;
                    }
                    match ext_dir.canonicalize() {
                        Ok(canon) if canon.starts_with(&addons_canonical) => {
                            addon_paths.push(browser_path_string(&canon));
                        }
                        _ => {
                            let msg = format!(
                                "Managed extension '{ext_raw}' escaped profile addons directory"
                            );
                            let _ = self.store.log("WARNING", &msg, id);
                            warnings.push(msg);
                        }
                    }
                }
            }

            let bookmarks_slice = profile
                .get("bookmarks")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let clean_bms = clean_managed_bookmarks(bookmarks_slice)?;
            let bm_addon_dir = prepare_bookmark_addon(&profile_dir, bookmarks_slice)
                .context("Bookmark addon preparation failed")?;
            addon_paths.push(browser_path_string(&bm_addon_dir));
            let ip_sync = if browser_proxy.is_some() {
                let sync = IpSync::prepare(&profile_dir, self.network.egress_url(), &browser_proxy.as_ref().unwrap().prefs)?;
                Some(sync)
            } else { None };
            // 7. Build and validate Camoufox config + startup preferences
            let mut launch_fp = profile
                .get("fingerprint")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if let Some(location) = profile.get("location").filter(|l| l.is_object()) {
                let has_loc = ["ip", "country", "timezone", "locale"]
                    .iter()
                    .any(|k| !string(location, k).is_empty())
                    || location.get("latitude").is_some_and(|v| !v.is_null())
                    || location.get("longitude").is_some_and(|v| !v.is_null());
                if has_loc {
                    self.fingerprints.apply_location(&mut launch_fp, location)?;
                }
            }

            let mut config_map = launch_fp
                .as_object()
                .cloned()
                .ok_or_else(|| anyhow!("Profile fingerprint must be a JSON object"))?;
            crate::fingerprints::ensure_window_dimensions(&mut config_map);
            if !config_map.contains_key("headers.User-Agent") {
                if let Some(ua) = config_map.get("navigator.userAgent").and_then(Value::as_str) {
                    config_map.insert("headers.User-Agent".into(), json!(ua));
                }
            }
            if browser_proxy.is_some() {
                // Camoufox spoofing forces default-route UDP discovery and fabricates unusable ICE.
                config_map.remove("webrtc:ipv4");
                config_map.remove("webrtc:ipv6");
            }
            let (host_w, host_h) = host_work_area();
            adapt_window_to_host(&mut config_map, host_w, host_h);


            config_map.remove("webGl2Enabled");
            config_map
                .entry("voices:blockIfNotDefined".to_owned())
                .or_insert(Value::Bool(true));
            config_map.insert(
                "addons".into(),
                Value::Array(addon_paths.into_iter().map(Value::String).collect()),
            );

            let search_engine = resolve_search_engine(Some(&profile), Some(&settings));
            let default_startup_url = resolve_default_startup_url(Some(&profile), Some(&settings));

            let user_prefs = build_default_prefs(
                &config_map,
                browser_proxy.as_ref().map(|bp| &bp.prefs),
                !clean_bms.is_empty(),
                Some(&search_engine),
                Some(&default_startup_url),
            );
            prepare_webrtc_pref(&browser_dir, &user_prefs)?;

            // Drop pref-backed DNT / GPC from CAMOU_CONFIG just like camoufox/utils.py
            config_map.remove("navigator.doNotTrack");
            config_map.remove("navigator.globalPrivacyControl");

            let prop_warnings = validate_and_filter_config(&mut config_map, &exe_path)?;
            for w in prop_warnings {
                let _ = self.store.log("WARNING", &w, id);
                warnings.push(w);
            }

            let config_env = encode_camou_config_env(&config_map)?;
            let prefs_env = encode_camou_prefs_env(&user_prefs)?;

            // 8. Validate startup URLs and construct native CLI command without shell interpolation
            let mut valid_urls: Vec<String> = Vec::new();
            if let Some(raw_urls) = profile.get("startup_urls").and_then(Value::as_array) {
                for raw_u in raw_urls {
                    let s = raw_u.as_str().unwrap_or("").trim();
                    if s.is_empty() {
                        continue;
                    }
                    match normalize_and_validate_url(s) {
                        Ok(normalized) => valid_urls.push(normalized),
                        Err(e) => {
                            let msg = format!("Skipped invalid startup URL '{s}': {e}");
                            let _ = self.store.log("WARNING", &msg, id);
                            warnings.push(msg);
                        }
                    }
                }
            }

            let mut cmd = Command::new(browser_path_string(&exe_path));
            if let Some(exe_dir) = exe_path.parent() {
                cmd.current_dir(browser_path_string(exe_dir));
            }
            cmd.arg("-no-remote");
            cmd.arg("--remote-debugging-port=0");
            if headless {
                cmd.arg("-headless");
            }
            cmd.arg("-wait-for-browser");
            let _ = ensure_distribution_policies(&exe_path, &search_engine);
            if !headless {
                cmd.arg("-foreground");
                prepare_browser_chrome_css(&exe_path)?;
                let launch_w = config_map
                    .get("window.outerWidth")
                    .and_then(Value::as_i64)
                    .filter(|&v| v > 0)
                    .unwrap_or(1280);
                let launch_h = config_map
                    .get("window.outerHeight")
                    .and_then(Value::as_i64)
                    .filter(|&v| v > 0)
                    .unwrap_or(800);
                let host_x = ((host_w - launch_w) / 2).max(0);
                let host_y = ((host_h - launch_h) / 2).max(0);
                if let Err(err) = prepare_xulstore_window(&browser_dir, launch_w, launch_h, host_x, host_y) {
                    let msg = format!("Failed to prepare xulstore window size/position: {err}");
                    let _ = self.store.log("WARNING", &msg, id);
                    warnings.push(msg);
                }
            }
            cmd.arg("-profile").arg(browser_path_string(&browser_dir));

            if valid_urls.is_empty() {
                cmd.arg("-url").arg(&default_startup_url);
            } else {
                for u in &valid_urls {
                    cmd.arg("-url").arg(u);
                }
            }

            // Clear any inherited CAMOU_CONFIG_* or CAMOU_PREFS_* environment variables
            for (k, _) in std::env::vars_os() {
                if let Some(k_str) = k.to_str() {
                    if k_str.starts_with("CAMOU_CONFIG_") || k_str.starts_with("CAMOU_PREFS_") {
                        cmd.env_remove(k_str);
                    }
                }
            }
            cmd.env("MOZ_CRASHREPORTER_DISABLE", "1")
                .env("MOZ_CRASHREPORTER_NO_REPORT", "1");
            for (k, v) in config_env {
                cmd.env(k, v);
            }
            for (k, v) in prefs_env {
                cmd.env(k, v);
            }

            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            }
            {
                let mut sessions = self.sessions.lock();
                if let Some(session) = sessions.get_mut(id) {
                    if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                        session.finish_stop();
                        session.stopping = false;
                        bail!("Launch cancelled: profile was stopped");
                    }
                }
            }


            let mut child = cmd
                .spawn()
                .with_context(|| format!("Failed to spawn Camoufox binary '{}'", exe_path.display()))?;
            let child_pid = child.id();

            #[cfg(windows)]
            let job = match ProcessJob::attach(child_pid) {
                Ok(j) => j,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!("Failed to attach browser to Windows Job Object: {err}"));
                }
            };

            let stderr_tail = Arc::new(Mutex::new(String::new()));
            let debug_endpoint = Arc::new(Mutex::new(None));
            if let Some(stderr) = child.stderr.take() {
                let tail_clone = Arc::clone(&stderr_tail);
                let debug_endpoint = Arc::clone(&debug_endpoint);
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stderr);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                let trimmed = line.trim();
                                if let Some(endpoint) = BrowserSession::endpoint(trimmed) {
                                    *debug_endpoint.lock() = Some(endpoint);
                                }
                                if !trimmed.is_empty() {
                                    let mut guard = tail_clone.lock();
                                    if guard.len() > 2048 {
                                        guard.drain(..1024);
                                    }
                                    if !guard.is_empty() {
                                        guard.push('\n');
                                    }
                                    guard.push_str(trimmed);
                                }
                            }
                        }
                    }
                });
            }

            #[cfg(windows)]
            let initial_cpu_sample = Some((Instant::now(), job.total_cpu_ticks()));
            #[cfg(not(windows))]
            let initial_cpu_sample = None;

            // Publish starting live session into sessions promptly after process ownership/Job attach
            {
                let mut sessions = self.sessions.lock();
                if let Some(existing) = sessions.get_mut(id) {
                    if (existing.stopping || existing.state == "stopping") && existing.error.is_empty() {
                        let _ = child.kill();
                        #[cfg(windows)]
                        job.terminate(0);
                        let _ = child.wait();
                        existing.finish_stop();
                        existing.stopping = false;
                        bail!("Launch cancelled: profile was stopped");
                    }
                }
                let session = ProfileSession {
                    child: Some(child),
                    #[cfg(windows)]
                    job: Some(job),
                    bridge: browser_proxy,
                    driver: None,
                    ip_sync,
                    pid: Some(child_pid),
                    state: "starting".into(),
                    error: String::new(),
                    stopping: false,
                    stderr_tail,
                    last_cpu_sample: initial_cpu_sample,
                    last_cpu_percent: 0.0,
                };
                sessions.insert(id.to_owned(), session);
            }

            // Verify fail-closed startup across brief stabilization window
            for _ in 0..6 {
                std::thread::sleep(Duration::from_millis(50));
                let mut sessions = self.sessions.lock();
                let Some(session) = sessions.get_mut(id) else {
                    bail!("Profile session not found");
                };
                if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                    session.finish_stop();
                    session.stopping = false;
                    bail!("Launch cancelled: profile was stopped");
                }
                if !session.is_alive() {
                    let reason = if session.error.is_empty() {
                        "Browser process exited immediately during startup".to_owned()
                    } else {
                        session.error.clone()
                    };
                    session.finish_stop();
                    bail!("{reason}");
                }
            }
            let ready = (|| -> Result<()> {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    let owned = {
                        let mut sessions = self.sessions.lock();
                        let Some(session) = sessions.get_mut(id) else {
                            bail!("Profile session not found");
                        };
                        if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                            session.finish_stop();
                            session.stopping = false;
                            bail!("Launch cancelled: profile was stopped");
                        }
                        if !session.is_alive() {
                            bail!("Trình duyệt đóng trước khi sẵn sàng: {}", session.error);
                        }
                        #[cfg(windows)]
                        let owned = session.job.as_ref().map(ProcessJob::pids).unwrap_or_default();
                        #[cfg(not(windows))]
                        let owned = vec![child_pid];
                        owned
                    };

                    let endpoint = debug_endpoint.lock().take();
                    if let Some(endpoint) = endpoint {
                        let mut driver = BrowserSession::connect(&endpoint, &owned)?;
                        // Await monitor installation instead of Camoufox's fire-and-forget addon bootstrap.
                        let monitor_path = self.sessions.lock().get(id)
                            .and_then(|session| session.ip_sync.as_ref())
                            .map(|sync| browser_path_string(&sync.addon_dir));
                        if let Some(path) = monitor_path {
                            driver.install_extension(&path).context("Không cài được tiện ích đồng bộ IP")?;
                        }
                        let mut sessions = self.sessions.lock();
                        let Some(session) = sessions.get_mut(id) else {
                            bail!("Profile session not found");
                        };
                        if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                            session.finish_stop();
                            session.stopping = false;
                            bail!("Launch cancelled: profile was stopped");
                        }
                        session.driver = Some(driver);
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        bail!("Trình duyệt không mở được phiên native nội bộ");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })();
            if let Err(error) = ready {
                let mut sessions = self.sessions.lock();
                if let Some(session) = sessions.get_mut(id) {
                    session.finish_stop();
                }
                return Err(error);
            }
            let sync_ready = (|| -> Result<()> {
                let places_path = browser_dir.join("places.sqlite");
                let deadline = Instant::now() + Duration::from_secs(20);
                loop {
                    let mut poll_ip: Option<Result<Option<String>>> = None;
                    let mut sync_is_ready = true;
                    {
                        let mut sessions = self.sessions.lock();
                        let Some(session) = sessions.get_mut(id) else {
                            bail!("Profile session not found");
                        };
                        if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                            session.finish_stop();
                            session.stopping = false;
                            bail!("Launch cancelled: profile was stopped");
                        }
                        if !session.is_alive() {
                            bail!("Trình duyệt đóng trước khi hoàn tất đồng bộ bookmark: {}", session.error);
                        }
                        if let Some(sync) = session.ip_sync.as_mut() {
                            poll_ip = Some(sync.poll());
                            sync_is_ready = sync.is_ready();
                        }
                    }

                    if let Some(ip_res) = poll_ip {
                        if let Some(ip) = ip_res? {
                            profile_dirty |= update_profile_ip(&mut profile, &ip)?;
                        }
                        if !sync_is_ready {
                            if Instant::now() >= deadline {
                                bail!("Đồng bộ IP không sẵn sàng sau 20 giây");
                            }
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                    }

                    if places_path.is_file() && verify_bookmark_sync_state(&places_path, &clean_bms) {
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        bail!("Managed bookmark synchronization timed out after 20 seconds");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })();
            if let Err(error) = sync_ready {
                let mut sessions = self.sessions.lock();
                if let Some(session) = sessions.get_mut(id) {
                    session.finish_stop();
                }
                return Err(error);
            }
            if profile_dirty {
                self.store.put("profiles", profile)?;
            }

            let active_pid = {
                let mut sessions = self.sessions.lock();
                let Some(session) = sessions.get_mut(id) else {
                    bail!("Profile session not found");
                };
                if (session.stopping || session.state == "stopping") && session.error.is_empty() {
                    session.finish_stop();
                    session.stopping = false;
                    bail!("Launch cancelled: profile was stopped");
                }
                if !session.is_alive() {
                    session.finish_stop();
                    bail!("Browser exited before launch could be completed");
                }
                session.state = "running".into();
                session.pid.unwrap_or(child_pid)
            };

            let _ = self.store.log(
                "INFO",
                &format!(
                    "Successfully launched profile '{profile_name}' (PID: {active_pid}, headless={headless})"
                ),
                id,
            );

            Ok(json!({
                "id": id,
                "state": "running",
                "pid": active_pid,
                "warnings": warnings,
            }))
        })();

        match attempt {
            Ok(val) => Ok(val),
            Err(err) => Err(self.record_launch_failure(id, err)),
        }
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        let grace = {
            let mut sessions = self.sessions.lock();
            let Some(session) = sessions.get_mut(id) else {
                return Ok(());
            };
            if !session.is_alive() && session.state != "starting" {
                session.finish_stop();
                return Ok(());
            }
            let grace = session.begin_graceful_stop();
            if !session.error.is_empty() { let _ = self.store.log("WARNING",&session.error,id); }
            grace
        };

        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !self.is_running(id) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        {
            let mut sessions = self.sessions.lock();
            if let Some(session) = sessions.get_mut(id) {
                if session.is_alive() { let _ = self.store.log("WARNING","Browser shutdown timed out; forcibly stopping owned process tree",id); }
                session.finish_stop();
            }
        }
        let _ = self.store.log("INFO", &format!("Stopped profile {id}"), id);
        Ok(())
    }

    pub fn stop_all(&self) -> Result<()> {
        let running_ids: Vec<String> = {
            let mut sessions = self.sessions.lock();
            sessions
                .iter_mut()
                .filter_map(|(id, s)| if s.is_alive() || s.state == "starting" { Some(id.clone()) } else { None })
                .collect()
        };
        for id in running_ids {
            if let Err(err) = self.stop(&id) {
                let _ = self.store.log(
                    "ERROR",
                    &format!("Error stopping profile {id}: {err}"),
                    &id,
                );
            }
        }
        Ok(())
    }

    pub fn status(&self) -> Result<Value> {
        let profiles = self.store.list("profiles")?;
        let mut sessions = self.sessions.lock();
        let mut statuses = Map::with_capacity(profiles.len());

        for mut profile in profiles {
            let pid_str = string(&profile, "id").to_owned();
            if pid_str.is_empty() {
                continue;
            }
            let entry = if let Some(session) = sessions.get_mut(&pid_str) {
                if session.is_alive() {
                    if session.state == "running" {
                        match session.refresh_proxy_ip() {
                            Ok(Some(ip)) => {
                                if update_profile_ip(&mut profile, &ip)? {
                                    profile = self.store.put("profiles", profile)?;
                                }
                            },
                            Ok(None) => {},
                            Err(error) => { let _ = self.store.log("ERROR", &format!("{error:#}"), &pid_str); },
                        }
                    }
                    let (cpu, mem) = session.sample_metrics();
                    json!({
                        "state": session.state,
                        "pid": session.pid,
                        "cpu_percent": cpu,
                        "memory_mb": mem,
                        "error": session.error,
                        "egress_ip": profile["location"]["ip"],
                    })
                } else {
                    json!({
                        "state": session.state,
                        "pid": Value::Null,
                        "cpu_percent": 0.0,
                        "memory_mb": 0.0,
                        "error": session.error,
                        "egress_ip": profile["location"]["ip"],
                    })
                }
            } else {
                json!({
                    "state": "stopped",
                    "pid": Value::Null,
                    "cpu_percent": 0.0,
                    "memory_mb": 0.0,
                    "error": "",
                    "egress_ip": profile["location"]["ip"],
                })
            };
            statuses.insert(pid_str, entry);
        }

        Ok(Value::Object(statuses))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.stop_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_user_preferences_fail_without_truncating_the_profile() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("user.js");
        let original = b"user_pref(\"browser.startup.homepage\", \"https://example.com\");\n";
        fs::write(&path, original).unwrap();
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(4 * 1024 * 1024 + 1).unwrap();
        let error = prepare_webrtc_pref(root.path(), &Map::new()).unwrap_err();
        assert!(error.to_string().contains("exceeds 4 MiB"));
        assert_eq!(fs::metadata(&path).unwrap().len(), 4 * 1024 * 1024 + 1);
        assert!(fs::read(&path).unwrap().starts_with(original));
    }


    fn write_mock_browser_bundle(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let exe = dir.join("camoufox.exe");
        fs::write(&exe, b"MZ-mock").unwrap();
        fs::write(
            dir.join("version.json"),
            r#"{"version":"156.0.1","build":"beta.36"}"#,
        )
        .unwrap();
        fs::write(
            dir.join("application.ini"),
            "[App]\nVersion=156.0.1-beta.36\n",
        )
        .unwrap();
        let props = json!([
            { "property": "navigator.userAgent", "type": "str" },
            { "property": "navigator.appVersion", "type": "str" },
            { "property": "navigator.platform", "type": "str" },
            { "property": "navigator.oscpu", "type": "str" },
            { "property": "navigator.hardwareConcurrency", "type": "uint" },
            { "property": "screen.width", "type": "uint" },
            { "property": "screen.height", "type": "uint" },
            { "property": "fonts", "type": "array" },
            { "property": "voices", "type": "array" },
            { "property": "voices:blockIfNotDefined", "type": "bool" },
            { "property": "addons", "type": "array" },
            { "property": "timezone", "type": "str" },
            { "property": "locale:language", "type": "str" },
            { "property": "locale:region", "type": "str" },
            { "property": "geolocation:latitude", "type": "double" },
            { "property": "geolocation:longitude", "type": "double" },
            { "property": "webrtc:ipv4", "type": "str" },
            { "property": "webGl:vendor", "type": "str" },
            { "property": "webGl:renderer", "type": "str" },
            { "property": "canvas:seed", "type": "uint", "removed": "156.0.1-beta.32" }
        ]);
        fs::write(
            dir.join("properties.json"),
            serde_json::to_string_pretty(&props).unwrap(),
        )
        .unwrap();
        exe
    }

    #[test]
    fn camou_config_and_prefs_chunking_and_ascii_escaping() {
        let mut config = Map::new();
        let long_unicode = " Tiếng Việt 🚀 ".repeat(350);
        config.insert(
            "navigator.userAgent".into(),
            Value::String(long_unicode.clone()),
        );
        config.insert("screen.width".into(), json!(1920));

        let chunks = encode_camou_config_env(&config).unwrap();
        assert!(chunks.len() >= 3);
        for (idx, (key, val)) in chunks.iter().enumerate() {
            assert_eq!(key, &format!("CAMOU_CONFIG_{}", idx + 1));
            assert!(
                val.is_ascii(),
                "chunk must be pure ASCII for Windows getenv"
            );
            assert!(val.len() <= CAMOU_CHUNK_SIZE);
        }

        let reassembled: String = chunks.into_iter().map(|(_, v)| v).collect();
        let parsed: Value = serde_json::from_str(&reassembled).unwrap();
        assert_eq!(parsed["navigator.userAgent"], long_unicode);
        assert_eq!(parsed["screen.width"], 1920);
    }

    #[test]
    fn validate_config_filters_unknown_and_removed_and_rejects_bad_types_or_voices() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = write_mock_browser_bundle(tmp.path());

        let mut cfg = Map::new();
        cfg.insert(
            "navigator.userAgent".into(),
            json!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0"
            ),
        );
        cfg.insert("screen.width".into(), json!(1920));
        cfg.insert("unknown.future.key".into(), json!("skip-me"));
        cfg.insert("canvas:seed".into(), json!(12345));
        cfg.insert(
            "voices".into(),
            json!([{
                "lang": "en-US",
                "name": "Microsoft David",
                "voiceUri": "urn:moz-tts:sapi:Microsoft David?en-US",
                "isDefault": true,
                "isLocalService": true
            }]),
        );

        let warnings = validate_and_filter_config(&mut cfg, &exe).unwrap();
        assert_eq!(warnings.len(), 2);
        assert!(!cfg.contains_key("unknown.future.key"));
        assert!(!cfg.contains_key("canvas:seed"));
        assert!(cfg.contains_key("navigator.userAgent"));
        assert!(cfg.contains_key("voices"));

        // Bad property type must fail closed
        let mut bad_type = cfg.clone();
        bad_type.insert("screen.width".into(), json!("not-a-uint"));
        assert!(validate_and_filter_config(&mut bad_type, &exe).is_err());

        // Incomplete voice entry must fail closed (#731)
        let mut bad_voices = cfg;
        bad_voices.insert(
            "voices".into(),
            json!([{"lang": "en-US", "name": "Incomplete Voice"}]),
        );
        assert!(validate_and_filter_config(&mut bad_voices, &exe).is_err());
    }


    #[test]
    fn bookmark_urls_reject_executable_schemes_and_option_injection() {
        for url in ["-headless", "javascript:alert(1)", "vbscript:msgbox(1)", ""] {
            assert!(normalize_and_validate_url(url).is_err());
        }
        assert!(prepare_bookmark_addon(tempfile::tempdir().unwrap().path(), &[json!({"url":"javascript:alert(1)"})]).is_err());
    }

    #[test]
    fn test_verify_bookmark_sync_state_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("places.sqlite");

        let empty_bms: Vec<Value> = vec![];
        let target_bms = vec![
            json!({"title": "Camoufox", "url": "https://example.com"}),
            json!({"title": "Docs", "url": "https://example.com/docs"}),
        ];

        // 1. Missing DB file: must never return true (even for empty bookmarks)
        assert!(!verify_bookmark_sync_state(&db_path, &empty_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // 2. Corrupted / uninitialized DB without toolbar folder: must return false
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE dummy (id INTEGER);").unwrap();
        }
        assert!(!verify_bookmark_sync_state(&db_path, &empty_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // 3. Initialize Firefox Places schema with toolbar folder (guid = 'toolbar_____')
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                r#"
                DROP TABLE dummy;
                CREATE TABLE moz_places (
                    id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    title TEXT
                );
                CREATE TABLE moz_bookmarks (
                    id INTEGER PRIMARY KEY,
                    type INTEGER NOT NULL,
                    fk INTEGER,
                    parent INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    title TEXT,
                    guid TEXT
                );
                INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (1, 2, NULL, 0, 0, 'root', 'root________');
                INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (3, 2, NULL, 1, 0, 'toolbar', 'toolbar_____');
                INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (4, 2, NULL, 1, 1, 'unfiled', 'unfiled_____');
                "#,
            )
            .unwrap();
        }

        // 4. Initial initialized state: no CamouManager folder -> empty bookmarks matches, target does not
        assert!(verify_bookmark_sync_state(&db_path, &empty_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // 5. A CamouManager folder exists outside toolbar (e.g. under unfiled parent=4): must NOT be used
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (10, 2, NULL, 4, 0, 'CamouManager', 'unfiled_cm___')",
                [],
            )
            .unwrap();
        }
        assert!(verify_bookmark_sync_state(&db_path, &empty_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // 6. Add CamouManager folder under toolbar (parent=3) with stale bookmarks
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (20, 2, NULL, 3, 0, 'CamouManager', 'tb_cm_______')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO moz_places (id, url, title) VALUES (21, 'https://old.com', 'Old')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (21, 1, 21, 20, 0, 'Old', 'bm_old______')",
                [],
            )
            .unwrap();
        }
        // Stale data does not match target, and non-empty folder does not match empty target
        assert!(!verify_bookmark_sync_state(&db_path, &empty_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // 7. Update DB to match target bookmarks
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM moz_bookmarks WHERE id = 21", []).unwrap();
            conn.execute("DELETE FROM moz_places WHERE id = 21", []).unwrap();

            conn.execute("INSERT INTO moz_places (id, url, title) VALUES (31, 'https://example.com', 'Camoufox')", []).unwrap();
            conn.execute("INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (31, 1, 31, 20, 0, 'Camoufox', 'bm_1________')", []).unwrap();
            conn.execute("INSERT INTO moz_places (id, url, title) VALUES (32, 'https://example.com/docs', 'Docs')", []).unwrap();
            conn.execute("INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (32, 1, 32, 20, 1, 'Docs', 'bm_2________')", []).unwrap();
        }
        assert!(verify_bookmark_sync_state(&db_path, &target_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &empty_bms));

        // 8. Order mismatch: swapping positions must fail verification
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("UPDATE moz_bookmarks SET position = 1 WHERE id = 31", []).unwrap();
            conn.execute("UPDATE moz_bookmarks SET position = 0 WHERE id = 32", []).unwrap();
        }
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // Restore correct order
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("UPDATE moz_bookmarks SET position = 0 WHERE id = 31", []).unwrap();
            conn.execute("UPDATE moz_bookmarks SET position = 1 WHERE id = 32", []).unwrap();
        }
        assert!(verify_bookmark_sync_state(&db_path, &target_bms));

        // 9. Extra child (separator type=3 or folder type=2): must reject
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, guid) VALUES (33, 3, NULL, 20, 2, '', 'sep_________')", []).unwrap();
        }
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));

        // Remove separator
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM moz_bookmarks WHERE id = 33", []).unwrap();
        }
        assert!(verify_bookmark_sync_state(&db_path, &target_bms));

        // 10. Removal / zero bookmarks: remove children and folder
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM moz_bookmarks WHERE parent = 20", []).unwrap();
            conn.execute("DELETE FROM moz_bookmarks WHERE id = 20", []).unwrap();
        }
        assert!(verify_bookmark_sync_state(&db_path, &empty_bms));
        assert!(!verify_bookmark_sync_state(&db_path, &target_bms));
    }

    #[cfg(windows)]
    #[test]
    fn job_object_tracks_and_terminates_process_tree_with_stats() {
        use std::os::windows::process::CommandExt;
        let mut child = Command::new("cmd.exe")
            .args(["/C", "ping -n 30 127.0.0.1 >NUL"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .spawn()
            .unwrap();
        let pid = child.id();
        let job = ProcessJob::attach(pid).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        assert!(job.active_processes() >= 1);
        assert!(job.pids().contains(&pid));
        assert!(job.sample_memory_mb(pid) > 0.0);

        job.terminate(0);
        let _ = child.wait();
        assert_eq!(job.active_processes(), 0);
    }

    #[test]
    fn lifecycle_limits_and_fail_closed_launch_statuses() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(root.path()).unwrap());
        let network = Arc::new(Network::new(Arc::clone(&store)));
        let fingerprints = Arc::new(FingerprintService::new(Arc::clone(&store)).unwrap());
        let runtime = Runtime::new(
            Arc::clone(&store),
            Arc::clone(&network),
            Arc::clone(&fingerprints),
        );

        let prof = store
            .put(
                "profiles",
                json!({
                    "name": "FailClosedProfile",
                    "os": "windows",
                    "browser_version": "v999.0.0-missing",
                    "startup_urls": [],
                    "bookmarks": [],
                    "extensions": []
                }),
            )
            .unwrap();
        let pid = string(&prof, "id").to_owned();

        // Launch must fail closed when pinned version is missing and record error status
        assert!(runtime.launch(&pid, true).is_err());
        assert!(!runtime.is_running(&pid));
        let st = runtime.status().unwrap();
        assert_eq!(st[&pid]["state"], "error");
        assert!(!string(&st[&pid], "error").is_empty());
    }

    #[test]
    fn test_discover_installed_versions_orders_stable_over_prerelease() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(root.path()).unwrap());

        let beta_dir = store.versions_dir.join("v156.0.1-beta.37");
        write_mock_browser_bundle(&beta_dir);

        let stable_dir = store.versions_dir.join("v156.0.1");
        write_mock_browser_bundle(&stable_dir);

        let installed = discover_installed_versions(&store).unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(string(&installed[0], "id"), "v156.0.1");
        assert_eq!(string(&installed[1], "id"), "v156.0.1-beta.37");
    }

    #[test]
    #[ignore]
    #[cfg(windows)]
    fn smoke_real_browser_socks_localhost_bidi() {
        let exe = PathBuf::from(std::env::var_os("CAMOUFOX_SMOKE_EXE").expect("CAMOUFOX_SMOKE_EXE required"));
        // Remote SOCKS DNS makes Gecko advertise localhost rather than 127.0.0.1.
        for headless in [true, false] {
            let home = tempfile::tempdir().unwrap();
            fs::write(home.path().join("user.js"), concat!(
                "user_pref(\"network.proxy.type\", 1);\n",
                "user_pref(\"network.proxy.socks\", \"127.0.0.1\");\n",
                "user_pref(\"network.proxy.socks_port\", 9);\n",
                "user_pref(\"network.proxy.socks_version\", 5);\n",
                "user_pref(\"network.proxy.socks_remote_dns\", true);\n",
                "user_pref(\"network.proxy.no_proxies_on\", \"\");\n",
            )).unwrap();
            let mut cmd = Command::new(&exe);
            cmd.arg("-no-remote").arg("--remote-debugging-port=0").arg("-wait-for-browser")
                .arg("-profile").arg(home.path()).arg("about:blank")
                .stdout(Stdio::null()).stderr(Stdio::piped());
            if headless { cmd.arg("-headless"); }
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            let mut child = cmd.spawn().unwrap();
            let job = ProcessJob::attach(child.id()).unwrap();
            let stderr = child.stderr.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    if let Some(endpoint) = BrowserSession::endpoint(&line) {
                        let _ = tx.send(endpoint);
                    }
                }
            });
            let endpoint = rx.recv_timeout(Duration::from_secs(15)).expect("Missing SOCKS BiDi endpoint");
            assert_eq!(endpoint.host_str(), Some("localhost"));
            let mut driver = BrowserSession::connect(&endpoint, &job.pids()).unwrap();
            driver.navigate_for_test("about:blank").unwrap();
            assert_eq!(driver.evaluate_json("JSON.stringify(location.href)").unwrap(), json!("about:blank"));
            driver.close().unwrap();
            child.wait().unwrap();
            reader.join().unwrap();
            eprintln!("SOCKS localhost BiDi: headless={headless}, session.new + page evaluation + browser.close passed");
        }
    }

    /// Isolated temporary-home smoke scenario for real Camoufox binary execution (run by parent via `--ignored`).
    #[test]
    #[ignore]
    fn smoke_real_browser_launch_probe_and_persistence() {
        let exe_candidate = match std::env::var("CAMOUFOX_SMOKE_EXE") {
            Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
            _ => {
                eprintln!("CAMOUFOX_SMOKE_EXE not set; skipping real browser smoke scenario");
                return;
            }
        };
        assert!(
            exe_candidate.is_file(),
            "Real Camoufox binary required at {}",
            exe_candidate.display()
        );

        let temp_home = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp_home.path()).unwrap());
        let network = Arc::new(Network::new(Arc::clone(&store)));
        let fingerprints = Arc::new(FingerprintService::new(Arc::clone(&store)).unwrap());
        let runtime = Arc::new(Runtime::new(
            Arc::clone(&store),
            Arc::clone(&network),
            Arc::clone(&fingerprints),
        ));
        let profiles = crate::profiles::Profiles::new(
            Arc::clone(&store),
            Arc::clone(&runtime),
            Arc::clone(&network),
            Arc::clone(&fingerprints),
        );

        store
            .put(
                "versions",
                json!({
                    "id": "v156.0.1-beta.36",
                    "name": "Camoufox beta.36",
                    "path": browser_path_string(&exe_candidate),
                    "release_url": "",
                    "installed_at": utcnow(),
                    "status": "installed"
                }),
            )
            .unwrap();

        let profile = profiles
            .create(json!({
                "name": "IsolatedSmokeProfile",
                "os": "linux",
                "browser_version": "",
                "proxy_id": "",
                "location": {
                    "ip": "203.0.113.42",
                    "country": "VN",
                    "timezone": "Asia/Ho_Chi_Minh",
                    "locale": "vi-VN",
                    "latitude": 10.8231,
                    "longitude": 106.6297,
                    "locked": true
                },
                "startup_urls": ["about:blank"],
                "bookmarks": [{"title": "Camoufox", "url": "https://example.com"}],
                "extensions": [],
                "fingerprint_meta": {}
            }))
            .unwrap();
        let id = string(&profile, "id").to_owned();

        // Import a real unpacked WebExtension into the profile
        let ext_src = temp_home.path().join("sample-ext");
        fs::create_dir_all(&ext_src).unwrap();
        fs::write(
            ext_src.join("manifest.json"),
            serde_json::to_string_pretty(&json!({
                "manifest_version": 2,
                "name": "Smoke Test Extension",
                "version": "1.0.0",
                "browser_specific_settings": {
                    "gecko": { "id": "smoke-ext@local.invalid" }
                },
                "background": { "scripts": ["bg.js"] }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(ext_src.join("bg.js"), "console.log('smoke-ext-loaded');").unwrap();
        let managed_ext = profiles.import_extension(&id, &ext_src).unwrap();
        assert!(managed_ext.starts_with("addons/"));

        let launched = runtime.launch(&id, true).unwrap();
        assert_eq!(launched["state"], "running");
        assert!(runtime.is_running(&id));

        // Duplicate launch must fail while running
        assert!(runtime.launch(&id, true).is_err());

        let mut observed_running = false;
        let poll_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < poll_deadline {
            if let Ok(status) = runtime.status() {
                if let Some(entry) = status.get(&id) {
                    if entry["state"] == "running" && entry["memory_mb"].as_f64().unwrap_or(0.0) > 0.0 {
                        observed_running = true;
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(observed_running, "Runtime status must report active running process with memory usage");
        let saved_fp = store.get("profiles", &id).unwrap().unwrap()["fingerprint"].clone();
        runtime.stop(&id).unwrap();
        assert!(!runtime.is_running(&id));

        let browser_dir = store.profile_dir(&id).unwrap().join("browser");
        assert!(browser_dir.join("prefs.js").exists());
        let places_db = browser_dir.join("places.sqlite");
        assert!(places_db.is_file(), "places.sqlite must exist after launch at {}", places_db.display());
        {
            let conn = rusqlite::Connection::open(&places_db).unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.title = 'Camoufox' AND p.url LIKE 'https://example.com%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            assert!(count >= 1, "Bookmark must be synced into places.sqlite by camoumanager-bookmarks@local.invalid");
        }

        // Relaunch and verify persistent fingerprint identity is preserved without re-rolling
        let relaunch = runtime.launch(&id, true).unwrap();
        assert_eq!(relaunch["state"], "running");
        assert!(runtime.is_running(&id));
        let after_fp = store.get("profiles", &id).unwrap().unwrap()["fingerprint"].clone();
        assert_eq!(saved_fp, after_fp);

        let status2 = runtime.status().unwrap();
        assert_eq!(status2[&id]["state"], "running");

        {
            let conn = rusqlite::Connection::open(&places_db).unwrap();
            let count2: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.title = 'Camoufox' AND p.url LIKE 'https://example.com%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            assert!(count2 >= 1, "Bookmark must remain persisted in places.sqlite across relaunch");
        }

        runtime.stop(&id).unwrap();
        assert!(!runtime.is_running(&id));
}

    #[test]
    #[ignore]
    fn smoke_real_browser_rotating_proxy_and_fail_closed() {
        use std::{io::{Read, Write}, net::{TcpListener, UdpSocket}, sync::atomic::{AtomicBool, Ordering}};
        let exe = PathBuf::from(std::env::var("CAMOUFOX_SMOKE_EXE").expect("CAMOUFOX_SMOKE_EXE required"));
        assert!(exe.is_file());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let current_ip = Arc::new(Mutex::new("203.0.113.11".to_owned()));
        let stopped = Arc::new(AtomicBool::new(false));
        let ip = current_ip.clone();
        let stop = stopped.clone();
        let worker = std::thread::spawn(move || {
            let mut clients = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let ip = ip.clone();
                        clients.push(std::thread::spawn(move || {
                            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                            let mut head = Vec::new();
                            let mut byte = [0];
                            while !head.ends_with(b"\r\n\r\n") {
                                if head.len() >= 16384 || stream.read_exact(&mut byte).is_err() { return; }
                                head.push(byte[0]);
                            }
                            let head = String::from_utf8_lossy(&head);
                            let authorized = head.lines().any(|line| line.eq_ignore_ascii_case("Proxy-Authorization: Basic YXVkaXQ6bG9jYWw="));
                            let (status, content_type, body) = if !authorized {
                                ("407 Proxy Authentication Required", "text/plain", "authentication required".to_owned())
                            } else if head.starts_with("GET http://egress.invalid/probe ") {
                                ("200 OK", "text/html", "<!doctype html><title>Privacy smoke</title>".to_owned())
                            } else {
                                ("200 OK", "application/json", json!({"ip": *ip.lock()}).to_string())
                            };
                            let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        }));
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                    Err(error) => panic!("Local proxy failed: {error}"),
                }
            }
            for client in clients { client.join().unwrap(); }
        });
        struct LocalProxy(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
        impl Drop for LocalProxy {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
                self.1.take().unwrap().join().unwrap();
            }
        }
        let _proxy = LocalProxy(stopped, Some(worker));
        let home = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(home.path()).unwrap());
        let mut network = Network::new(store.clone());
        network.egress_url = Some("http://egress.invalid/".into());
        let network = Arc::new(network);
        let fingerprints = Arc::new(FingerprintService::new(store.clone()).unwrap());
        let runtime = Arc::new(Runtime::new(store.clone(), network.clone(), fingerprints.clone()));
        let profiles = crate::profiles::Profiles::new(store.clone(), runtime.clone(), network.clone(), fingerprints);
        store.put("versions", json!({"id": "v156.0.1-beta.37", "path": browser_path_string(&exe), "status": "installed"})).unwrap();
        let proxy = store.put("proxies", json!({"name": "Local smoke proxy", "server": format!("http://127.0.0.1:{port}"), "username": "audit", "password": "local", "enabled": true})).unwrap();
        let profile = profiles.create(json!({
            "name": "RotatingProxySmoke", "os": "macos", "browser_version": "v156.0.1-beta.37",
            "proxy_id": proxy["id"], "location": {"locked": true, "ip": "198.51.100.9", "timezone": "Asia/Ho_Chi_Minh", "locale": "vi-VN"},
            "startup_urls": ["http://egress.invalid/probe"], "fingerprint_meta": {"use_preset": true}
        })).unwrap();
        let id = string(&profile, "id");
        fs::write(store.profile_dir(id).unwrap().join("browser/user.js"),
            "user_pref(\"media.peerconnection.enabled\", true);\nuser_pref(\"browser.startup.homepage\", \"about:blank\");\n").unwrap();
        assert_eq!(runtime.launch(id, true).unwrap()["state"], "running");
        runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().navigate_for_test("http://egress.invalid/probe").unwrap();
        let route = UdpSocket::bind("0.0.0.0:0").unwrap();
        route.connect("192.0.2.1:9").unwrap();
        let stun = UdpSocket::bind((route.local_addr().unwrap().ip(), 0)).unwrap();
        stun.set_nonblocking(true).unwrap();
        let native_probe = r#"(() => {
            const PeerConnection = globalThis.RTCPeerConnection || globalThis.mozRTCPeerConnection;
            if (typeof PeerConnection !== 'function') {
                return JSON.stringify({blocked: true, dpr: devicePixelRatio});
            }
            const pc = new PeerConnection({iceServers: [{urls: 'stun:STUN_ENDPOINT'}]});
            globalThis.__privacyProbe = pc;
            pc.createDataChannel('privacy-smoke');
            pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(error => {
                globalThis.__privacyProbeError = String(error);
            });
            return JSON.stringify({blocked: false, dpr: devicePixelRatio});
        })()"#.replace("STUN_ENDPOINT", &stun.local_addr().unwrap().to_string());
        let probe = || runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json(&native_probe).unwrap();
        let cookie = runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json(
            "(() => { document.cookie = 'privacy_session=persisted; Max-Age=3600; Path=/; SameSite=Lax'; return JSON.stringify(document.cookie); })()").unwrap();
        assert!(cookie.as_str().unwrap().contains("privacy_session=persisted"), "Initial cookie write failed: {cookie}");
        let initial = store.get("profiles", id).unwrap().unwrap();
        let mut stable_identity = initial["fingerprint"].clone();
        stable_identity.as_object_mut().unwrap().remove("webrtc:ipv4");
        stable_identity.as_object_mut().unwrap().remove("webrtc:ipv6");
        let pid = runtime.status().unwrap()[id]["pid"].clone();
        for address in ["203.0.113.11", "203.0.113.12", "203.0.113.13", "2001:db8::12", "203.0.113.14"] {
            *current_ip.lock() = address.to_owned();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let status = runtime.status().unwrap();
                assert_eq!(status[id]["state"], "running", "{status}");
                assert_eq!(status[id]["pid"], pid, "Rotation must not restart the browser: {status}");
                if status[id]["egress_ip"] == address { break; }
                assert!(Instant::now() < deadline, "Rotating IP was not updated: {status}");
                std::thread::sleep(Duration::from_millis(100));
            }
            let native = probe();
            assert_eq!(native["blocked"], false, "WebRTC must remain available behind proxy: {native}");
            std::thread::sleep(Duration::from_secs(1));
            let error = stun.recv_from(&mut [0; 2048]).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "Direct STUN traffic escaped proxy");
            let saved = store.get("profiles", id).unwrap().unwrap();
            assert_eq!(saved["location"]["ip"], address);
            assert_eq!(saved["location"]["timezone"], "Asia/Ho_Chi_Minh");
            let mut identity = saved["fingerprint"].clone();
            identity.as_object_mut().unwrap().remove("webrtc:ipv4");
            identity.as_object_mut().unwrap().remove("webrtc:ipv6");
            assert_eq!(identity, stable_identity);
            if let Some(dpr) = identity["window.devicePixelRatio"].as_f64() { assert_eq!(native["dpr"].as_f64(), Some(dpr)); }
            println!("PASS live IP rotation, same browser PID, no direct STUN UDP and stable identity: {address}");
        }
        *current_ip.lock() = "invalid-ip".into();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = runtime.status().unwrap();
            assert_eq!(status[id]["state"], "running", "{status}");
            assert_eq!(status[id]["pid"], pid, "{status}");
            assert_eq!(status[id]["egress_ip"], "203.0.113.14", "Invalid IP must not replace the last valid IP");
            if !status[id]["error"].as_str().unwrap().is_empty() { break; }
            assert!(Instant::now() < deadline, "Invalid IP was not reported: {status}");
            std::thread::sleep(Duration::from_millis(100));
        }
        println!("PASS invalid IP reports an error without closing the browser or replacing its IP");
        *current_ip.lock() = "203.0.113.14".into();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = runtime.status().unwrap();
            assert_eq!(status[id]["state"], "running", "{status}");
            assert_eq!(status[id]["pid"], pid, "{status}");
            if status[id]["error"] == "" { break; }
            assert!(Instant::now() < deadline, "IP monitor did not recover: {status}");
            std::thread::sleep(Duration::from_millis(100));
        }
        let cookie = runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json("JSON.stringify(document.cookie)").unwrap();
        assert!(cookie.as_str().unwrap().contains("privacy_session=persisted"), "{cookie}");
        runtime.stop(id).unwrap();
        println!("PASS session cookie survives live IP changes and monitor recovery");
        assert_eq!(runtime.launch(id, true).unwrap()["state"], "running");
        assert_eq!(runtime.status().unwrap()[id]["egress_ip"], "203.0.113.14");
        runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().navigate_for_test("http://egress.invalid/probe").unwrap();
        let cookie = runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json("JSON.stringify(document.cookie)").unwrap();
        assert!(cookie.as_str().unwrap().contains("privacy_session=persisted"), "Cookie lost on monitor reinstall: {cookie}");
        runtime.stop(id).unwrap();
        println!("PASS monitor reinstall confirms current session IP and preserves cookies");
        profiles.update(id, json!({"proxy_id": "", "startup_urls": ["about:blank"]})).unwrap();
        runtime.launch(id, true).unwrap();
        let navigation = runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().navigate_for_test("about:blank");
        assert!(navigation.is_ok(), "Direct navigation failed: {navigation:?}; status: {:?}; stderr: {}",
            runtime.status().unwrap(), runtime.sessions.lock().get(id).unwrap().stderr_tail.lock().as_str());
        let direct = probe();
        assert_eq!(direct["blocked"], false, "Direct profile must retain WebRTC: {direct}");
        stun.set_nonblocking(false).unwrap();
        stun.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut packet = [0; 2048];
        let (length, _) = match stun.recv_from(&mut packet) {
            Ok(packet) => packet,
            Err(error) => {
                let state = runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json(
                    "JSON.stringify({error: globalThis.__privacyProbeError, ice: globalThis.__privacyProbe.iceGatheringState, signaling: globalThis.__privacyProbe.signalingState})").unwrap();
                panic!("Direct positive control did not reach STUN: {error}; native state: {state}");
            }
        };
        assert!(length >= 20, "Expected a STUN binding request");
        assert_eq!(&packet[4..8], &[0x21, 0x12, 0xa4, 0x42], "Expected STUN magic cookie");
        runtime.sessions.lock().get_mut(id).unwrap().driver.as_mut().unwrap().evaluate_json(
            "(() => { globalThis.__privacyProbe.close(); delete globalThis.__privacyProbe; return JSON.stringify(true); })()").unwrap();
        runtime.stop(id).unwrap();
        println!("PASS proxy-to-direct transition restores WebRTC and confirms UDP listener works");
    }

    #[test]
    fn deterministic_startup_stop_all_cancels_and_prevents_resurrection() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(root.path()).unwrap());
        let network = Arc::new(Network::new(Arc::clone(&store)));
        let fingerprints = Arc::new(FingerprintService::new(Arc::clone(&store)).unwrap());
        let runtime = Runtime::new(
            Arc::clone(&store),
            Arc::clone(&network),
            Arc::clone(&fingerprints),
        );

        let p1 = store
            .put(
                "profiles",
                json!({
                    "name": "Profile1",
                    "os": "windows",
                    "browser_version": "",
                    "startup_urls": [],
                    "bookmarks": [],
                    "extensions": []
                }),
            )
            .unwrap();
        let id1 = string(&p1, "id").to_owned();

        let st = runtime.status().unwrap();
        assert_eq!(st[&id1]["state"], "stopped");
        assert!(st[&id1]["pid"].is_null());

        {
            let mut sessions = runtime.sessions.lock();
            sessions.insert(id1.clone(), ProfileSession::new_starting());
        }
        assert!(runtime.is_running(&id1));
        let st = runtime.status().unwrap();
        assert_eq!(st[&id1]["state"], "starting");
        assert!(st[&id1]["pid"].is_null());

        runtime.stop_all().unwrap();
        assert!(!runtime.is_running(&id1));
        let st = runtime.status().unwrap();
        assert_eq!(st[&id1]["state"], "stopped");

        #[cfg(windows)]
        {
            use std::process::Command;
            use std::os::windows::process::CommandExt;
            let mut cmd = Command::new("cmd.exe");
            cmd.arg("/c").arg("ping -n 10 127.0.0.1 >nul");
            cmd.creation_flags(0x08000000);
            let child = cmd.spawn().unwrap();
            let child_pid = child.id();
            let job = ProcessJob::attach(child_pid).unwrap();

            {
                let mut sessions = runtime.sessions.lock();
                sessions.insert(
                    id1.clone(),
                    ProfileSession {
                        child: Some(child),
                        job: Some(job),
                        bridge: None,
                        driver: None,
                        ip_sync: None,
                        pid: Some(child_pid),
                        state: "starting".into(),
                        error: String::new(),
                        stopping: false,
                        stderr_tail: Arc::new(Mutex::new(String::new())),
                        last_cpu_sample: None,
                        last_cpu_percent: 0.0,
                    },
                );
            }

            let st = runtime.status().unwrap();
            assert_eq!(st[&id1]["state"], "starting");
            assert_eq!(st[&id1]["pid"], child_pid);

            runtime.stop_all().unwrap();

            let st = runtime.status().unwrap();
            assert_eq!(st[&id1]["state"], "stopped");
            assert!(st[&id1]["pid"].is_null());
            assert!(!runtime.is_running(&id1));

            let handle = unsafe {
                windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    child_pid,
                )
            };
            if !handle.is_null() {
                let mut code = 0u32;
                unsafe {
                    windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut code);
                    windows_sys::Win32::Foundation::CloseHandle(handle);
                }
                assert_ne!(code, 259, "Process must not be STILL_ACTIVE (259)");
            }
        }
    }

    #[test]
    #[ignore]
    fn smoke_real_browser_startup_stop_all_cancellation() {
        let exe_candidate = match std::env::var("CAMOUFOX_SMOKE_EXE") {
            Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
            _ => {
                let default_path = PathBuf::from(
                    r"C:\Users\Huy\AppData\Local\CamouManagerRust\versions\v156.0.1-beta.36\camoufox.exe",
                );
                if default_path.is_file() {
                    default_path
                } else {
                    eprintln!("CAMOUFOX_SMOKE_EXE not set; skipping real browser smoke scenario");
                    return;
                }
            }
        };
        assert!(
            exe_candidate.is_file(),
            "Real Camoufox binary required at {}",
            exe_candidate.display()
        );

        let temp_home = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp_home.path()).unwrap());
        let network = Arc::new(Network::new(Arc::clone(&store)));
        let fingerprints = Arc::new(FingerprintService::new(Arc::clone(&store)).unwrap());
        let runtime = Arc::new(Runtime::new(
            Arc::clone(&store),
            Arc::clone(&network),
            Arc::clone(&fingerprints),
        ));
        let profiles = crate::profiles::Profiles::new(
            Arc::clone(&store),
            Arc::clone(&runtime),
            Arc::clone(&network),
            Arc::clone(&fingerprints),
        );

        store
            .put(
                "versions",
                json!({
                    "id": "v156.0.1-beta.36",
                    "name": "Camoufox beta.36",
                    "path": browser_path_string(&exe_candidate),
                    "release_url": "",
                    "installed_at": utcnow(),
                    "status": "installed"
                }),
            )
            .unwrap();

        let profile = profiles
            .create(json!({
                "name": "StartupCancelProfile",
                "os": "windows",
                "browser_version": "v156.0.1-beta.36",
                "proxy_id": "",
                "startup_urls": ["about:blank"],
                "bookmarks": [],
                "extensions": []
            }))
            .unwrap();
        let pid_str = string(&profile, "id").to_owned();

        let rt_clone = Arc::clone(&runtime);
        let pid_clone = pid_str.clone();
        let launch_handle = std::thread::spawn(move || rt_clone.launch(&pid_clone, true));

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut observed_starting_pid = None;
        while Instant::now() < deadline {
            let st = runtime.status().unwrap();
            let entry = &st[&pid_str];
            if entry["state"] == "starting" {
                if let Some(pid) = entry["pid"].as_u64() {
                    observed_starting_pid = Some(pid as u32);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        assert!(
            observed_starting_pid.is_some(),
            "Expected starting browser with PID to be observed"
        );
        let browser_pid = observed_starting_pid.unwrap();

        runtime.stop_all().unwrap();

        let launch_result = launch_handle.join().unwrap();
        assert!(
            launch_result.is_err(),
            "Launch must fail or be cancelled, not return success"
        );

        std::thread::sleep(Duration::from_millis(500));
        let final_st = runtime.status().unwrap();
        assert_ne!(
            final_st[&pid_str]["state"], "running",
            "Profile must not resurrect to running after stop_all"
        );
        assert!(!runtime.is_running(&pid_str));

        #[cfg(windows)]
        {
            let handle = unsafe {
                windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    browser_pid,
                )
            };
            if !handle.is_null() {
                let mut code = 0u32;
                unsafe {
                    windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut code);
                    windows_sys::Win32::Foundation::CloseHandle(handle);
                }
                assert_ne!(code, 259, "Process must not be STILL_ACTIVE (259)");
            }
        }
    }

    #[test]
    fn test_host_work_area_and_window_adaptation() {
        let (host_w, host_h) = host_work_area();
        assert!(host_w > 0, "host width must be positive: {host_w}");
        assert!(host_h > 0, "host height must be positive: {host_h}");

        // When spoofed screen is larger than host, window dimensions fit within host work area
        let mut config = Map::new();
        let large_screen_w = host_w + 500;
        let large_avail_h = host_h + 400;
        config.insert("screen.width".into(), json!(large_screen_w));
        config.insert("screen.height".into(), json!(host_h + 450));
        config.insert("screen.availHeight".into(), json!(large_avail_h));
        config.insert("window.innerWidth".into(), json!(large_screen_w));
        config.insert("window.innerHeight".into(), json!(large_avail_h));

        adapt_window_to_host(&mut config, host_w, host_h);

        let launch_w = config["window.outerWidth"].as_i64().expect("outerWidth");
        let launch_h = config["window.outerHeight"].as_i64().expect("outerHeight");

        // Window fits within host work area
        assert!(
            launch_w <= host_w,
            "launch width must fit within host width: {launch_w} <= {host_w}"
        );
        assert!(
            launch_h <= host_h,
            "launch height must fit within host height: {launch_h} <= {host_h}"
        );
        let expected_w = (host_w - 40).min(large_screen_w).max(800);
        let expected_h = (host_h - 60).min(large_avail_h).max(600);
        assert_eq!(launch_w, expected_w);
        assert_eq!(launch_h, expected_h);

        // Responsive reflow: innerWidth and innerHeight removed
        assert!(
            !config.contains_key("window.innerWidth"),
            "window.innerWidth must be removed from CAMOU_CONFIG"
        );
        assert!(
            !config.contains_key("window.innerHeight"),
            "window.innerHeight must be removed from CAMOU_CONFIG"
        );

        // Centered screenX and screenY
        let sx = config["window.screenX"].as_i64().expect("screenX");
        let sy = config["window.screenY"].as_i64().expect("screenY");
        assert_eq!(sx, ((large_screen_w - launch_w) / 2).max(0));
        assert_eq!(sy, ((large_avail_h - launch_h) / 2).max(0));

        // When spoofed screen is smaller than host, dimensions don't clamp to host,
        // but innerWidth/innerHeight are still removed
        let mut small_cfg = Map::new();
        small_cfg.insert("screen.width".into(), json!(1024));
        small_cfg.insert("screen.height".into(), json!(768));
        small_cfg.insert("screen.availHeight".into(), json!(728));
        small_cfg.insert("window.outerWidth".into(), json!(1000));
        small_cfg.insert("window.outerHeight".into(), json!(700));
        small_cfg.insert("window.innerWidth".into(), json!(980));
        small_cfg.insert("window.innerHeight".into(), json!(650));

        adapt_window_to_host(&mut small_cfg, 1920, 1080);
        assert_eq!(small_cfg["window.outerWidth"], 1000);
        assert_eq!(small_cfg["window.outerHeight"], 700);
        assert!(!small_cfg.contains_key("window.innerWidth"));
        assert!(!small_cfg.contains_key("window.innerHeight"));

        // Fallback to screen.height when screen.availHeight is missing
        let mut no_avail = Map::new();
        no_avail.insert("screen.width".into(), json!(2560));
        no_avail.insert("screen.height".into(), json!(1440));
        adapt_window_to_host(&mut no_avail, 1920, 1040);
        assert_eq!(no_avail["window.outerWidth"], 1880);
        assert_eq!(no_avail["window.outerHeight"], 980);
        assert!(!no_avail.contains_key("window.innerWidth"));
        assert!(!no_avail.contains_key("window.innerHeight"));
    }

    #[test]
    fn test_default_search_prefs_and_custom_override() {
        let mut config = Map::new();
        config.insert("navigator.oscpu".into(), json!("Windows NT 10.0; Win64; x64"));

        // Defaults to DuckDuckGo and https://duckduckgo.com
        let default_prefs = build_default_prefs(&config, None, false, None, None);
        assert_eq!(default_prefs["browser.search.suggest.enabled"], true);
        assert_eq!(
            default_prefs["browser.startup.homepage"],
            "https://duckduckgo.com"
        );

        // Custom search engine and homepage override
        let custom_prefs = build_default_prefs(
            &config,
            None,
            false,
            Some("Google"),
            Some("https://google.com"),
        );
        assert_eq!(custom_prefs["browser.search.suggest.enabled"], true);
        assert_eq!(custom_prefs["browser.startup.homepage"], "https://google.com");
    }

    #[test]
    fn test_search_engine_and_startup_urls_fallback() {
        // Defaults when profile and settings are None
        assert_eq!(resolve_search_engine(None, None), "DuckDuckGo");
        assert_eq!(resolve_default_startup_url(None, None), "https://duckduckgo.com");

        // Profile override takes precedence
        let profile_custom = json!({
            "search_engine": "Brave",
            "default_startup_url": "https://search.brave.com"
        });
        let settings = json!({
            "default_search_engine": "DuckDuckGo",
            "default_startup_url": "https://duckduckgo.com"
        });
        assert_eq!(
            resolve_search_engine(Some(&profile_custom), Some(&settings)),
            "Brave"
        );
        assert_eq!(
            resolve_default_startup_url(Some(&profile_custom), Some(&settings)),
            "https://search.brave.com"
        );

        // Settings used when profile has no override
        let profile_empty = json!({});
        let settings_custom = json!({
            "default_search_engine": "Ecosia",
            "default_startup_url": "https://www.ecosia.org"
        });
        assert_eq!(
            resolve_search_engine(Some(&profile_empty), Some(&settings_custom)),
            "Ecosia"
        );
        assert_eq!(
            resolve_default_startup_url(Some(&profile_empty), Some(&settings_custom)),
            "https://www.ecosia.org"
        );

        // Profile startup_url alternate key
        let profile_alt = json!({
            "startup_url": "https://lobste.rs"
        });
        assert_eq!(
            resolve_default_startup_url(Some(&profile_alt), Some(&settings)),
            "https://lobste.rs"
        );

        // Invalid default startup URLs fall back gracefully
        let profile_invalid = json!({
            "default_startup_url": "javascript:alert(1)"
        });
        assert_eq!(
            resolve_default_startup_url(Some(&profile_invalid), None),
            "https://duckduckgo.com"
        );
        let settings_invalid = json!({
            "default_startup_url": "-headless"
        });
        assert_eq!(
            resolve_default_startup_url(None, Some(&settings_invalid)),
            "https://duckduckgo.com"
        );
        // Profile invalid falls back to valid settings URL
        assert_eq!(
            resolve_default_startup_url(Some(&profile_invalid), Some(&settings_custom)),
            "https://www.ecosia.org"
        );

        // Empty startup URLs fallback in launch args
        let empty_urls: Vec<String> = Vec::new();
        let fallback_args = resolve_launch_args(&empty_urls, "https://duckduckgo.com");
        assert_eq!(fallback_args, vec!["-url", "https://duckduckgo.com"]);
        assert!(!fallback_args.contains(&"about:blank".to_string()));

        // Non-empty startup URLs preserve given URLs
        let specified_urls = vec!["https://example.org".to_string(), "https://rust-lang.org".to_string()];
        let specified_args = resolve_launch_args(&specified_urls, "https://duckduckgo.com");
        assert_eq!(
            specified_args,
            vec!["-url", "https://example.org", "-url", "https://rust-lang.org"]
        );
    }

    #[test]
    fn test_prepare_xulstore_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xulstore.json");

        // 1. Initial creation when xulstore.json does not exist
        prepare_xulstore_window(dir.path(), 1280, 800, 100, 50).unwrap();
        assert!(path.exists());

        let raw: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let main_win = &raw["chrome://browser/content/browser.xhtml"]["main-window"];
        assert_eq!(main_win["width"], "1280");
        assert_eq!(main_win["height"], "800");
        assert_eq!(main_win["screenX"], "100");
        assert_eq!(main_win["screenY"], "50");
        assert_eq!(main_win["sizemode"], "normal");

        // 2. Updating existing xulstore.json preserves other elements and overrides main-window geometry
        let mut existing_root = raw.clone();
        existing_root["chrome://browser/content/browser.xhtml"]["main-window"]["custom-attr"] = json!("custom-val");
        existing_root["chrome://browser/content/browser.xhtml"]["other-bar"] = json!({"visible": true});
        existing_root["other-url"] = json!({"state": 1});
        fs::write(&path, serde_json::to_string_pretty(&existing_root).unwrap()).unwrap();

        prepare_xulstore_window(dir.path(), 1920, 1080, 200, 150).unwrap();

        let updated: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let updated_win = &updated["chrome://browser/content/browser.xhtml"]["main-window"];
        assert_eq!(updated_win["width"], "1920");
        assert_eq!(updated_win["height"], "1080");
        assert_eq!(updated_win["screenX"], "200");
        assert_eq!(updated_win["screenY"], "150");
        assert_eq!(updated_win["sizemode"], "normal");
        assert_eq!(updated_win["custom-attr"], "custom-val");
        assert_eq!(updated["chrome://browser/content/browser.xhtml"]["other-bar"]["visible"], true);
        assert_eq!(updated["other-url"]["state"], 1);

        // 3. Error when browser directory cannot be created or accessed returns Err
        let file_path = dir.path().join("blocked_dir");
        fs::write(&file_path, "not a directory").unwrap();
        assert!(prepare_xulstore_window(&file_path.join("child"), 1280, 800, 0, 0).is_err());
    }

    #[test]
    fn test_prepare_browser_chrome_css() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("camoufox.exe");
        let css_path = dir.path().join("chrome.css");

        let initial_css = ":root[remotecontrol] #remote-control-box { display: inline-block; }\n:root[remotecontrol] .urlbar-background { background-image: linear-gradient(blue, green); }\n";
        fs::write(&css_path, initial_css).unwrap();
        prepare_browser_chrome_css(&exe).unwrap();
        let content_after_first = fs::read_to_string(&css_path).unwrap();
        assert_ne!(content_after_first, initial_css);
        assert!(content_after_first.starts_with(initial_css));

        prepare_browser_chrome_css(&exe).unwrap();
        let content_after_second = fs::read_to_string(&css_path).unwrap();
        assert_eq!(content_after_first, content_after_second);

        let blocked = dir.path().join("not_a_dir");
        fs::write(&blocked, "file").unwrap();
        assert!(prepare_browser_chrome_css(&blocked.join("camoufox.exe")).is_err());
    }

    #[test]
    fn test_ensure_distribution_policies() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("camoufox.exe");
        fs::write(&exe, b"").unwrap();
        ensure_distribution_policies(&exe, "DuckDuckGo").unwrap();
        let policy_file = dir.path().join("distribution/policies.json");
        assert!(policy_file.is_file());
        let val: Value = serde_json::from_str(&fs::read_to_string(&policy_file).unwrap()).unwrap();
        assert_eq!(val["policies"]["SearchEngines"]["Default"], "DuckDuckGo");
        assert_eq!(val["policies"]["SearchEngines"]["PreventInstalls"], false);
        let adds = val["policies"]["SearchEngines"]["Add"].as_array().unwrap();
        assert!(adds.iter().any(|e| e["Name"] == "DuckDuckGo" && e["URLTemplate"].as_str().unwrap().contains("{searchTerms}")));
    }
}
