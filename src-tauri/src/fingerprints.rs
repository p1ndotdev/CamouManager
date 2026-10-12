use anyhow::{anyhow, bail, Context, Result};
use parking_lot::ReentrantMutex;
use rand::{seq::SliceRandom, Rng};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::Duration,
};

use crate::{
    files::reject_link,
    fpgen::{
        self, gpu_fits_os, gpu_screen_is_plausible, intel_mac_misfit,
        is_software_renderer, sample_webgl_for_screen, webgl_for_gpu, DetRng,
    },
    store::{safe_component, string, utcnow, Store},
};

const FONTS_RAW: &str = include_str!("../data/fonts.json");
const ESSENTIAL_FONTS_RAW: &str = include_str!("../data/essential-fonts.json");
const FONT_BASES_RAW: &str = include_str!("../data/font-bases.json");
const FONT_GROUPS_RAW: &str = include_str!("../data/font-groups.json");
const VOICE_MANIFESTS_RAW: &str = include_str!("../data/voice-manifests.json");
const VOICE_URIS_RAW: &str = include_str!("../data/voice-uris.json");
const MEDIA_DEVICES_RAW: &str = include_str!("../data/media-devices.json");
const PRESETS_RAW: &str = include_str!("../data/fingerprint-presets.json");
const PRESETS_V150_RAW: &str = include_str!("../data/fingerprint-presets-v150.json");
const PROPERTIES_RAW: &str = include_str!("../data/properties.json");

pub const SOURCE_URL: &str =
    "https://api.github.com/repos/daijro/camoufox/contents/python/src/camoufox";
pub const RAW_SOURCE_PREFIX: &str = "https://raw.githubusercontent.com/daijro/camoufox/";
pub const MAX_DATA_BYTES: usize = 8 * 1024 * 1024;
const PRESETS_V150_MIN_FF: u32 = 149;

const MODERN_SCREEN_FLOOR: (i64, i64) = (1366, 768);
const BROWSER_CHROME_HEIGHT: i64 = 86;
const MAX_PLAUSIBLE_TOUCH_POINTS: i64 = 10;

const PLAUSIBLE_CORE_COUNTS: &[i64] = &[4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 32];
const APPLE_SILICON_CORES: &[i64] = &[8, 10, 11, 12, 14, 16, 20, 24, 28, 32];

const PLAUSIBLE_DPR_WIN: &[f64] = &[1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0];
const PLAUSIBLE_DPR_MAC: &[f64] = &[1.0, 2.0];
const PLAUSIBLE_DPR_LIN: &[f64] = &[1.0, 1.25, 1.5, 1.75, 2.0];

const MACOS_MARKER_FONTS: &[&str] = &["Helvetica Neue"];
const LINUX_MARKER_FONTS: &[&str] = &[
    "Noto Sans",
    "Noto Serif",
    "DejaVu Sans Mono",
    "Arimo",
    "Cousine",
    "Tinos",
    "Twemoji Mozilla",
];
const WINDOWS_MARKER_FONTS: &[&str] = &["Segoe UI", "Tahoma", "Cambria Math", "Nirmala UI"];

const MAC_NOVELTY_VOICES: &[&str] = &[
    "Albert",
    "Bad News",
    "Bahh",
    "Bells",
    "Boing",
    "Bubbles",
    "Cellos",
    "Wobble",
    "Good News",
    "Jester",
    "Organ",
    "Superstar",
    "Trinoids",
    "Whisper",
    "Zarvox",
    "Fred",
    "Junior",
    "Kathy",
    "Ralph",
    "Bruce",
    "Vicki",
    "Victoria",
    "Agnes",
    "Princess",
    "Hysterical",
    "Pipe Organ",
    "Deranged",
    "Alex",
];
const MAC_ELOQUENCE_VOICES: &[&str] = &[
    "Eddy", "Flo", "Grandma", "Grandpa", "Reed", "Rocko", "Sandy", "Shelley",
];

const VOICE_FIELDS: &[&str] = &["lang", "name", "voiceUri", "isDefault", "isLocalService"];

#[derive(Clone, Debug)]
pub struct PropertySpec {
    pub expected_type: String,
    pub removed: bool,
}

struct CatalogData {
    fonts: HashMap<String, Vec<String>>,
    essential_fonts: HashMap<String, HashSet<String>>,
    font_bases: Value,
    font_groups: Value,
    voice_manifests: Value,
    voice_uris_mac: HashMap<String, String>,
    media_devices: Value,
    presets_base: Value,
    presets_v150: Value,
    properties: HashMap<String, PropertySpec>,
}

static CATALOGS: LazyLock<CatalogData> = LazyLock::new(|| {
    let fonts_val: Value = serde_json::from_str(FONTS_RAW).expect("valid fonts.json");
    let mut fonts = HashMap::new();
    if let Some(obj) = fonts_val.as_object() {
        for (k, v) in obj {
            let list = v
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            fonts.insert(k.clone(), list);
        }
    }

    let ess_val: Value =
        serde_json::from_str(ESSENTIAL_FONTS_RAW).expect("valid essential-fonts.json");
    let mut essential_fonts = HashMap::new();
    if let Some(obj) = ess_val.as_object() {
        for (k, v) in obj {
            let set = v
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            essential_fonts.insert(k.clone(), set);
        }
    }

    let font_bases: Value = serde_json::from_str(FONT_BASES_RAW).expect("valid font-bases.json");
    let font_groups: Value = serde_json::from_str(FONT_GROUPS_RAW).expect("valid font-groups.json");
    let voice_manifests: Value =
        serde_json::from_str(VOICE_MANIFESTS_RAW).expect("valid voice-manifests.json");

    let voice_uris_val: Value =
        serde_json::from_str(VOICE_URIS_RAW).expect("valid voice-uris.json");
    let mut voice_uris_mac = HashMap::new();
    if let Some(mac_obj) = voice_uris_val.get("mac").and_then(Value::as_object) {
        for (k, v) in mac_obj {
            if let Some(s) = v.as_str() {
                voice_uris_mac.insert(k.clone(), s.to_owned());
            }
        }
    }

    let media_devices: Value =
        serde_json::from_str(MEDIA_DEVICES_RAW).expect("valid media-devices.json");
    let presets_base: Value =
        serde_json::from_str(PRESETS_RAW).expect("valid fingerprint-presets.json");
    let presets_v150: Value =
        serde_json::from_str(PRESETS_V150_RAW).expect("valid fingerprint-presets-v150.json");

    let properties = parse_properties_json(PROPERTIES_RAW).expect("valid bundled properties.json");

    CatalogData {
        fonts,
        essential_fonts,
        font_bases,
        font_groups,
        voice_manifests,
        voice_uris_mac,
        media_devices,
        presets_base,
        presets_v150,
        properties,
    }
});

fn parse_properties_json(raw: &str) -> Result<HashMap<String, PropertySpec>> {
    let list: Value = serde_json::from_str(raw).context("Invalid properties.json")?;
    let arr = list
        .as_array()
        .ok_or_else(|| anyhow!("properties.json must be a JSON array"))?;
    let mut map = HashMap::with_capacity(arr.len());
    for item in arr {
        let Some(prop) = item.get("property").and_then(Value::as_str) else {
            continue;
        };
        let Some(ty) = item.get("type").and_then(Value::as_str) else {
            continue;
        };
        let removed = item.get("removed").is_some();
        map.insert(
            prop.to_owned(),
            PropertySpec {
                expected_type: ty.to_owned(),
                removed,
            },
        );
    }
    Ok(map)
}

pub fn parse_major_version(ver: Option<&str>) -> u32 {
    static DIGIT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\d+").expect("static digit regex"));
    let Some(v) = ver else {
        return 135;
    };
    let clean = v.trim().trim_start_matches(['v', 'V']);
    DIGIT_RE
        .find(clean)
        .and_then(|m| m.as_str().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(135)
}

fn resolve_os_pair(raw_os: Option<&str>) -> Result<(&'static str, &'static str)> {
    match raw_os.unwrap_or("windows").trim().to_ascii_lowercase().as_str() {
        "" | "win" | "windows" => Ok(("windows", "win")),
        "mac" | "macos" | "darwin" => Ok(("macos", "mac")),
        "lin" | "linux" => Ok(("linux", "lin")),
        other => bail!("Hệ điều hành không hợp lệ: {other}"),
    }
}

fn infer_os_pair_from_config(config: &Map<String, Value>) -> (&'static str, &'static str) {
    let plat = config
        .get("navigator.platform")
        .and_then(Value::as_str)
        .unwrap_or("");
    let ua = config
        .get("navigator.userAgent")
        .and_then(Value::as_str)
        .unwrap_or("");
    if plat.starts_with("Win") || ua.contains("Windows") {
        ("windows", "win")
    } else if plat.starts_with("Mac") || ua.contains("Macintosh") {
        ("macos", "mac")
    } else {
        ("linux", "lin")
    }
}

pub fn app_version_from_user_agent(user_agent: &str) -> Option<String> {
    let rest = user_agent.strip_prefix("Mozilla/5.0 (")?;
    let (inside, _) = rest.split_once(')')?;
    let mut kept = Vec::new();
    for part in inside.split(';') {
        let token = part.trim();
        if token.is_empty()
            || token.starts_with("rv:")
            || matches!(token, "Win64" | "x64" | "Mobile" | "Tablet")
            || token.starts_with("Linux ")
            || token.starts_with("Intel Mac OS X")
        {
            continue;
        }
        if token.starts_with("Windows") {
            kept.push("Windows".to_owned());
        } else {
            kept.push(token.to_owned());
        }
    }
    if kept.is_empty() {
        None
    } else {
        Some(format!("5.0 ({})", kept.join("; ")))
    }
}

fn rewrite_ff_version_in_ua(ua: &str, major: u32) -> String {
    static RV_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"rv:\d+(?:\.\d+)?").expect("static rv regex"));
    static FF_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"Firefox/\d+(?:\.\d+)?").expect("static ff regex"));
    let step1 = RV_RE.replace_all(ua, format!("rv:{major}.0"));
    FF_RE
        .replace_all(&step1, format!("Firefox/{major}.0"))
        .into_owned()
}

fn compute_initial_seed(config: &Map<String, Value>, salt: u64) -> u64 {
    let mut hasher = Sha256::new();
    for key in [
        "navigator.userAgent",
        "navigator.platform",
        "screen.width",
        "screen.height",
        "navigator.hardwareConcurrency",
    ] {
        if let Some(val) = config.get(key) {
            match val {
                Value::String(s) => hasher.update(s.as_bytes()),
                Value::Number(n) => hasher.update(n.to_string().as_bytes()),
                _ => {}
            }
        }
        hasher.update(b"|");
    }
    hasher.update(salt.to_be_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

pub fn identity_seed_from_config(config: &Map<String, Value>) -> u64 {
    let audio_seed = config
        .get("audio:seed")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let mut hasher = Sha256::new();
    hasher.update(audio_seed.to_be_bytes());
    for key in ["navigator.platform", "screen.width", "screen.height"] {
        hasher.update(b"|");
        if let Some(val) = config.get(key) {
            match val {
                Value::String(s) => hasher.update(s.as_bytes()),
                Value::Number(n) => hasher.update(n.to_string().as_bytes()),
                _ => {}
            }
        }
    }
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

fn from_preset(preset: &Value, major: u32) -> Map<String, Value> {
    let mut config = Map::new();
    if let Some(nav) = preset.get("navigator").and_then(Value::as_object) {
        if let Some(ua) = nav.get("userAgent").and_then(Value::as_str) {
            config.insert(
                "navigator.userAgent".into(),
                json!(rewrite_ff_version_in_ua(ua, major)),
            );
        }
        if let Some(plat) = nav.get("platform").and_then(Value::as_str) {
            config.insert("navigator.platform".into(), json!(plat));
        }
        if let Some(hc) = nav.get("hardwareConcurrency").and_then(Value::as_i64) {
            if hc > 0 {
                config.insert("navigator.hardwareConcurrency".into(), json!(hc));
            }
        }
        if let Some(oscpu) = nav.get("oscpu").and_then(Value::as_str) {
            config.insert("navigator.oscpu".into(), json!(oscpu));
        } else if let Some(plat) = nav.get("platform").and_then(Value::as_str) {
            let oscpu = if plat == "MacIntel" {
                Some("Intel Mac OS X 10.15")
            } else if plat == "Win32" {
                Some("Windows NT 10.0; Win64; x64")
            } else if plat.to_ascii_lowercase().contains("linux") {
                Some("Linux x86_64")
            } else {
                None
            };
            if let Some(oscpu) = oscpu {
                config.insert("navigator.oscpu".into(), json!(oscpu));
            }
        }
        if let Some(app_ver) = nav.get("appVersion").and_then(Value::as_str) {
            config.insert("navigator.appVersion".into(), json!(app_ver));
        } else if let Some(ua) = config.get("navigator.userAgent").and_then(Value::as_str) {
            if let Some(derived) = app_version_from_user_agent(ua) {
                config.insert("navigator.appVersion".into(), json!(derived));
            }
        }
        let mtp = nav
            .get("maxTouchPoints")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0);
        config.insert("navigator.maxTouchPoints".into(), json!(mtp));
    }

    if let Some(screen) = preset.get("screen").and_then(Value::as_object) {
        for (src_k, dst_k) in [
            ("width", "screen.width"),
            ("height", "screen.height"),
            ("availWidth", "screen.availWidth"),
            ("availHeight", "screen.availHeight"),
        ] {
            if let Some(v) = screen.get(src_k).and_then(Value::as_i64).filter(|&v| v > 0) {
                config.insert(dst_k.into(), json!(v));
            }
        }
        if let Some(cd) = screen
            .get("colorDepth")
            .and_then(Value::as_i64)
            .filter(|&v| v > 0)
        {
            config.insert("screen.colorDepth".into(), json!(cd));
            config.insert("screen.pixelDepth".into(), json!(cd));
        }
        if let Some(dpr) = screen
            .get("devicePixelRatio")
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
            })
            .filter(|&v| v > 0.0 && v.is_finite())
        {
            config.insert("window.devicePixelRatio".into(), json!(dpr));
        }
    }

    if let Some(webgl) = preset.get("webgl").and_then(Value::as_object) {
        if let Some(vendor) = webgl
            .get("unmaskedVendor")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            config.insert("webGl:vendor".into(), json!(vendor));
        }
        if let Some(renderer) = webgl
            .get("unmaskedRenderer")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            config.insert("webGl:renderer".into(), json!(renderer));
        }
    }

    if let Some(tz) = preset
        .get("timezone")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        config.insert("timezone".into(), json!(tz));
    }

    config
}

fn from_fpgen(fp: &Value, major: u32) -> Map<String, Value> {
    let mut config = Map::new();
    if let Some(nav) = fp.get("navigator").and_then(Value::as_object) {
        if let Some(ua) = nav.get("userAgent").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            config.insert(
                "navigator.userAgent".into(),
                json!(rewrite_ff_version_in_ua(ua, major)),
            );
        }
        if let Some(app_ver) = nav.get("appVersion").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            config.insert(
                "navigator.appVersion".into(),
                json!(rewrite_ff_version_in_ua(app_ver, major)),
            );
        }
        if let Some(oscpu) = nav
            .get("oscpu")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "undefined")
        {
            config.insert("navigator.oscpu".into(), json!(oscpu));
        }
        if let Some(plat) = nav.get("platform").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            config.insert("navigator.platform".into(), json!(plat));
        }
        if let Some(hc) = nav.get("hardwareConcurrency").and_then(Value::as_i64).filter(|&v| v > 0) {
            config.insert("navigator.hardwareConcurrency".into(), json!(hc));
        }
        let mtp = nav
            .get("maxTouchPoints")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0);
        config.insert("navigator.maxTouchPoints".into(), json!(mtp));
    }

    if let Some(screen) = fp.get("screen").and_then(Value::as_object) {
        for (src_k, dst_k) in [
            ("availLeft", "screen.availLeft"),
            ("availTop", "screen.availTop"),
            ("availWidth", "screen.availWidth"),
            ("availHeight", "screen.availHeight"),
            ("height", "screen.height"),
            ("width", "screen.width"),
            ("colorDepth", "screen.colorDepth"),
            ("pixelDepth", "screen.pixelDepth"),
        ] {
            if let Some(v) = screen.get(src_k).and_then(Value::as_i64) {
                if v != 0 {
                    config.insert(dst_k.into(), json!(v.max(0)));
                }
            }
        }
    }

    if let Some(win) = fp.get("window").and_then(Value::as_object) {
        for (src_k, dst_k) in [
            ("outerHeight", "window.outerHeight"),
            ("outerWidth", "window.outerWidth"),
        ] {
            if let Some(v) = win.get(src_k).and_then(Value::as_i64).filter(|&v| v > 0) {
                config.insert(dst_k.into(), json!(v));
            }
        }
        if let Some(sx) = win.get("screenX").and_then(Value::as_i64).filter(|&v| v != 0) {
            config.insert("window.screenX".into(), json!(sx));
        }
        if let Some(sy) = win.get("screenY").and_then(Value::as_i64).filter(|&v| v != 0) {
            config.insert("window.screenY".into(), json!(sy));
        }
    }

    handle_screen_xy(&mut config, fp);
    config
}

fn handle_screen_xy(config: &mut Map<String, Value>, fp: &Value) {
    if config.contains_key("window.screenY") {
        return;
    }
    let screen_x = fp
        .get("window")
        .and_then(|w| w.get("screenX"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if screen_x == 0 {
        config.insert("window.screenX".into(), json!(0));
        config.insert("window.screenY".into(), json!(0));
        return;
    }
    if (-50..=50).contains(&screen_x) {
        config.insert("window.screenY".into(), json!(screen_x));
        return;
    }
    let avail_h = fp
        .get("screen")
        .and_then(|s| s.get("availHeight"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let outer_h = fp
        .get("window")
        .and_then(|w| w.get("outerHeight"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let diff = avail_h - outer_h;
    let mut rng = rand::thread_rng();
    let sy = if diff == 0 {
        0
    } else if diff > 0 {
        rng.gen_range(0..diff)
    } else {
        rng.gen_range(diff..0)
    };
    config.insert("window.screenY".into(), json!(sy));
}

pub fn fix_navigator_arch(config: &mut Map<String, Value>, os_short: &str) {
    let ua = config
        .get("navigator.userAgent")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    match os_short {
        "lin" => {
            let target = if ua.contains("Linux i686") {
                "Linux i686"
            } else {
                "Linux x86_64"
            };
            config.insert("navigator.platform".into(), json!(target));
            config.insert("navigator.oscpu".into(), json!(target));
        }
        "win" => {
            config.insert("navigator.platform".into(), json!("Win32"));
            config.insert("navigator.oscpu".into(), json!("Windows NT 10.0; Win64; x64"));
        }
        "mac" => {
            config.insert("navigator.platform".into(), json!("MacIntel"));
            config.insert("navigator.oscpu".into(), json!("Intel Mac OS X 10.15"));
        }
        _ => {}
    }

    if !ua.is_empty() {
        if let Some(derived) = app_version_from_user_agent(&ua) {
            config.insert("navigator.appVersion".into(), json!(derived));
        }
    }
}

fn host_cpu_count() -> i64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i64)
        .unwrap_or(8)
}

pub fn fix_hardware_concurrency(config: &mut Map<String, Value>) {
    let cap = host_cpu_count().max(4);
    let host_val = PLAUSIBLE_CORE_COUNTS
        .iter()
        .copied()
        .rfind(|&c| c <= cap)
        .unwrap_or(PLAUSIBLE_CORE_COUNTS[0]);

    if let Some(drawn) = config
        .get("navigator.hardwareConcurrency")
        .and_then(Value::as_i64)
        .filter(|&d| d >= 1)
    {
        let target = drawn.min(cap);
        let snapped = PLAUSIBLE_CORE_COUNTS
            .iter()
            .copied()
            .rfind(|&c| c <= target)
            .unwrap_or(PLAUSIBLE_CORE_COUNTS[0]);
        config.insert("navigator.hardwareConcurrency".into(), json!(snapped));
    } else {
        config.insert("navigator.hardwareConcurrency".into(), json!(host_val));
    }
}

pub fn repair_screen_orientation(config: &mut Map<String, Value>) -> bool {
    let Some(w) = config.get("screen.width").and_then(Value::as_i64) else {
        return false;
    };
    let Some(h) = config.get("screen.height").and_then(Value::as_i64) else {
        return false;
    };
    if w <= 0 || h <= 0 || h <= w {
        return false;
    }
    config.insert("screen.width".into(), json!(h));
    config.insert("screen.height".into(), json!(w));
    if let (Some(aw), Some(ah)) = (
        config.get("screen.availWidth").and_then(Value::as_i64),
        config.get("screen.availHeight").and_then(Value::as_i64),
    ) {
        if aw > 0 && ah > 0 {
            config.insert("screen.availWidth".into(), json!(ah));
            config.insert("screen.availHeight".into(), json!(aw));
        }
    }
    true
}

pub fn raise_screen_to_modern_floor(config: &mut Map<String, Value>) {
    let (min_w, min_h) = MODERN_SCREEN_FLOOR;
    let sw = config
        .get("screen.width")
        .and_then(Value::as_i64)
        .unwrap_or(1920);
    let sh = config
        .get("screen.height")
        .and_then(Value::as_i64)
        .unwrap_or(1080);

    if sw >= min_w && sh >= min_h {
        return;
    }

    let aw = config.get("screen.availWidth").and_then(Value::as_i64);
    let ah = config.get("screen.availHeight").and_then(Value::as_i64);
    let gap_w = aw.filter(|&v| v > 0).map(|v| (sw - v).max(0));
    let gap_h = ah.filter(|&v| v > 0).map(|v| (sh - v).max(0));

    let new_w = sw.max(min_w);
    let new_h = sh.max(min_h);
    config.insert("screen.width".into(), json!(new_w));
    config.insert("screen.height".into(), json!(new_h));
    if let Some(gw) = gap_w {
        config.insert("screen.availWidth".into(), json!((new_w - gw).max(1)));
    }
    if let Some(gh) = gap_h {
        config.insert("screen.availHeight".into(), json!((new_h - gh).max(1)));
    }
}

pub fn fix_screen_no_taskbar(config: &mut Map<String, Value>, os_short: &str) {
    let Some(sw) = config.get("screen.width").and_then(Value::as_i64).filter(|&v| v > 0) else {
        return;
    };
    let Some(sh) = config.get("screen.height").and_then(Value::as_i64).filter(|&v| v > 0) else {
        return;
    };
    if !config.contains_key("screen.availWidth") {
        config.insert("screen.availWidth".into(), json!(sw));
    }
    let ah = config
        .get("screen.availHeight")
        .and_then(Value::as_i64)
        .unwrap_or(sh);
    if ah != sh {
        return;
    }
    let taskbar = match os_short {
        "win" => 40,
        "mac" => 25,
        _ => 27,
    };
    let new_avail = (sh - taskbar).max(1);
    config.insert("screen.availHeight".into(), json!(new_avail));
    if let Some(oh) = config
        .get("window.outerHeight")
        .and_then(Value::as_i64)
        .filter(|&v| v > new_avail)
    {
        let ih = config.get("window.innerHeight").and_then(Value::as_i64);
        let chrome = ih.map(|i| (oh - i).max(0)).unwrap_or(0);
        config.insert("window.outerHeight".into(), json!(new_avail));
        if ih.is_some() {
            config.insert("window.innerHeight".into(), json!((new_avail - chrome).max(1)));
        }
    }
}

pub fn clamp_window_dimensions(config: &mut Map<String, Value>) {
    for (screen_k, avail_k, outer_k, inner_k) in [
        (
            "screen.width",
            "screen.availWidth",
            "window.outerWidth",
            "window.innerWidth",
        ),
        (
            "screen.height",
            "screen.availHeight",
            "window.outerHeight",
            "window.innerHeight",
        ),
    ] {
        let screen = config.get(screen_k).and_then(Value::as_i64);
        let avail = config.get(avail_k).and_then(Value::as_i64);
        let outer = config.get(outer_k).and_then(Value::as_i64);
        let inner = config.get(inner_k).and_then(Value::as_i64);

        if let (Some(s), Some(a)) = (screen, avail) {
            if a > s {
                config.insert(avail_k.into(), json!(s));
            }
        }
        let avail_clamped = config.get(avail_k).and_then(Value::as_i64).or(screen);
        if let (Some(o), Some(cap)) = (outer, avail_clamped) {
            if o > cap {
                let chrome = inner.map(|i| (o - i).max(0)).unwrap_or(0);
                config.insert(outer_k.into(), json!(cap));
                if inner.is_some() {
                    config.insert(inner_k.into(), json!((cap - chrome).max(1)));
                }
            }
        }
        let outer_clamped = config.get(outer_k).and_then(Value::as_i64).or(outer);
        if let (Some(i_now), Some(o_cap)) = (config.get(inner_k).and_then(Value::as_i64), outer_clamped)
        {
            if i_now > o_cap {
                config.insert(inner_k.into(), json!(o_cap));
            }
        }
    }
}

pub fn clamp_window_position(config: &mut Map<String, Value>) {
    for (screen_k, outer_k, pos_k) in [
        ("screen.width", "window.outerWidth", "window.screenX"),
        ("screen.height", "window.outerHeight", "window.screenY"),
    ] {
        let Some(pos) = config.get(pos_k).and_then(Value::as_i64) else {
            continue;
        };
        let Some(screen) = config.get(screen_k).and_then(Value::as_i64).filter(|&v| v > 0) else {
            continue;
        };
        let Some(outer) = config.get(outer_k).and_then(Value::as_i64).filter(|&v| v > 0) else {
            continue;
        };
        let clamped = pos.clamp(0, (screen - outer).max(0));
        config.insert(pos_k.into(), json!(clamped));
    }
}

pub fn generate_random_font_subset(
    target_os: &str,
    seed: u64,
    locale: Option<&str>,
) -> Vec<String> {
    let mut rng = DetRng::new(seed);
    let catalogs = &*CATALOGS;
    let (os_key, markers) = match target_os {
        "windows" | "win" => ("win", WINDOWS_MARKER_FONTS),
        "linux" | "lin" => ("lin", LINUX_MARKER_FONTS),
        _ => ("mac", MACOS_MARKER_FONTS),
    };

    let full_list = catalogs
        .fonts
        .get(os_key)
        .or_else(|| catalogs.fonts.get("mac"))
        .cloned()
        .unwrap_or_default();
    let essential = catalogs.essential_fonts.get(os_key);

    let mut base: Vec<String> = Vec::new();
    if let Some(bases) = catalogs.font_bases.get(os_key).and_then(Value::as_array) {
        if !bases.is_empty() {
            let roll = rng.next_f64();
            let mut cumulative = 0.0;
            let mut picked = bases.last();
            for b in bases {
                cumulative += b.get("weight").and_then(Value::as_f64).unwrap_or(0.0);
                if roll < cumulative {
                    picked = Some(b);
                    break;
                }
            }
            if let Some(arr) = picked.and_then(|b| b.get("fonts")).and_then(Value::as_array) {
                base = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect();
            }
        }
    }

    if base.is_empty() {
        if let Some(ess) = essential {
            base = full_list.iter().filter(|f| ess.contains(*f)).cloned().collect();
        }
    }

    let mut result = Vec::new();
    let mut chosen = HashSet::new();
    for f in base {
        if chosen.insert(f.clone()) {
            result.push(f);
        }
    }

    if let Some(ess) = essential {
        for f in &full_list {
            if ess.contains(f) && chosen.insert(f.clone()) {
                result.push(f.clone());
            }
        }
    }

    if let Some(units) = catalogs.font_groups.get(os_key).and_then(Value::as_array) {
        let loc_lower = locale.unwrap_or("").to_ascii_lowercase();
        for unit in units {
            if let Some(req) = unit.get("requiresLocale").and_then(Value::as_str) {
                if !loc_lower.starts_with(&req.to_ascii_lowercase()) {
                    continue;
                }
            }
            let prob = unit.get("prob").and_then(Value::as_f64).unwrap_or(0.0);
            if rng.next_f64() >= prob {
                continue;
            }
            let Some(unit_fonts) = unit.get("fonts").and_then(Value::as_array) else {
                continue;
            };
            let members: Vec<String> = unit_fonts
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|f| !chosen.contains(*f))
                .map(str::to_owned)
                .collect();
            if members.is_empty() {
                continue;
            }

            if unit.get("kind").and_then(Value::as_str) == Some("alacarte") {
                let mut count = members.len();
                if let Some(sizes) = unit.get("sizes").and_then(Value::as_array).filter(|s| !s.is_empty()) {
                    let total_w: f64 = sizes
                        .iter()
                        .map(|s| s.get("w").and_then(Value::as_f64).unwrap_or(0.0))
                        .sum();
                    let roll = rng.next_f64() * total_w;
                    let mut cum = 0.0;
                    count = sizes
                        .last()
                        .and_then(|s| s.get("n"))
                        .and_then(Value::as_u64)
                        .unwrap_or(1) as usize;
                    for s in sizes {
                        cum += s.get("w").and_then(Value::as_f64).unwrap_or(0.0);
                        if roll < cum {
                            count = s.get("n").and_then(Value::as_u64).unwrap_or(1) as usize;
                            break;
                        }
                    }
                }
                let k = count.clamp(1, members.len());
                for idx in rng.sample_indices(members.len(), k) {
                    let font = &members[idx];
                    if chosen.insert(font.clone()) {
                        result.push(font.clone());
                    }
                }
            } else {
                for font in members {
                    if chosen.insert(font.clone()) {
                        result.push(font);
                    }
                }
            }
        }
    }

    for &m in markers {
        if chosen.insert(m.to_owned()) {
            result.push(m.to_owned());
        }
    }

    result
}

fn ascii_fold_voice_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            let folded = match ch {
                'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' => Some('a'),
                'Á' | 'À' | 'Â' | 'Ä' | 'Ã' | 'Å' => Some('A'),
                'é' | 'è' | 'ê' | 'ë' => Some('e'),
                'É' | 'È' | 'Ê' | 'Ë' => Some('E'),
                'í' | 'ì' | 'î' | 'ï' => Some('i'),
                'Í' | 'Ì' | 'Î' | 'Ï' => Some('I'),
                'ó' | 'ò' | 'ô' | 'ö' | 'õ' => Some('o'),
                'Ó' | 'Ò' | 'Ô' | 'Ö' | 'Õ' => Some('O'),
                'ú' | 'ù' | 'û' | 'ü' => Some('u'),
                'Ú' | 'Ù' | 'Û' | 'Ü' => Some('U'),
                'ç' => Some('c'),
                'Ç' => Some('C'),
                'ñ' => Some('n'),
                'Ñ' => Some('N'),
                _ => None,
            };
            if let Some(c) = folded {
                out.push(c);
            }
        }
    }
    out
}

fn build_voice_uri(os_key: &str, name: &str, lang: &str) -> String {
    match os_key {
        "lin" => {
            let mut escaped = String::with_capacity(name.len() + 8);
            for ch in name.chars() {
                if ch == ' ' {
                    escaped.push_str("%20");
                } else if (ch as u32) <= 0x7F {
                    escaped.push(ch);
                } else {
                    let mut buf = [0u8; 4];
                    for &b in ch.encode_utf8(&mut buf).as_bytes() {
                        escaped.push_str(&format!("%{b:02X}"));
                    }
                }
            }
            format!("urn:moz-tts:speechd:{escaped}?{lang}")
        }
        "win" => format!("urn:moz-tts:sapi:{name}?{lang}"),
        _ => {
            let lookup_key = format!("{name}|{lang}");
            if let Some(uri) = CATALOGS.voice_uris_mac.get(&lookup_key) {
                return uri.clone();
            }
            let ascii_name = ascii_fold_voice_name(name);
            if MAC_NOVELTY_VOICES.contains(&name) {
                format!("urn:moz-tts:osx:com.apple.speech.synthesis.voice.{ascii_name}")
            } else if MAC_ELOQUENCE_VOICES.contains(&name) {
                format!("urn:moz-tts:osx:com.apple.eloquence.{lang}.{ascii_name}")
            } else {
                format!("urn:moz-tts:osx:com.apple.voice.compact.{lang}.{ascii_name}")
            }
        }
    }
}

fn split_voice_entry(entry: &str) -> Option<(&str, &str, &str)> {
    let (before_type, vtype) = entry.rsplit_once(':')?;
    let (name, lang) = before_type.rsplit_once(':')?;
    if name.is_empty() || lang.is_empty() {
        return None;
    }
    Some((name, lang, vtype))
}

fn resolve_display_pack(packs: &Map<String, Value>, fallback: &str, locale: Option<&str>) -> String {
    if let Some(loc) = locale.filter(|s| !s.is_empty()) {
        if packs.contains_key(loc) {
            return loc.to_owned();
        }
        if let Some((_, matched_k)) = packs
            .keys()
            .find(|k| k.eq_ignore_ascii_case(loc))
            .map(|k| (true, k.clone()))
        {
            return matched_k;
        }
        let lang_prefix = loc.split(['-', '_']).next().unwrap_or("").to_ascii_lowercase();
        for key in packs.keys() {
            let k_lang = key.split('-').next().unwrap_or("").to_ascii_lowercase();
            if k_lang == lang_prefix {
                return key.clone();
            }
        }
    }
    if packs.contains_key(fallback) {
        fallback.to_owned()
    } else {
        packs.keys().next().cloned().unwrap_or_else(|| "en-US".to_owned())
    }
}

fn weighted_sample_values(
    rng: &mut DetRng,
    items: &[String],
    k: usize,
    weight_fn: impl Fn(&str) -> f64,
) -> Vec<String> {
    let mut pool: Vec<String> = items.to_vec();
    let mut out = Vec::with_capacity(k.min(pool.len()));
    while !pool.is_empty() && out.len() < k {
        let total: f64 = pool.iter().map(|x| weight_fn(x)).sum();
        let mut r = rng.next_f64() * total;
        let mut picked_idx = pool.len() - 1;
        for (i, item) in pool.iter().enumerate() {
            r -= weight_fn(item);
            if r <= 0.0 {
                picked_idx = i;
                break;
            }
        }
        out.push(pool.remove(picked_idx));
    }
    out
}

pub fn generate_random_voice_subset(
    target_os: &str,
    locale: Option<&str>,
    seed: u64,
) -> Vec<Value> {
    let mut rng = DetRng::new(seed);
    let os_key = match target_os {
        "windows" | "win" => "win",
        "linux" | "lin" => "lin",
        _ => "mac",
    };
    let manifests = &CATALOGS.voice_manifests;
    let Some(manifest) = manifests
        .get(os_key)
        .or_else(|| manifests.get("mac"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut legacy: Vec<String> = Vec::new();

    if let Some(entries) = manifest.get("base").and_then(Value::as_array) {
        for e in entries.iter().filter_map(Value::as_str) {
            if seen.insert(e.to_owned()) {
                out.push(e.to_owned());
            }
        }
    }

    let packs = manifest.get("langPacks").and_then(Value::as_object);
    let mut chosen_packs: HashSet<String> = HashSet::new();

    fn take_pack(
        pack: &Map<String, Value>,
        rng: &mut DetRng,
        seen: &mut HashSet<String>,
        out: &mut Vec<String>,
        legacy: &mut Vec<String>,
    ) {
        if let Some(one_core) = pack.get("oneCore").and_then(Value::as_array) {
            for e in one_core.iter().filter_map(Value::as_str) {
                if seen.insert(e.to_owned()) {
                    out.push(e.to_owned());
                }
            }
        }
        if let Some(desktop) = pack
            .get("desktop")
            .and_then(Value::as_array)
            .filter(|d| !d.is_empty())
        {
            let d_prob = pack.get("desktopProb").and_then(Value::as_f64).unwrap_or(0.0);
            if rng.next_f64() < d_prob {
                for e in desktop.iter().filter_map(Value::as_str) {
                    if !legacy.iter().any(|x| x == e) {
                        legacy.push(e.to_owned());
                    }
                }
            }
        }
    }

    if let Some(packs_map) = packs.filter(|m| !m.is_empty()) {
        let fallback = manifest
            .get("fallbackLocale")
            .and_then(Value::as_str)
            .unwrap_or("en-US");
        let key = resolve_display_pack(packs_map, fallback, locale);
        chosen_packs.insert(key.clone());
        if let Some(pack_obj) = packs_map.get(&key).and_then(Value::as_object) {
            take_pack(pack_obj, &mut rng, &mut seen, &mut out, &mut legacy);
        }
    }

    if let Some(additions) = manifest.get("additions").and_then(Value::as_array) {
        let loc_lower = locale.unwrap_or("").to_ascii_lowercase();
        for addition in additions {
            if addition.get("deferred").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            if let Some(req) = addition.get("requiresLocale").and_then(Value::as_str) {
                if !loc_lower.starts_with(&req.to_ascii_lowercase()) {
                    continue;
                }
            }
            let prob = addition.get("prob").and_then(Value::as_f64).unwrap_or(0.0);
            if rng.next_f64() >= prob {
                continue;
            }
            let kind = addition.get("kind").and_then(Value::as_str).unwrap_or("");
            match kind {
                "bundle" => {
                    if let Some(voices) = addition.get("voices").and_then(Value::as_array) {
                        for e in voices.iter().filter_map(Value::as_str) {
                            if seen.insert(e.to_owned()) {
                                out.push(e.to_owned());
                            }
                        }
                    }
                }
                "alacarte" => {
                    let sizes = addition
                        .get("sizes")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_else(|| vec![json!({"n": 1, "w": 1.0})]);
                    let k = rng
                        .choose_weighted(&sizes, |s| s.get("w").and_then(Value::as_f64).unwrap_or(1.0))
                        .and_then(|s| s.get("n"))
                        .and_then(Value::as_u64)
                        .unwrap_or(1) as usize;
                    let voices: Vec<String> = addition
                        .get("voices")
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    for e in weighted_sample_values(&mut rng, &voices, k, |_| 1.0) {
                        if seen.insert(e.clone()) {
                            let e_lower = e.to_ascii_lowercase();
                            let idx = out
                                .iter()
                                .position(|v| v.to_ascii_lowercase() > e_lower)
                                .unwrap_or(out.len());
                            out.insert(idx, e);
                        }
                    }
                }
                "groups" => {
                    if let Some(packs_map) = packs {
                        let eligible: Vec<String> = addition
                            .get("groups")
                            .and_then(Value::as_array)
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(Value::as_str)
                                    .filter(|g| packs_map.contains_key(*g) && !chosen_packs.contains(*g))
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default();
                        if eligible.is_empty() {
                            continue;
                        }
                        let k = if let Some(sizes) =
                            addition.get("sizes").and_then(Value::as_array).filter(|s| !s.is_empty())
                        {
                            rng.choose_weighted(sizes, |s| {
                                s.get("w").and_then(Value::as_f64).unwrap_or(1.0)
                            })
                            .and_then(|s| s.get("n"))
                            .and_then(Value::as_u64)
                            .unwrap_or(1) as usize
                        } else {
                            eligible.len()
                        };
                        let sampled_groups = weighted_sample_values(&mut rng, &eligible, k, |g| {
                            packs_map
                                .get(g)
                                .and_then(|p| p.get("weight"))
                                .and_then(Value::as_f64)
                                .unwrap_or(0.01)
                        });
                        for g in sampled_groups {
                            chosen_packs.insert(g.clone());
                            if let Some(pack_obj) = packs_map.get(&g).and_then(Value::as_object) {
                                take_pack(pack_obj, &mut rng, &mut seen, &mut out, &mut legacy);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    out.extend(legacy);
    out.into_iter()
        .filter_map(|entry| {
            let (name, lang, vtype) = split_voice_entry(&entry)?;
            Some(json!({
                "name": name,
                "lang": lang,
                "voiceUri": build_voice_uri(os_key, name, lang),
                "isDefault": false,
                "isLocalService": vtype == "local",
            }))
        })
        .collect()
}

pub fn set_media_devices_defaults(config: &mut Map<String, Value>, os_short: &str, seed: u64) {
    if config.keys().any(|k| k.starts_with("mediaDevices:")) {
        return;
    }
    let mut rng = DetRng::new(seed);
    let media_cat = &CATALOGS.media_devices;
    let Some(cat) = media_cat
        .get(os_short)
        .or_else(|| media_cat.get("win"))
        .and_then(Value::as_object)
    else {
        return;
    };

    let mut mics: Vec<(String, String)> = Vec::new();
    let mut outs: Vec<(String, String)> = Vec::new();
    let mut cams: Vec<(String, String)> = Vec::new();
    let mut group_counter = 0usize;

    let mut next_group = || {
        group_counter += 1;
        format!("hw-{group_counter}")
    };

    let add_item = |item: &Value,
                    grp: &str,
                    include_mics: bool,
                    mics: &mut Vec<(String, String)>,
                    outs: &mut Vec<(String, String)>,
                    cams: &mut Vec<(String, String)>,
                    next_group: &mut dyn FnMut() -> String| {
        if include_mics {
            if let Some(arr) = item.get("mics").and_then(Value::as_array) {
                for m in arr.iter().filter_map(Value::as_str) {
                    mics.push((m.to_owned(), grp.to_owned()));
                }
            }
        }
        if let Some(arr) = item.get("outs").and_then(Value::as_array) {
            for o in arr.iter().filter_map(Value::as_str) {
                outs.push((o.to_owned(), grp.to_owned()));
            }
        }
        if let Some(cam) = item.get("cam").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            cams.push((cam.to_owned(), next_group()));
        }
    };

    let p_no_mic = match os_short {
        "win" => 0.08,
        "lin" => 0.20,
        _ => 0.0,
    };
    let p_builtin_cam = match os_short {
        "win" => 0.78,
        "lin" => 0.45,
        _ => 0.0,
    };

    let mut no_mic = false;
    if let Some(cards) = cat.get("cards").and_then(Value::as_array) {
        if let Some(card) =
            rng.choose_weighted(cards, |c| c.get("w").and_then(Value::as_f64).unwrap_or(1.0))
        {
            no_mic = rng.next_f64() < p_no_mic;
            let card_grp = next_group();
            add_item(
                card,
                &card_grp,
                !no_mic,
                &mut mics,
                &mut outs,
                &mut cams,
                &mut next_group,
            );
        }
    }

    let eff_p_cam = if no_mic {
        p_builtin_cam * 0.3
    } else {
        p_builtin_cam
    };
    if rng.next_f64() < eff_p_cam {
        if let Some(cameras) = cat.get("cameras").and_then(Value::as_array) {
            let builtin: Vec<&Value> = cameras
                .iter()
                .filter(|c| c.get("mic").and_then(Value::as_str).is_none())
                .collect();
            if let Some(&cam_obj) =
                rng.choose_weighted(&builtin, |c| c.get("w").and_then(Value::as_f64).unwrap_or(1.0))
            {
                if let Some(cam_name) = cam_obj.get("cam").and_then(Value::as_str) {
                    cams.push((cam_name.to_owned(), next_group()));
                }
            }
        }
    }

    let p_headset = cat.get("p_headset").and_then(Value::as_f64).unwrap_or(0.0);
    if rng.next_f64() < p_headset {
        if let Some(headsets) = cat.get("headsets").and_then(Value::as_array) {
            if let Some(hs) =
                rng.choose_weighted(headsets, |c| c.get("w").and_then(Value::as_f64).unwrap_or(1.0))
            {
                let grp = next_group();
                add_item(
                    hs,
                    &grp,
                    true,
                    &mut mics,
                    &mut outs,
                    &mut cams,
                    &mut next_group,
                );
            }
        }
    }

    let p_display = cat.get("p_display").and_then(Value::as_f64).unwrap_or(0.0);
    if rng.next_f64() < p_display {
        if let Some(displays) = cat.get("displays").and_then(Value::as_array) {
            if let Some(disp) =
                rng.choose_weighted(displays, |c| c.get("w").and_then(Value::as_f64).unwrap_or(1.0))
            {
                let grp = next_group();
                add_item(
                    disp,
                    &grp,
                    true,
                    &mut mics,
                    &mut outs,
                    &mut cams,
                    &mut next_group,
                );
            }
        }
    }

    let p_extra_camera = cat.get("p_extra_camera").and_then(Value::as_f64).unwrap_or(0.0);
    if rng.next_f64() < p_extra_camera {
        if let Some(cameras) = cat.get("cameras").and_then(Value::as_array) {
            let external: Vec<&Value> = cameras
                .iter()
                .filter(|c| c.get("mic").and_then(Value::as_str).is_some())
                .collect();
            let pool: Vec<&Value> = if external.is_empty() {
                cameras.iter().collect()
            } else {
                external
            };
            if let Some(&cam_obj) =
                rng.choose_weighted(&pool, |c| c.get("w").and_then(Value::as_f64).unwrap_or(1.0))
            {
                let grp = next_group();
                if let Some(cam_name) = cam_obj.get("cam").and_then(Value::as_str) {
                    cams.push((cam_name.to_owned(), grp.clone()));
                }
                if let Some(mic_name) = cam_obj.get("mic").and_then(Value::as_str) {
                    mics.push((mic_name.to_owned(), grp));
                }
            }
        }
    }

    if cat
        .get("monitor_sources")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        for (label, grp) in outs.clone() {
            mics.push((format!("Monitor of {label}"), grp));
        }
    }

    config.insert("mediaDevices:enabled".into(), json!(true));
    config.insert("mediaDevices:micros".into(), json!(mics.len()));
    config.insert("mediaDevices:webcams".into(), json!(cams.len()));
    config.insert("mediaDevices:speakers".into(), json!(outs.len()));
    config.insert(
        "mediaDevices:microphoneLabels".into(),
        json!(mics.iter().map(|(l, _)| l).collect::<Vec<_>>()),
    );
    config.insert(
        "mediaDevices:microphoneGroups".into(),
        json!(mics.iter().map(|(_, g)| g).collect::<Vec<_>>()),
    );
    config.insert(
        "mediaDevices:webcamLabels".into(),
        json!(cams.iter().map(|(l, _)| l).collect::<Vec<_>>()),
    );
    config.insert(
        "mediaDevices:webcamGroups".into(),
        json!(cams.iter().map(|(_, g)| g).collect::<Vec<_>>()),
    );
    config.insert(
        "mediaDevices:speakerLabels".into(),
        json!(outs.iter().map(|(l, _)| l).collect::<Vec<_>>()),
    );
    config.insert(
        "mediaDevices:speakerGroups".into(),
        json!(outs.iter().map(|(_, g)| g).collect::<Vec<_>>()),
    );
}

pub fn drop_incoherent_source_values(config: &mut Map<String, Value>, os_short: &str) {
    let renderer = config
        .get("webGl:renderer")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if renderer.is_empty() {
        return;
    }
    let cores = config.get("navigator.hardwareConcurrency").and_then(Value::as_i64);
    let width = config.get("screen.width").and_then(Value::as_i64);
    let height = config.get("screen.height").and_then(Value::as_i64);

    let bad_os = !gpu_fits_os(&renderer, os_short);
    let bad_mac = os_short == "mac" && intel_mac_misfit(&renderer, cores, width, height).is_some();
    let bad_sw = is_software_renderer(&renderer) || renderer == "Mozilla";
    let bad_screen = !gpu_screen_is_plausible(&renderer, width, height);

    if bad_os || bad_mac || bad_sw || bad_screen {
        config.remove("webGl:renderer");
        config.remove("webGl:vendor");
    }
}

pub fn validate_coherence(config: &Map<String, Value>, os_short: &str) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    let renderer = config
        .get("webGl:renderer")
        .and_then(Value::as_str)
        .unwrap_or("");
    let is_apple_silicon = renderer.contains("Apple M");
    let cores = config.get("navigator.hardwareConcurrency").and_then(Value::as_i64);
    let width = config.get("screen.width").and_then(Value::as_i64);
    let height = config.get("screen.height").and_then(Value::as_i64);

    if is_apple_silicon {
        if let Some(c) = cores {
            if !APPLE_SILICON_CORES.contains(&c) {
                violations.push((
                    "apple-silicon-cores".into(),
                    format!("{renderer:?} with hardwareConcurrency {c}; Apple Silicon starts at 8"),
                ));
            }
        }
    }

    if !renderer.is_empty() && !gpu_fits_os(renderer, os_short) {
        violations.push((
            "gpu-matches-os".into(),
            format!("{os_short} identity with incompatible renderer {renderer:?}"),
        ));
    }

    if os_short == "mac" {
        if let Some(detail) = intel_mac_misfit(renderer, cores, width, height) {
            violations.push(("intel-mac-hardware".into(), detail));
        }
    }

    if let Some(depth) = config.get("screen.colorDepth").and_then(Value::as_i64) {
        if depth != 24 && depth != 30 {
            violations.push((
                "color-depth".into(),
                format!("screen.colorDepth {depth}; Firefox reports 24 or 30"),
            ));
        } else if os_short == "mac" && is_apple_silicon && depth != 30 {
            violations.push((
                "color-depth".into(),
                format!("Apple Silicon Mac with colorDepth {depth}; deep colour is 30"),
            ));
        }
    }

    if let Some(touch_val) = config.get("navigator.maxTouchPoints") {
        if let Some(touch) = touch_val.as_i64() {
            if !(0..=MAX_PLAUSIBLE_TOUCH_POINTS).contains(&touch) {
                violations.push((
                    "touch-points".into(),
                    format!("navigator.maxTouchPoints {touch} out of 0..={MAX_PLAUSIBLE_TOUCH_POINTS}"),
                ));
            } else if os_short == "mac" && touch != 0 {
                violations.push((
                    "touch-points".into(),
                    format!("macOS identity with maxTouchPoints {touch}"),
                ));
            }
        } else {
            violations.push((
                "touch-points".into(),
                "navigator.maxTouchPoints is not an integer".into(),
            ));
        }
    }

    if let Some(dpr) = config.get("window.devicePixelRatio").and_then(Value::as_f64) {
        let allowed = match os_short {
            "win" => PLAUSIBLE_DPR_WIN,
            "mac" => PLAUSIBLE_DPR_MAC,
            _ => PLAUSIBLE_DPR_LIN,
        };
        if !allowed.iter().any(|&v| (v - dpr).abs() < 1e-6) {
            violations.push((
                "device-pixel-ratio".into(),
                format!("window.devicePixelRatio {dpr} is not plausible for {os_short}"),
            ));
        }
    }

    if let (Some(inner), Some(outer)) = (
        config.get("window.innerHeight").and_then(Value::as_i64).filter(|&v| v > 0),
        config.get("window.outerHeight").and_then(Value::as_i64).filter(|&v| v > 0),
    ) {
        if outer - inner < BROWSER_CHROME_HEIGHT {
            violations.push((
                "window-chrome".into(),
                format!(
                    "window.outerHeight {outer} - innerHeight {inner} < {BROWSER_CHROME_HEIGHT}"
                ),
            ));
        }
    }

    if let (Some(w), Some(h)) = (width.filter(|&v| v > 0), height.filter(|&v| v > 0)) {
        if h > w {
            violations.push(("screen-shape".into(), format!("portrait screen {w}x{h}")));
        } else if w < 1024 {
            violations.push(("screen-shape".into(), format!("tiny desktop screen {w}x{h}")));
        }
    }

    let avail_w = config.get("screen.availWidth").and_then(Value::as_i64);
    let avail_h = config.get("screen.availHeight").and_then(Value::as_i64);
    if let (Some(w), Some(aw)) = (width.filter(|&v| v > 0), avail_w.filter(|&v| v > 0)) {
        if aw > w {
            violations.push((
                "avail-bounds".into(),
                format!("screen.availWidth {aw} exceeds screen.width {w}"),
            ));
        }
    }
    if let (Some(h), Some(ah)) = (height.filter(|&v| v > 0), avail_h.filter(|&v| v > 0)) {
        if ah > h {
            violations.push((
                "avail-bounds".into(),
                format!("screen.availHeight {ah} exceeds screen.height {h}"),
            ));
        }
    }

    let ua = config
        .get("navigator.userAgent")
        .and_then(Value::as_str)
        .unwrap_or("");
    let platform = config
        .get("navigator.platform")
        .and_then(Value::as_str)
        .unwrap_or("");
    let oscpu = config
        .get("navigator.oscpu")
        .and_then(Value::as_str)
        .unwrap_or("");
    if ua.contains("x86_64") && (platform.contains("armv") || oscpu.contains("armv")) {
        violations.push((
            "arch-agreement".into(),
            format!("UA x86_64 vs platform/oscpu {platform:?}/{oscpu:?}"),
        ));
    }

    violations
}

pub fn apply_coherence(config: &mut Map<String, Value>, os_short: &str) -> Vec<(String, String)> {
    let is_apple_silicon = config
        .get("webGl:renderer")
        .and_then(Value::as_str)
        .unwrap_or("")
        .contains("Apple M");

    if is_apple_silicon {
        if let Some(cores) = config.get("navigator.hardwareConcurrency").and_then(Value::as_i64) {
            if !APPLE_SILICON_CORES.contains(&cores) {
                let snapped = APPLE_SILICON_CORES
                    .iter()
                    .copied()
                    .find(|&c| c >= cores)
                    .unwrap_or(*APPLE_SILICON_CORES.last().unwrap());
                config.insert("navigator.hardwareConcurrency".into(), json!(snapped));
            }
        }
    }

    if config.contains_key("screen.colorDepth") || config.contains_key("screen.pixelDepth") {
        let mut depth = config
            .get("screen.colorDepth")
            .and_then(Value::as_i64)
            .unwrap_or(24);
        if depth != 24 && depth != 30 {
            depth = 24;
        }
        if os_short == "mac" && is_apple_silicon {
            depth = 30;
        }
        config.insert("screen.colorDepth".into(), json!(depth));
        config.insert("screen.pixelDepth".into(), json!(depth));
    }

    if let Some(touch_val) = config.get("navigator.maxTouchPoints") {
        let touch_opt = touch_val.as_i64();
        let invalid = touch_opt.is_none_or(|t| !(0..=MAX_PLAUSIBLE_TOUCH_POINTS).contains(&t));
        if os_short == "mac" || invalid {
            config.insert("navigator.maxTouchPoints".into(), json!(0));
        }
    }

    if let Some(dpr) = config.get("window.devicePixelRatio").and_then(Value::as_f64) {
        let allowed = match os_short {
            "win" => PLAUSIBLE_DPR_WIN,
            "mac" => PLAUSIBLE_DPR_MAC,
            _ => PLAUSIBLE_DPR_LIN,
        };
        let nearest = allowed
            .iter()
            .copied()
            .min_by(|a, b| (a - dpr).abs().total_cmp(&(b - dpr).abs()))
            .unwrap_or(1.0);
        config.insert("window.devicePixelRatio".into(), json!(nearest));
    }

    if let (Some(inner), Some(outer)) = (
        config.get("window.innerHeight").and_then(Value::as_i64).filter(|&v| v > 0),
        config.get("window.outerHeight").and_then(Value::as_i64).filter(|&v| v > 0),
    ) {
        if outer - inner < BROWSER_CHROME_HEIGHT {
            let avail = config
                .get("screen.availHeight")
                .or_else(|| config.get("screen.height"))
                .and_then(Value::as_i64);
            if avail.is_none_or(|a| inner + BROWSER_CHROME_HEIGHT <= a) {
                config.insert("window.outerHeight".into(), json!(inner + BROWSER_CHROME_HEIGHT));
            } else {
                config.insert(
                    "window.innerHeight".into(),
                    json!((outer - BROWSER_CHROME_HEIGHT).max(1)),
                );
            }
        }
    }

    if let Some(w) = config.get("screen.width").and_then(Value::as_i64).filter(|&v| v > 0) {
        if config
            .get("screen.availWidth")
            .and_then(Value::as_i64)
            .is_some_and(|aw| aw > w)
        {
            config.insert("screen.availWidth".into(), json!(w));
        }
    }
    if let Some(h) = config.get("screen.height").and_then(Value::as_i64).filter(|&v| v > 0) {
        if config
            .get("screen.availHeight")
            .and_then(Value::as_i64)
            .is_some_and(|ah| ah > h)
        {
            config.insert("screen.availHeight".into(), json!(h));
        }
    }

    validate_coherence(config, os_short)
}

fn validate_value_type(value: &Value, expected_type: &str) -> bool {
    match expected_type {
        "str" => value.is_string(),
        "int" => {
            value.is_i64()
                || value.is_u64()
                || value.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0)
        }
        "uint" => {
            value.as_u64().is_some()
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

pub fn validate_voices(voices: &Value) -> Result<()> {
    let arr = voices
        .as_array()
        .ok_or_else(|| anyhow!("Invalid type for property voices: expected array"))?;
    for (idx, voice) in arr.iter().enumerate() {
        let obj = voice.as_object().ok_or_else(|| {
            anyhow!("Invalid voices[{idx}]: expected object with {{lang, name, voiceUri, isDefault, isLocalService}}")
        })?;
        for &field in VOICE_FIELDS {
            if !obj.contains_key(field) {
                bail!("Invalid voices[{idx}]: missing required field '{field}'");
            }
        }
        if !obj["lang"].is_string()
            || !obj["name"].is_string()
            || !obj["voiceUri"].is_string()
            || !obj["isDefault"].is_boolean()
            || !obj["isLocalService"].is_boolean()
        {
            bail!("Invalid voices[{idx}]: field types do not match MaskConfig::MVoices");
        }
    }
    Ok(())
}

fn load_external_properties(properties_path: Option<&Path>) -> Option<HashMap<String, PropertySpec>> {
    let path = properties_path?;
    let candidates = if path.file_name().is_some_and(|n| n == "properties.json") {
        vec![path.to_path_buf()]
    } else if path.is_file() {
        let parent = path.parent()?;
        vec![
            parent.join("properties.json"),
            parent
                .parent()
                .map(|p| p.join("Resources").join("properties.json"))
                .unwrap_or_else(|| parent.join("properties.json")),
        ]
    } else {
        vec![path.join("properties.json")]
    };
    for candidate in candidates {
        if let Ok(raw) = fs::read_to_string(&candidate) {
            if let Ok(parsed) = parse_properties_json(&raw) {
                return Some(parsed);
            }
        }
    }
    None
}

pub fn sanitize_for_browser(config: &mut Value, properties_path: Option<&Path>) -> Result<()> {
    let map = config
        .as_object_mut()
        .ok_or_else(|| anyhow!("Fingerprint config must be a JSON object"))?;
    let external = load_external_properties(properties_path);
    let specs = external.as_ref().unwrap_or(&CATALOGS.properties);

    map.retain(|k, _| specs.get(k).is_some_and(|spec| !spec.removed));

    for (key, val) in map.iter() {
        let spec = &specs[key];
        if !validate_value_type(val, &spec.expected_type) {
            bail!(
                "Invalid type for property {key}: expected {}, got {val}",
                spec.expected_type
            );
        }
        if key == "voices" {
            validate_voices(val)?;
        }
    }
    Ok(())
}

pub fn validate_config(config: &Value, properties_path: Option<&Path>) -> Result<()> {
    let map = config
        .as_object()
        .ok_or_else(|| anyhow!("Fingerprint config must be a JSON object"))?;
    let external = load_external_properties(properties_path);
    let specs = external.as_ref().unwrap_or(&CATALOGS.properties);

    for (key, val) in map {
        let Some(spec) = specs.get(key) else {
            bail!("Unsupported Camoufox property: {key}");
        };
        if spec.removed {
            bail!("Removed Camoufox property: {key}");
        }
        if !validate_value_type(val, &spec.expected_type) {
            bail!(
                "Invalid type for property {key}: expected {}, got {val}",
                spec.expected_type
            );
        }
        if key == "voices" {
            validate_voices(val)?;
        }
    }
    Ok(())
}

pub fn validate_preset_dataset(data: &Value) -> Result<()> {
    let Some(presets_obj) = data.get("presets").and_then(Value::as_object) else {
        bail!("Invalid fingerprint preset dataset");
    };
    let mut total_count = 0usize;
    for os_name in ["windows", "macos", "linux"] {
        if let Some(val) = presets_obj.get(os_name) {
            let Some(list) = val.as_array() else {
                bail!("Invalid preset OS collection for {os_name}");
            };
            for preset in list {
                let Some(p_obj) = preset.as_object() else {
                    bail!("Unsupported fingerprint preset schema");
                };
                let Some(nav) = p_obj.get("navigator").and_then(Value::as_object) else {
                    bail!("Unsupported fingerprint preset schema");
                };
                if !p_obj.get("screen").is_some_and(Value::is_object) {
                    bail!("Unsupported fingerprint preset schema");
                }
                if !nav
                    .get("userAgent")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty())
                {
                    bail!("Preset is missing a browser identity");
                }
                total_count += 1;
            }
        }
    }
    if total_count == 0 {
        bail!("Empty fingerprint preset dataset");
    }
    Ok(())
}

pub fn git_blob_sha1(raw: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", raw.len()).as_bytes());
    hasher.update(raw);
    hex::encode(hasher.finalize())
}

fn sha256_hex(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

fn sample_bundled_preset(target_os: &str, major: u32) -> Option<Value> {
    let catalogs = &*CATALOGS;
    let dataset = if major >= PRESETS_V150_MIN_FF {
        &catalogs.presets_v150
    } else {
        &catalogs.presets_base
    };
    let candidates = dataset
        .get("presets")
        .and_then(|p| p.get(target_os))
        .and_then(Value::as_array)?;
    let mut rng = rand::thread_rng();
    candidates.choose(&mut rng).cloned()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CoordInput {
    Omitted,
    Clear,
    Valid(f64),
}

fn parse_coord(val_opt: Option<&Value>, min: f64, max: f64) -> Result<CoordInput> {
    let Some(val) = val_opt else {
        return Ok(CoordInput::Omitted);
    };
    if val.is_null() {
        return Ok(CoordInput::Clear);
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(CoordInput::Clear);
        }
        if let Ok(num) = trimmed.parse::<f64>() {
            if num.is_finite() && (min..=max).contains(&num) {
                return Ok(CoordInput::Valid(num));
            }
        }
        bail!("Geolocation coordinates out of valid range");
    }
    if let Some(num) = val.as_f64() {
        if num.is_finite() && (min..=max).contains(&num) {
            return Ok(CoordInput::Valid(num));
        }
        bail!("Geolocation coordinates out of valid range");
    }
    bail!("Geolocation coordinates out of valid range");
}

pub struct FingerprintService {
    store: Arc<Store>,
    root: PathBuf,
    lock: ReentrantMutex<()>,
}

impl FingerprintService {
    pub fn new(store: Arc<Store>) -> Result<Self> {
        let root = store.root.join("fingerprint-data");
        Ok(Self {
            store,
            root,
            lock: ReentrantMutex::new(()),
        })
    }

    fn resolve_version_and_path(&self, profile: &Value) -> (u32, Option<PathBuf>) {
        let explicit = string(profile, "browser_version");
        let installed = self.store.list("versions").unwrap_or_default();
        if !explicit.is_empty() {
            let major = parse_major_version(Some(explicit));
            let path = installed
                .iter()
                .find(|v| string(v, "id") == explicit || string(v, "name") == explicit)
                .map(|v| PathBuf::from(string(v, "path")))
                .filter(|p| !p.as_os_str().is_empty());
            (major, path)
        } else if let Some(first) = installed.first() {
            let ver_str = if !string(first, "id").is_empty() {
                string(first, "id")
            } else {
                string(first, "name")
            };
            let major = parse_major_version(Some(ver_str));
            let path = PathBuf::from(string(first, "path"));
            (major, (!path.as_os_str().is_empty()).then_some(path))
        } else {
            (135, None)
        }
    }

    pub fn generate(&self, profile: &Value) -> Result<Value> {
        let (target_os, os_short) = resolve_os_pair(profile.get("os").and_then(Value::as_str))?;
        let (major, exe_path) = self.resolve_version_and_path(profile);
        let use_preset = profile
            .pointer("/fingerprint_meta/use_preset")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let salt: u64 = rand::thread_rng().gen();
        let mut config = Map::new();

        if use_preset {
            let preset = if let Some(sampled) = self.sample_downloaded_preset(target_os, major)? {
                Some(sampled)
            } else {
                sample_bundled_preset(target_os, major)
            };
            if let Some(p) = preset {
                config = from_preset(&p, major);
            }
        }

        if config.is_empty() {
            let fp = fpgen::generate_fingerprint(target_os, None, None)?;
            config = from_fpgen(&fp, major);
        }

        repair_screen_orientation(&mut config);
        fix_navigator_arch(&mut config, os_short);
        fix_hardware_concurrency(&mut config);
        raise_screen_to_modern_floor(&mut config);
        fix_screen_no_taskbar(&mut config, os_short);
        clamp_window_dimensions(&mut config);
        clamp_window_position(&mut config);

        let base_seed = compute_initial_seed(&config, salt);
        let audio_seed =
            (((base_seed.wrapping_mul(2654435761).wrapping_add(97)) & 0xFFFF_FFFF) as u32).max(1);
        config.insert("audio:seed".into(), json!(audio_seed));

        let seed = identity_seed_from_config(&config);
        let loc_obj = profile.get("location").unwrap_or(&Value::Null);
        let raw_locale = loc_obj
            .get("locale")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("en-US");

        config.insert(
            "fonts".into(),
            json!(generate_random_font_subset(target_os, seed, Some(raw_locale))),
        );

        set_media_devices_defaults(&mut config, os_short, seed);

        drop_incoherent_source_values(&mut config, os_short);

        let width = config.get("screen.width").and_then(Value::as_i64);
        let height = config.get("screen.height").and_then(Value::as_i64);
        let cores = config
            .get("navigator.hardwareConcurrency")
            .and_then(Value::as_i64);

        let mut webgl_fp = if let (Some(vendor), Some(renderer)) = (
            config
                .get("webGl:vendor")
                .and_then(Value::as_str)
                .map(str::to_owned),
            config
                .get("webGl:renderer")
                .and_then(Value::as_str)
                .map(str::to_owned),
        ) {
            webgl_for_gpu(os_short, &vendor, &renderer, seed)
                .or_else(|_| sample_webgl_for_screen(os_short, width, height, seed, cores))?
        } else {
            sample_webgl_for_screen(os_short, width, height, seed, cores)?
        };
        webgl_fp.remove("webGl2Enabled");
        config.extend(webgl_fp);

        apply_coherence(&mut config, os_short);
        clamp_window_dimensions(&mut config);
        clamp_window_position(&mut config);

        let mut config_val = Value::Object(config);
        self.apply_location(&mut config_val, loc_obj)?;
        sanitize_for_browser(&mut config_val, exe_path.as_deref())?;

        let _ = self.store.log(
            "INFO",
            &format!(
                "Generated persistent fingerprint for {}: UA: {}, screen: {}x{}",
                if string(profile, "name").is_empty() {
                    "profile"
                } else {
                    string(profile, "name")
                },
                string(&config_val, "navigator.userAgent"),
                config_val["screen.width"],
                config_val["screen.height"]
            ),
            string(profile, "id"),
        );

        Ok(config_val)
    }

    pub fn apply_location(&self, config: &mut Value, location: &Value) -> Result<()> {
        if config.as_object().is_none_or(|m| m.is_empty()) {
            *config = self.generate(&json!({ "location": location }))?;
            return Ok(());
        }
        let fp = config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Fingerprint config must be a JSON object"))?;

        let raw_locale = location
            .get("locale")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("en-US");

        let parts: Vec<&str> = raw_locale
            .split(['-', '_'])
            .filter(|s| !s.is_empty())
            .collect();
        let (lang, region, script_opt) = if parts.len() >= 3 && parts[1].len() == 4 {
            let s = parts[1];
            let script = format!(
                "{}{}",
                s[..1].to_ascii_uppercase(),
                s[1..].to_ascii_lowercase()
            );
            (
                parts[0].to_ascii_lowercase(),
                parts[2].to_ascii_uppercase(),
                Some(script),
            )
        } else if parts.len() >= 2 {
            (
                parts[0].to_ascii_lowercase(),
                parts[1].to_ascii_uppercase(),
                None,
            )
        } else {
            let fallback_region = location
                .get("country")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("US")
                .to_ascii_uppercase();
            (
                parts.first().copied().unwrap_or("en").to_ascii_lowercase(),
                fallback_region,
                None,
            )
        };

        fp.insert("locale:language".into(), json!(lang));
        fp.insert("locale:region".into(), json!(region));
        if let Some(script) = script_opt {
            fp.insert("locale:script".into(), json!(script));
        } else {
            fp.remove("locale:script");
        }

        if let Some(tz_val) = location.get("timezone") {
            if tz_val.is_null() {
                fp.remove("timezone");
            } else if let Some(tz) = tz_val.as_str() {
                let trimmed = tz.trim();
                if trimmed.is_empty() {
                    fp.remove("timezone");
                } else {
                    fp.insert("timezone".into(), json!(trimmed));
                }
            } else {
                bail!("Invalid timezone: expected string");
            }
        }

        let lat_input = parse_coord(location.get("latitude"), -90.0, 90.0)?;
        let lon_input = parse_coord(location.get("longitude"), -180.0, 180.0)?;
        match (lat_input, lon_input) {
            (CoordInput::Omitted, CoordInput::Omitted) => {}
            (CoordInput::Valid(lat), CoordInput::Valid(lon)) => {
                fp.insert("geolocation:latitude".into(), json!(lat));
                fp.insert("geolocation:longitude".into(), json!(lon));
            }
            _ => {
                fp.remove("geolocation:latitude");
                fp.remove("geolocation:longitude");
            }
        }

        if let Some(ip_val) = location.get("ip") {
            if ip_val.is_null() {
                fp.remove("webrtc:ipv4");
                fp.remove("webrtc:ipv6");
            } else if let Some(ip_str) = ip_val.as_str() {
                let ip = ip_str.trim();
                if ip.is_empty() {
                    fp.remove("webrtc:ipv4");
                    fp.remove("webrtc:ipv6");
                } else if ip.parse::<Ipv4Addr>().is_ok() {
                    fp.insert("webrtc:ipv4".into(), json!(ip));
                    fp.remove("webrtc:ipv6");
                } else if ip.parse::<Ipv6Addr>().is_ok() {
                    fp.insert("webrtc:ipv6".into(), json!(ip));
                    fp.remove("webrtc:ipv4");
                } else {
                    bail!("Invalid WebRTC IP address: {ip}");
                }
            } else {
                bail!("Invalid WebRTC IP address: {ip_val}");
            }
        }

        let (target_os, _) = infer_os_pair_from_config(fp);
        let seed = identity_seed_from_config(fp);
        let voice_locale = format!("{lang}-{region}");
        fp.insert(
            "voices".into(),
            json!(generate_random_voice_subset(
                target_os,
                Some(&voice_locale),
                seed
            )),
        );
        fp.insert("voices:blockIfNotDefined".into(), json!(true));

        sanitize_for_browser(config, None)
    }

    pub fn retarget_version(&self, config: &mut Value, major: u32) -> Result<()> {
        if major == 0 {
            bail!("Invalid Firefox major version: 0");
        }
        let fp = config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Fingerprint config must be a JSON object"))?;

        for key in ["navigator.userAgent", "headers.User-Agent"] {
            if let Some(ua) = fp.get(key).and_then(Value::as_str) {
                fp.insert(key.into(), json!(rewrite_ff_version_in_ua(ua, major)));
            }
        }

        if let Some(ua) = fp
            .get("navigator.userAgent")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            if let Some(derived) = app_version_from_user_agent(&ua) {
                fp.insert("navigator.appVersion".into(), json!(derived));
            }
        } else if let Some(app_ver) = fp.get("navigator.appVersion").and_then(Value::as_str) {
            fp.insert(
                "navigator.appVersion".into(),
                json!(rewrite_ff_version_in_ua(app_ver, major)),
            );
        }

        sanitize_for_browser(config, None)
    }

    pub fn info(&self) -> Result<Value> {
        let _guard = self.lock.lock();
        let path = self.root.join("metadata.json");
        if !path.exists() {
            return Ok(json!({ "updated_at": "", "files": [] }));
        }
        reject_link(&path)?;
        let raw = fs::read_to_string(&path).context("Failed to read fingerprint metadata.json")?;
        let parsed: Value =
            serde_json::from_str(&raw).context("Invalid fingerprint metadata.json")?;
        Ok(parsed)
    }

    pub fn sample_downloaded_preset(&self, target_os: &str, major: u32) -> Result<Option<Value>> {
        let _guard = self.lock.lock();
        let metadata = self.info()?;
        let snapshot = string(&metadata, "snapshot");
        if snapshot.is_empty() {
            return Ok(None);
        }
        safe_component(snapshot)?;
        let files = metadata
            .get("files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut eligible: Vec<&Value> = files
            .iter()
            .filter(|entry| {
                let min_ff = entry
                    .get("min_firefox_version")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                min_ff <= major
            })
            .collect();
        eligible.sort_by_key(|entry| {
            std::cmp::Reverse(
                entry
                    .get("min_firefox_version")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
        });

        let snap_dir = self.root.join(snapshot);
        reject_link(&snap_dir)?;

        for entry in eligible {
            let name = string(entry, "name");
            safe_component(name)?;
            let expected_sha256 = string(entry, "sha256");
            let file_path = snap_dir.join(name);
            reject_link(&file_path)?;
            let raw = fs::read(&file_path)
                .with_context(|| format!("Missing cached preset file {name}"))?;
            if sha256_hex(&raw) != expected_sha256 {
                bail!("Cached fingerprint preset integrity check failed");
            }
            let dataset: Value = serde_json::from_slice(&raw)?;
            validate_preset_dataset(&dataset)?;
            if let Some(candidates) = dataset
                .get("presets")
                .and_then(|p| p.get(target_os))
                .and_then(Value::as_array)
                .filter(|c| !c.is_empty())
            {
                let mut rng = rand::thread_rng();
                return Ok(candidates.choose(&mut rng).cloned());
            }
        }
        Ok(None)
    }

    pub fn update(&self) -> Result<Value> {
        let _guard = self.lock.lock();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("CamouManager/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to initialize HTTP client")?;

        let listing_resp = client
            .get(SOURCE_URL)
            .header("Accept", "application/vnd.github+json")
            .send()
            .context("Failed to fetch official fingerprint dataset listing")?
            .error_for_status()
            .context("Official fingerprint dataset listing returned HTTP error")?;

        let listing: Value = listing_resp
            .json()
            .context("Invalid JSON in official fingerprint dataset listing")?;
        let arr = listing
            .as_array()
            .ok_or_else(|| anyhow!("Unexpected GitHub contents listing format"))?;

        static PRESET_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^fingerprint-presets(?:-v\d+)?\.json$").expect("static preset name regex")
        });

        let entries: Vec<&Value> = arr
            .iter()
            .filter(|e| {
                string(e, "type") == "file" && PRESET_NAME_RE.is_match(string(e, "name"))
            })
            .collect();

        if entries.is_empty() {
            bail!("Official fingerprint presets not found");
        }

        self.stage_and_commit_entries(&entries, SOURCE_URL, |url| {
            if !url.starts_with(RAW_SOURCE_PREFIX) {
                bail!("Unexpected fingerprint dataset source");
            }
            let mut resp = client
                .get(url)
                .send()
                .context("Failed to download fingerprint preset file")?
                .error_for_status()
                .context("Fingerprint preset download returned HTTP error")?;
            let mut body = Vec::new();
            resp.by_ref()
                .take((MAX_DATA_BYTES + 1) as u64)
                .read_to_end(&mut body)?;
            if body.len() > MAX_DATA_BYTES {
                bail!("Fingerprint data download exceeds safe size");
            }
            Ok(body)
        })
    }

    pub fn stage_and_commit_entries<F>(
        &self,
        entries: &[&Value],
        source: &str,
        mut fetch_fn: F,
    ) -> Result<Value>
    where
        F: FnMut(&str) -> Result<Vec<u8>>,
    {
        let _guard = self.lock.lock();
        if entries.is_empty() {
            bail!("Official fingerprint presets not found");
        }
        static PRESET_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^fingerprint-presets(?:-v\d+)?\.json$").expect("static preset name regex")
        });

        reject_link(&self.root)?;
        fs::create_dir_all(&self.root)?;

        let existing = self.info()?;
        let existing_snapshot = string(&existing, "snapshot");
        let mut old_by_name: HashMap<String, Value> = HashMap::new();
        if let Some(old_files) = existing.get("files").and_then(Value::as_array) {
            for f in old_files {
                let n = string(f, "name");
                if !n.is_empty() {
                    old_by_name.insert(n.to_owned(), f.clone());
                }
            }
        }

        let mut files_meta = Vec::with_capacity(entries.len());
        let mut staged: Vec<(String, Vec<u8>)> = Vec::with_capacity(entries.len());

        for entry in entries {
            let size = entry.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
            if size == 0 || size > MAX_DATA_BYTES {
                bail!("Fingerprint preset dataset exceeds safe size");
            }
            let name = string(entry, "name");
            if !PRESET_NAME_RE.is_match(name) {
                bail!("Invalid fingerprint preset filename: {name}");
            }
            safe_component(name)?;
            let url = string(entry, "download_url");
            if !url.starts_with(RAW_SOURCE_PREFIX) {
                bail!("Unexpected fingerprint dataset source");
            }
            let expected_git_sha = string(entry, "sha");

            let reused = if !existing_snapshot.is_empty() {
                let current_path = self.root.join(existing_snapshot).join(name);
                if current_path.is_file()
                    && old_by_name
                        .get(name)
                        .is_some_and(|old| string(old, "git_sha") == expected_git_sha)
                {
                    fs::read(&current_path).ok()
                } else {
                    None
                }
            } else {
                None
            };

            let raw = match reused {
                Some(bytes) => bytes,
                None => fetch_fn(url)?,
            };

            if raw.is_empty() || raw.len() > MAX_DATA_BYTES {
                bail!("Fingerprint data download exceeds safe size");
            }

            let actual_git_sha = git_blob_sha1(&raw);
            if actual_git_sha != expected_git_sha {
                bail!("Fingerprint data integrity check failed");
            }

            let dataset: Value =
                serde_json::from_slice(&raw).context("Invalid JSON in fingerprint preset dataset")?;
            validate_preset_dataset(&dataset)?;

            let min_ff = dataset
                .get("min_firefox_version")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let count: usize = dataset["presets"]
                .as_object()
                .map(|m| {
                    m.values()
                        .filter_map(Value::as_array)
                        .map(Vec::len)
                        .sum()
                })
                .unwrap_or(0);

            files_meta.push(json!({
                "name": name,
                "git_sha": actual_git_sha,
                "sha256": sha256_hex(&raw),
                "min_firefox_version": min_ff,
                "count": count,
            }));
            staged.push((name.to_owned(), raw));
        }

        let concat_shas: String = files_meta
            .iter()
            .map(|f| string(f, "git_sha"))
            .collect();
        let snapshot = sha256_hex(concat_shas.as_bytes())[..16].to_owned();
        let snap_dir = self.root.join(&snapshot);
        reject_link(&snap_dir)?;
        fs::create_dir_all(&snap_dir)?;

        for (name, raw) in &staged {
            let target = snap_dir.join(name);
            reject_link(&target)?;
            if !target.exists() {
                let part = snap_dir.join(format!("{name}.part"));
                reject_link(&part)?;
                fs::write(&part, raw)?;
                fs::rename(&part, &target)?;
            }
        }

        let total_presets: u64 = files_meta
            .iter()
            .filter_map(|f| f.get("count").and_then(Value::as_u64))
            .sum();

        let metadata = json!({
            "updated_at": utcnow(),
            "snapshot": snapshot,
            "source": source,
            "files": files_meta,
        });

        let temp_meta = self.root.join("metadata.json.part");
        let final_meta = self.root.join("metadata.json");
        reject_link(&temp_meta)?;
        reject_link(&final_meta)?;
        fs::write(&temp_meta, serde_json::to_vec_pretty(&metadata)?)?;
        fs::rename(&temp_meta, &final_meta)?;

        let _ = self.store.log(
            "INFO",
            &format!("Fingerprint preset data refreshed: {total_presets} presets"),
            "",
        );

        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> (tempfile::TempDir, Arc<Store>, FingerprintService) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let service = FingerprintService::new(store.clone()).unwrap();
        (dir, store, service)
    }

    #[test]
    fn generates_coherent_identities_across_os_in_synthetic_and_preset_modes() {
        let (_dir, _store, service) = test_service();
        for (os, expected_plat, os_short) in [
            ("windows", "Win32", "win"),
            ("macos", "MacIntel", "mac"),
            ("linux", "Linux x86_64", "lin"),
        ] {
            for use_preset in [false, true] {
                let profile = json!({
                    "name": format!("{os}-{use_preset}"),
                    "os": os,
                    "browser_version": "v156.0.1-beta.36",
                    "fingerprint_meta": { "use_preset": use_preset },
                    "location": {
                        "locale": "en-US",
                        "timezone": "America/New_York",
                        "country": "US",
                        "latitude": 40.7128,
                        "longitude": -74.006,
                        "ip": "198.51.100.42"
                    }
                });
                let fp = service.generate(&profile).unwrap();
                validate_config(&fp, None).unwrap();

                let map = fp.as_object().unwrap();
                assert_eq!(string(&fp, "navigator.platform"), expected_plat);
                assert!(string(&fp, "navigator.userAgent").contains("Firefox/156.0"));
                assert!(string(&fp, "navigator.userAgent").contains("rv:156.0"));
                assert!(!string(&fp, "navigator.appVersion").is_empty());
                assert!(!string(&fp, "navigator.oscpu").is_empty());

                let sw = map["screen.width"].as_i64().unwrap();
                let sh = map["screen.height"].as_i64().unwrap();
                let aw = map["screen.availWidth"].as_i64().unwrap();
                let ah = map["screen.availHeight"].as_i64().unwrap();
                assert!(sw >= 1366 && sh >= 768 && sw >= sh);
                assert!(aw <= sw && ah < sh);

                if os_short == "mac" {
                    assert_eq!(map["navigator.maxTouchPoints"].as_i64().unwrap(), 0);
                } else {
                    let touch = map["navigator.maxTouchPoints"].as_i64().unwrap();
                    assert!((0..=10).contains(&touch));
                }

                let renderer = string(&fp, "webGl:renderer");
                assert!(!renderer.is_empty());
                assert!(!is_software_renderer(renderer));
                assert_ne!(renderer, "Mozilla");
                assert!(gpu_fits_os(renderer, os_short));
                assert!(map["webGl:parameters"].is_object());
                assert!(map["webGl:supportedExtensions"].is_array());
                assert!(map["webGl:shaderPrecisionFormats"].is_object());
                assert!(!map.contains_key("webGl2Enabled"));

                let exts: Vec<&str> = map["webGl:supportedExtensions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                assert!(!exts.contains(&"WEBGL_multi_draw"));

                assert!(!map["fonts"].as_array().unwrap().is_empty());
                assert_eq!(map["voices:blockIfNotDefined"], json!(true));
                assert_eq!(map["mediaDevices:enabled"], json!(true));
                assert!(map["audio:seed"].as_u64().unwrap() >= 1);
                assert_eq!(string(&fp, "webrtc:ipv4"), "198.51.100.42");

                let violations = validate_coherence(map, os_short);
                assert!(
                    violations.is_empty(),
                    "unexpected coherence violations for {os} (preset={use_preset}): {violations:?}"
                );
            }
        }
    }

    #[test]
    fn retarget_version_and_apply_location_preserve_stable_identity() {
        let (_dir, _store, service) = test_service();
        let profile = json!({
            "name": "StableWin",
            "os": "windows",
            "browser_version": "v135.0.0",
            "location": {
                "locale": "en-US",
                "timezone": "America/Chicago",
                "country": "US"
            }
        });
        let mut fp = service.generate(&profile).unwrap();
        let orig_seed = fp["audio:seed"].clone();
        let orig_fonts = fp["fonts"].clone();
        let orig_renderer = fp["webGl:renderer"].clone();
        let orig_media = fp["mediaDevices:microphoneLabels"].clone();
        let orig_en_voices = fp["voices"].clone();

        service.retarget_version(&mut fp, 156).unwrap();
        assert!(string(&fp, "navigator.userAgent").contains("Firefox/156.0"));
        assert!(string(&fp, "navigator.userAgent").contains("rv:156.0"));
        assert_eq!(fp["audio:seed"], orig_seed);
        assert_eq!(fp["fonts"], orig_fonts);
        assert_eq!(fp["webGl:renderer"], orig_renderer);
        assert_eq!(fp["mediaDevices:microphoneLabels"], orig_media);

        service
            .apply_location(
                &mut fp,
                &json!({
                    "locale": "fr-FR",
                    "timezone": "Europe/Paris",
                    "country": "FR",
                    "latitude": 48.8566,
                    "longitude": 2.3522,
                    "ip": "2001:db8::1"
                }),
            )
            .unwrap();
        assert_eq!(string(&fp, "locale:language"), "fr");
        assert_eq!(string(&fp, "locale:region"), "FR");
        assert_eq!(string(&fp, "timezone"), "Europe/Paris");
        assert_eq!(string(&fp, "webrtc:ipv6"), "2001:db8::1");
        assert!(fp.get("webrtc:ipv4").is_none());
        assert_eq!(fp["audio:seed"], orig_seed);
        assert_eq!(fp["fonts"], orig_fonts);
        assert_eq!(fp["webGl:renderer"], orig_renderer);
        let fr_voices = fp["voices"].as_array().unwrap();
        assert!(fr_voices.iter().any(|v| string(v, "lang") == "fr-FR"));

        service
            .apply_location(
                &mut fp,
                &json!({
                    "locale": "en-US",
                    "timezone": "America/Chicago",
                    "country": "US"
                }),
            )
            .unwrap();
        assert_eq!(fp["voices"], orig_en_voices);
    }

    #[test]
    fn repairs_incoherent_arch_hardware_and_touch_constraints() {
        let mut config = Map::new();
        config.insert(
            "navigator.userAgent".into(),
            json!("Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"),
        );
        config.insert("navigator.platform".into(), json!("Linux armv81"));
        config.insert("navigator.oscpu".into(), json!("Linux armv81"));
        config.insert("navigator.appVersion".into(), json!("5.0 (Windows)"));
        fix_navigator_arch(&mut config, "lin");
        assert_eq!(config["navigator.platform"], json!("Linux x86_64"));
        assert_eq!(config["navigator.oscpu"], json!("Linux x86_64"));
        assert_eq!(config["navigator.appVersion"], json!("5.0 (X11)"));

        let mut mac_cfg = Map::new();
        mac_cfg.insert("webGl:renderer".into(), json!("Apple M1, or similar"));
        mac_cfg.insert("navigator.hardwareConcurrency".into(), json!(4));
        mac_cfg.insert("screen.colorDepth".into(), json!(24));
        mac_cfg.insert("navigator.maxTouchPoints".into(), json!(5));
        mac_cfg.insert("window.devicePixelRatio".into(), json!(1.818));
        mac_cfg.insert("screen.width".into(), json!(1440));
        mac_cfg.insert("screen.height".into(), json!(2560));
        mac_cfg.insert("screen.availWidth".into(), json!(1440));
        mac_cfg.insert("screen.availHeight".into(), json!(2560));
        mac_cfg.insert("window.outerHeight".into(), json!(800));
        mac_cfg.insert("window.innerHeight".into(), json!(750));

        assert!(repair_screen_orientation(&mut mac_cfg));
        fix_screen_no_taskbar(&mut mac_cfg, "mac");
        let remaining = apply_coherence(&mut mac_cfg, "mac");
        assert!(remaining.is_empty(), "remaining violations: {remaining:?}");
        assert_eq!(mac_cfg["navigator.hardwareConcurrency"], json!(8));
        assert_eq!(mac_cfg["screen.colorDepth"], json!(30));
        assert_eq!(mac_cfg["screen.pixelDepth"], json!(30));
        assert_eq!(mac_cfg["navigator.maxTouchPoints"], json!(0));
        assert_eq!(mac_cfg["window.devicePixelRatio"], json!(2.0));
        assert_eq!(mac_cfg["screen.width"], json!(2560));
        assert_eq!(mac_cfg["screen.height"], json!(1440));
        assert!(
            mac_cfg["window.outerHeight"].as_i64().unwrap()
                - mac_cfg["window.innerHeight"].as_i64().unwrap()
                >= BROWSER_CHROME_HEIGHT
        );
    }

    #[test]
    fn fpgen_model_enforces_constraints_and_rejects_contradictions() {
        let mut valid = Map::new();
        valid.insert("browser".into(), json!("Firefox"));
        valid.insert("os".into(), json!("Windows"));
        let sample = fpgen::generate_with_constraints(&valid, true).unwrap();
        assert_eq!(sample["navigator"]["platform"], json!("Win32"));

        let mut invalid_val = Map::new();
        invalid_val.insert("browser".into(), json!("Firefox"));
        invalid_val.insert("os".into(), json!("NonExistentOS"));
        assert!(fpgen::generate_with_constraints(&invalid_val, true).is_err());

        let mut contradictory = Map::new();
        contradictory.insert("browser".into(), json!("Firefox"));
        contradictory.insert("os".into(), json!("MacOS"));
        contradictory.insert("navigator.platform".into(), json!("Linux armv81"));
        assert!(fpgen::generate_with_constraints(&contradictory, true).is_err());
    }

    #[test]
    fn preset_dataset_update_is_atomic_and_verifies_integrity() {
        let (_dir, _store, service) = test_service();
        let valid_payload = serde_json::to_vec(&json!({
            "version": 1,
            "min_firefox_version": 150,
            "presets": {
                "windows": [{
                    "navigator": {
                        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
                        "platform": "Win32",
                        "hardwareConcurrency": 8,
                        "maxTouchPoints": 0
                    },
                    "screen": {
                        "width": 1920,
                        "height": 1080,
                        "availWidth": 1920,
                        "availHeight": 1040,
                        "colorDepth": 24
                    }
                }]
            }
        }))
        .unwrap();
        let valid_sha = git_blob_sha1(&valid_payload);
        let entry = json!({
            "type": "file",
            "name": "fingerprint-presets-v150.json",
            "size": valid_payload.len(),
            "sha": valid_sha,
            "download_url": "https://raw.githubusercontent.com/daijro/camoufox/main/python/src/camoufox/fingerprint-presets-v150.json"
        });

        let committed = service
            .stage_and_commit_entries(&[&entry], SOURCE_URL, |_| Ok(valid_payload.clone()))
            .unwrap();
        let orig_snapshot = string(&committed, "snapshot").to_owned();
        assert!(!orig_snapshot.is_empty());

        let bad_hash_entry = json!({
            "type": "file",
            "name": "fingerprint-presets-v150.json",
            "size": valid_payload.len(),
            "sha": "0000000000000000000000000000000000000000",
            "download_url": "https://raw.githubusercontent.com/daijro/camoufox/main/python/src/camoufox/fingerprint-presets-v150.json"
        });
        assert!(service
            .stage_and_commit_entries(&[&bad_hash_entry], SOURCE_URL, |_| Ok(valid_payload.clone()))
            .is_err());

        let bad_url_entry = json!({
            "type": "file",
            "name": "fingerprint-presets-v150.json",
            "size": valid_payload.len(),
            "sha": valid_sha,
            "download_url": "https://evil.example.com/fingerprint-presets-v150.json"
        });
        assert!(service
            .stage_and_commit_entries(&[&bad_url_entry], SOURCE_URL, |_| Ok(valid_payload.clone()))
            .is_err());

        assert_eq!(string(&service.info().unwrap(), "snapshot"), orig_snapshot);

        let cached_file = service
            .root
            .join(&orig_snapshot)
            .join("fingerprint-presets-v150.json");
        fs::write(&cached_file, b"{\"tampered\":true}").unwrap();
        assert!(service.sample_downloaded_preset("windows", 156).is_err());
    }

    #[test]
    fn apply_location_explicit_clears_and_partial_updates() {
        let (_dir, _store, service) = test_service();
        let profile = json!({
            "name": "LocProfile",
            "os": "windows",
            "browser_version": "v156.0.1-beta.36",
            "location": {
                "locale": "fr-FR",
                "timezone": "Europe/Paris",
                "country": "FR",
                "latitude": 48.8566,
                "longitude": 2.3522,
                "ip": "198.51.100.42"
            }
        });
        let mut fp = service.generate(&profile).unwrap();
        assert_eq!(string(&fp, "timezone"), "Europe/Paris");
        assert_eq!(string(&fp, "webrtc:ipv4"), "198.51.100.42");
        assert!(fp.get("webrtc:ipv6").is_none());
        assert_eq!(fp["geolocation:latitude"], json!(48.8566));
        assert_eq!(fp["geolocation:longitude"], json!(2.3522));

        // 1. IPv4 -> IPv6 transition removes IPv4; omitted fields retain values
        service
            .apply_location(
                &mut fp,
                &json!({
                    "ip": "2001:db8::1"
                }),
            )
            .unwrap();
        assert_eq!(string(&fp, "webrtc:ipv6"), "2001:db8::1");
        assert!(fp.get("webrtc:ipv4").is_none());
        assert_eq!(string(&fp, "timezone"), "Europe/Paris");
        assert_eq!(fp["geolocation:latitude"], json!(48.8566));
        assert_eq!(fp["geolocation:longitude"], json!(2.3522));

        // 2. IPv6 -> IPv4 transition removes IPv6
        service
            .apply_location(
                &mut fp,
                &json!({
                    "ip": "203.0.113.19"
                }),
            )
            .unwrap();
        assert_eq!(string(&fp, "webrtc:ipv4"), "203.0.113.19");
        assert!(fp.get("webrtc:ipv6").is_none());

        // 3. Partial update preserves existing coordinates and IP
        service
            .apply_location(
                &mut fp,
                &json!({
                    "locale": "de-DE",
                    "timezone": "Europe/Berlin",
                    "country": "DE"
                }),
            )
            .unwrap();
        assert_eq!(string(&fp, "timezone"), "Europe/Berlin");
        assert_eq!(string(&fp, "webrtc:ipv4"), "203.0.113.19");
        assert_eq!(fp["geolocation:latitude"], json!(48.8566));
        assert_eq!(fp["geolocation:longitude"], json!(2.3522));

        // 4. Explicit clears (ProfileEditor format) remove all corresponding overrides
        service
            .apply_location(
                &mut fp,
                &json!({
                    "timezone": "",
                    "ip": "",
                    "latitude": null,
                    "longitude": null
                }),
            )
            .unwrap();
        assert!(fp.get("timezone").is_none());
        assert!(fp.get("webrtc:ipv4").is_none());
        assert!(fp.get("webrtc:ipv6").is_none());
        assert!(fp.get("geolocation:latitude").is_none());
        assert!(fp.get("geolocation:longitude").is_none());

        // 5. Explicit clear with null timezone/ip and empty coordinate strings
        service
            .apply_location(
                &mut fp,
                &json!({
                    "timezone": "Asia/Tokyo",
                    "ip": "198.51.100.99",
                    "latitude": 35.6762,
                    "longitude": 139.6503
                }),
            )
            .unwrap();
        assert_eq!(string(&fp, "timezone"), "Asia/Tokyo");
        assert_eq!(string(&fp, "webrtc:ipv4"), "198.51.100.99");
        service
            .apply_location(
                &mut fp,
                &json!({
                    "timezone": null,
                    "ip": null,
                    "latitude": "",
                    "longitude": ""
                }),
            )
            .unwrap();
        assert!(fp.get("timezone").is_none());
        assert!(fp.get("webrtc:ipv4").is_none());
        assert!(fp.get("geolocation:latitude").is_none());
        assert!(fp.get("geolocation:longitude").is_none());

        // 6. One coordinate missing or cleared cannot leave stale mismatched pair
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": 40.7128,
                    "longitude": -74.006
                }),
            )
            .unwrap();
        assert_eq!(fp["geolocation:latitude"], json!(40.7128));
        assert_eq!(fp["geolocation:longitude"], json!(-74.006));

        // 6a: latitude updated while longitude omitted -> clears pair to prevent mismatch
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": 48.8566
                }),
            )
            .unwrap();
        assert!(fp.get("geolocation:latitude").is_none());
        assert!(fp.get("geolocation:longitude").is_none());

        // 6b: reset, then latitude updated while longitude is null -> clears pair
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": 40.7128,
                    "longitude": -74.006
                }),
            )
            .unwrap();
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": 48.8566,
                    "longitude": null
                }),
            )
            .unwrap();
        assert!(fp.get("geolocation:latitude").is_none());
        assert!(fp.get("geolocation:longitude").is_none());

        // 6c: reset, then latitude null while longitude provided -> clears pair
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": 40.7128,
                    "longitude": -74.006
                }),
            )
            .unwrap();
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": null,
                    "longitude": -74.006
                }),
            )
            .unwrap();
        assert!(fp.get("geolocation:latitude").is_none());
        assert!(fp.get("geolocation:longitude").is_none());

        // 6d: reset, then latitude omitted while longitude null -> clears pair
        service
            .apply_location(
                &mut fp,
                &json!({
                    "latitude": 40.7128,
                    "longitude": -74.006
                }),
            )
            .unwrap();
        service
            .apply_location(
                &mut fp,
                &json!({
                    "longitude": null
                }),
            )
            .unwrap();
        assert!(fp.get("geolocation:latitude").is_none());
        assert!(fp.get("geolocation:longitude").is_none());

        // 7. Invalid values rejection
        assert!(service
            .apply_location(&mut fp, &json!({ "latitude": 91.0, "longitude": 0.0 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "latitude": -91.0, "longitude": 0.0 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "latitude": 0.0, "longitude": 181.0 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "latitude": 0.0, "longitude": -181.0 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "latitude": "invalid", "longitude": 0.0 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "latitude": "NaN", "longitude": 0.0 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "ip": "not-an-ip" }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "ip": 12345 }))
            .is_err());
        assert!(service
            .apply_location(&mut fp, &json!({ "timezone": 123 }))
            .is_err());
    }

    #[test]
    fn from_preset_preserves_device_pixel_ratio_and_identity() {
        let preset_dpr2 = json!({
            "navigator": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
                "platform": "Win32"
            },
            "screen": {
                "width": 1920,
                "height": 1080,
                "availWidth": 1920,
                "availHeight": 1040,
                "devicePixelRatio": 2
            }
        });
        let mut cfg2 = from_preset(&preset_dpr2, 150);
        assert_eq!(cfg2.get("window.devicePixelRatio"), Some(&json!(2.0)));
        apply_coherence(&mut cfg2, "win");
        assert_eq!(cfg2["window.devicePixelRatio"], json!(2.0));

        let preset_dpr_frac = json!({
            "navigator": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
                "platform": "Win32"
            },
            "screen": {
                "width": 1920,
                "height": 1080,
                "availWidth": 1920,
                "availHeight": 1040,
                "devicePixelRatio": 1.25
            }
        });
        let mut cfg_frac = from_preset(&preset_dpr_frac, 150);
        assert_eq!(cfg_frac.get("window.devicePixelRatio"), Some(&json!(1.25)));
        apply_coherence(&mut cfg_frac, "win");
        assert_eq!(cfg_frac["window.devicePixelRatio"], json!(1.25));

        // Persistent identity is unaffected by devicePixelRatio presence
        let mut cfg_no_dpr = cfg2.clone();
        cfg_no_dpr.remove("window.devicePixelRatio");
        assert_eq!(
            identity_seed_from_config(&cfg2),
            identity_seed_from_config(&cfg_no_dpr)
        );

        // Preset without DPR does not invent a default DPR
        let preset_bare = json!({
            "navigator": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
                "platform": "Win32"
            },
            "screen": {
                "width": 1920,
                "height": 1080
            }
        });
        let cfg_bare = from_preset(&preset_bare, 150);
        assert!(cfg_bare.get("window.devicePixelRatio").is_none());

        // Non-positive or non-finite DPR values are ignored
        for bad_val in [json!(0), json!(-2.0), json!("invalid")] {
            let p = json!({
                "navigator": {
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
                    "platform": "Win32"
                },
                "screen": {
                    "width": 1920,
                    "height": 1080,
                    "devicePixelRatio": bad_val
                }
            });
            let c = from_preset(&p, 150);
            assert!(c.get("window.devicePixelRatio").is_none());
        }
    }
}
