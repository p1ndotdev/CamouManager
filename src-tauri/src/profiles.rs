use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path, sync::Arc};
use crate::{files::{copy_tree, extract_zip, reject_link}, fingerprints::FingerprintService, network::Network, runtime::Runtime, store::{new_id, require_str, safe_component, string, utcnow, Store}};

pub struct Profiles {
    store: Arc<Store>,
    runtime: Arc<Runtime>,
    network: Arc<Network>,
    fingerprints: Arc<FingerprintService>,
}

pub fn validate_url(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() { bail!("URL không được trống"); }
    let value = if !raw.contains("://") && !["about:", "data:", "blob:", "file:"].iter().any(|p| raw.starts_with(p)) { format!("https://{raw}") } else { raw.to_owned() };
    let parsed = url::Url::parse(&value).context("URL không hợp lệ")?;
    if !["http", "https", "about", "file", "ws", "wss", "data", "blob"].contains(&parsed.scheme()) { bail!("Giao thức URL không được hỗ trợ"); }
    Ok(value)
}

pub fn validate_location(value: &Value) -> Result<Value> {
    if !value.is_null() && !value.is_object() { bail!("Vị trí phải là object"); }
    let mut out = json!({"ip":"", "country":"", "timezone":"", "locale":"", "latitude":null, "longitude":null, "locked":false});
    for key in ["ip", "country", "timezone", "locale"] {
        if let Some(v) = value.get(key) { if !v.is_null() { out[key] = json!(v.as_str().ok_or_else(|| anyhow!("'{key}' phải là chuỗi"))?.trim()); } }
    }
    for (key, bound) in [("latitude", 90.0), ("longitude", 180.0)] {
        if let Some(v) = value.get(key).filter(|v| !v.is_null() && v.as_str() != Some("")) {
            let number = v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).ok_or_else(|| anyhow!("'{key}' phải là số"))?;
            if !number.is_finite() || number.abs() > bound { bail!("'{key}' ngoài phạm vi ±{bound}"); }
            out[key] = json!(number);
        }
    }
    if let Some(v) = value.get("locked") { out["locked"] = json!(v.as_bool().ok_or_else(|| anyhow!("locked phải là boolean"))?); }
    Ok(out)
}

fn strings(value: &Value, key: &str) -> Result<Vec<String>> {
    value.get(key).unwrap_or(&Value::Null).as_array().ok_or_else(|| anyhow!("'{key}' phải là danh sách"))?.iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| anyhow!("'{key}' phải chứa chuỗi"))).collect()
}
fn extension_path(value: &str) -> Result<&str> {
    let folder = value.strip_prefix("addons/").ok_or_else(|| anyhow!("Đường dẫn extension không hợp lệ"))?;
    safe_component(folder)?;
    Ok(folder)
}

fn extension_identity(manifest: &Value) -> Result<&str> {
    manifest.pointer("/browser_specific_settings/gecko/id").and_then(Value::as_str)
        .or_else(|| manifest.get("name").and_then(Value::as_str))
        .ok_or_else(|| anyhow!("Extension thiếu tên/ID"))
}

fn validate_profile_schema(data: &Value, current: Option<&Value>) -> Result<Value> {
    let obj = data.as_object().ok_or_else(|| anyhow!("Dữ liệu hồ sơ phải là object"))?;
    let mut record = current.cloned().unwrap_or_else(|| json!({"name":"", "group":"", "tags":[], "note":"", "browser_version":"", "os":"windows", "search_engine":"", "location":{}, "startup_urls":[], "bookmarks":[], "extensions":[], "fingerprint_meta":{}}));
    for key in ["name", "group", "note", "browser_version", "os", "proxy_id", "search_engine"] {
        if let Some(v) = obj.get(key) { record[key] = json!(v.as_str().ok_or_else(|| anyhow!("'{key}' phải là chuỗi"))?.trim()); }
    }
    let name = require_str(&record, "name")?;
    if name.chars().count() > 256 { bail!("Tên hồ sơ tối đa 256 ký tự"); }
    if !["windows", "macos", "linux"].contains(&string(&record, "os")) { bail!("Hệ điều hành không hợp lệ"); }
    if let Some(v) = obj.get("tags") {
        let tags = strings(&json!({"tags":v}), "tags")?.into_iter().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect::<BTreeSet<_>>();
        record["tags"] = json!(tags);
    }
    if obj.contains_key("location") || current.is_none() { record["location"] = validate_location(data.get("location").unwrap_or(&Value::Null))?; }
    if obj.contains_key("startup_urls") { record["startup_urls"] = json!(strings(data, "startup_urls")?.iter().map(|s| validate_url(s)).collect::<Result<Vec<_>>>()?); }
    if let Some(value) = obj.get("bookmarks") {
        let bookmarks = value.as_array().ok_or_else(|| anyhow!("bookmarks phải là danh sách"))?.iter().map(|b| {
            let url = validate_url(require_str(b, "url")?)?;
            let title = b.get("title").and_then(Value::as_str).unwrap_or("").trim();
            Ok(json!({"title":if title.is_empty() { &url } else { title }, "url":url}))
        }).collect::<Result<Vec<_>>>()?;
        record["bookmarks"] = json!(bookmarks);
    }
    if obj.contains_key("extensions") {
        let extensions = strings(data, "extensions")?;
        for path in &extensions { extension_path(path)?; }
        record["extensions"] = json!(extensions);
    }
    if let Some(v) = obj.get("fingerprint") {
        if !v.is_object() {
            bail!("'fingerprint' phải là object");
        }
        record["fingerprint"] = v.clone();
    }
    if let Some(v) = obj.get("fingerprint_meta") {
        let meta_obj = v
            .as_object()
            .ok_or_else(|| anyhow!("'fingerprint_meta' phải là object"))?;
        if let Some(curr_meta) = record.get_mut("fingerprint_meta").and_then(Value::as_object_mut) {
            for (k, val) in meta_obj {
                curr_meta.insert(k.clone(), val.clone());
            }
        } else {
            record["fingerprint_meta"] = v.clone();
        }
    }
    Ok(record)
}

pub(crate) fn validate_backup_profile_record(data: &Value) -> Result<Value> {
    let obj = data.as_object().ok_or_else(|| anyhow!("Dữ liệu hồ sơ phải là object"))?;
    let id = string(data, "id");
    safe_component(id)?;
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("ID hồ sơ trong backup không hợp lệ");
    }
    for key in ["name", "os", "proxy_id"] {
        if !obj.get(key).is_some_and(Value::is_string) { bail!("Thiếu trường '{key}' hoặc không phải chuỗi"); }
    }
    let loc = obj.get("location").ok_or_else(|| anyhow!("Thiếu trường 'location'"))?;
    if !loc.is_object() {
        bail!("'location' phải là object");
    }
    if obj.get("fingerprint").and_then(Value::as_object).is_none_or(|fp| fp.is_empty()) {
        bail!("Backup thiếu fingerprint hợp lệ");
    }

    let mut record = validate_profile_schema(data, None)?;
    record["id"] = json!(id);
    if let Some(created_at) = obj.get("created_at").and_then(Value::as_str) {
        record["created_at"] = json!(created_at);
    }
    if let Some(updated_at) = obj.get("updated_at").and_then(Value::as_str) {
        record["updated_at"] = json!(updated_at);
    }
    Ok(record)
}

impl Profiles {
    pub fn new(store: Arc<Store>, runtime: Arc<Runtime>, network: Arc<Network>, fingerprints: Arc<FingerprintService>) -> Self { Self { store, runtime, network, fingerprints } }
    pub fn get(&self, id: &str) -> Result<Value> { self.store.get("profiles", id)?.ok_or_else(|| anyhow!("Không tìm thấy hồ sơ '{id}'")) }
    pub fn closed(&self, id: &str) -> Result<Value> {
        let record = self.get(id)?;
        if self.runtime.is_running(id) { bail!("Hồ sơ '{id}' đang chạy, không thể thay đổi"); }
        Ok(record)
    }
    fn validate(&self, data: &Value, current: Option<&Value>) -> Result<Value> {
        let mut record = validate_profile_schema(data, current)?;
        let proxy_id = string(&record, "proxy_id");
        if !proxy_id.is_empty() && self.store.get("proxies", proxy_id)?.is_none() { bail!("Proxy không tồn tại"); }
        if current.is_some_and(|old| string(old, "proxy_id") != proxy_id) {
            if record["location"]["locked"].as_bool().unwrap_or(false) {
                record["location"]["ip"] = json!("");
            } else {
                record["location"] = validate_location(&Value::Null)?;
            }
            if record.get("fingerprint").and_then(Value::as_object).is_some_and(|fp| !fp.is_empty()) {
                let location = record["location"].clone();
                self.fingerprints.apply_location(&mut record["fingerprint"], &location)?;
            }
        }
        Ok(record)
    }
    fn auto_proxy(&self) -> Result<String> {
        let proxies = self.store.list("proxies")?;
        let profiles = self.store.list("profiles")?;
        proxies.iter().filter(|p| p.get("enabled").and_then(Value::as_bool).unwrap_or(true))
            .min_by_key(|p| profiles.iter().filter(|row| string(row,"proxy_id") == string(p,"id")).count())
            .map(|p| string(p,"id").to_owned()).ok_or_else(|| anyhow!("Không có proxy được kích hoạt để tự động gán"))
    }
    fn directories(&self, id: &str) -> Result<()> {
        let dir = self.store.profile_dir(id)?;
        for name in ["browser", "addons"] { reject_link(&dir.join(name))?; fs::create_dir_all(dir.join(name))?; }
        Ok(())
    }
    pub fn create(&self, data: Value) -> Result<Value> {
        let _guard = self.store.operation.lock();
        let mut record = self.validate(&data, None)?;
        if record.get("proxy_id").is_none() {
            let settings = self.store.settings()?;
            record["proxy_id"] = if settings["auto_assign_proxy"].as_bool().unwrap_or(false) { json!(self.auto_proxy()?) } else {
                let default = string(&settings,"default_proxy_id");
                json!(if !default.is_empty() && self.store.get("proxies", default)?.is_some() { default } else { "" })
            };
        }
        let loc = &record["location"];
        if !loc["locked"].as_bool().unwrap_or(false) && ["ip","country","timezone","locale"].iter().all(|k| string(loc,k).is_empty()) {
            let proxy = self.store.get("proxies", string(&record,"proxy_id"))?;
            record["location"] = self.network.detect(proxy.as_ref())?;
        }
        if record.get("fingerprint").and_then(Value::as_object).is_none_or(|v| v.is_empty()) { record["fingerprint"] = self.fingerprints.generate(&record)?; }
        record["fingerprint_meta"]["generated_at"] = json!(utcnow());
        let id = new_id(); record["id"] = json!(id);
        let path = self.store.profile_dir(&id)?;
        let result = (|| { self.directories(&id)?; self.store.put("profiles", record) })();
        if result.is_err() && path.exists() { fs::remove_dir_all(&path).context("Dọn hồ sơ tạo thất bại")?; }
        let saved = result?;
        self.store.log("INFO", &format!("Đã tạo hồ sơ '{}'",string(&saved,"name")), &id)?;
        Ok(saved)
    }
    pub fn update(&self, id: &str, data: Value) -> Result<Value> {
        let _guard = self.store.operation.lock();
        let old = self.closed(id)?;
        let mut record = self.validate(&data, Some(&old))?;
        if data.get("location").is_some() && string(&old,"proxy_id") == string(&record,"proxy_id") {
            let location = record["location"].clone();
            self.fingerprints.apply_location(&mut record["fingerprint"], &location)?;
        }
        if string(&old,"os") != string(&record,"os")
            || old["fingerprint_meta"]["use_preset"].as_bool().unwrap_or(false) != record["fingerprint_meta"]["use_preset"].as_bool().unwrap_or(false)
            || string(&old["fingerprint_meta"], "screen") != string(&record["fingerprint_meta"], "screen") {
            record["fingerprint"] = self.fingerprints.generate(&record)?;
            record["fingerprint_meta"]["regenerated_at"] = json!(utcnow());
        } else if old["browser_version"] != record["browser_version"] && !string(&record,"browser_version").is_empty() {
            let major = browser_major(string(&record,"browser_version"))?;
            self.fingerprints.retarget_version(&mut record["fingerprint"], major)?;
        }
        self.directories(id)?;
        self.store.put("profiles", record)
    }
    pub fn duplicate(&self, id: &str, full: bool, name: &str) -> Result<Value> {
        let _guard = self.store.operation.lock();
        let mut record = if full { self.closed(id)? } else { self.get(id)? };
        let new = new_id();
        let source = self.store.profile_dir(id)?;
        let target = self.store.profile_dir(&new)?;
        record["id"] = json!(new);
        record["name"] = json!(if name.trim().is_empty() { format!("{} (Copy)",string(&record,"name")) } else { name.trim().to_owned() });
        record.as_object_mut().unwrap().remove("created_at");
        record.as_object_mut().unwrap().remove("updated_at");
        let result = (|| {
            self.directories(&new)?;
            for folder in if full { &["browser","addons"][..] } else { &["addons"][..] } {
                if source.join(folder).exists() { copy_tree(&source.join(folder), &target.join(folder))?; }
            }
            if full {
                for lock in ["parent.lock","lock",".parentlock",".startup-incomplete"] {
                    let path = target.join("browser").join(lock);
                    if path.exists() { fs::remove_file(path)?; }
                }
            } else {
                record["fingerprint"] = self.fingerprints.generate(&record)?;
                record["fingerprint_meta"]["generated_at"] = json!(utcnow());
                record["fingerprint_meta"]["duplicated_from"] = json!(id);
            }
            self.store.put("profiles", record)
        })();
        if result.is_err() && target.exists() { fs::remove_dir_all(target)?; }
        result
    }
    pub fn delete_many(&self, ids: &[String]) -> Result<()> {
        let _guard = self.store.operation.lock();
        let targets = ids.iter().collect::<BTreeSet<_>>();
        for id in &targets { self.closed(id)?; reject_link(&self.store.profile_dir(id)?)?; }
        for id in targets {
            let path = self.store.profile_dir(id)?;
            if path.exists() { fs::remove_dir_all(&path).context("Không thể xóa dữ liệu hồ sơ")?; }
            self.store.delete("profiles", id)?;
        }
        Ok(())
    }
    pub fn set_many(&self, ids: &[String], key: &str, value: Value) -> Result<()> {
        let _guard = self.store.operation.lock();
        if !["proxy_id","tags","group"].contains(&key) { bail!("Trường thay đổi hàng loạt không hợp lệ"); }
        let data = json!({key:value});
        let records = ids.iter().map(|id| self.validate(&data, Some(&self.closed(id)?))).collect::<Result<Vec<_>>>()?;
        self.store.put_many("profiles", records)?;
        Ok(())
    }
    pub fn regenerate(&self, id: &str) -> Result<Value> {
        let _guard = self.store.operation.lock();
        let mut record = self.closed(id)?;
        record["fingerprint"] = self.fingerprints.generate(&record)?;
        record["fingerprint_meta"]["regenerated_at"] = json!(utcnow());
        self.store.put("profiles", record)
    }
    pub fn import_extension(&self, id: &str, source: &Path) -> Result<String> {
        let _guard = self.store.operation.lock();
        let mut record = self.closed(id)?;
        reject_link(source)?;
        let profile = self.store.profile_dir(id)?;
        self.directories(id)?;
        let stage = tempfile::Builder::new().prefix(".addon-stage-").tempdir_in(&profile)?;
        let unpacked = stage.path().join("unpacked");
        if source.is_file() {
            extract_zip(fs::File::open(source)?, &unpacked, 100 * 1024 * 1024, None)?;
        } else if source.is_dir() { copy_tree(source, &unpacked)?; }
        else { bail!("Nguồn extension không tồn tại"); }
        let root = if unpacked.join("manifest.json").is_file() { unpacked.clone() } else {
            let candidates = fs::read_dir(&unpacked)?.map(|entry| entry.map(|e| e.path())).collect::<std::io::Result<Vec<_>>>()?;
            candidates.into_iter().find(|p| p.is_dir() && p.join("manifest.json").is_file()).ok_or_else(|| anyhow!("Không tìm thấy manifest.json của extension"))?
        };
        reject_link(&root)?;
        let manifest_path = root.join("manifest.json");
        reject_link(&manifest_path)?;
        if fs::metadata(&manifest_path)?.len() > 1024 * 1024 { bail!("Manifest extension quá lớn"); }
        let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        if !manifest.is_object() || manifest.get("manifest_version").and_then(Value::as_u64).is_none() { bail!("Manifest extension không hợp lệ"); }
        use sha2::{Digest, Sha256};
        let identity = extension_identity(&manifest)?;
        let mut folder = format!("addon_{}", hex::encode(Sha256::digest(identity.as_bytes())));
        for managed in strings(&record, "extensions")? {
            let existing_folder = extension_path(&managed)?;
            let existing_dir = profile.join(&managed);
            reject_link(&existing_dir)?;
            let existing_manifest = existing_dir.join("manifest.json");
            reject_link(&existing_manifest)?;
            if !existing_manifest.exists() { continue; }
            if fs::metadata(&existing_manifest)?.len() > 1024 * 1024 { bail!("Manifest extension quá lớn"); }
            let existing: Value = serde_json::from_slice(&fs::read(&existing_manifest)?)?;
            if extension_identity(&existing)? == identity {
                folder = existing_folder.to_owned();
                break;
            }
        }
        fn size(path: &Path, total: &mut u64) -> Result<()> {
            reject_link(path)?;
            if path.is_dir() { for entry in fs::read_dir(path)? { size(&entry?.path(), total)?; } }
            else {
                let bytes = fs::metadata(path)?.len();
                *total = total.checked_add(bytes).ok_or_else(|| anyhow!("Extension quá lớn"))?;
                if bytes > 50 * 1024 * 1024 || *total > 100 * 1024 * 1024 { bail!("Extension vượt giới hạn kích thước"); }
            }
            Ok(())
        }
        size(&root, &mut 0)?;
        let target = profile.join("addons").join(&folder);
        reject_link(&target)?;
        let previous = stage.path().join("previous");
        let had_previous = target.exists();
        if had_previous { fs::rename(&target, &previous)?; }
        let managed = format!("addons/{folder}");
        let result = (|| {
            fs::rename(&root, &target)?;
            let extensions = record["extensions"].as_array_mut().ok_or_else(|| anyhow!("Danh sách extension không hợp lệ"))?;
            if !extensions.iter().any(|v| v.as_str() == Some(&managed)) { extensions.push(json!(managed)); }
            self.store.put("profiles", record)?;
            Ok(())
        })();
        if let Err(error) = result {
            if target.exists() { fs::remove_dir_all(&target)?; }
            if had_previous { fs::rename(&previous, &target).context("Khôi phục extension cũ thất bại")?; }
            return Err(error);
        }
        Ok(managed)
    }
    pub fn remove_extension(&self, id: &str, managed: &str) -> Result<()> {
        let _guard = self.store.operation.lock();
        let mut record = self.closed(id)?;
        extension_path(managed)?;
        let profile = self.store.profile_dir(id)?;
        let target = profile.join(managed);
        reject_link(&target)?;
        let stage = tempfile::Builder::new().prefix(".addon-remove-").tempdir_in(&profile)?;
        let previous = stage.path().join("previous");
        let existed = target.exists();
        if existed { fs::rename(&target,&previous)?; }
        record["extensions"].as_array_mut().ok_or_else(|| anyhow!("Danh sách extension không hợp lệ"))?.retain(|v| v.as_str() != Some(managed));
        if let Err(error) = self.store.put("profiles",record) {
            if existed { fs::rename(&previous,&target).context("Khôi phục extension thất bại")?; }
            return Err(error);
        }
        Ok(())
    }
}

pub fn browser_major(version: &str) -> Result<u32> {
    version.trim_start_matches('v').split('.').next().unwrap_or("").parse().context("Phiên bản trình duyệt không hợp lệ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_input_rejects_escape_and_invalid_coordinates() {
        for path in ["addons/../outside", "addons/C:secret", "addons/CON", "addons/x\\y", "addons/.hidden"] { assert!(extension_path(path).is_err(),"{path}"); }
        assert!(validate_location(&json!({"latitude":91})).is_err());
        assert!(validate_location(&json!({"longitude":"NaN"})).is_err());
        assert!(validate_location(&json!({"locked":"false"})).is_err());
        let loc = validate_location(&json!({"latitude":"-90","longitude":180,"locked":true})).unwrap();
        assert_eq!(loc["latitude"],-90.0); assert_eq!(loc["longitude"],180.0);
        assert_eq!(validate_url("example.com/path").unwrap(),"https://example.com/path");
        assert!(validate_url("javascript://alert(1)").is_err());
        assert!(validate_url("").is_err());
        assert_eq!(browser_major("v156.0.1-beta.36").unwrap(),156);
    }

    #[test]
    fn update_regenerates_fingerprint_when_screen_resolution_changes() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let network = Arc::new(Network::new(store.clone()));
        let fingerprints = Arc::new(FingerprintService::new(store.clone()).unwrap());
        let runtime = Arc::new(Runtime::new(store.clone(), network.clone(), fingerprints.clone()));
        let profiles = Profiles::new(store.clone(), runtime.clone(), network.clone(), fingerprints.clone());

        let created = profiles.create(json!({
            "name": "Screen Test",
            "os": "windows",
            "fingerprint_meta": { "screen": "1920x1080" }
        })).unwrap();
        let id = created["id"].as_str().unwrap();
        assert_eq!(created["fingerprint"]["screen.width"], 1920);
        assert_eq!(created["fingerprint"]["screen.height"], 1080);

        let updated = profiles.update(id, json!({
            "fingerprint_meta": { "screen": "1366x768" }
        })).unwrap();
        assert_eq!(updated["fingerprint"]["screen.width"], 1366);
        assert_eq!(updated["fingerprint"]["screen.height"], 768);
        assert_eq!(updated["fingerprint_meta"]["screen"], "1366x768");
        assert!(updated["fingerprint_meta"]["regenerated_at"].is_string());
    }

    #[test]
    fn update_preserves_legacy_profile_fingerprint_without_screen() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let network = Arc::new(Network::new(store.clone()));
        let fingerprints = Arc::new(FingerprintService::new(store.clone()).unwrap());
        let runtime = Arc::new(Runtime::new(store.clone(), network.clone(), fingerprints.clone()));
        let profiles = Profiles::new(store, runtime, network, fingerprints);

        let created = profiles.create(json!({
            "name": "Legacy Profile",
            "os": "windows",
            "fingerprint_meta": { "use_preset": true }
        })).unwrap();
        let id = created["id"].as_str().unwrap();
        assert!(created["fingerprint_meta"].get("screen").is_none());
        let orig_fp = created["fingerprint"].clone();

        let updated = profiles.update(id, json!({
            "name": "Renamed Legacy Profile",
            "tags": ["work"],
            "fingerprint_meta": { "use_preset": true, "screen": "" }
        })).unwrap();

        assert_eq!(updated["name"], "Renamed Legacy Profile");
        assert_eq!(updated["fingerprint"], orig_fp);
        assert!(updated["fingerprint_meta"].get("regenerated_at").is_none());
    }

    #[test]
    fn profile_accepts_and_preserves_search_engine() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(temp.path()).unwrap());
        let network = Arc::new(Network::new(store.clone()));
        let fingerprints = Arc::new(FingerprintService::new(store.clone()).unwrap());
        let runtime = Arc::new(Runtime::new(store.clone(), network.clone(), fingerprints.clone()));
        let profiles = Profiles::new(store, runtime, network, fingerprints);

        let created = profiles.create(json!({
            "name": "DuckDuckGo Profile",
            "os": "windows",
            "search_engine": "DuckDuckGo"
        })).unwrap();
        assert_eq!(created["search_engine"], "DuckDuckGo");

        let id = created["id"].as_str().unwrap();
        let updated = profiles.update(id, json!({
            "search_engine": "Google"
        })).unwrap();
        assert_eq!(updated["search_engine"], "Google");
    }
}
