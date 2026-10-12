use anyhow::{anyhow, bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use parking_lot::{Mutex, ReentrantMutex};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use std::{fs, path::{Path, PathBuf}, sync::LazyLock};

pub fn utcnow() -> String { Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true) }
pub fn new_id() -> String { uuid::Uuid::new_v4().simple().to_string() }
pub fn string<'a>(value: &'a Value, key: &str) -> &'a str { value.get(key).and_then(Value::as_str).unwrap_or("") }
pub fn require_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let result = value.get(key).and_then(Value::as_str).ok_or_else(|| anyhow!("'{key}' phải là chuỗi"))?.trim();
    if result.is_empty() { bail!("Thiếu '{key}'"); }
    Ok(result)
}
pub fn safe_component(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 || id.starts_with('.') || id.contains("..")
        || !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) || id.ends_with('.') {
        bail!("ID hoặc tên thư mục không hợp lệ");
    }
    let base = id.split('.').next().unwrap_or("").to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"].contains(&base.as_str()) {
        bail!("Tên thư mục được Windows dành riêng");
    }
    Ok(())
}
pub fn redact(text: &str) -> String {
    static URL_AUTH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(https?|socks5h?)://[^\s/@]+(?::[^\s/@]*)?@").expect("static regex"));
    static SECRET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(password|passwd|authorization|proxy-authorization|cookie|token)([\s\"':=]+)([^\s,;}]+)"#).expect("static regex"));
    let clean = URL_AUTH.replace_all(text, "$1://***@");
    SECRET.replace_all(&clean, "$1$2***").into_owned()
}

pub struct Store {
    pub root: PathBuf,
    pub profiles_dir: PathBuf,
    pub versions_dir: PathBuf,
    pub backups_dir: PathBuf,
    pub operation: ReentrantMutex<()>,
    db: Mutex<Connection>,
}

impl Store {
    pub fn default_root() -> Result<PathBuf> {
        if let Some(root) = std::env::var_os("CAMOUMANAGER_HOME") { return Ok(PathBuf::from(root)); }
        if let Some(local) = std::env::var_os("LOCALAPPDATA") { return Ok(PathBuf::from(local).join("CamouManagerRust")); }
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("Không xác định được thư mục dữ liệu"))?;
        Ok(PathBuf::from(home).join(".local/share/CamouManagerRust"))
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        let root = root.as_ref().canonicalize()?;
        let profiles_dir = root.join("profiles");
        let versions_dir = root.join("versions");
        let backups_dir = root.join("backups");
        for directory in [&profiles_dir, &versions_dir, &backups_dir] { crate::files::reject_link(directory)?; fs::create_dir_all(directory)?; }
        crate::files::reject_link(&root.join("state.sqlite3"))?;
        let db = Connection::open(root.join("state.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_secs(30))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL,profile_id TEXT NOT NULL);
            PRAGMA user_version=3;")?;
        Ok(Self { root, profiles_dir, versions_dir, backups_dir, operation: ReentrantMutex::new(()), db: Mutex::new(db) })
    }
    fn kind(kind: &str) -> Result<()> {
        if !["profiles", "proxies", "versions"].contains(&kind) { bail!("Loại dữ liệu không hợp lệ"); }
        Ok(())
    }
    pub fn list(&self, kind: &str) -> Result<Vec<Value>> {
        Self::kind(kind)?;
        let db = self.db.lock();
        let mut statement = db.prepare_cached("SELECT payload FROM records WHERE kind=? ORDER BY rowid")?;
        let rows = statement.query_map([kind], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }
    pub fn get(&self, kind: &str, id: &str) -> Result<Option<Value>> {
        Self::kind(kind)?;
        let raw: Option<String> = self.db.lock().query_row("SELECT payload FROM records WHERE kind=? AND id=?", params![kind, id], |row| row.get(0)).optional()?;
        raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into)).transpose()
    }
    pub fn put(&self, kind: &str, data: Value) -> Result<Value> {
        self.put_batch(vec![(kind, data)])?.into_iter().next().ok_or_else(|| anyhow!("Không lưu được dữ liệu"))
    }
    pub fn put_many(&self, kind: &str, data: Vec<Value>) -> Result<Vec<Value>> {
        self.put_batch(data.into_iter().map(|data| (kind, data)).collect())
    }
    pub fn put_batch(&self, records: Vec<(&str, Value)>) -> Result<Vec<Value>> {
        let mut db = self.db.lock();
        let transaction = db.transaction()?;
        let now = utcnow();
        let mut saved = Vec::with_capacity(records.len());
        for (kind, mut data) in records {
            Self::kind(kind)?;
            let map = data.as_object_mut().ok_or_else(|| anyhow!("Bản ghi phải là đối tượng JSON"))?;
            let id = match map.get("id") {
                Some(Value::String(id)) if !id.is_empty() => id.clone(),
                Some(Value::Null) | None => new_id(),
                _ => bail!("ID bản ghi không hợp lệ"),
            };
            safe_component(&id)?;
            let old: Option<String> = transaction.query_row("SELECT payload FROM records WHERE kind=? AND id=?", params![kind, id], |row| row.get(0)).optional()?;
            let previous = old.map(|s| serde_json::from_str::<Value>(&s)).transpose()?;
            let created = previous.as_ref().and_then(|v| v.get("created_at")).and_then(Value::as_str).unwrap_or(&now).to_owned();
            map.insert("id".into(), Value::String(id.clone()));
            map.insert("created_at".into(), Value::String(created));
            map.insert("updated_at".into(), Value::String(now.clone()));
            transaction.execute("INSERT INTO records(kind,id,payload) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload", params![kind, id, serde_json::to_string(&data)?])?;
            saved.push(data);
        }
        transaction.commit()?;
        Ok(saved)
    }
    pub fn delete(&self, kind: &str, id: &str) -> Result<()> {
        Self::kind(kind)?;
        self.db.lock().execute("DELETE FROM records WHERE kind=? AND id=?", params![kind, id])?;
        Ok(())
    }
    pub fn settings(&self) -> Result<Value> {
        let raw: Option<String> = self.db.lock().query_row("SELECT payload FROM settings WHERE id=1", [], |row| row.get(0)).optional()?;
        let mut defaults = json!({"max_running":4,"default_proxy_id":"","auto_assign_proxy":false,"backup_interval_hours":0,"backup_retention":10,"auto_check_updates":true,"update_check_hours":24,"auto_download_updates":false,"last_scheduled_backup_at":"","last_update_check_at":""});
        if let Some(raw) = raw {
            let saved: Map<String, Value> = serde_json::from_str(&raw)?;
            defaults.as_object_mut().expect("object defaults").extend(saved);
        }
        Ok(defaults)
    }
    pub fn save_settings(&self, data: Value) -> Result<Value> {
        let _operation = self.operation.lock();
        let data = data.as_object().ok_or_else(|| anyhow!("Cài đặt phải là đối tượng JSON"))?;
        let mut settings = self.settings()?;
        let target = settings.as_object_mut().expect("object settings");
        for (key, value) in data {
            if key == "backup_password" { bail!("Mật khẩu sao lưu chỉ giữ trong RAM"); }
            if !target.contains_key(key) { bail!("Cài đặt không được hỗ trợ: {key}"); }
            target.insert(key.clone(), value.clone());
        }
        for (key, low, high) in [("max_running",1,64),("backup_retention",1,1000),("backup_interval_hours",0,8760),("update_check_hours",0,8760)] {
            let value = target[key].as_i64().ok_or_else(|| anyhow!("{key} phải là số nguyên"))?;
            if !(low..=high).contains(&value) { bail!("{key} phải trong khoảng {low}–{high}"); }
        }
        for key in ["auto_assign_proxy", "auto_check_updates", "auto_download_updates"] {
            if !target[key].is_boolean() { bail!("{key} phải là boolean"); }
        }
        for key in ["default_proxy_id", "last_scheduled_backup_at", "last_update_check_at"] {
            if !target[key].is_string() { bail!("{key} phải là chuỗi"); }
        }
        let proxy_id = string(&settings, "default_proxy_id");
        if !proxy_id.is_empty() && self.get("proxies", proxy_id)?.is_none() { bail!("Proxy mặc định không tồn tại"); }
        self.db.lock().execute("INSERT INTO settings(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", [serde_json::to_string(&settings)?])?;
        Ok(settings)
    }
    pub fn profile_dir(&self, id: &str) -> Result<PathBuf> {
        if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) { bail!("ID hồ sơ không hợp lệ"); }
        crate::files::reject_link(&self.profiles_dir)?;
        let path = self.profiles_dir.join(id);
        crate::files::reject_link(&path)?;
        Ok(path)
    }
    pub fn redact_text(&self, text: &str) -> String {
        let mut clean = redact(text);
        if let Ok(proxies) = self.list("proxies") {
            for proxy in proxies {
                for key in ["password", "username"] {
                    let secret = string(&proxy, key);
                    if !secret.is_empty() { clean = clean.replace(secret, "***"); }
                }
            }
        }
        clean
    }
    pub fn log(&self, level: &str, message: &str, profile_id: &str) -> Result<()> {
        let clean = self.redact_text(message);
        let db = self.db.lock();
        db.execute("INSERT INTO logs(time,level,message,profile_id) VALUES(?,?,?,?)", params![utcnow(), level.to_ascii_uppercase(), clean, profile_id])?;
        db.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 5000)", [])?;
        Ok(())
    }
    pub fn logs(&self) -> Result<Vec<Value>> {
        let db = self.db.lock();
        let mut statement = db.prepare_cached("SELECT id,time,level,message,profile_id FROM logs ORDER BY id DESC LIMIT 1000")?;
        let rows = statement.query_map([], |row| Ok(json!({"id":row.get::<_,i64>(0)?,"time":row.get::<_,String>(1)?,"level":row.get::<_,String>(2)?,"message":row.get::<_,String>(3)?,"profile_id":row.get::<_,String>(4)?})))?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }
    pub fn export_logs(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let mut output = std::io::BufWriter::new(fs::File::create(path).context("Không mở được file xuất log")?);
        for row in self.logs()?.into_iter().rev() {
            writeln!(output, "{} [{}] {} {}", string(&row,"time"),string(&row,"level"),string(&row,"profile_id"),string(&row,"message"))?;
        }
        output.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_record_transaction_rolls_back_on_invalid_id() {
        let root = tempfile::tempdir().unwrap(); let store = Store::open(root.path()).unwrap();
        assert!(store.put_batch(vec![("profiles",json!({"name":"valid"})),("proxies",json!({"id":"../bad"}))]).is_err());
        assert!(store.list("profiles").unwrap().is_empty());
        assert!(store.list("proxies").unwrap().is_empty());
    }
    #[test]
    fn settings_validation_preserves_saved_values_and_never_saves_password() {
        let root = tempfile::tempdir().unwrap(); let store = Store::open(root.path()).unwrap();
        store.save_settings(json!({"max_running":7})).unwrap();
        assert!(store.save_settings(json!({"max_running":0})).is_err());
        assert!(store.save_settings(json!({"backup_password":"secret"})).is_err());
        assert_eq!(store.settings().unwrap()["max_running"],7);
        assert!(store.settings().unwrap().get("backup_password").is_none());
    }
    #[test]
    fn logs_redact_url_and_literal_credentials() {
        let root = tempfile::tempdir().unwrap(); let store = Store::open(root.path()).unwrap();
        store.put("proxies",json!({"username":"private-user","password":"private-pass"})).unwrap();
        store.log("ERROR","http://user:pass@localhost private-user private-pass password=another-secret", "").unwrap();
        let logs = store.logs().unwrap(); let message = string(&logs[0],"message");
        for secret in ["user:pass", "private-user", "private-pass", "another-secret"] { assert!(!message.contains(secret)); }
    }
}
