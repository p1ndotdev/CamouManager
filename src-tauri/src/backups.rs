use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    files::{extract_zip, reject_link},
    runtime::Runtime,
    store::{new_id, safe_component, string, utcnow, Store},
};

const MAGIC: &[u8; 8] = b"CMFRST01";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 7;
const HEADER_LEN: usize = 8 + 1 + SALT_LEN + NONCE_LEN; // 32 bytes

const SCRYPT_LOG_N: u8 = 14; // N = 16384
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_KEY_LEN: usize = 32;

const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB
const MAX_MANIFEST_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_SINGLE_FILE: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
const MAX_TOTAL_UNCOMPRESSED: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
const MAX_ENTRIES: usize = 100_000;
const MAX_METADATA_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB consistent IPC bound

#[derive(Clone, Copy, Debug)]
struct ArchiveLimits {
    max_single_file: u64,
    max_total_uncompressed: u64,
    max_entries: usize,
    max_manifest_size: u64,
    max_metadata_size: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_single_file: MAX_SINGLE_FILE,
            max_total_uncompressed: MAX_TOTAL_UNCOMPRESSED,
            max_entries: MAX_ENTRIES,
            max_manifest_size: MAX_MANIFEST_SIZE,
            max_metadata_size: MAX_METADATA_SIZE,
        }
    }
}


pub(crate) fn cleanup_legacy_residues(root: &Path) -> Result<()> {
    cleanup_legacy_residues_in_dir(root)?;
    let backups_dir = root.join("backups");
    if backups_dir.is_dir() {
        cleanup_legacy_residues_in_dir(&backups_dir)?;
    }
    Ok(())
}

fn is_legacy_residue_filename(name: &str) -> bool {
    let stripped = if let Some(s) = name.strip_prefix("._backup_zip_") {
        s
    } else if let Some(s) = name.strip_prefix("_backup_zip_") {
        s
    } else if let Some(s) = name.strip_prefix("_decrypted_zip_") {
        s
    } else {
        return false;
    };
    stripped.strip_suffix(".tmp").is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn cleanup_legacy_residues_in_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    reject_link(dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if is_legacy_residue_filename(name) {
                reject_link(&path)?;
                if path.is_file() {
                    fs::remove_file(&path).with_context(|| {
                        format!("Failed to remove legacy backup temporary file '{}'", path.display())
                    })?;
                }
            }
        }
    }
    Ok(())
}
const LOCK_FILES: &[&str] = &["parent.lock", "lock", ".parentlock"];

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_KEY_LEN)
        .map_err(|e| anyhow!("Scrypt param error: {e}"))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| anyhow!("Scrypt error: {e}"))?;
    Ok(key)
}

fn stream_encrypt<R: Read, W: Write>(reader: R, writer: W, password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("Password cannot be empty for encrypted backup");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut header = [0u8; HEADER_LEN];
    header[0..8].copy_from_slice(MAGIC);
    header[8] = FORMAT_VERSION;
    header[9..25].copy_from_slice(&salt);
    header[25..32].copy_from_slice(&nonce);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let nonce_ga = aead::generic_array::GenericArray::from_slice(&nonce);
    let mut encryptor = EncryptorBE32::from_aead(cipher, nonce_ga);

    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    writer.write_all(&header)?;

    let mut current_buf = vec![0u8; CHUNK_SIZE];
    let mut current_len = 0usize;
    while current_len < CHUNK_SIZE {
        let n = reader.read(&mut current_buf[current_len..])?;
        if n == 0 {
            break;
        }
        current_len += n;
    }

    let mut next_buf = vec![0u8; CHUNK_SIZE];
    loop {
        let mut next_len = 0usize;
        while next_len < CHUNK_SIZE {
            let n = reader.read(&mut next_buf[next_len..])?;
            if n == 0 {
                break;
            }
            next_len += n;
        }

        if next_len == 0 {
            let ct = encryptor
                .encrypt_last(Payload {
                    msg: &current_buf[..current_len],
                    aad: &header,
                })
                .map_err(|_| anyhow!("Encryption failure"))?;
            let len_bytes = (ct.len() as u32).to_be_bytes();
            writer.write_all(&len_bytes)?;
            writer.write_all(&ct)?;
            break;
        } else {
            let ct = encryptor
                .encrypt_next(Payload {
                    msg: &current_buf[..current_len],
                    aad: &header,
                })
                .map_err(|_| anyhow!("Encryption failure"))?;
            let len_bytes = (ct.len() as u32).to_be_bytes();
            writer.write_all(&len_bytes)?;
            writer.write_all(&ct)?;

            std::mem::swap(&mut current_buf, &mut next_buf);
            current_len = next_len;
        }
    }
    writer.flush()?;
    Ok(())
}

fn stream_decrypt<R: Read, W: Write>(
    reader: R,
    writer: W,
    password: &str,
    max_total: u64,
) -> Result<()> {
    if password.is_empty() {
        bail!("Password required for encrypted backup");
    }

    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    let mut header = [0u8; HEADER_LEN];
    if let Err(e) = reader.read_exact(&mut header) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            bail!("Corrupted backup archive: file truncated");
        }
        return Err(e.into());
    }

    if &header[0..8] != MAGIC {
        bail!("Invalid or unrecognized backup archive format");
    }
    if header[8] != FORMAT_VERSION {
        bail!("Unsupported backup encryption format version: {}", header[8]);
    }

    let salt = &header[9..25];
    let nonce = &header[25..32];

    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let nonce_ga = aead::generic_array::GenericArray::from_slice(nonce);
    let mut decryptor = DecryptorBE32::from_aead(cipher, nonce_ga);

    let mut chunk_len_buf = [0u8; 4];
    if let Err(e) = reader.read_exact(&mut chunk_len_buf) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            bail!("Corrupted backup archive: file truncated");
        }
        return Err(e.into());
    }
    let current_len = u32::from_be_bytes(chunk_len_buf) as usize;
    if current_len < 16 || current_len > CHUNK_SIZE + 16 {
        bail!("Corrupted backup archive: invalid chunk length");
    }
    let mut current_ct = vec![0u8; current_len];
    reader
        .read_exact(&mut current_ct)
        .context("Corrupted backup archive: file truncated")?;

    let mut total_decrypted: u64 = 0;
    loop {
        let mut next_len_buf = [0u8; 4];
        match reader.read_exact(&mut next_len_buf) {
            Ok(()) => {
                let pt = decryptor
                    .decrypt_next(Payload {
                        msg: &current_ct,
                        aad: &header,
                    })
                    .map_err(|_| anyhow!("Incorrect backup password or corrupted archive"))?;

                total_decrypted = total_decrypted
                    .checked_add(pt.len() as u64)
                    .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
                if total_decrypted > max_total {
                    bail!("Archive exceeds total maximum uncompressed size limit");
                }
                writer.write_all(&pt)?;

                let next_len = u32::from_be_bytes(next_len_buf) as usize;
                if next_len < 16 || next_len > CHUNK_SIZE + 16 {
                    bail!("Corrupted backup archive: invalid chunk length");
                }
                if current_ct.len() != next_len {
                    current_ct.resize(next_len, 0);
                }
                reader
                    .read_exact(&mut current_ct)
                    .context("Corrupted backup archive: file truncated")?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let pt = decryptor
                    .decrypt_last(Payload {
                        msg: &current_ct,
                        aad: &header,
                    })
                    .map_err(|_| anyhow!("Incorrect backup password or corrupted archive"))?;

                total_decrypted = total_decrypted
                    .checked_add(pt.len() as u64)
                    .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
                if total_decrypted > max_total {
                    bail!("Archive exceeds total maximum uncompressed size limit");
                }
                writer.write_all(&pt)?;
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    writer.flush()?;
    Ok(())
}


fn scheduled_meta_path(store: &Store) -> PathBuf {
    store.root.join(".scheduled_backups.json")
}

fn load_scheduled_files(store: &Store) -> HashSet<String> {
    let path = scheduled_meta_path(store);
    let Ok(data) = fs::read_to_string(&path) else {
        return HashSet::new();
    };
    let Ok(val) = serde_json::from_str::<Value>(&data) else {
        return HashSet::new();
    };
    val.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .filter(|name| {
                    safe_component(name).is_ok() && store.backups_dir.join(name).is_file()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn save_scheduled_files(store: &Store, files: &HashSet<String>) -> Result<()> {
    let path = scheduled_meta_path(store);
    let staging = path.with_extension(format!("tmp.{}", new_id()));
    let list: Vec<&str> = files.iter().map(String::as_str).collect();
    let json_bytes = serde_json::to_vec_pretty(&list)?;
    fs::write(&staging, json_bytes)?;
    fs::rename(&staging, &path)?;
    Ok(())
}

fn add_scheduled_file(store: &Store, filename: &str) -> Result<()> {
    let mut files = load_scheduled_files(store);
    files.insert(filename.to_string());
    save_scheduled_files(store, &files)
}

fn remove_scheduled_file(store: &Store, filename: &str) -> Result<()> {
    let mut files = load_scheduled_files(store);
    files.remove(filename);
    save_scheduled_files(store, &files)
}

fn validate_proxy_record(data: &Value) -> Result<Value> {
    let obj = data.as_object().ok_or_else(|| anyhow!("Proxy phải là object"))?;
    let id = string(data, "id");
    safe_component(id)?;
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("ID proxy trong backup không hợp lệ");
    }

    let server_raw = obj
        .get("server")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Thiếu server proxy"))?;
    let parsed = crate::network::parse_proxy_line(server_raw)?;

    let mut record = data.clone();
    let map = record.as_object_mut().unwrap();

    map.insert("server".into(), parsed["server"].clone());

    let username = match obj.get("username") {
        Some(Value::String(u)) => u.clone(),
        None => string(&parsed, "username").to_string(),
        _ => bail!("'username' phải là chuỗi"),
    };
    let password = match obj.get("password") {
        Some(Value::String(p)) => p.clone(),
        None => string(&parsed, "password").to_string(),
        _ => bail!("'password' phải là chuỗi"),
    };
    map.insert("username".into(), json!(username));
    map.insert("password".into(), json!(password));

    let name = match obj.get("name") {
        Some(Value::String(n)) if !n.trim().is_empty() => n.trim().to_string(),
        None | Some(Value::String(_)) => string(&parsed, "name").to_string(),
        _ => bail!("'name' phải là chuỗi"),
    };
    map.insert("name".into(), json!(name));

    let enabled = match obj.get("enabled") {
        Some(Value::Bool(b)) => *b,
        None => true,
        _ => bail!("'enabled' phải là boolean"),
    };
    map.insert("enabled".into(), json!(enabled));

    if let Some(lc) = obj.get("last_check") {
        if !lc.is_object() {
            bail!("'last_check' phải là object");
        }
        for key in ["ip", "country", "error", "checked_at"] {
            if lc.get(key).is_some_and(|value| !value.is_string()) { bail!("last_check.{key} phải là chuỗi"); }
        }
        if lc.get("ok").is_some_and(|value| !value.is_boolean()) { bail!("last_check.ok phải là boolean"); }
        if let Some(value) = lc.get("latency_ms") {
            if value.as_f64().is_none_or(|number| !number.is_finite() || number < 0.0) { bail!("last_check.latency_ms phải là số không âm"); }
        }
    } else {
        map.insert("last_check".into(), json!({}));
    }

    Ok(record)
}

struct VerifiedArchive {
    archive_file: File,
    is_encrypted: bool,
    manifest: Value,
}

pub struct Backups {
    store: Arc<Store>,
    runtime: Arc<Runtime>,
    session_password: Mutex<String>,
    is_running_scheduled: Mutex<bool>,
    last_error: Mutex<String>,
}

impl Backups {
    pub fn new(store: Arc<Store>, runtime: Arc<Runtime>) -> Self {
        Self {
            store,
            runtime,
            session_password: Mutex::new(String::new()),
            is_running_scheduled: Mutex::new(false),
            last_error: Mutex::new(String::new()),
        }
    }

    pub fn set_password(&self, password: &str) -> Result<Value> {
        *self.session_password.lock() = password.to_string();
        *self.last_error.lock() = String::new();
        self.state()
    }

    pub fn state(&self) -> Result<Value> {
        let settings = self.store.settings()?;
        let interval = settings
            .get("backup_interval_hours")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let last_at = string(&settings, "last_scheduled_backup_at").to_string();
        let has_pwd = !self.session_password.lock().is_empty();
        let is_running = *self.is_running_scheduled.lock();
        let last_err = self.last_error.lock().clone();

        let state = if interval <= 0 {
            "disabled"
        } else if is_running {
            "running"
        } else if !last_err.is_empty() {
            "error"
        } else if !has_pwd {
            "password_required"
        } else {
            "waiting"
        };

        Ok(json!({
            "state": state,
            "message": last_err,
            "last_at": last_at,
        }))
    }

    pub fn tick(&self) -> Result<bool> {
        let settings = self.store.settings()?;
        let interval = settings
            .get("backup_interval_hours")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if interval <= 0 {
            return Ok(false);
        }

        let password = self.session_password.lock().clone();
        if password.is_empty() {
            return Ok(false);
        }

        let now = chrono::Utc::now();
        let last_at_str = string(&settings, "last_scheduled_backup_at");
        if !last_at_str.is_empty() {
            if let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(last_at_str) {
                let elapsed_secs = (now - last_dt.with_timezone(&chrono::Utc)).num_seconds();
                if elapsed_secs < interval * 3600 {
                    return Ok(false);
                }
            }
        }

        {
            let mut running = self.is_running_scheduled.lock();
            if *running {
                return Ok(false);
            }
            *running = true;
        }

        let result = self.run_scheduled_backup(&password);
        *self.is_running_scheduled.lock() = false;

        match result {
            Ok(Some(_path)) => {
                *self.last_error.lock() = String::new();
                let retention = settings
                    .get("backup_retention")
                    .and_then(Value::as_i64)
                    .unwrap_or(5) as usize;
                self.apply_retention(retention)?;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(err) => {
                let msg = err.to_string();
                let _ = self
                    .store
                    .log("WARNING", &format!("Scheduled backup failed: {msg}"), "");
                *self.last_error.lock() = msg;
                Err(err)
            }
        }
    }

    fn run_scheduled_backup(&self, password: &str) -> Result<Option<PathBuf>> {
        let _operation = self.store.operation.lock();
        let profiles = self.store.list("profiles")?;
        if profiles.is_empty() {
            bail!("No profiles available for scheduled backup");
        }

        let eligible: Vec<String> = profiles
            .iter()
            .map(|p| string(p, "id").to_string())
            .filter(|id| !self.runtime.is_running(id))
            .collect();

        if eligible.is_empty() {
            return Ok(None);
        }

        let backup_path = self.create_internal(&eligible, None, password, true, ArchiveLimits::default())?;

        let now_str = utcnow();
        self.store.save_settings(json!({
            "last_scheduled_backup_at": now_str,
        }))?;

        Ok(Some(backup_path))
    }

    pub fn apply_retention(&self, retention_count: usize) -> Result<()> {
        if retention_count == 0 {
            return Ok(());
        }

        let backups_dir = &self.store.backups_dir;
        let scheduled_names = load_scheduled_files(&self.store);

        let mut scheduled_files = Vec::new();
        if backups_dir.exists() {
            for entry in fs::read_dir(backups_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                        if scheduled_names.contains(file_name) {
                            if let Ok(meta) = entry.metadata() {
                                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                let file_name = file_name.to_owned();
                                scheduled_files.push((mtime, path, file_name));
                            }
                        }
                    }
                }
            }
        }

        scheduled_files.sort_by(|a, b| b.0.cmp(&a.0));

        let mut remaining = HashSet::new();
        for (i, (_mtime, path, name)) in scheduled_files.into_iter().enumerate() {
            if i >= retention_count {
                if let Err(e) = fs::remove_file(&path) {
                    let _ = self.store.log(
                        "WARNING",
                        &format!("Failed to delete old scheduled backup {}: {e}", path.display()),
                        "",
                    );
                    remaining.insert(name);
                } else {
                    let _ = self.store.log(
                        "INFO",
                        &format!("Retention policy removed old scheduled backup: {name}"),
                        "",
                    );
                }
            } else {
                remaining.insert(name);
            }
        }

        save_scheduled_files(&self.store, &remaining)?;
        Ok(())
    }

    fn resolve_destination(
        &self,
        destination: Option<&Path>,
        has_password: bool,
        is_scheduled: bool,
    ) -> Result<PathBuf> {
        let ext = if has_password { ".enc.zip" } else { ".zip" };
        let prefix = if is_scheduled {
            "scheduled_backup"
        } else {
            "backup"
        };
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let short_id = &new_id()[..6];
        let default_name = format!("{prefix}_{ts}_{short_id}{ext}");

        match destination {
            None => {
                fs::create_dir_all(&self.store.backups_dir)?;
                Ok(self.store.backups_dir.join(default_name))
            }
            Some(dest) => {
                let dest_str = dest.to_string_lossy();
                if dest.is_dir() || dest_str.ends_with('/') || dest_str.ends_with('\\') {
                    fs::create_dir_all(dest)?;
                    Ok(dest.join(default_name))
                } else {
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    Ok(dest.to_path_buf())
                }
            }
        }
    }

    fn scrub_profile_paths(profile: &Value) -> Result<Value> {
        let clean = profile.clone();
        if let Some(extensions) = clean.get("extensions").and_then(Value::as_array) {
            for ext in extensions {
                let ext_str = ext
                    .as_str()
                    .ok_or_else(|| anyhow!("Invalid extension entry in profile"))?;
                let folder = ext_str
                    .strip_prefix("addons/")
                    .ok_or_else(|| anyhow!("Invalid managed extension path"))?;
                safe_component(folder)?;
            }
        }
        Ok(clean)
    }

    fn collect_files_recursive(
        root: &Path,
        dir: &Path,
        results: &mut Vec<(PathBuf, String)>,
        skip_lock_files: bool,
    ) -> Result<()> {
        reject_link(dir)?;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            reject_link(&path)?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                Self::collect_files_recursive(root, &path, results, skip_lock_files)?;
            } else if file_type.is_file() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if skip_lock_files && LOCK_FILES.contains(&name) {
                        continue;
                    }
                }
                let rel = path.strip_prefix(root)?;
                let rel_posix = rel.to_string_lossy().replace('\\', "/");
                results.push((path, rel_posix));
            }
        }
        Ok(())
    }

    fn write_dir_to_zip<W: Write + Seek>(
        zip: &mut ZipWriter<W>,
        dir: &Path,
        prefix: &str,
        manifest: &mut BTreeMap<String, Value>,
        opts: SimpleFileOptions,
        skip_lock_files: bool,
        total_uncompressed: &mut u64,
        entry_count: &mut usize,
        limits: &ArchiveLimits,
    ) -> Result<()> {
        reject_link(dir)?;
        let mut entries = Vec::new();
        Self::collect_files_recursive(dir, dir, &mut entries, skip_lock_files)?;
        entries.sort_by(|a, b| a.1.cmp(&b.1));

        let mut buffer = vec![0u8; CHUNK_SIZE];
        for (abs_path, rel_posix) in entries {
            reject_link(&abs_path)?;
            *entry_count += 1;
            if *entry_count > limits.max_entries {
                bail!("ZIP contains too many entries");
            }

            let arcname = format!("{prefix}/{rel_posix}");
            let mut file = File::open(&abs_path)?;
            if file.metadata()?.len() > limits.max_single_file {
                bail!("Archive entry exceeds maximum file size limit: {arcname}");
            }
            zip.start_file(&arcname, opts)?;
            let mut hasher = Sha256::new();
            let mut file_size: u64 = 0;

            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                file_size = file_size
                    .checked_add(n as u64)
                    .ok_or_else(|| anyhow!("Archive entry exceeds maximum file size limit: {arcname}"))?;
                if file_size > limits.max_single_file {
                    bail!("Archive entry exceeds maximum file size limit: {arcname}");
                }
                *total_uncompressed = (*total_uncompressed)
                    .checked_add(n as u64)
                    .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
                if *total_uncompressed > limits.max_total_uncompressed {
                    bail!("Archive exceeds total maximum uncompressed size limit");
                }
                hasher.update(&buffer[..n]);
                zip.write_all(&buffer[..n])?;
            }

            manifest.insert(
                arcname,
                json!({
                    "sha256": hex::encode(hasher.finalize()),
                    "size": file_size,
                }),
            );
        }
        Ok(())
    }

    fn populate_backup_zip<W: Write + Seek>(
        &self,
        zip: &mut ZipWriter<W>,
        profiles_to_backup: &[Value],
        proxies_dict: &BTreeMap<String, Value>,
        versions_dict: &BTreeMap<String, Value>,
        has_proxy_credentials: bool,
        is_scheduled: bool,
        limits: &ArchiveLimits,
    ) -> Result<()> {
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let mut files_manifest = BTreeMap::new();
        let mut clean_profiles_meta = Vec::new();
        let mut total_uncompressed: u64 = 0;
        let mut entry_count: usize = 0;

        for prof in profiles_to_backup {
            let pid = string(prof, "id");
            let clean_prof = Self::scrub_profile_paths(prof)?;
            let prof_json_bytes = serde_json::to_vec_pretty(&clean_prof)?;
            if prof_json_bytes.len() as u64 > limits.max_metadata_size {
                bail!("Profile metadata exceeds maximum size limit");
            }
            if prof_json_bytes.len() as u64 > limits.max_single_file { bail!("Archive entry exceeds maximum file size limit"); }
            entry_count += 1;
            if entry_count > limits.max_entries {
                bail!("ZIP contains too many entries");
            }
            total_uncompressed = total_uncompressed
                .checked_add(prof_json_bytes.len() as u64)
                .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
            if total_uncompressed > limits.max_total_uncompressed {
                bail!("Archive exceeds total maximum uncompressed size limit");
            }

            let prof_json_arc = format!("profiles/{pid}/profile.json");
            let mut hasher = Sha256::new();
            hasher.update(&prof_json_bytes);
            files_manifest.insert(
                prof_json_arc.clone(),
                json!({
                    "sha256": hex::encode(hasher.finalize()),
                    "size": prof_json_bytes.len(),
                }),
            );

            zip.start_file(&prof_json_arc, opts)?;
            zip.write_all(&prof_json_bytes)?;

            let addons_count = clean_prof
                .get("extensions")
                .and_then(Value::as_array)
                .map_or(0, |a| a.len());
            clean_profiles_meta.push(json!({
                "id": pid,
                "name": string(&clean_prof, "name"),
                "browser_version": string(&clean_prof, "browser_version"),
                "proxy_id": string(&clean_prof, "proxy_id"),
                "addons_count": addons_count,
            }));

            let prof_dir = self.store.profile_dir(pid)?;
            if prof_dir.is_dir() {
                let browser_dir = prof_dir.join("browser");
                if browser_dir.is_dir() {
                    Self::write_dir_to_zip(
                        zip,
                        &browser_dir,
                        &format!("profiles/{pid}/browser"),
                        &mut files_manifest,
                        opts,
                        true,
                        &mut total_uncompressed,
                        &mut entry_count,
                        limits,
                    )?;
                }
                let addons_dir = prof_dir.join("addons");
                if addons_dir.is_dir() {
                    Self::write_dir_to_zip(
                        zip,
                        &addons_dir,
                        &format!("profiles/{pid}/addons"),
                        &mut files_manifest,
                        opts,
                        false,
                        &mut total_uncompressed,
                        &mut entry_count,
                        limits,
                    )?;
                }
            }
        }

        let mut proxies_meta = Vec::new();
        for (px_id, px_data) in proxies_dict {
            let px_bytes = serde_json::to_vec_pretty(px_data)?;
            if px_bytes.len() as u64 > limits.max_metadata_size {
                bail!("Proxy metadata exceeds maximum size limit");
            }
            if px_bytes.len() as u64 > limits.max_single_file { bail!("Archive entry exceeds maximum file size limit"); }
            entry_count += 1;
            if entry_count > limits.max_entries {
                bail!("ZIP contains too many entries");
            }
            total_uncompressed = total_uncompressed
                .checked_add(px_bytes.len() as u64)
                .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
            if total_uncompressed > limits.max_total_uncompressed {
                bail!("Archive exceeds total maximum uncompressed size limit");
            }

            let px_arc = format!("proxies/{px_id}.json");
            let mut hasher = Sha256::new();
            hasher.update(&px_bytes);
            files_manifest.insert(
                px_arc.clone(),
                json!({
                    "sha256": hex::encode(hasher.finalize()),
                    "size": px_bytes.len(),
                }),
            );

            zip.start_file(&px_arc, opts)?;
            zip.write_all(&px_bytes)?;

            let has_creds =
                !string(px_data, "username").is_empty() || !string(px_data, "password").is_empty();
            proxies_meta.push(json!({
                "id": px_id,
                "name": string(px_data, "name"),
                "server": string(px_data, "server"),
                "has_credentials": has_creds,
                "has_password": !string(px_data, "password").is_empty(),
            }));
        }

        let manifest = json!({
            "schema_version": 1,
            "app": "CamouManager",
            "created_at": utcnow(),
            "is_scheduled": is_scheduled,
            "profiles_count": profiles_to_backup.len(),
            "has_proxy_credentials": has_proxy_credentials,
            "profiles": clean_profiles_meta,
            "proxies": proxies_meta,
            "versions": versions_dict,
            "compatibility": {
                "os": "windows",
                "notes": "Cross-PC portable backup. Firefox databases (places, cookies, storage) and addons are portable across systems. Binaries are not included; target PC must have matching Camoufox browser version installed in the Versions tab.",
            },
            "files": files_manifest,
        });

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        if manifest_bytes.len() as u64 > limits.max_manifest_size {
            bail!("Manifest file exceeds size limit");
        }
        if manifest_bytes.len() as u64 > limits.max_single_file { bail!("Archive entry exceeds maximum file size limit"); }
        entry_count += 1;
        if entry_count > limits.max_entries {
            bail!("ZIP contains too many entries");
        }
        total_uncompressed = total_uncompressed
            .checked_add(manifest_bytes.len() as u64)
            .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
        if total_uncompressed > limits.max_total_uncompressed {
            bail!("Archive exceeds total maximum uncompressed size limit");
        }

        zip.start_file("manifest.json", opts)?;
        zip.write_all(&manifest_bytes)?;
        Ok(())
    }

    pub fn create(&self, ids: &[String], destination: Option<&Path>, password: &str) -> Result<PathBuf> {
        self.create_internal(ids, destination, password, false, ArchiveLimits::default())
    }

    #[cfg(test)]
    fn create_with_limits(
        &self,
        ids: &[String],
        destination: Option<&Path>,
        password: &str,
        limits: ArchiveLimits,
    ) -> Result<PathBuf> {
        self.create_internal(ids, destination, password, false, limits)
    }

    fn create_internal(
        &self,
        ids: &[String],
        destination: Option<&Path>,
        password: &str,
        is_scheduled: bool,
        limits: ArchiveLimits,
    ) -> Result<PathBuf> {
        if ids.is_empty() {
            bail!("No profile IDs specified for backup");
        }

        let target_path = self.resolve_destination(destination, !password.is_empty(), is_scheduled)?;

        let _operation = self.store.operation.lock();

        let mut profiles_to_backup = Vec::with_capacity(ids.len());
        for pid in ids {
            safe_component(pid)?;
            let prof = self
                .store
                .get("profiles", pid)?
                .ok_or_else(|| anyhow!("Profile '{pid}' not found"))?;
            if self.runtime.is_running(pid) {
                bail!(
                    "Cannot backup running profile: '{pid}' ({})",
                    string(&prof, "name")
                );
            }
            profiles_to_backup.push(prof);
        }

        let mut proxies_dict = BTreeMap::new();
        let mut versions_dict = BTreeMap::new();
        let mut has_proxy_credentials = false;

        for prof in &profiles_to_backup {
            let px_id = string(prof, "proxy_id");
            if !px_id.is_empty() {
                let px = self.store.get("proxies", px_id)?.ok_or_else(|| {
                    anyhow!(
                        "Assigned proxy '{px_id}' for profile '{}' ({}) not found in store",
                        string(prof, "name"),
                        string(prof, "id")
                    )
                })?;
                if !string(&px, "username").is_empty() || !string(&px, "password").is_empty() {
                    has_proxy_credentials = true;
                }
                proxies_dict.insert(px_id.to_string(), px);
            }

            let ver_id = string(prof, "browser_version");
            if !ver_id.is_empty() && !versions_dict.contains_key(ver_id) {
                let v = self.store.get("versions", ver_id)?;
                let v_data = match v {
                    Some(ver) => json!({
                        "id": string(&ver, "id"),
                        "name": string(&ver, "name"),
                        "release_url": string(&ver, "release_url"),
                    }),
                    None => json!({
                        "id": ver_id,
                        "name": ver_id,
                        "release_url": "",
                    }),
                };
                versions_dict.insert(ver_id.to_string(), v_data);
            }
        }

        if let Some(p) = target_path.parent() {
            fs::create_dir_all(p)?;
            reject_link(p)?;
        }

        let temp_dest_path = target_path.with_file_name(format!(
            ".{}.{}.part",
            target_path.file_name().unwrap_or_default().to_string_lossy(),
            &new_id()[..6]
        ));

        let build_and_finalize = || -> Result<()> {
            if !password.is_empty() {
                let mut temp_file = tempfile::tempfile_in(&self.store.root)?;
                {
                    let mut zip = ZipWriter::new(&mut temp_file);
                    self.populate_backup_zip(
                        &mut zip,
                        &profiles_to_backup,
                        &proxies_dict,
                        &versions_dict,
                        has_proxy_credentials,
                        is_scheduled,
                        &limits,
                    )?;
                    zip.finish()?;
                }
                temp_file.seek(SeekFrom::Start(0))?;
                let mut dest_file = File::create(&temp_dest_path)?;
                stream_encrypt(&mut temp_file, &mut dest_file, password)?;
                dest_file.flush()?;
            } else {
                let dest_file = File::create(&temp_dest_path)?;
                let mut zip = ZipWriter::new(dest_file);
                self.populate_backup_zip(
                    &mut zip,
                    &profiles_to_backup,
                    &proxies_dict,
                    &versions_dict,
                    has_proxy_credentials,
                    is_scheduled,
                    &limits,
                )?;
                zip.finish()?;
            }

            let final_size = fs::metadata(&temp_dest_path)?.len();
            if final_size > limits.max_total_uncompressed + 1024 * 1024 {
                bail!("Archive exceeds total maximum uncompressed size limit");
            }

            fs::rename(&temp_dest_path, &target_path)?;

            if is_scheduled {
                if let Some(name) = target_path.file_name().and_then(|s| s.to_str()) {
                    add_scheduled_file(&self.store, name)?;
                }
            }

            let _ = self.store.log(
                "INFO",
                &format!(
                    "Created backup ({}) with {} profile(s) at {}",
                    if password.is_empty() {
                        "unencrypted"
                    } else {
                        "encrypted"
                    },
                    ids.len(),
                    target_path.file_name().unwrap_or_default().to_string_lossy()
                ),
                "",
            );
            Ok(())
        };

        let res = build_and_finalize();
        if res.is_err() {
            let _ = fs::remove_file(&temp_dest_path);
        }
        res.map(|_| target_path)
    }

    fn verify_archive(&self, path: &Path, password: &str) -> Result<VerifiedArchive> {
        self.verify_archive_with_limits(path, password, ArchiveLimits::default())
    }

    fn verify_archive_with_limits(
        &self,
        path: &Path,
        password: &str,
        limits: ArchiveLimits,
    ) -> Result<VerifiedArchive> {
        if !path.exists() {
            bail!("Backup file not found: {}", path.display());
        }
        reject_link(path)?;

        let file_size = fs::metadata(path)?.len();
        if file_size == 0 {
            bail!("Corrupted backup archive: file is empty");
        }
        if file_size > limits.max_total_uncompressed + 1024 * 1024 {
            bail!("Archive exceeds total maximum uncompressed size limit");
        }

        let mut head = [0u8; 8];
        {
            let mut f = File::open(path)?;
            f.read_exact(&mut head)?;
        }

        let is_encrypted;
        let mut archive_file = if &head == MAGIC {
            is_encrypted = true;
            if password.is_empty() {
                bail!("Password required for encrypted backup");
            }
            let mut temp_dec = tempfile::tempfile_in(&self.store.root)?;
            let src = File::open(path)?;
            stream_decrypt(src, &mut temp_dec, password, limits.max_total_uncompressed)?;
            #[cfg(test)]
            if std::env::var_os("CAMOU_TEST_ABRUPT_EXIT_CHILD").is_some() {
                std::process::exit(0);
            }
            temp_dec.seek(SeekFrom::Start(0))?;
            temp_dec
        } else if head.starts_with(b"PK") {
            is_encrypted = false;
            File::open(path)?
        } else {
            bail!("Invalid or unrecognized backup archive format");
        };

        let verify_res: Result<Value> = (|| {
            archive_file.seek(SeekFrom::Start(0))?;
            let mut zip = ZipArchive::new(&mut archive_file)
                .map_err(|e| anyhow!("Corrupted backup archive: invalid zip structure ({e})"))?;

            if zip.len() > limits.max_entries {
                bail!("ZIP contains too many entries");
            }

            let mut manifest_info = None;
            let mut namelist = HashSet::with_capacity(zip.len());
            let mut total_uncompressed: u64 = 0;

            for index in 0..zip.len() {
                let entry = zip.by_index(index)?;
                let fname = entry.name().to_string();

                if !namelist.insert(fname.clone()) {
                    bail!("Duplicate archive entries are not allowed");
                }

                if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
                    bail!("Symlinks not allowed in backup archive: {fname}");
                }

                if fname.starts_with('/')
                    || fname.starts_with('\\')
                    || fname.contains('\\')
                    || fname.contains(':')
                    || fname.split('/').any(|p| p == ".." || p == ".")
                {
                    bail!("Zip traversal detected: {fname}");
                }

                if entry.size() > limits.max_single_file {
                    bail!("Archive entry exceeds maximum file size limit: {fname}");
                }
                total_uncompressed = total_uncompressed
                    .checked_add(entry.size())
                    .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;
                if total_uncompressed > limits.max_total_uncompressed {
                    bail!("Archive exceeds total maximum uncompressed size limit");
                }

                if fname == "manifest.json" {
                    if entry.size() > limits.max_manifest_size {
                        bail!("Manifest file exceeds size limit");
                    }
                    manifest_info = Some(index);
                } else if fname.starts_with("proxies/") || fname.strip_prefix("profiles/")
                    .and_then(|path| path.split_once('/')).is_some_and(|(_, path)| path == "profile.json") {
                    if entry.size() > limits.max_metadata_size {
                        bail!("Metadata entry exceeds declared size limit: {fname}");
                    }
                }
            }

            let manifest_index = manifest_info
                .ok_or_else(|| anyhow!("Invalid backup archive: missing manifest.json"))?;

            let mut manifest_bytes = Vec::new();
            {
                let mut mf_entry = zip.by_index(manifest_index)?;
                let mut buffer = [0u8; CHUNK_SIZE];
                let mut decompressed_manifest_len: u64 = 0;
                loop {
                    let n = mf_entry.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    decompressed_manifest_len = decompressed_manifest_len
                        .checked_add(n as u64)
                        .ok_or_else(|| anyhow!("Manifest file exceeds size limit"))?;
                    if decompressed_manifest_len > limits.max_manifest_size {
                        bail!("Manifest file exceeds size limit");
                    }
                    manifest_bytes.extend_from_slice(&buffer[..n]);
                }
            }

            let manifest: Value = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| anyhow!("Corrupted backup archive: unreadable manifest ({e})"))?;

            if !manifest.is_object() {
                bail!("Backup manifest must be an object");
            }

            let schema_version = manifest
                .get("schema_version")
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("Invalid backup manifest: missing or invalid schema_version"))?;
            if schema_version != 1 {
                bail!("Unsupported backup schema version: {schema_version}");
            }

            let manifest_files = manifest
                .get("files")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow!("Invalid backup manifest: missing files integrity section"))?;

            for fname in &namelist {
                if fname.ends_with('/') || fname == "manifest.json" {
                    continue;
                }
                if !manifest_files.contains_key(fname) {
                    bail!("Unexpected file in backup archive: {fname}");
                }
                if !fname.starts_with("profiles/") && !fname.starts_with("proxies/") {
                    bail!("Unexpected file path in backup archive: {fname}");
                }
            }

            let mut total_actual_uncompressed: u64 = manifest_bytes.len() as u64;
            if total_actual_uncompressed > limits.max_total_uncompressed {
                bail!("Archive exceeds total maximum uncompressed size limit");
            }

            let mut buffer = vec![0u8; CHUNK_SIZE];
            for (expected_file, meta) in manifest_files {
                if !namelist.contains(expected_file) {
                    bail!("Corrupted backup archive: missing file {expected_file}");
                }

                let expected_size = meta
                    .get("size")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("Missing file size: {expected_file}"))?;
                let expected_hash = meta
                    .get("sha256")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("Missing SHA-256 integrity hash: {expected_file}"))?;

                if expected_size > limits.max_single_file {
                    bail!("Archive entry exceeds maximum file size limit: {expected_file}");
                }

                let mut entry = zip
                    .by_name(expected_file)
                    .map_err(|e| anyhow!("Corrupted file in backup archive: {expected_file} ({e})"))?;

                if entry.size() > limits.max_single_file {
                    bail!("Archive entry exceeds maximum file size limit: {expected_file}");
                }

                let mut hasher = Sha256::new();
                let mut actual_size: u64 = 0;

                loop {
                    let n = entry.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    actual_size = actual_size
                        .checked_add(n as u64)
                        .ok_or_else(|| anyhow!("Archive entry exceeds maximum file size limit: {expected_file}"))?;
                    total_actual_uncompressed = total_actual_uncompressed
                        .checked_add(n as u64)
                        .ok_or_else(|| anyhow!("Archive exceeds total maximum uncompressed size limit"))?;

                    if actual_size > limits.max_single_file {
                        bail!("Archive entry exceeds maximum file size limit: {expected_file}");
                    }
                    if actual_size > entry.size() || actual_size > expected_size {
                        bail!("Corrupted file in backup (size mismatch): {expected_file}");
                    }
                    if total_actual_uncompressed > limits.max_total_uncompressed {
                        bail!("Archive exceeds total maximum uncompressed size limit");
                    }

                    hasher.update(&buffer[..n]);
                }

                if actual_size != expected_size {
                    bail!("Corrupted file in backup (size mismatch): {expected_file}");
                }
                let actual_hash = hex::encode(hasher.finalize());
                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    bail!("Corrupted file in backup (integrity check failed): {expected_file}");
                }
            }

            let profiles = manifest
                .get("profiles")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("Invalid profile manifest"))?;
            let proxies = manifest
                .get("proxies")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("Invalid proxy manifest"))?;

            let mut profile_ids = Vec::with_capacity(profiles.len());
            let mut proxy_ids = Vec::with_capacity(proxies.len());

            for p in proxies {
                let id = string(p, "id");
                safe_component(id)?;
                if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
                    bail!("Invalid record ID in backup");
                }
                proxy_ids.push(id.to_string());
            }
            let mut px_set = HashSet::new();
            for id in &proxy_ids {
                if !px_set.insert(id) {
                    bail!("Duplicate record IDs in backup");
                }
            }

            for p in profiles {
                let id = string(p, "id");
                safe_component(id)?;
                if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
                    bail!("Invalid record ID in backup");
                }
                profile_ids.push(id.to_string());
            }
            let mut prof_set = HashSet::new();
            for id in &profile_ids {
                if !prof_set.insert(id) {
                    bail!("Duplicate record IDs in backup");
                }
            }

            for proxy_id in &proxy_ids {
                let arc_name = format!("proxies/{proxy_id}.json");
                if !manifest_files.contains_key(&arc_name) {
                    bail!("Missing assigned proxy definition");
                }
                let mut p_entry = zip.by_name(&arc_name)?;
                if p_entry.size() > limits.max_metadata_size {
                    bail!("Metadata entry exceeds declared size limit: {arc_name}");
                }
                let mut p_bytes = Vec::new();
                p_entry.by_ref().take(limits.max_metadata_size + 1).read_to_end(&mut p_bytes)?;
                if p_bytes.len() as u64 > limits.max_metadata_size {
                    bail!("Archive entry exceeds maximum file size limit: {arc_name}");
                }
                let p_data: Value = serde_json::from_slice(&p_bytes)?;
                if string(&p_data, "id") != proxy_id {
                    bail!("Proxy ID does not match archive metadata");
                }
                validate_proxy_record(&p_data)?;
            }

            for profile_id in &profile_ids {
                let arc_name = format!("profiles/{profile_id}/profile.json");
                if !manifest_files.contains_key(&arc_name) {
                    bail!("Missing profile definition");
                }
                let mut p_entry = zip.by_name(&arc_name)?;
                if p_entry.size() > limits.max_metadata_size {
                    bail!("Metadata entry exceeds declared size limit: {arc_name}");
                }
                let mut p_bytes = Vec::new();
                p_entry.by_ref().take(limits.max_metadata_size + 1).read_to_end(&mut p_bytes)?;
                if p_bytes.len() as u64 > limits.max_metadata_size {
                    bail!("Archive entry exceeds maximum file size limit: {arc_name}");
                }
                let p_data: Value = serde_json::from_slice(&p_bytes)?;
                if string(&p_data, "id") != profile_id {
                    bail!("Profile ID does not match archive metadata");
                }
                let px_id = string(&p_data, "proxy_id");
                if !px_id.is_empty() && !proxy_ids.contains(&px_id.to_string()) {
                    bail!("Assigned proxy is missing; refusing to restore a direct-IP profile");
                }
                crate::profiles::validate_backup_profile_record(&p_data)?;
            }

            for fname in manifest_files.keys() {
                let parts: Vec<&str> = fname.split('/').collect();
                if parts[0] == "profiles" {
                    if parts.len() < 3
                        || !profile_ids.contains(&parts[1].to_string())
                        || !["browser", "addons", "profile.json"].contains(&parts[2])
                        || (parts[2] == "profile.json" && parts.len() != 3)
                    {
                        bail!("Unexpected profile data in backup");
                    }
                } else if parts[0] == "proxies" {
                    if parts.len() != 2
                        || !proxy_ids.iter().any(|id| parts[1] == format!("{id}.json"))
                    {
                        bail!("Unexpected proxy data in backup");
                    }
                }
            }

            Ok(manifest)
        })();

        match verify_res {
            Ok(manifest) => {
                archive_file.seek(SeekFrom::Start(0))?;
                Ok(VerifiedArchive {
                    archive_file,
                    is_encrypted,
                    manifest,
                })
            }
            Err(e) => Err(e),
        }
    }


    pub fn inspect(&self, path: &Path, password: &str) -> Result<Value> {
        let verified = self.verify_archive(path, password)?;
        let manifest = &verified.manifest;

        let manifest_profiles = manifest
            .get("profiles")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let manifest_proxies = manifest
            .get("proxies")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let manifest_versions = manifest.get("versions").cloned().unwrap_or(json!({}));
        let manifest_files = manifest
            .get("files")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let installed_versions: HashSet<String> = self
            .store
            .list("versions")?
            .iter()
            .map(|v| string(v, "id").to_string())
            .collect();

        let mut missing_versions = Vec::new();
        if let Some(obj) = manifest_versions.as_object() {
            for (vid, _) in obj {
                if !vid.is_empty() && !installed_versions.contains(vid) {
                    missing_versions.push(vid.clone());
                }
            }
        }

        let has_proxy_credentials = manifest
            .get("has_proxy_credentials")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let warning = if has_proxy_credentials {
            "Archive contains saved proxy authentication credentials (passwords/tokens). Keep this backup secure."
        } else {
            ""
        };

        let compatibility_warning = if !missing_versions.is_empty() {
            format!(
                "Missing browser version(s): {}. Please install them via the Versions tab before launching.",
                missing_versions.join(", ")
            )
        } else {
            String::new()
        };

        let compat_notes = manifest
            .pointer("/compatibility/notes")
            .and_then(Value::as_str)
            .unwrap_or(
                "Firefox databases are portable across PCs. Target system requires matching Camoufox executable.",
            );

        let total_uncompressed: u64 = manifest_files
            .values()
            .filter_map(|v| v.get("size").and_then(Value::as_u64))
            .sum();

        let redacted_proxies = manifest_proxies.iter().map(|proxy| json!({
            "id":string(proxy,"id"),
            "name":string(proxy,"name"),
            "server":string(proxy,"server"),
            "has_credentials":proxy["has_credentials"].as_bool().unwrap_or(false),
            "has_password":proxy["has_password"].as_bool().unwrap_or(false),
        })).collect::<Vec<_>>();

        Ok(json!({
            "path": path.to_string_lossy(),
            "schema_version": manifest.get("schema_version").and_then(Value::as_i64).unwrap_or(1),
            "created_at": string(manifest, "created_at"),
            "is_encrypted": verified.is_encrypted,
            "is_scheduled": manifest.get("is_scheduled").and_then(Value::as_bool).unwrap_or(false),
            "profiles_count": manifest_profiles.len(),
            "profiles": manifest_profiles,
            "proxies": redacted_proxies,
            "versions": manifest_versions,
            "missing_versions": missing_versions,
            "has_proxy_credentials": has_proxy_credentials,
            "warning": warning,
            "compatibility_warning": compatibility_warning,
            "compatibility_notes": compat_notes,
            "file_count": manifest_files.len(),
            "total_size": total_uncompressed,
        }))
    }

    pub fn restore(&self, path: &Path, password: &str) -> Result<Vec<Value>> {
        self.restore_with_limits(path, password, ArchiveLimits::default())
    }

    fn restore_with_limits(
        &self,
        path: &Path,
        password: &str,
        limits: ArchiveLimits,
    ) -> Result<Vec<Value>> {
        let mut verified = self.verify_archive_with_limits(path, password, limits)?;
        let manifest = &verified.manifest;

        let manifest_profiles = manifest
            .get("profiles")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let manifest_proxies = manifest
            .get("proxies")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut proxy_id_map = HashMap::new();
        for px in &manifest_proxies {
            let old_id = string(px, "id");
            if !old_id.is_empty() {
                proxy_id_map.insert(old_id.to_string(), new_id());
            }
        }

        let mut profile_id_map = HashMap::new();
        for prof in &manifest_profiles {
            let old_id = string(prof, "id");
            if !old_id.is_empty() {
                profile_id_map.insert(old_id.to_string(), new_id());
            }
        }

        let staging_dir = self.store.root.join(format!("_restore_stage_{}", new_id()));
        fs::create_dir_all(&staging_dir)?;

        let mut staged_proxies = Vec::with_capacity(manifest_proxies.len());
        let mut staged_profiles = Vec::with_capacity(manifest_profiles.len());

        let extract_res: Result<()> = (|| {
            verified.archive_file.seek(SeekFrom::Start(0))?;
            extract_zip(&mut verified.archive_file, &staging_dir, limits.max_total_uncompressed, None)?;

            for (old_px_id, new_px_id) in &proxy_id_map {
                let px_file = staging_dir.join("proxies").join(format!("{old_px_id}.json"));
                reject_link(&px_file)?;
                let meta = fs::metadata(&px_file)?;
                if meta.len() > limits.max_metadata_size {
                    bail!("Proxy metadata file exceeds maximum size limit: {}", px_file.display());
                }
                let fh = File::open(&px_file)?;
                let mut raw = String::new();
                fh.take(limits.max_metadata_size + 1).read_to_string(&mut raw)?;
                if raw.len() as u64 > limits.max_metadata_size {
                    bail!("Proxy metadata file exceeds maximum size limit: {}", px_file.display());
                }
                let data: Value = serde_json::from_str(&raw)?;
                let mut validated_px = validate_proxy_record(&data)?;
                if let Some(obj) = validated_px.as_object_mut() {
                    obj.insert("id".into(), Value::String(new_px_id.clone()));
                }
                staged_proxies.push(validated_px);
            }

            let staged_profs_dir = staging_dir.join("staged_profiles");
            fs::create_dir_all(&staged_profs_dir)?;

            for (old_prof_id, new_prof_id) in &profile_id_map {
                let prof_file = staging_dir
                    .join("profiles")
                    .join(old_prof_id)
                    .join("profile.json");
                reject_link(&prof_file)?;
                let meta = fs::metadata(&prof_file)?;
                if meta.len() > limits.max_metadata_size {
                    bail!("Profile metadata file exceeds maximum size limit: {}", prof_file.display());
                }
                let fh = File::open(&prof_file)?;
                let mut raw = String::new();
                fh.take(limits.max_metadata_size + 1).read_to_string(&mut raw)?;
                if raw.len() as u64 > limits.max_metadata_size {
                    bail!("Profile metadata file exceeds maximum size limit: {}", prof_file.display());
                }
                let data: Value = serde_json::from_str(&raw)?;
                let mut validated_prof = crate::profiles::validate_backup_profile_record(&data)?;
                if let Some(obj) = validated_prof.as_object_mut() {
                    obj.insert("id".into(), Value::String(new_prof_id.clone()));
                    let old_px = obj.get("proxy_id").and_then(Value::as_str).unwrap_or("");
                    if !old_px.is_empty() {
                        let new_px = proxy_id_map.get(old_px).cloned().unwrap_or_default();
                        obj.insert("proxy_id".into(), Value::String(new_px));
                    }
                }
                staged_profiles.push(validated_prof);

                let src_prof_dir = staging_dir.join("profiles").join(old_prof_id);
                let dest_staged_dir = staged_profs_dir.join(new_prof_id);
                fs::rename(&src_prof_dir, &dest_staged_dir)?;
            }
            Ok(())
        })();

        if let Err(e) = extract_res {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(e);
        }

        let _operation = self.store.operation.lock();
        let mut created_dirs = Vec::new();

        let commit_res: Result<Vec<Value>> = (|| {
            let staged_profs_dir = staging_dir.join("staged_profiles");
            for (_old_id, new_id) in &profile_id_map {
                let src = staged_profs_dir.join(new_id);
                let dest = self.store.profile_dir(new_id)?;
                if dest.exists() {
                    bail!("Restore ID collision; existing profile data will not be overwritten");
                }
                fs::remove_file(src.join("profile.json"))?;
                fs::create_dir_all(src.join("browser"))?;
                fs::create_dir_all(src.join("addons"))?;
                fs::rename(&src, &dest)?;
                created_dirs.push(dest);
            }
            #[cfg(test)]
            if std::env::var_os("CAMOU_TEST_RESTORE_PUBLICATION_EXIT").is_some() {
                std::process::exit(0);
            }


            let mut batch = Vec::new();
            for px in staged_proxies {
                batch.push(("proxies", px));
            }
            for prof in staged_profiles {
                batch.push(("profiles", prof));
            }

            let saved_batch = self.store.put_batch(batch)?;

            let restored_profiles: Vec<Value> = saved_batch
                .into_iter()
                .filter(|r| r.get("server").is_none())
                .collect();

            for p in &restored_profiles {
                let id = string(p, "id");
                let name = string(p, "name");
                let _ = self.store.log(
                    "INFO",
                    &format!("Restored profile '{name}' ({id}) from backup"),
                    id,
                );
            }

            Ok(restored_profiles)
        })();

        let _ = fs::remove_dir_all(&staging_dir);

        match commit_res {
            Ok(profs) => Ok(profs),
            Err(err) => {
                for dir in created_dirs.iter().rev() {
                    let _ = fs::remove_dir_all(dir);
                }
                Err(anyhow!("Restore failed and was rolled back: {err}"))
            }
        }
    }

    pub fn list(&self) -> Result<Vec<Value>> {
        fs::create_dir_all(&self.store.backups_dir)?;
        let scheduled_names = load_scheduled_files(&self.store);

        let mut results = Vec::new();
        let mut files: Vec<PathBuf> = fs::read_dir(&self.store.backups_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                if !p.is_file() {
                    return false;
                }
                if reject_link(p).is_err() {
                    return false;
                }
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                !name.ends_with(".part") && !name.ends_with(".tmp") && !name.starts_with('.')
            })
            .collect();

        files.sort_by(|a, b| {
            let ma = fs::metadata(a)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let mb = fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            mb.cmp(&ma)
        });

        for f in files {
            let Ok(meta) = fs::metadata(&f) else { continue };
            let size = meta.len();
            let mtime = meta
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let mtime_iso = chrono::DateTime::<chrono::Utc>::from(mtime)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let filename = f
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let mut head = [0u8; 8];
            let Ok(mut fp) = File::open(&f) else { continue };
            if fp.read_exact(&mut head).is_err() {
                continue;
            };

            let is_sched = scheduled_names.contains(&filename);

            if &head == MAGIC {
                results.push(json!({
                    "path": f.to_string_lossy(),
                    "filename": filename,
                    "size": size,
                    "size_mb": (size as f64 / (1024.0 * 1024.0) * 100.0).round() / 100.0,
                    "created_at": mtime_iso,
                    "is_encrypted": true,
                    "is_scheduled": is_sched,
                    "profiles_count": Value::Null,
                    "has_proxy_credentials": Value::Null,
                    "warning": "Encrypted archive",
                }));
            } else if head.starts_with(b"PK") {
                let mut p_count = 0;
                let mut has_cred = false;
                let mut c_at = mtime_iso.clone();

                if let Ok(mut zip) = ZipArchive::new(fp) {
                    if let Ok(mut mf) = zip.by_name("manifest.json") {
                        if mf.size() <= MAX_MANIFEST_SIZE {
                            let mut raw = Vec::new();
                            let mut buffer = [0u8; CHUNK_SIZE];
                            let mut actual_len: u64 = 0;
                            let mut exceeded = false;
                            while let Ok(n) = mf.read(&mut buffer) {
                                if n == 0 {
                                    break;
                                }
                                actual_len += n as u64;
                                if actual_len > MAX_MANIFEST_SIZE {
                                    exceeded = true;
                                    break;
                                }
                                raw.extend_from_slice(&buffer[..n]);
                            }
                            if !exceeded {
                                if let Ok(m) = serde_json::from_slice::<Value>(&raw) {
                                    p_count = m
                                        .get("profiles")
                                        .and_then(Value::as_array)
                                        .map_or(0, |a| a.len());
                                    has_cred = m
                                        .get("has_proxy_credentials")
                                        .and_then(Value::as_bool)
                                        .unwrap_or(false);
                                    if let Some(cat) = m.get("created_at").and_then(Value::as_str) {
                                        c_at = cat.to_string();
                                    }
                                }
                            }
                        }
                    }
                }

                results.push(json!({
                    "path": f.to_string_lossy(),
                    "filename": filename,
                    "size": size,
                    "size_mb": (size as f64 / (1024.0 * 1024.0) * 100.0).round() / 100.0,
                    "created_at": c_at,
                    "is_encrypted": false,
                    "is_scheduled": is_sched,
                    "profiles_count": p_count,
                    "has_proxy_credentials": has_cred,
                    "warning": if has_cred { "Contains proxy credentials" } else { "" },
                }));
            }
        }

        Ok(results)
    }

    pub fn delete(&self, path: &Path) -> Result<()> {
        let _operation = self.store.operation.lock();
        reject_link(path)?;

        let target_path = path.canonicalize().context("File not found")?;
        let backups_dir = self
            .store
            .backups_dir
            .canonicalize()
            .context("Backups dir not found")?;

        reject_link(&target_path)?;
        reject_link(&backups_dir)?;

        if !target_path.starts_with(&backups_dir) || target_path == backups_dir {
            bail!("Cannot delete files outside managed backup directory");
        }

        if !target_path.is_file() {
            bail!("Backup target must be a file");
        }

        let current_backups = self.list()?;
        let in_list = current_backups.iter().any(|b| {
            let p_str = string(b, "path");
            Path::new(p_str)
                .canonicalize()
                .map_or(false, |c| c == target_path)
        });
        if !in_list {
            bail!(
                "Backup file '{}' is not in managed backups list",
                target_path.display()
            );
        }

        fs::remove_file(&target_path)?;

        if let Some(name) = target_path.file_name().and_then(|s| s.to_str()) {
            let _ = remove_scheduled_file(&self.store, name);
        }

        let _ = self.store.log(
            "INFO",
            &format!(
                "Deleted backup file {}",
                target_path.file_name().unwrap_or_default().to_string_lossy()
            ),
            "",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_stream_roundtrip_tamper_and_wrong_password() {
        let payload = vec![0x5a; CHUNK_SIZE * 2 + 7];
        let mut encrypted = Vec::new();
        stream_encrypt(payload.as_slice(), &mut encrypted, "correct-password").unwrap();
        assert!(!encrypted.windows(payload.len()).any(|window| window == payload));
        let mut decrypted = Vec::new();
        stream_decrypt(encrypted.as_slice(), &mut decrypted, "correct-password", MAX_TOTAL_UNCOMPRESSED).unwrap();
        assert_eq!(decrypted, payload);
        assert!(stream_decrypt(encrypted.as_slice(), std::io::sink(), "wrong-password", MAX_TOTAL_UNCOMPRESSED).is_err());
        let mut tampered = encrypted.clone();
        let index = tampered.len() - 10;
        tampered[index] ^= 0x55;
        assert!(stream_decrypt(tampered.as_slice(), std::io::sink(), "correct-password", MAX_TOTAL_UNCOMPRESSED).is_err());
        assert!(stream_decrypt(&encrypted[..encrypted.len() - 20], std::io::sink(), "correct-password", MAX_TOTAL_UNCOMPRESSED).is_err());
        assert!(stream_decrypt(encrypted.as_slice(), std::io::sink(), "correct-password", payload.len() as u64 - 1).is_err());
    }

    #[test]
    fn archive_traversal_is_rejected_without_creating_escaped_files() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path().join("dest")).unwrap();
        let bad_zip = root.path().join("traversal.zip");

        // Build malicious zip with ../escaped.txt
        {
            let file = File::create(&bad_zip).unwrap();
            let mut zip = ZipWriter::new(file);
            let opts = SimpleFileOptions::default();
            zip.start_file("../escaped.txt", opts).unwrap();
            zip.write_all(b"malicious-payload").unwrap();
            zip.finish().unwrap();
        }

        // Parent files::extract_zip or verify_archive rejects it
        let out_dir = root.path().join("extracted");
        assert!(extract_zip(File::open(&bad_zip).unwrap(), &out_dir, 10_000_000, None).is_err());
        assert!(!root.path().join("escaped.txt").exists());
        assert!(store.list("profiles").unwrap().is_empty());
    }

    #[test]
    fn schedule_state_transitions() {
        let root = tempfile::tempdir().unwrap();
        let backend = crate::backend::Backend::open(root.path().join("store")).unwrap();
        let backups = &backend.backups;
        backend.store.save_settings(json!({"backup_interval_hours":0})).unwrap();
        assert_eq!(backups.state().unwrap()["state"], "disabled");
        assert!(!backups.tick().unwrap());

        backend.store.save_settings(json!({"backup_interval_hours":24})).unwrap();
        assert_eq!(backups.state().unwrap()["state"], "password_required");
        assert!(!backups.tick().unwrap());
        assert_eq!(backups.set_password("session-secret").unwrap()["state"], "waiting");
        assert!(backups.tick().is_err());
        assert_eq!(backups.state().unwrap()["state"], "error");
        assert_eq!(backups.set_password("session-secret").unwrap()["state"], "waiting");

        let profile = backend.profiles.create(json!({
            "name":"Scheduled", "os":"windows", "proxy_id":"",
            "location":{"locked":true}, "fingerprint_meta":{"use_preset":false}
        })).unwrap();
        assert!(backups.tick().unwrap());
        assert_eq!(backups.state().unwrap()["state"], "waiting");
        assert!(!backups.tick().unwrap());
        let archives = backups.list().unwrap();
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[0]["is_encrypted"], true);
        assert_eq!(archives[0]["is_scheduled"], true);
        let path = Path::new(archives[0]["path"].as_str().unwrap());
        assert!(backups.inspect(path, "wrong-password").is_err());
        let info = backups.inspect(path, "session-secret").unwrap();
        assert_eq!(info["profiles"][0]["id"], profile["id"]);
        assert_eq!(backups.set_password("").unwrap()["state"], "password_required");
        assert!(!backups.tick().unwrap());
    }

    #[test]
    fn retention_managed_only_preserves_manual_and_unrelated_files() {
        let root = tempfile::tempdir().unwrap();
        let backend = crate::backend::Backend::open(root.path().join("store")).unwrap();
        let store = &backend.store;

        let backups_dir = &store.backups_dir;
        fs::create_dir_all(backups_dir).unwrap();

        // 1. Create a manually named backup file
        let manual_file = backups_dir.join("scheduled_backup_keep_manual.zip");
        fs::write(&manual_file, b"manual backup").unwrap();

        // 2. Create an unrelated text file
        let unrelated_file = backups_dir.join("scheduled_backup_notes.txt");
        fs::write(&unrelated_file, b"Do not delete this").unwrap();

        // 3. Create two scheduled files tracked in .scheduled_backups.json
        let sched_1 = backups_dir.join("scheduled_backup_20261011_010000_111111.enc.zip");
        let sched_2 = backups_dir.join("scheduled_backup_20261011_020000_222222.enc.zip");
        fs::write(&sched_1, b"sched 1").unwrap();
        fs::write(&sched_2, b"sched 2").unwrap();

        add_scheduled_file(&store, "scheduled_backup_20261011_010000_111111.enc.zip").unwrap();
        add_scheduled_file(&store, "scheduled_backup_20261011_020000_222222.enc.zip").unwrap();

        File::options().write(true).open(&sched_1).unwrap().set_times(
            fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
        ).unwrap();
        File::options().write(true).open(&sched_2).unwrap().set_times(
            fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2))
        ).unwrap();
        backend.backups.apply_retention(0).unwrap();
        assert!(sched_1.exists());
        backend.backups.apply_retention(1).unwrap();
        assert!(!sched_1.exists());
        assert_eq!(fs::read(&sched_2).unwrap(), b"sched 2");
        let scheduled_names = load_scheduled_files(store);
        assert!(!scheduled_names.contains("scheduled_backup_20261011_010000_111111.enc.zip"));
        assert!(scheduled_names.contains("scheduled_backup_20261011_020000_222222.enc.zip"));

        // Manual and unrelated files are preserved
        assert!(manual_file.exists());
        assert_eq!(fs::read_to_string(&unrelated_file).unwrap(), "Do not delete this");
    }

    #[test]
    fn restore_remaps_ids_preserves_identity_and_credentials() {
        let root = tempfile::tempdir().unwrap();
        let src_store = Arc::new(Store::open(root.path().join("src")).unwrap());
        let dst_store = Arc::new(Store::open(root.path().join("dst")).unwrap());

        let proxy = src_store
            .put(
                "proxies",
                json!({
                    "name": "Secret proxy",
                    "server": "http://127.0.0.1:9000",
                    "username": "user",
                    "password": "secret"
                }),
            )
            .unwrap();
        let px_id = string(&proxy, "id").to_string();

        let profile = src_store
            .put(
                "profiles",
                json!({
                    "name": "Portable",
                    "os": "windows",
                    "location": {
                        "ip": "1.2.3.4",
                        "country": "US",
                        "timezone": "America/New_York",
                        "locale": "en-US",
                        "latitude": 40.7128,
                        "longitude": -74.006,
                        "locked": true
                    },
                    "proxy_id": px_id,
                    "browser_version": "v156.0.1-beta.36",
                    "fingerprint": {"navigator.userAgent": "portable-identity"},
                    "extensions": ["addons/my_ext"],
                    "note": "Literal path: C:\\Temp\\file.txt"
                }),
            )
            .unwrap();
        let prof_id = string(&profile, "id").to_string();

        let p_dir = src_store.profile_dir(&prof_id).unwrap();
        fs::create_dir_all(p_dir.join("browser")).unwrap();
        fs::write(p_dir.join("browser").join("cookies.sqlite"), b"cookie-data-123").unwrap();
        fs::create_dir_all(p_dir.join("addons").join("my_ext")).unwrap();
        fs::write(p_dir.join("addons").join("my_ext").join("manifest.json"), b"{\"version\":\"1\"}").unwrap();

        let network = Arc::new(crate::network::Network::new(src_store.clone()));
        {
            let fps = crate::fingerprints::FingerprintService::new(src_store.clone()).unwrap();
            let runtime = Arc::new(crate::runtime::Runtime::new(src_store.clone(), network, Arc::new(fps)));
            let backups = Backups::new(src_store.clone(), runtime);

            let archive_path = backups.create(&[prof_id.clone()], None, "password123").unwrap();
            assert!(archive_path.exists());

            // Inspect with wrong password fails
            assert!(backups.inspect(&archive_path, "wrong").is_err());

            // Inspect with correct password succeeds
            let info = backups.inspect(&archive_path, "password123").unwrap();
            assert_eq!(info["profiles_count"], 1);
            assert_eq!(info["has_proxy_credentials"], true);
            assert_eq!(info["proxies"][0]["has_credentials"],true);
            assert_eq!(info["proxies"][0]["has_password"],true);
            assert!(info["proxies"][0].get("password").is_none());
            assert!(info["proxies"][0].get("username").is_none());

            // Restore into dst_store
            let dst_network = Arc::new(crate::network::Network::new(dst_store.clone()));
            {
                let dst_fps = crate::fingerprints::FingerprintService::new(dst_store.clone()).unwrap();
                let dst_runtime = Arc::new(crate::runtime::Runtime::new(dst_store.clone(), dst_network, Arc::new(dst_fps)));
                let dst_backups = Backups::new(dst_store.clone(), dst_runtime);

                // Tamper test: flipped byte fails restore and leaves dst_store empty
                let enc_bytes = fs::read(&archive_path).unwrap();
                let mut bad_bytes = enc_bytes.clone();
                let flip_idx = bad_bytes.len() - 15;
                bad_bytes[flip_idx] ^= 0x99;
                let bad_archive = root.path().join("bad.cmbak");
                fs::write(&bad_archive, bad_bytes).unwrap();

                assert!(dst_backups.restore(&bad_archive, "password123").is_err());
                assert!(dst_store.list("profiles").unwrap().is_empty());
                assert!(dst_store.list("proxies").unwrap().is_empty());

                // Successful restore into dst_store
                let restored = dst_backups.restore(&archive_path, "password123").unwrap();
                assert_eq!(restored.len(), 1);
                let r_prof = &restored[0];
                let r_prof_id = string(r_prof, "id");
                let r_proxy_id = string(r_prof, "proxy_id");

                // Fresh IDs
                assert_ne!(r_prof_id, prof_id);
                assert_ne!(r_proxy_id, px_id);

                // Preserved proxy credentials in dst_store
                let saved_proxy = dst_store.get("proxies", r_proxy_id).unwrap().unwrap();
                assert_eq!(string(&saved_proxy, "password"), "secret");
                assert_eq!(string(&saved_proxy, "username"), "user");

                // Preserved note, fingerprint
                assert_eq!(r_prof["note"], "Literal path: C:\\Temp\\file.txt");
                assert_eq!(r_prof["fingerprint"]["navigator.userAgent"], "portable-identity");

                // Preserved files
                let dst_p_dir = dst_store.profile_dir(r_prof_id).unwrap();
                assert_eq!(fs::read(dst_p_dir.join("browser").join("cookies.sqlite")).unwrap(), b"cookie-data-123");
                assert!(dst_p_dir.join("addons").join("my_ext").join("manifest.json").is_file());
            }
        }
    }

    #[test]
    fn hash_valid_invalid_profile_and_proxy_restore_writes_no_records_or_final_dirs() {
        let root = tempfile::tempdir().unwrap();
        let dst_store = Arc::new(Store::open(root.path().join("dst")).unwrap());
        let dst_network = Arc::new(crate::network::Network::new(dst_store.clone()));
        let dst_fps = crate::fingerprints::FingerprintService::new(dst_store.clone()).unwrap();
        let dst_runtime = Arc::new(crate::runtime::Runtime::new(dst_store.clone(), dst_network, Arc::new(dst_fps)));
        let dst_backups = Backups::new(dst_store.clone(), dst_runtime);

        let build_archive = |zip_path: &Path, prof_id: &str, prof_val: Option<Value>, px_id: &str, px_val: Option<Value>| {
            let file = File::create(zip_path).unwrap();
            let mut zip = ZipWriter::new(file);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            let mut files_manifest = BTreeMap::new();
            let mut profiles_meta = Vec::new();
            let mut proxies_meta = Vec::new();

            if let Some(prof) = prof_val {
                let bytes = serde_json::to_vec_pretty(&prof).unwrap();
                let arc_name = format!("profiles/{prof_id}/profile.json");
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                files_manifest.insert(arc_name.clone(), json!({
                    "sha256": hex::encode(hasher.finalize()),
                    "size": bytes.len(),
                }));
                zip.start_file(&arc_name, opts).unwrap();
                zip.write_all(&bytes).unwrap();
                profiles_meta.push(json!({
                    "id": prof_id,
                    "name": prof.get("name").and_then(Value::as_str).unwrap_or(""),
                    "browser_version": "",
                    "proxy_id": prof.get("proxy_id").and_then(Value::as_str).unwrap_or(""),
                    "addons_count": 0,
                }));
            }

            if let Some(px) = px_val {
                let bytes = serde_json::to_vec_pretty(&px).unwrap();
                let arc_name = format!("proxies/{px_id}.json");
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                files_manifest.insert(arc_name.clone(), json!({
                    "sha256": hex::encode(hasher.finalize()),
                    "size": bytes.len(),
                }));
                zip.start_file(&arc_name, opts).unwrap();
                zip.write_all(&bytes).unwrap();
                proxies_meta.push(json!({
                    "id": px_id,
                    "name": px.get("name").and_then(Value::as_str).unwrap_or(""),
                    "server": px.get("server").and_then(Value::as_str).unwrap_or(""),
                    "has_credentials": false,
                    "has_password": false,
                }));
            }

            let manifest = json!({
                "schema_version": 1,
                "app": "CamouManager",
                "created_at": utcnow(),
                "is_scheduled": false,
                "profiles_count": profiles_meta.len(),
                "has_proxy_credentials": false,
                "profiles": profiles_meta,
                "proxies": proxies_meta,
                "versions": {},
                "compatibility": {
                    "os": "windows",
                    "notes": "Test",
                },
                "files": files_manifest,
            });

            let mf_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            zip.start_file("manifest.json", opts).unwrap();
            zip.write_all(&mf_bytes).unwrap();
            zip.finish().unwrap();
        };

        // 1. Hash-valid profile lacking location
        let pid1 = "11111111111111111111111111111111";
        let zip1 = root.path().join("missing_loc.zip");
        build_archive(&zip1, pid1, Some(json!({"id": pid1, "name": "NoLoc", "os": "windows", "proxy_id":"", "fingerprint":{"audio:seed":1}})), "", None);
        assert!(dst_backups.restore(&zip1, "").is_err());
        assert!(dst_store.list("profiles").unwrap().is_empty());
        assert!(dst_store.list("proxies").unwrap().is_empty());
        assert!(!dst_store.root.join("profiles").exists() || fs::read_dir(dst_store.root.join("profiles")).unwrap().next().is_none());

        // 2. Hash-valid profile with name exceeding limit (300 chars)
        let pid2 = "22222222222222222222222222222222";
        let zip2 = root.path().join("long_name.zip");
        let long_name = "x".repeat(300);
        build_archive(&zip2, pid2, Some(json!({"id": pid2, "name": long_name, "os": "windows", "proxy_id":"", "location": {}, "fingerprint":{"audio:seed":1}})), "", None);
        assert!(dst_backups.restore(&zip2, "").is_err());
        assert!(dst_store.list("profiles").unwrap().is_empty());

        // 3. Hash-valid proxy with invalid scheme
        let pxid = "33333333333333333333333333333333";
        let zip3 = root.path().join("bad_proxy.zip");
        build_archive(&zip3, "", None, pxid, Some(json!({"id": pxid, "server": "ftp://proxy.local:1080"})));
        assert!(dst_backups.restore(&zip3, "").is_err());
        assert!(dst_store.list("proxies").unwrap().is_empty());
        assert!(dst_store.list("profiles").unwrap().is_empty());

        let valid = json!({"id":pid1, "name":"Validated", "os":"windows", "proxy_id":"", "location":{}, "fingerprint":{"audio:seed":1}});
        let mut no_proxy = valid.clone();
        no_proxy.as_object_mut().unwrap().remove("proxy_id");
        let mut no_fingerprint = valid.clone();
        no_fingerprint.as_object_mut().unwrap().remove("fingerprint");
        let mut bad_coordinate = valid.clone();
        bad_coordinate["location"]["latitude"] = json!(91);
        let mut bad_url = valid;
        bad_url["startup_urls"] = json!(["javascript://alert(1)"]);
        for profile in [no_proxy, no_fingerprint, bad_coordinate, bad_url] {
            build_archive(&zip1, pid1, Some(profile), "", None);
            assert!(dst_backups.restore(&zip1, "").is_err());
            assert!(dst_store.list("profiles").unwrap().is_empty());
            assert!(dst_store.list("proxies").unwrap().is_empty());
            assert!(fs::read_dir(&dst_store.profiles_dir).unwrap().next().is_none());
        }
        for fields in [json!({"enabled":"false"}), json!({"password":null}), json!({"last_check":{"ip":{}}})] {
            let mut proxy = json!({"id":pxid, "server":"http://127.0.0.1:1080"});
            proxy.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
            build_archive(&zip3, "", None, pxid, Some(proxy));
            assert!(dst_backups.restore(&zip3, "").is_err());
            assert!(dst_store.list("proxies").unwrap().is_empty());
        }
    }

    #[test]
    #[cfg(windows)]
    fn retention_retries_after_transient_file_lock() {
        let root = tempfile::tempdir().unwrap();
        let backend = crate::backend::Backend::open(root.path().join("store")).unwrap();
        let store = &backend.store;

        let backups_dir = &store.backups_dir;
        fs::create_dir_all(backups_dir).unwrap();

        let s1_name = "scheduled_backup_20261011_010000_111111.enc.zip";
        let s2_name = "scheduled_backup_20261011_020000_222222.enc.zip";
        let sched_1 = backups_dir.join(s1_name);
        let sched_2 = backups_dir.join(s2_name);
        fs::write(&sched_1, b"sched 1").unwrap();
        fs::write(&sched_2, b"sched 2").unwrap();

        add_scheduled_file(store, s1_name).unwrap();
        add_scheduled_file(store, s2_name).unwrap();

        File::options().write(true).open(&sched_1).unwrap().set_times(
            fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
        ).unwrap();
        File::options().write(true).open(&sched_2).unwrap().set_times(
            fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2))
        ).unwrap();

        // Hold a share-lock on sched_1 to simulate Windows file lock
        use std::os::windows::fs::OpenOptionsExt;
        let lock = File::options().read(true).share_mode(1).open(&sched_1).unwrap();

        backend.backups.apply_retention(1).unwrap();
        // Failed removal must keep the filename in scheduled metadata
        assert!(sched_1.exists());
        let scheduled_names = load_scheduled_files(store);
        assert!(scheduled_names.contains(s1_name));
        assert!(scheduled_names.contains(s2_name));

        // Release the lock and retry retention
        drop(lock);
        backend.backups.apply_retention(1).unwrap();
        assert!(!sched_1.exists());
        assert!(sched_2.exists());
        let scheduled_names = load_scheduled_files(store);
        assert!(!scheduled_names.contains(s1_name));
        assert!(scheduled_names.contains(s2_name));
    }
    fn patch_zip_entry_uncompressed_size(path: &Path, target_name: &str, new_size: u32) {
        let mut data = fs::read(path).unwrap();
        let target_bytes = target_name.as_bytes();
        let size_bytes = new_size.to_le_bytes();

        let mut i = 0;
        while i + 30 <= data.len() {
            if &data[i..i + 4] == b"PK\x03\x04" {
                let fn_len = u16::from_le_bytes([data[i + 26], data[i + 27]]) as usize;
                if i + 30 + fn_len <= data.len()
                    && fn_len == target_bytes.len()
                    && &data[i + 30..i + 30 + fn_len] == target_bytes
                {
                    data[i + 22..i + 26].copy_from_slice(&size_bytes);
                }
                i += 30;
            } else {
                i += 1;
            }
        }

        let mut j = 0;
        while j + 46 <= data.len() {
            if &data[j..j + 4] == b"PK\x01\x02" {
                let fn_len = u16::from_le_bytes([data[j + 28], data[j + 29]]) as usize;
                if j + 46 + fn_len <= data.len()
                    && fn_len == target_bytes.len()
                    && &data[j + 46..j + 46 + fn_len] == target_bytes
                {
                    data[j + 24..j + 28].copy_from_slice(&size_bytes);
                }
                j += 46;
            } else {
                j += 1;
            }
        }

        fs::write(path, data).unwrap();
    }

    #[test]
    fn verify_archive_rejects_deflated_manifest_exceeding_max_size_with_small_declared_size() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(root.path().join("store")).unwrap());
        let network = Arc::new(crate::network::Network::new(store.clone()));
        let fps = crate::fingerprints::FingerprintService::new(store.clone()).unwrap();
        let runtime = Arc::new(crate::runtime::Runtime::new(store.clone(), network, Arc::new(fps)));
        let backups = Backups::new(store, runtime);

        let zip_path = root.path().join("large_manifest.zip");
        {
            let file = File::create(&zip_path).unwrap();
            let mut zip = ZipWriter::new(file);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

            let mut large_manifest = Vec::with_capacity(10 * 1024 * 1024 + 2048);
            large_manifest.extend_from_slice(b"{\"schema_version\":1,\"app\":\"CamouManager\",\"padding\":\"");
            large_manifest.resize(10 * 1024 * 1024 + 1024, b'A');
            large_manifest.extend_from_slice(b"\"}");

            zip.start_file("manifest.json", opts).unwrap();
            zip.write_all(&large_manifest).unwrap();
            zip.finish().unwrap();
        }

        patch_zip_entry_uncompressed_size(&zip_path, "manifest.json", 2);

        let res = backups.inspect(&zip_path, "");
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("Manifest file exceeds size limit"));
    }

    #[test]
    fn verify_archive_rejects_malicious_file_sizes_in_hashing() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(root.path().join("store")).unwrap());
        let network = Arc::new(crate::network::Network::new(store.clone()));
        let fps = crate::fingerprints::FingerprintService::new(store.clone()).unwrap();
        let runtime = Arc::new(crate::runtime::Runtime::new(store.clone(), network, Arc::new(fps)));
        let backups = Backups::new(store, runtime);

        let pid = "11111111111111111111111111111111";
        let profile_content = json!({
            "id": pid,
            "name": "TestProfile",
            "os": "windows",
            "proxy_id": "",
            "location": {},
            "fingerprint": {"audio:seed": 1}
        });
        let prof_bytes = serde_json::to_vec_pretty(&profile_content).unwrap();
        let arc_name = format!("profiles/{pid}/profile.json");

        let mut hasher = Sha256::new();
        hasher.update(&prof_bytes);
        let actual_hash = hex::encode(hasher.finalize());

        // 1. Entry uncompressed size in ZIP header patched to 2 bytes, actual > 2 bytes
        let zip_path1 = root.path().join("zip_declared_size_lying.zip");
        {
            let file = File::create(&zip_path1).unwrap();
            let mut zip = ZipWriter::new(file);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

            let manifest = json!({
                "schema_version": 1,
                "app": "CamouManager",
                "created_at": utcnow(),
                "is_scheduled": false,
                "profiles_count": 1,
                "has_proxy_credentials": false,
                "profiles": [{"id": pid, "name": "TestProfile", "browser_version": "", "proxy_id": "", "addons_count": 0}],
                "proxies": [],
                "versions": {},
                "files": {
                    arc_name.clone(): {
                        "size": prof_bytes.len(),
                        "sha256": actual_hash
                    }
                }
            });
            let mf_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            zip.start_file("manifest.json", opts).unwrap();
            zip.write_all(&mf_bytes).unwrap();

            zip.start_file(&arc_name, opts).unwrap();
            zip.write_all(&prof_bytes).unwrap();
            zip.finish().unwrap();
        }
        patch_zip_entry_uncompressed_size(&zip_path1, &arc_name, 2);

        let res1 = backups.inspect(&zip_path1, "");
        assert!(res1.is_err());
        let err1 = res1.err().unwrap().to_string();
        assert!(err1.contains("size mismatch"));

        // 2. Manifest expected size lies (declares 2 bytes), actual > 2 bytes
        let zip_path2 = root.path().join("manifest_expected_size_lying.zip");
        {
            let file = File::create(&zip_path2).unwrap();
            let mut zip = ZipWriter::new(file);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

            let manifest = json!({
                "schema_version": 1,
                "app": "CamouManager",
                "created_at": utcnow(),
                "is_scheduled": false,
                "profiles_count": 1,
                "has_proxy_credentials": false,
                "profiles": [{"id": pid, "name": "TestProfile", "browser_version": "", "proxy_id": "", "addons_count": 0}],
                "proxies": [],
                "versions": {},
                "files": {
                    arc_name.clone(): {
                        "size": 2,
                        "sha256": actual_hash
                    }
                }
            });
            let mf_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            zip.start_file("manifest.json", opts).unwrap();
            zip.write_all(&mf_bytes).unwrap();

            zip.start_file(&arc_name, opts).unwrap();
            zip.write_all(&prof_bytes).unwrap();
            zip.finish().unwrap();
        }

        let res2 = backups.inspect(&zip_path2, "");
        assert!(res2.is_err());
        let err2 = res2.err().unwrap().to_string();
        assert!(err2.contains("size mismatch"));

        // 3. Manifest expected size exceeds MAX_SINGLE_FILE
        let zip_path3 = root.path().join("manifest_exceeds_max_single_file.zip");
        {
            let file = File::create(&zip_path3).unwrap();
            let mut zip = ZipWriter::new(file);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

            let manifest = json!({
                "schema_version": 1,
                "app": "CamouManager",
                "created_at": utcnow(),
                "is_scheduled": false,
                "profiles_count": 1,
                "has_proxy_credentials": false,
                "profiles": [{"id": pid, "name": "TestProfile", "browser_version": "", "proxy_id": "", "addons_count": 0}],
                "proxies": [],
                "versions": {},
                "files": {
                    arc_name.clone(): {
                        "size": MAX_SINGLE_FILE + 1,
                        "sha256": actual_hash
                    }
                }
            });
            let mf_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            zip.start_file("manifest.json", opts).unwrap();
            zip.write_all(&mf_bytes).unwrap();

            zip.start_file(&arc_name, opts).unwrap();
            zip.write_all(&prof_bytes).unwrap();
            zip.finish().unwrap();
        }

        let res3 = backups.inspect(&zip_path3, "");
        assert!(res3.is_err());
        let err3 = res3.err().unwrap().to_string();
        assert!(err3.contains("maximum file size limit"));
    }

    #[test]
    fn crash_safe_plaintext_cleanup_child_and_roundtrip() {
        if let Ok(dir) = std::env::var("CAMOU_TEST_ABRUPT_EXIT_CHILD") {
            let backend = crate::backend::Backend::open(PathBuf::from(dir)).unwrap();
            let archive = std::env::var("CAMOU_TEST_CRASH_ARCHIVE").unwrap();
            backend.backups.inspect(Path::new(&archive), "super-secret").unwrap();
            panic!("Crash injection was not reached after plaintext decryption");
        }
        let root = tempfile::tempdir().unwrap();
        // 2. Encrypted roundtrip create, inspect, restore leaves zero plaintext residue
        let backend = crate::backend::Backend::open(root.path().join("store")).unwrap();
        let p = backend.profiles.create(json!({
            "name": "EncryptedRoundtrip",
            "os": "windows",
            "proxy_id": "",
            "location": {"locked": true},
            "fingerprint": {"audio:seed": 42}
        })).unwrap();
        let pid = string(&p, "id");
        fs::write(backend.store.profile_dir(pid).unwrap().join("browser/cookies.sqlite"), b"private-cookie-test").unwrap();
        let enc_dest = root.path().join("encrypted.cmbak");
        let path = backend.backups.create(&[pid.to_string()], Some(&enc_dest), "super-secret").unwrap();
        assert_eq!(path, enc_dest);
        assert!(enc_dest.exists());
        let child_home = root.path().join("crashed-inspection");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .env("CAMOU_TEST_ABRUPT_EXIT_CHILD", &child_home)
            .env("CAMOU_TEST_CRASH_ARCHIVE", &enc_dest)
            .args(["crash_safe_plaintext_cleanup_child_and_roundtrip", "--nocapture"])
            .status().unwrap();
        assert!(status.success());
        for entry in fs::read_dir(&child_home).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!bytes.starts_with(b"PK"), "Abrupt inspection left a plaintext ZIP in {:?}", entry.path());
                assert!(!bytes.windows(b"private-cookie-test".len()).any(|bytes| bytes == b"private-cookie-test"),
                    "Abrupt inspection left decrypted cookies in {:?}", entry.path());
            }
        }

        // Inspect
        let info = backend.backups.inspect(&enc_dest, "super-secret").unwrap();
        assert_eq!(info["profiles_count"], 1);

        // Restore into new store
        let dst_backend = crate::backend::Backend::open(root.path().join("dst_store")).unwrap();
        let restored = dst_backend.backups.restore(&enc_dest, "super-secret").unwrap();
        assert_eq!(restored.len(), 1);
        let restored_id = string(&restored[0], "id");
        assert_eq!(fs::read(dst_backend.store.profile_dir(restored_id).unwrap().join("browser/cookies.sqlite")).unwrap(), b"private-cookie-test");

        // Check neither store root has any .tmp files
        for store_dir in [&backend.store.root, &dst_backend.store.root] {
            for entry in fs::read_dir(store_dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                assert!(!name.ends_with(".tmp"), "Found temporary file in store root: {name}");
                assert!(!name.contains("_backup_zip_") && !name.contains("_decrypted_zip_"), "Found backup tmp residue: {name}");
            }
        }

        // 3. Legacy residue cleanup removes known legacy residues and surfaces errors
        let leg1 = backend.store.root.join("_backup_zip_11111111111111111111111111111111.tmp");
        let leg2 = backend.store.root.join("_decrypted_zip_22222222222222222222222222222222.tmp");
        fs::write(&leg1, b"legacy 1").unwrap();
        fs::write(&leg2, b"legacy 2").unwrap();
        let unrelated = backend.store.root.join("_backup_zip_report.tmp");
        fs::write(&unrelated, b"unrelated user file").unwrap();
        assert!(leg1.exists());
        assert!(leg2.exists());
        cleanup_legacy_residues(&backend.store.root).unwrap();
        assert!(!leg1.exists());
        assert!(!leg2.exists());
        assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated user file");
    }

    #[test]
    fn restore_publication_rollback_ordering_deterministic_failure() {
        if let Ok(dir) = std::env::var("CAMOU_TEST_RESTORE_PUBLICATION_EXIT") {
            let backend = crate::backend::Backend::open(PathBuf::from(dir)).unwrap();
            let archive = std::env::var("CAMOU_TEST_CRASH_ARCHIVE").unwrap();
            backend.backups.restore(Path::new(&archive), "").unwrap();
            panic!("Publication crash injection was not reached");
        }
        let root = tempfile::tempdir().unwrap();
        let src_store = Arc::new(Store::open(root.path().join("src")).unwrap());
        let src_net = Arc::new(crate::network::Network::new(src_store.clone()));
        let src_fps = Arc::new(crate::fingerprints::FingerprintService::new(src_store.clone()).unwrap());
        let src_runtime = Arc::new(crate::runtime::Runtime::new(src_store.clone(), src_net, src_fps.clone()));
        let src_backups = Backups::new(src_store.clone(), src_runtime);

        let p = src_store.put("profiles", json!({
            "name": "RollbackTest",
            "os": "windows",
            "proxy_id": "",
            "location": {},
            "fingerprint": {"audio:seed": 7}
        })).unwrap();
        let pid = string(&p, "id");
        let prof_dir = src_store.profile_dir(pid).unwrap();
        fs::create_dir_all(prof_dir.join("browser")).unwrap();
        fs::write(prof_dir.join("browser").join("cookies.sqlite"), b"browser-cookie-data").unwrap();

        let archive = root.path().join("archive.zip");
        src_backups.create(&[pid.to_string()], Some(&archive), "").unwrap();

        let dst_store = Arc::new(Store::open(root.path().join("dst")).unwrap());
        let dst_net = Arc::new(crate::network::Network::new(dst_store.clone()));
        let dst_fps = Arc::new(crate::fingerprints::FingerprintService::new(dst_store.clone()).unwrap());
        let dst_runtime = Arc::new(crate::runtime::Runtime::new(dst_store.clone(), dst_net, dst_fps));
        let dst_backups = Backups::new(dst_store.clone(), dst_runtime);
        let crashed_home = root.path().join("crashed-restore");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .env("CAMOU_TEST_RESTORE_PUBLICATION_EXIT", &crashed_home)
            .env("CAMOU_TEST_CRASH_ARCHIVE", &archive)
            .args(["restore_publication_rollback_ordering_deterministic_failure", "--nocapture"])
            .status().unwrap();
        assert!(status.success());
        let reopened = crate::backend::Backend::open(crashed_home).unwrap();
        assert!(reopened.store.list("profiles").unwrap().is_empty());
        assert!(reopened.store.list("proxies").unwrap().is_empty());
        let published: Vec<_> = fs::read_dir(&reopened.store.profiles_dir).unwrap().map(|entry| entry.unwrap().path()).collect();
        assert_eq!(published.len(), 1, "Fault must occur after profile directory publication");
        assert_eq!(fs::read(published[0].join("browser/cookies.sqlite")).unwrap(), b"browser-cookie-data");

        // Inject SQLite trigger to simulate deterministic DB failure during put_batch
        let database = rusqlite::Connection::open(dst_store.root.join("state.sqlite3")).unwrap();
        database.execute(
            "CREATE TRIGGER fail_profiles BEFORE INSERT ON records WHEN NEW.kind = 'profiles' BEGIN SELECT RAISE(ABORT, 'Simulated DB failure during restore'); END;",
            [],
        ).unwrap();

        let res = dst_backups.restore(&archive, "");
        assert!(res.is_err());
        let err_str = res.err().unwrap().to_string();
        assert!(err_str.contains("Restore failed and was rolled back") || err_str.contains("Simulated DB failure"));

        // Ordering & cleanup verification:
        // No DB records exist
        assert!(dst_store.list("profiles").unwrap().is_empty());
        // All published profile directories in dst_store.profiles_dir were removed by rollback!
        let remaining_profile_dirs: Vec<_> = fs::read_dir(&dst_store.profiles_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(remaining_profile_dirs.is_empty(), "Found orphan published profile dirs after rollback: {:?}", remaining_profile_dirs);

        // Now drop trigger and verify normal restore succeeds
        database.execute("DROP TRIGGER fail_profiles;", []).unwrap();
        let restored = dst_backups.restore(&archive, "").unwrap();
        assert_eq!(restored.len(), 1);
        let restored_id = string(&restored[0], "id");
        assert_eq!(fs::read(dst_store.profile_dir(restored_id).unwrap().join("browser/cookies.sqlite")).unwrap(), b"browser-cookie-data");
    }

    #[test]
    fn create_and_restore_matching_boundaries_small_limits() {
        let root = tempfile::tempdir().unwrap();
        let source = crate::backend::Backend::open(root.path().join("source")).unwrap();
        let profile = source.profiles.create(json!({"name": "Limits", "os": "windows", "proxy_id": "",
            "location": {"locked": true}, "fingerprint": {"audio:seed": 9}})).unwrap();
        let id = string(&profile, "id").to_owned();
        let payload = vec![b'C'; 8192];
        fs::write(source.store.profile_dir(&id).unwrap().join("browser/profile.json"), &payload).unwrap();
        let baseline = source.backups.create(&[id.clone()], Some(&root.path().join("baseline.zip")), "").unwrap();
        let mut zip = ZipArchive::new(File::open(&baseline).unwrap()).unwrap();
        let mut limits = ArchiveLimits {max_single_file: 0, max_total_uncompressed: 0,
            max_entries: zip.len(), max_manifest_size: 0, max_metadata_size: 0};
        let profile_metadata = format!("profiles/{id}/profile.json");
        for index in 0..zip.len() {
            let entry = zip.by_index(index).unwrap();
            limits.max_single_file = limits.max_single_file.max(entry.size());
            limits.max_total_uncompressed += entry.size();
            if entry.name() == "manifest.json" { limits.max_manifest_size = entry.size(); }
            if entry.name() == profile_metadata { limits.max_metadata_size = entry.size(); }
        }
        let matching = source.backups.create_with_limits(&[id.clone()], Some(&root.path().join("matching.zip")), "", limits).unwrap();
        let target = crate::backend::Backend::open(root.path().join("target")).unwrap();
        let restored = target.backups.restore_with_limits(&matching, "", limits).unwrap();
        assert_eq!(restored[0]["fingerprint"], profile["fingerprint"]);
        assert_eq!(fs::read(target.store.profile_dir(string(&restored[0], "id")).unwrap().join("browser/profile.json")).unwrap(), payload);
        for (name, tighter) in [
            ("single", ArchiveLimits {max_single_file: limits.max_single_file - 1, ..limits}),
            ("total", ArchiveLimits {max_total_uncompressed: limits.max_total_uncompressed - 1, ..limits}),
            ("entries", ArchiveLimits {max_entries: limits.max_entries - 1, ..limits}),
            ("manifest", ArchiveLimits {max_manifest_size: limits.max_manifest_size - 1, ..limits}),
            ("metadata", ArchiveLimits {max_metadata_size: limits.max_metadata_size - 1, ..limits}),
        ] {
            let rejected = root.path().join(format!("rejected-{name}.zip"));
            assert!(source.backups.create_with_limits(&[id.clone()], Some(&rejected), "", tighter).is_err(), "Writer accepted {name} overflow");
            assert!(!rejected.exists(), "Failed backup was published");
            assert!(target.backups.restore_with_limits(&baseline, "", tighter).is_err(), "Reader accepted {name} overflow");
            assert_eq!(target.store.list("profiles").unwrap().len(), 1, "Rejected restore published records");
        }
    }

    #[test]
    fn scheduler_mixed_running_and_stopped_and_all_running() {
        let root = tempfile::tempdir().unwrap();
        let backend = crate::backend::Backend::open(root.path().join("store")).unwrap();
        let backups = &backend.backups;

        backend.store.save_settings(json!({
            "backup_interval_hours": 24,
        })).unwrap();
        backups.set_password("scheduled-secret").unwrap();

        let p1 = backend.profiles.create(json!({
            "name": "Profile1",
            "os": "windows",
            "proxy_id": "",
            "location": {"locked": true},
            "fingerprint": {"audio:seed": 1}
        })).unwrap();
        let p1_id = string(&p1, "id").to_string();

        let p2 = backend.profiles.create(json!({
            "name": "Profile2",
            "os": "windows",
            "proxy_id": "",
            "location": {"locked": true},
            "fingerprint": {"audio:seed": 2}
        })).unwrap();
        let p2_id = string(&p2, "id").to_string();

        // 1. ALL RUNNING: both profiles marked running
        backend.runtime.mark_starting_for_test(&p1_id);
        backend.runtime.mark_starting_for_test(&p2_id);

        let ticked_all_running = backups.tick().unwrap();
        // Returns false because none remain to be backed up
        assert!(!ticked_all_running);
        assert_eq!(backups.state().unwrap()["state"], "waiting");
        assert!(backups.list().unwrap().is_empty());
        let settings = backend.store.settings().unwrap();
        let last_at = string(&settings, "last_scheduled_backup_at");
        assert!(last_at.is_empty(), "last_scheduled_backup_at must not be set when all profiles are running");

        // 2. MIXED RUNNING AND STOPPED: stop Profile2 while Profile1 is still running
        backend.runtime.stop(&p2_id).unwrap();
        assert!(backend.runtime.is_running(&p1_id));
        assert!(!backend.runtime.is_running(&p2_id));

        let ticked_mixed = backups.tick().unwrap();
        assert!(ticked_mixed);
        assert_eq!(backups.state().unwrap()["state"], "waiting");

        let archives = backups.list().unwrap();
        assert_eq!(archives.len(), 1);
        let path = Path::new(archives[0]["path"].as_str().unwrap());
        let info = backups.inspect(path, "scheduled-secret").unwrap();
        let backed_up_ids: Vec<String> = info["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| string(p, "id").to_string())
            .collect();
        assert_eq!(backed_up_ids, vec![p2_id]);

        let settings = backend.store.settings().unwrap();
        let last_at = string(&settings, "last_scheduled_backup_at");
        assert!(!last_at.is_empty(), "last_scheduled_backup_at must be recorded on successful backup");

        // Cleanup running session
        backend.runtime.stop(&p1_id).unwrap();
    }

    #[test]
    fn metadata_oversize_and_actual_decoded_bound() {
        let root = tempfile::tempdir().unwrap();
        for proxy_metadata in [false, true] {
            let source = crate::backend::Backend::open(root.path().join(format!("source-{proxy_metadata}"))).unwrap();
            let proxy = if proxy_metadata {
                source.store.put("proxies", json!({"name": "Proxy", "server": "http://127.0.0.1:19001", "enabled": true,
                    "padding": "A".repeat(MAX_METADATA_SIZE as usize)})).unwrap()
            } else { Value::Null };
            let mut profile = json!({"name": "Metadata", "os": "windows", "proxy_id": string(&proxy, "id"),
                "location": {"locked": true}, "fingerprint": {"audio:seed": 9}});
            if !proxy_metadata { profile["padding"] = json!("A".repeat(MAX_METADATA_SIZE as usize)); }
            let profile = source.store.put("profiles", profile).unwrap();
            let id = string(&profile, "id").to_owned();
            let permissive = ArchiveLimits {max_metadata_size: MAX_METADATA_SIZE + 4096, ..ArchiveLimits::default()};
            let archive = source.backups.create_with_limits(&[id.clone()], Some(&root.path().join(format!("oversized-{proxy_metadata}.zip"))), "", permissive).unwrap();
            assert!(fs::metadata(&archive).unwrap().len() < 64 * 1024, "Fixture must be small despite large decoded metadata");
            assert!(source.backups.inspect(&archive, "").unwrap_err().to_string().contains("Metadata entry exceeds declared size limit"));
            let target = crate::backend::Backend::open(root.path().join(format!("target-{proxy_metadata}"))).unwrap();
            assert!(target.backups.restore(&archive, "").is_err());
            assert!(target.store.list("profiles").unwrap().is_empty());
            assert!(target.store.list("proxies").unwrap().is_empty());
            let restored = target.backups.restore_with_limits(&archive, "", permissive).unwrap();
            assert_eq!(restored[0]["fingerprint"], profile["fingerprint"], "Oversized fixture must otherwise be a valid archive");
            let rejected = root.path().join(format!("rejected-metadata-{proxy_metadata}.zip"));
            assert!(source.backups.create(&[id], Some(&rejected), "").is_err());
            assert!(!rejected.exists());
        }
    }
}
