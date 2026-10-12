use anyhow::{anyhow, bail, Result};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use tauri::{AppHandle, Emitter};
use crate::{backups::Backups, fingerprints::FingerprintService, network::{Network, summary}, profiles::Profiles, runtime::Runtime, store::{require_str, string, Store}, versions::Versions};

pub struct Backend {
    pub store: Arc<Store>,
    pub network: Arc<Network>,
    pub fingerprints: Arc<FingerprintService>,
    pub runtime: Arc<Runtime>,
    pub versions: Arc<Versions>,
    pub backups: Arc<Backups>,
    pub profiles: Profiles,
    activity: Mutex<Activity>,
    pub closing: AtomicBool,
    pub english: AtomicBool,
    stopped: AtomicBool,
}
#[derive(Default)]
struct Activity { busy: usize, mutations: usize, shutdown: bool }
struct Operation<'a> { backend: &'a Backend, mutation: bool }
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let mut activity = self.backend.activity.lock();
        activity.busy -= 1;
        if self.mutation { activity.mutations -= 1; }
    }
}

impl Backend {
    pub fn open(root: PathBuf) -> Result<Self> {
        let store = Arc::new(Store::open(root)?);
        let network = Arc::new(Network::new(store.clone()));
        let fingerprints = Arc::new(FingerprintService::new(store.clone())?);
        let runtime = Arc::new(Runtime::new(store.clone(), network.clone(), fingerprints.clone()));
        let versions = Arc::new(Versions::new(store.clone()));
        let backups = Arc::new(Backups::new(store.clone(), runtime.clone()));
        let profiles = Profiles::new(store.clone(),runtime.clone(),network.clone(),fingerprints.clone());
        Ok(Self { store, network, fingerprints, runtime, versions, backups, profiles, activity: Mutex::new(Activity::default()), closing: AtomicBool::new(false), english: AtomicBool::new(false), stopped: AtomicBool::new(false) })
    }
    pub fn status(&self) -> Result<Value> {
        let statuses = self.runtime.status()?;
        let running = statuses.as_object().map(|m| m.values().filter(|s| matches!(string(s,"state"),"running"|"starting"|"stopping")).count()).unwrap_or(0);
        Ok(json!({"statuses":statuses,"running_count":running,"max_running":self.store.settings()?["max_running"],"backup":self.backups.state()?,"installation":self.versions.status(),"busy":self.activity.lock().busy}))
    }
    pub fn snapshot(&self) -> Result<Value> {
        let statuses = self.runtime.status()?;
        let proxies = self.store.list("proxies")?;
        let mut profiles = self.store.list("profiles")?;
        for profile in &mut profiles {
            let id = string(profile,"id").to_owned();
            let proxy = proxies.iter().find(|p| string(p,"id") == string(profile,"proxy_id"));
            let proxy_name = proxy.map(|p| string(p,"name")).unwrap_or("").to_owned();
            let map = profile.as_object_mut().ok_or_else(|| anyhow!("Hồ sơ lưu trữ không hợp lệ"))?;
            map.remove("fingerprint");
            map.insert("proxy_name".into(),json!(proxy_name));
            if let Some(status) = statuses.get(&id).and_then(Value::as_object) { map.extend(status.clone()); }
            else { map.insert("state".into(),json!("stopped")); }
        }
        Ok(json!({"profiles":profiles,"proxies":proxies.iter().map(summary).collect::<Vec<_>>(),"versions":self.versions.installed()?,"settings":self.store.settings()?,"fingerprint_data":self.fingerprints.info()?,"root":self.store.root,"backup":self.backups.state()?,"installation":self.versions.status()}))
    }
    pub fn shutdown(&self) -> Result<()> {
        {
            let mut activity = self.activity.lock();
            if activity.mutations > 0 || self.versions.is_active() { bail!("Có tác vụ thay đổi dữ liệu đang chạy"); }
            activity.shutdown = true;
        }
        if let Err(error) = self.runtime.stop_all() { self.activity.lock().shutdown = false; return Err(error); }
        self.stopped.store(true,Ordering::Release);
        Ok(())
    }
    fn begin(&self, mutation: bool) -> Result<Operation<'_>> {
        let mut activity = self.activity.lock();
        if activity.shutdown { bail!("Ứng dụng đang đóng"); }
        activity.busy += 1;
        if mutation { activity.mutations += 1; }
        Ok(Operation { backend:self, mutation })
    }
    fn check_proxy_closed(&self, id: &str) -> Result<()> {
        if !id.is_empty() && self.store.list("profiles")?.iter().any(|p| string(p,"proxy_id") == id && self.runtime.is_running(string(p,"id"))) { bail!("Proxy đang được sử dụng bởi hồ sơ đang chạy"); }
        Ok(())
    }
    pub fn request(&self, method: &str, params: Value, app: Option<&AppHandle>) -> Result<Value> {
        if !params.is_object() || method.len() > 80 || serde_json::to_vec(&params)?.len() > 4 * 1024 * 1024 { bail!("Yêu cầu không hợp lệ hoặc vượt 4 MiB"); }
        for key in ["id","proxy_id","name","path","password","text","group","destination","action","language"] {
            if params.get(key).is_some_and(|v| !v.is_string()) { bail!("'{key}' phải là chuỗi"); }
        }
        for key in ["full","headless"] {
            if params.get(key).is_some_and(|v| !v.is_boolean()) { bail!("'{key}' phải là boolean"); }
        }
        for key in ["ids","tags"] {
            if let Some(value) = params.get(key) {
                let rows = value.as_array().ok_or_else(|| anyhow!("'{key}' phải là danh sách"))?;
                if rows.iter().any(|v| !v.is_string()) || (key == "ids" && rows.is_empty()) { bail!("'{key}' không hợp lệ"); }
            }
        }
        for key in ["data","proxy"] {
            if params.get(key).is_some_and(|v| !v.is_object()) { bail!("'{key}' phải là object"); }
        }
        if method == "app.shutdown" { self.shutdown()?; return Ok(Value::Null); }
        let mutation = !matches!(method,"app.snapshot"|"app.status"|"app.language"|"profile.get"|"location.detect"|"backup.list"|"backup.inspect"|"versions.available"|"versions.installed"|"versions.control"|"logs.list");
        let operation = self.begin(mutation)?;
        let id = || require_str(&params,"id");
        let data = || params.get("data").cloned().ok_or_else(|| anyhow!("Thiếu data"));
        let ids = || -> Result<Vec<String>> { params["ids"].as_array().ok_or_else(|| anyhow!("ids phải là danh sách"))?.iter().map(|v| v.as_str().filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_owned()).ok_or_else(|| anyhow!("ID phải là chuỗi không trống"))).collect() };
        let result = match method {
            "app.snapshot" => self.snapshot(),
            "app.status" => self.status(),
            "app.language" => {
                let language = params.get("language").and_then(Value::as_str).ok_or_else(|| anyhow!("Thiếu 'language'"))?;
                match language {
                    "vi" => self.english.store(false, Ordering::Relaxed),
                    "en" => self.english.store(true, Ordering::Relaxed),
                    _ => bail!("Ngôn ngữ không hợp lệ"),
                }
                Ok(Value::Null)
            },
            "profile.get" => self.profiles.get(id()?),
            "profile.create" => self.profiles.create(data()?),
            "profile.update" => self.profiles.update(id()?,data()?),
            "profile.delete" => { self.profiles.delete_many(&ids()?)?; Ok(Value::Null) },
            "profile.duplicate" => self.profiles.duplicate(id()?,params["full"].as_bool().unwrap_or(false),string(&params,"name")),
            "profile.launch"|"profile.stop" => {
                let mut succeeded = Vec::new();
                let mut errors = Vec::new();
                for id in ids()? {
                    let result = if method == "profile.launch" { self.runtime.launch(&id,params["headless"].as_bool().unwrap_or(false)).map(|_| ()) } else { self.runtime.stop(&id) };
                    match result {
                        Ok(()) => succeeded.push(id),
                        Err(error) => errors.push(json!({"id":id,"message":crate::store::redact(&format!("{error:#}"))})),
                    }
                }
                Ok(json!({"succeeded":succeeded,"errors":errors}))
            },
            "profile.stop_all" => { self.runtime.stop_all()?; Ok(Value::Null) },
            "profile.assign_proxy" => { self.profiles.set_many(&ids()?,"proxy_id",json!(string(&params,"proxy_id")))?; Ok(Value::Null) },
            "profile.set_tags" => { self.profiles.set_many(&ids()?,"tags",params["tags"].clone())?; Ok(Value::Null) },
            "profile.set_group" => { self.profiles.set_many(&ids()?,"group",json!(string(&params,"group")))?; Ok(Value::Null) },
            "profile.regenerate" => self.profiles.regenerate(id()?),
            "profile.import_extension" => self.profiles.import_extension(id()?,Path::new(require_str(&params,"path")?)).map(|p| json!(p)),
            "profile.remove_extension" => { self.profiles.remove_extension(id()?,require_str(&params,"name")?)?; Ok(Value::Null) },
            "location.detect" => {
                let proxy = if params["proxy"].is_object() { Some(params["proxy"].clone()) } else if !string(&params,"proxy_id").is_empty() { Some(self.store.get("proxies",string(&params,"proxy_id"))?.ok_or_else(|| anyhow!("Proxy không tồn tại"))?) } else { None };
                self.network.detect(proxy.as_ref())
            },
            "proxy.save" => {
                let _lock = self.store.operation.lock();
                let data = data()?;
                self.check_proxy_closed(string(&data,"id"))?;
                self.network.save(data).map(|p| summary(&p))
            },
            "proxy.import" => self.network.import_text(require_str(&params,"text")?).map(|p| json!(p.iter().map(summary).collect::<Vec<_>>())),
            "proxy.delete" => {
                let _lock = self.store.operation.lock(); self.check_proxy_closed(id()?)?;
                self.network.delete(id()?, &self.profiles)?; Ok(Value::Null)
            },
            "proxy.check" => {
                let proxy = if params["proxy"].is_object() { params["proxy"].clone() } else { self.store.get("proxies",id()?)?.ok_or_else(|| anyhow!("Proxy không tồn tại"))? };
                self.network.check(&proxy)
            },
            "proxy.check_all" => self.network.check_all().map(|rows| json!(rows)),
            "backup.list" => self.backups.list().map(|rows| json!(rows)),
            "backup.create" => {
                let dest = string(&params,"destination");
                self.backups.create(&ids()?,if dest.is_empty() { None } else { Some(Path::new(dest)) },string(&params,"password")).map(|p| json!(p))
            },
            "backup.inspect" => self.backups.inspect(Path::new(require_str(&params,"path")?),string(&params,"password")),
            "backup.restore" => self.backups.restore(Path::new(require_str(&params,"path")?),string(&params,"password")).map(|p| json!(p)),
            "backup.delete" => { self.backups.delete(Path::new(require_str(&params,"path")?))?; Ok(Value::Null) },
            "backup.set_password" => self.backups.set_password(string(&params,"password")),
            "settings.save" => self.store.save_settings(data()?),
            "versions.available" => self.versions.available().map(|p| json!(p)),
            "versions.installed" => self.versions.installed().map(|p| json!(p)),
            "versions.install" => self.versions.install(id()?).map(|p| p.unwrap_or(Value::Null)),
            "versions.delete" => { self.versions.delete(id()?)?; Ok(Value::Null) },
            "versions.control" => self.versions.control(id()?,require_str(&params,"action")?),
            "versions.check_updates" => {
                let result = self.versions.check_updates()?;
                self.store.save_settings(json!({"last_update_check_at":crate::store::utcnow()}))?;
                Ok(result)
            },
            "fingerprint_data.update" => self.fingerprints.update(),
            "logs.list" => self.store.logs().map(|p| json!(p)),
            "logs.export" => { self.store.export_logs(Path::new(require_str(&params,"path")?))?; Ok(Value::Null) },
            _ => bail!("Phương thức không được hỗ trợ: {method}"),
        };
        drop(operation);
        if result.is_ok() {
            if let Some(app) = app {
                let resources: &[&str] = match method {
                    "backup.restore" => &["profiles","proxies","backups"],
                    "proxy.delete" => &["proxies","profiles","settings"],
                    "proxy.save"|"proxy.import"|"proxy.check"|"proxy.check_all" => &["proxies"],
                    "settings.save" => &["settings"],
                    "versions.install"|"versions.delete"|"versions.check_updates" => &["versions","profiles"],
                    "fingerprint_data.update" => &["fingerprint_data"],
                    "backup.create"|"backup.delete" => &["backups"],
                    method if method.starts_with("profile.") && method != "profile.get" => &["profiles"],
                    _ => &[],
                };
                for resource in resources { let _ = app.emit("app:changed",json!({"resource":resource})); }
                if let Ok(status) = self.status() { let _ = app.emit("app:status",status); }
            }
        }
        result
    }
    pub fn start_scheduler(self: &Arc<Self>, app: AppHandle) {
        let weak = Arc::downgrade(self);
        std::thread::spawn(move || {
            let mut last_tick = Instant::now() - Duration::from_secs(60);
            let scheduled = Arc::new(AtomicBool::new(false));
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let Some(backend) = weak.upgrade() else { break; };
                if backend.stopped.load(Ordering::Acquire) { break; }
                match backend.status() {
                    Ok(status) => { let _ = app.emit("app:status",status); },
                    Err(error) => { let _ = backend.store.log("ERROR",&error.to_string(),""); }
                }
                if last_tick.elapsed() < Duration::from_secs(60) { continue; }
                if scheduled.swap(true,Ordering::AcqRel) { continue; }
                last_tick = Instant::now();
                let worker = backend.clone();
                let app = app.clone();
                let scheduled = scheduled.clone();
                std::thread::spawn(move || {
                    (|| {
                    let Ok(_operation) = worker.begin(true) else { return; };
                    match worker.backups.tick() {
                        Ok(true) => { let _ = app.emit("app:changed",json!({"resource":"backups"})); },
                        Ok(false) => {},
                        Err(error) => { let _ = worker.store.log("ERROR",&error.to_string(),""); }
                    }
                    let settings = match worker.store.settings() { Ok(v) => v, Err(_) => return };
                    let hours = settings["update_check_hours"].as_u64().unwrap_or(24);
                    let due = chrono::DateTime::parse_from_rfc3339(string(&settings,"last_update_check_at")).map(|last| (chrono::Utc::now() - last.with_timezone(&chrono::Utc)).num_seconds() >= hours.saturating_mul(3600).min(i64::MAX as u64) as i64).unwrap_or(true);
                    if due && hours > 0 && settings["auto_check_updates"].as_bool().unwrap_or(false) && !worker.versions.is_active() {
                        match worker.versions.check_updates() {
                            Ok(result) => {
                                if !string(&result,"error").is_empty() {
                                    let _ = app.emit("app:notice",json!({"level":"warning","message":worker.store.redact_text(string(&result,"error"))}));
                                } else if result["has_update"].as_bool().unwrap_or(false) {
                                    let name = string(&result["latest_version"],"name");
                                    let message = if worker.english.load(Ordering::Relaxed) {
                                        format!("New Camoufox version available: {name}. Open Settings to download and install.")
                                    } else {
                                        format!("Có phiên bản Camoufox mới: {name}. Mở Cài đặt để tải và cài đặt.")
                                    };
                                    let _ = app.emit("app:notice",json!({"level":"info","message":message}));
                                }
                                let _ = worker.store.save_settings(json!({"last_update_check_at":crate::store::utcnow()}));
                                let _ = app.emit("app:changed",json!({"resource":"versions"}));
                            },
                            Err(error) => {
                                let _ = worker.store.log("ERROR",&error.to_string(),"");
                                let message = if worker.english.load(Ordering::Relaxed) {
                                    format!("Update check failed: {error:#}")
                                } else {
                                    format!("Kiểm tra cập nhật thất bại: {error:#}")
                                };
                                let _ = app.emit("app:notice",json!({"level":"warning","message":worker.store.redact_text(&message)}));
                            }
                        }
                    }
                    })();
                    scheduled.store(false,Ordering::Release);
                });
            }
        });
    }
}
