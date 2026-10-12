#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::{path::PathBuf, sync::{Arc, atomic::Ordering}};
use serde_json::Value;
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use camoumanager::{backend::Backend, store::redact};

#[tauri::command]
async fn app_request(backend: tauri::State<'_, Arc<Backend>>, app: tauri::AppHandle, method: String, params: Value) -> Result<Value, String> {
    let backend = backend.inner().clone();
    if method == "app.language" {
        return backend.request(&method, params, Some(&app)).map_err(|error| backend.store.redact_text(&format!("{error:#}")));
    }
    tauri::async_runtime::spawn_blocking(move || {
        backend.request(&method,params,Some(&app)).map_err(|error| backend.store.redact_text(&format!("{error:#}")))
    }).await.map_err(|error| redact(&error.to_string()))?
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") { let _ = window.unminimize(); let _ = window.set_focus(); }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let root = std::env::var_os("CAMOUMANAGER_HOME").map(PathBuf::from)
                .unwrap_or(app.path().local_data_dir()?.join("CamouManagerRust"));
            let backend = Arc::new(Backend::open(root)?);
            backend.start_scheduler(app.handle().clone());
            app.manage(backend);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![app_request])
        .on_window_event(|window,event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let app = window.app_handle().clone();
                let window = window.clone();
                let backend = app.state::<Arc<Backend>>().inner().clone();
                if backend.closing.swap(true,Ordering::SeqCst) { return; }
                tauri::async_runtime::spawn(async move {
                    let worker = backend.clone();
                    let result = tauri::async_runtime::spawn_blocking(move || worker.shutdown()).await;
                    match result {
                        Ok(Ok(())) => {
                            let _ = window.destroy();
                            app.exit(0);
                        }
                        error => {
                            backend.closing.store(false,Ordering::SeqCst);
                            let detail = match error { Ok(Err(error)) => format!("{error:#}"), Err(error) => error.to_string(), _ => unreachable!() };
                            let text = if backend.english.load(Ordering::Relaxed) {
                                format!("Unable to close application: {}\nPlease wait for operations to finish and try again.",redact(&detail))
                            } else {
                                format!("Chưa thể đóng ứng dụng: {}\nHãy chờ tác vụ hoàn tất rồi đóng lại.",redact(&detail))
                            };
                            let _ = app.emit("app:notice",serde_json::json!({"level":"warning","message":text}));
                            app.dialog().message(text).title("CamouManager").kind(MessageDialogKind::Warning).show(|_| {});
                        }
                    }
                });
            }
        })
        .build(tauri::generate_context!())
        .expect("Không khởi động được CamouManager");
    app.run(|app,event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(backend) = app.try_state::<Arc<Backend>>() { let _ = backend.runtime.stop_all(); }
        }
    });
}
