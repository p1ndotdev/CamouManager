use camoumanager::backend::Backend;
use serde_json::{json,Value};
use std::fs;

fn create(backend: &Backend, name: &str) -> Value {
    backend.request("profile.create",json!({"data":{
        "name":name,"os":"windows","proxy_id":"",
        "location":{"locked":true,"country":"VN","timezone":"Asia/Ho_Chi_Minh","locale":"vi-VN","latitude":10.8,"longitude":106.7},
        "fingerprint_meta":{"use_preset":false}
    }}),None).unwrap()
}

#[test]
fn duplication_separates_browser_data_and_preserves_full_identity() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().to_owned()).unwrap();
    let profile = create(&backend,"Original");
    let id = profile["id"].as_str().unwrap();
    let browser = backend.store.profile_dir(id).unwrap().join("browser");
    fs::write(browser.join("cookies.sqlite"),b"closed persistent session").unwrap();
    fs::write(browser.join("parent.lock"),b"stale lock").unwrap();
    let full = backend.request("profile.duplicate",json!({"id":id,"full":true}),None).unwrap();
    let full_browser = backend.store.profile_dir(full["id"].as_str().unwrap()).unwrap().join("browser");
    assert_eq!(full["fingerprint"],profile["fingerprint"]);
    assert_eq!(fs::read(full_browser.join("cookies.sqlite")).unwrap(),b"closed persistent session");
    assert!(!full_browser.join("parent.lock").exists());
    let config = backend.request("profile.duplicate",json!({"id":id,"full":false}),None).unwrap();
    let config_browser = backend.store.profile_dir(config["id"].as_str().unwrap()).unwrap().join("browser");
    assert!(!config_browser.join("cookies.sqlite").exists());
    assert_ne!(config["fingerprint"],profile["fingerprint"]);
    assert_eq!(fs::read(browser.join("cookies.sqlite")).unwrap(),b"closed persistent session");
}

#[test]
fn bulk_preflight_prevents_partial_mutation_and_metadata_edits_keep_identity() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().to_owned()).unwrap();
    let first = create(&backend,"First");
    let second = create(&backend,"Second");
    let id = first["id"].as_str().unwrap();
    assert!(backend.request("profile.set_group",json!({"ids":[id,"00000000000000000000000000000000"],"group":"Changed"}),None).is_err());
    assert_eq!(backend.profiles.get(id).unwrap()["group"],"");
    let edited = backend.request("profile.update",json!({"id":id,"data":{"name":"Renamed","tags":["a","a","b"],"note":"saved"}}),None).unwrap();
    assert_eq!(edited["fingerprint"],first["fingerprint"]);
    assert_eq!(edited["tags"],json!(["a","b"]));
    backend.request("profile.set_group",json!({"ids":[id,second["id"]],"group":"Both"}),None).unwrap();
    assert_eq!(backend.profiles.get(id).unwrap()["group"],"Both");
    assert_eq!(backend.profiles.get(second["id"].as_str().unwrap()).unwrap()["group"],"Both");
}

#[test]
fn unencrypted_export_restores_identity_and_session_at_selected_destination() {
    let root = tempfile::tempdir().unwrap();
    let destination = match std::env::var_os("CAMOUMANAGER_SMOKE_BACKUP_DIR") {
        Some(path) => tempfile::tempdir_in(path).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let source = Backend::open(root.path().join("source")).unwrap();
    let profile = create(&source, "Exported");
    let id = profile["id"].as_str().unwrap();
    fs::write(source.store.profile_dir(id).unwrap().join("browser/cookies.sqlite"), b"exported session").unwrap();
    let archive = source.backups.create(&[id.to_owned()], Some(&destination.path().join("nested/export.zip")), "").unwrap();
    assert_eq!(source.backups.inspect(&archive, "").unwrap()["is_encrypted"], false);
    let target = Backend::open(root.path().join("target")).unwrap();
    let restored = target.backups.restore(&archive, "").unwrap();
    let restored_id = restored[0]["id"].as_str().unwrap();
    assert_ne!(restored_id, id);
    assert_eq!(restored[0]["fingerprint"], profile["fingerprint"]);
    assert_eq!(fs::read(target.store.profile_dir(restored_id).unwrap().join("browser/cookies.sqlite")).unwrap(), b"exported session");
}

#[test]
fn localized_extension_names_remain_distinct_and_reimport_updates_in_place() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().join("store")).unwrap();
    let profile = create(&backend, "Extensions");
    let id = profile["id"].as_str().unwrap();
    let extension = root.path().join("extension");
    fs::create_dir(&extension).unwrap();
    let manifest = extension.join("manifest.json");
    fs::write(&manifest, json!({"manifest_version":2,"name":"广告拦截器","version":"1.0"}).to_string()).unwrap();
    let first = backend.profiles.import_extension(id, &extension).unwrap();
    fs::write(&manifest, json!({"manifest_version":2,"name":"Блокировщик","version":"1.0"}).to_string()).unwrap();
    let second = backend.profiles.import_extension(id, &extension).unwrap();
    assert_ne!(first, second);
    fs::write(&manifest, json!({"manifest_version":2,"name":"广告拦截器","version":"2.0"}).to_string()).unwrap();
    assert_eq!(backend.profiles.import_extension(id, &extension).unwrap(), first);
    let updated: Value = serde_json::from_slice(&fs::read(backend.store.profile_dir(id).unwrap().join(&first).join("manifest.json")).unwrap()).unwrap();
    assert_eq!(updated["version"], "2.0");
    let other: Value = serde_json::from_slice(&fs::read(backend.store.profile_dir(id).unwrap().join(&second).join("manifest.json")).unwrap()).unwrap();
    assert_eq!(other["name"], "Блокировщик");
    let saved = backend.profiles.get(id).unwrap();
    assert_eq!(saved["extensions"], json!([first, second]));
    assert_eq!(saved["fingerprint"], profile["fingerprint"]);
}

#[test]
fn extension_names_that_collide_on_windows_preserve_both_imports() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().join("store")).unwrap();
    let profile = create(&backend, "Collisions");
    let id = profile["id"].as_str().unwrap();
    let extension = root.path().join("extension");
    fs::create_dir(&extension).unwrap();
    let names = ["Tool A".to_owned(), "Tool_A".to_owned(), "tool_a".to_owned(), format!("{}x", "a".repeat(100)), format!("{}y", "a".repeat(100))];
    let mut imported = Vec::new();
    for name in &names {
        fs::write(extension.join("manifest.json"), json!({"manifest_version":2,"name":name,"version":"1.0"}).to_string()).unwrap();
        imported.push(backend.profiles.import_extension(id, &extension).unwrap());
    }
    for (name, managed) in names.iter().zip(&imported) {
        let manifest: Value = serde_json::from_slice(&fs::read(backend.store.profile_dir(id).unwrap().join(managed).join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["name"], *name);
        fs::write(extension.join("manifest.json"), json!({"manifest_version":2,"name":name,"version":"2.0"}).to_string()).unwrap();
        assert_eq!(backend.profiles.import_extension(id, &extension).unwrap(), *managed);
    }
    assert_eq!(backend.profiles.get(id).unwrap()["extensions"], json!(imported));
}

#[test]
fn reimport_updates_existing_extension_directory_by_gecko_identity() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().join("store")).unwrap();
    let profile = create(&backend, "Existing extension");
    let id = profile["id"].as_str().unwrap();
    let old = backend.store.profile_dir(id).unwrap().join("addons/Tool_A");
    fs::create_dir(&old).unwrap();
    let mut manifest = json!({"manifest_version":2,"name":"Tool A","version":"1.0","browser_specific_settings":{"gecko":{"id":"tool@local.invalid"}}});
    fs::write(old.join("manifest.json"), manifest.to_string()).unwrap();
    backend.profiles.update(id, json!({"extensions":["addons/Tool_A"]})).unwrap();
    let source = root.path().join("updated");
    fs::create_dir(&source).unwrap();
    manifest["name"] = json!("Renamed Tool");
    manifest["version"] = json!("2.0");
    fs::write(source.join("manifest.json"), manifest.to_string()).unwrap();
    assert_eq!(backend.profiles.import_extension(id, &source).unwrap(), "addons/Tool_A");
    let updated: Value = serde_json::from_slice(&fs::read(old.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(updated["name"], "Renamed Tool");
    assert_eq!(updated["version"], "2.0");
    assert_eq!(backend.profiles.get(id).unwrap()["extensions"], json!(["addons/Tool_A"]));
}

#[test]
fn proxy_reassignment_clears_stale_ip_in_single_and_bulk_updates() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().to_owned()).unwrap();
    let a = backend.network.save(json!({"server":"http://127.0.0.1:19001"})).unwrap();
    let b = backend.network.save(json!({"server":"http://127.0.0.1:19002"})).unwrap();
    for locked in [false, true] {
        let profile = backend.profiles.create(json!({"name":"Reassigned", "proxy_id":a["id"], "os":"windows",
            "location":{"ip":"198.51.100.9", "country":"VN", "timezone":"Asia/Ho_Chi_Minh", "locale":"vi-VN", "latitude":10.8, "longitude":106.7, "locked":locked}})).unwrap();
        let id = profile["id"].as_str().unwrap();
        if locked {
            backend.request("profile.update",json!({"id":id,"data":{"proxy_id":b["id"]}}),None).unwrap();
        } else {
            backend.request("profile.assign_proxy",json!({"ids":[id],"proxy_id":b["id"]}),None).unwrap();
        }
        let saved = backend.profiles.get(id).unwrap();
        assert_eq!(saved["proxy_id"], b["id"]);
        assert_eq!(saved["location"]["ip"], "");
        assert!(saved["fingerprint"].get("webrtc:ipv4").is_none());
        assert!(saved["fingerprint"].get("webrtc:ipv6").is_none());
        assert_eq!(saved["fingerprint"]["audio:seed"], profile["fingerprint"]["audio:seed"]);
        assert_eq!(saved["fingerprint"]["fonts"], profile["fingerprint"]["fonts"]);
        if locked {
            assert_eq!(saved["location"]["timezone"], "Asia/Ho_Chi_Minh");
            assert_eq!(saved["fingerprint"]["geolocation:latitude"], 10.8);
        } else {
            assert_eq!(saved["location"]["timezone"], "");
            assert!(saved["fingerprint"].get("timezone").is_none());
            assert!(saved["fingerprint"].get("geolocation:latitude").is_none());
            assert!(saved["fingerprint"].get("geolocation:longitude").is_none());
        }
    }
}

#[test]
fn deleting_proxy_clears_stale_location_without_changing_identity_or_session() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().to_owned()).unwrap();
    let proxy = backend.network.save(json!({"server":"http://127.0.0.1:19001"})).unwrap();
    let other = create(&backend, "Unrelated");
    backend.store.save_settings(json!({"default_proxy_id":proxy["id"]})).unwrap();
    let profiles = [false, true].map(|locked| backend.profiles.create(json!({
        "name":"Deleted proxy", "proxy_id":proxy["id"], "os":"windows",
        "location":{"ip":"198.51.100.9", "country":"VN", "timezone":"Asia/Ho_Chi_Minh", "locale":"vi-VN", "latitude":10.8, "longitude":106.7, "locked":locked}
    })).unwrap());
    for profile in &profiles {
        let browser = backend.store.profile_dir(profile["id"].as_str().unwrap()).unwrap().join("browser");
        fs::write(browser.join("cookies.sqlite"), b"persistent session").unwrap();
    }
    backend.request("proxy.delete", json!({"id":proxy["id"]}), None).unwrap();
    assert!(backend.store.get("proxies", proxy["id"].as_str().unwrap()).unwrap().is_none());
    assert_eq!(backend.store.settings().unwrap()["default_proxy_id"], "");
    assert_eq!(backend.profiles.get(other["id"].as_str().unwrap()).unwrap(), other);
    for profile in profiles {
        let id = profile["id"].as_str().unwrap();
        let saved = backend.profiles.get(id).unwrap();
        assert_eq!(saved["proxy_id"], "");
        assert_eq!(saved["location"]["ip"], "");
        assert!(saved["fingerprint"].get("webrtc:ipv4").is_none());
        assert!(saved["fingerprint"].get("webrtc:ipv6").is_none());
        assert_eq!(saved["fingerprint"]["audio:seed"], profile["fingerprint"]["audio:seed"]);
        assert_eq!(saved["fingerprint"]["fonts"], profile["fingerprint"]["fonts"]);
        if profile["location"]["locked"] == true {
            assert_eq!(saved["location"]["timezone"], "Asia/Ho_Chi_Minh");
            assert_eq!(saved["fingerprint"]["geolocation:latitude"], 10.8);
        } else {
            assert_eq!(saved["location"]["timezone"], "");
            assert!(saved["fingerprint"].get("timezone").is_none());
            assert!(saved["fingerprint"].get("geolocation:latitude").is_none());
            assert!(saved["fingerprint"].get("geolocation:longitude").is_none());
        }
        assert_eq!(fs::read(backend.store.profile_dir(id).unwrap().join("browser/cookies.sqlite")).unwrap(), b"persistent session");
    }
}

#[test]
fn explicit_default_and_direct_choices_override_automatic_proxy_assignment() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().to_owned()).unwrap();
    let default = backend.network.save(json!({"server":"http://127.0.0.1:19001"})).unwrap();
    let automatic = backend.network.save(json!({"server":"http://127.0.0.1:19002"})).unwrap();
    let occupied = create(&backend, "Using default");
    backend.profiles.update(occupied["id"].as_str().unwrap(), json!({"proxy_id":default["id"]})).unwrap();
    backend.store.save_settings(json!({"default_proxy_id":default["id"],"auto_assign_proxy":true})).unwrap();
    for (name, proxy_id) in [("Explicit default", default["id"].as_str().unwrap()), ("Explicit direct", "")] {
        let saved = backend.profiles.create(json!({"name":name,"proxy_id":proxy_id,"location":{"locked":true}})).unwrap();
        assert_eq!(saved["proxy_id"], proxy_id);
    }
    let saved = backend.profiles.create(json!({"name":"Automatic", "location":{"locked":true}})).unwrap();
    assert_eq!(saved["proxy_id"], automatic["id"]);
}

#[test]
fn app_language_selection_and_validation() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::open(root.path().to_owned()).unwrap();
    assert!(!backend.english.load(std::sync::atomic::Ordering::Relaxed));

    assert_eq!(backend.request("app.language", json!({"language": "en"}), None).unwrap(), Value::Null);
    assert!(backend.english.load(std::sync::atomic::Ordering::Relaxed));

    assert_eq!(backend.request("app.language", json!({"language": "vi"}), None).unwrap(), Value::Null);
    assert!(!backend.english.load(std::sync::atomic::Ordering::Relaxed));

    backend.request("app.language", json!({"language": "en"}), None).unwrap();
    assert!(backend.english.load(std::sync::atomic::Ordering::Relaxed));

    assert!(backend.request("app.language", json!({"language": "invalid"}), None).is_err());
    assert!(backend.english.load(std::sync::atomic::Ordering::Relaxed));

    assert!(backend.request("app.language", json!({"language": 123}), None).is_err());
    assert!(backend.english.load(std::sync::atomic::Ordering::Relaxed));

    assert!(backend.request("app.language", json!({}), None).is_err());
    assert!(backend.english.load(std::sync::atomic::Ordering::Relaxed));
}
