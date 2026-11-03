# CamouManager

Desktop profile manager for [Camoufox](https://github.com/daijro/camoufox) on Windows (x64), built with Rust, Tauri 2, and React/TypeScript.

## Features

- Create, clone, and run isolated browser profiles (fingerprints, cookies, extensions, bookmarks).
- Manage HTTP/HTTPS/SOCKS5 proxies with health checks and automatic IP/GeoIP location sync.
- Download, pin, and batch-switch Camoufox versions across profiles.
- Password-encrypted profile backups and restores (AES-GCM).
- Built-in GitHub self-updater with optional auto-update.
- English and Vietnamese interface.

## Getting Started

1. Download `CamouManager-Setup.exe` or `CamouManager-Portable.zip` from [Releases](https://github.com/p1ndotdev/CamouManager/releases).
2. Open **Settings → Versions & Fingerprint Data** to install a Camoufox release.
3. Open **Profiles → Create**, configure your profile, and click **Launch**.

Profile data is stored in `%LOCALAPPDATA%\CamouManagerRust` by default (customizable via `CAMOUMANAGER_HOME`).

## License

Licensed under [GPL-3.0-only](LICENSE). Source code: https://github.com/p1ndotdev/CamouManager.
