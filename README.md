# CamouManager

Ứng dụng Windows quản lý hồ sơ trình duyệt [Camoufox](https://github.com/daijro/camoufox), xây dựng bằng Rust, Tauri 2 và React/TypeScript.

## Tính năng

- Tạo, nhân bản và chạy nhiều hồ sơ với fingerprint, cookie và tiện ích riêng.
- Quản lý proxy HTTP/HTTPS/SOCKS5, kiểm tra IP và vị trí.
- Tải, cập nhật và ghim phiên bản Camoufox cho từng hồ sơ.
- Sao lưu, khôi phục và mã hóa bản sao lưu bằng mật khẩu.
- Giao diện Tiếng Việt / English, màu Firefox và icon cáo đeo kính đen.

## Sử dụng

Yêu cầu **Windows 10/11 x64** và **Microsoft Edge WebView2 Runtime**.

1. Cài bản setup hoặc mở `CamouManager.exe` trong bản portable.
2. Vào **Cài đặt → Phiên bản & Dữ liệu Fingerprint** để tải Camoufox.
3. Vào **Hồ sơ → Tạo mới**, cấu hình profile rồi nhấn **Khởi động**.

Đổi Tiếng Việt / English tại **Cài đặt → Ngôn ngữ giao diện**. Lựa chọn được ghi nhớ, không thay đổi locale của fingerprint. Log và chi tiết lỗi kỹ thuật giữ nguyên ngôn ngữ gốc.

## Phát triển

Cần Node.js 22.12+ hoặc 24 LTS, Rust stable MSVC và Visual Studio Build Tools với **Desktop development with C++ / Windows SDK**.

```powershell
npm ci
npm run desktop:dev
```

Build và kiểm thử:

```powershell
npm run build
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
```

Đóng gói installer và portable vào `dist/`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build.ps1
```

Script tạo lại `dist/CamouManager`; không để dữ liệu cá nhân trong thư mục này.

## Dữ liệu & lưu ý

- Dữ liệu nằm tại `%LOCALAPPDATA%\CamouManagerRust`; có thể chọn thư mục khác bằng `CAMOUMANAGER_HOME`.
- Backup chứa cookie, phiên đăng nhập và thông tin proxy. Nên đặt mật khẩu; không chia sẻ profile hoặc backup với người không tin cậy.
- Sao lưu tự động chỉ chạy khi app mở, bỏ qua hồ sơ đang chạy; mật khẩu phiên cần nhập lại sau mỗi lần mở app.
- Không hỗ trợ dữ liệu/backup của bản Python cũ. Gỡ cài đặt chỉ xóa dữ liệu mặc định khi chọn **Delete app data**; dữ liệu cũ và thư mục tùy chỉnh không bị xóa.
- Ưu tiên proxy sticky session. Không cam kết chống khóa tài khoản; lỗi IP/WebRTC có thể khiến phiên bị đóng để bảo vệ kết nối.
- Chỉ dùng phần mềm/tiện ích đáng tin cậy: cổng điều khiển BiDi nội bộ không có xác thực và tiện ích Experiment có quyền Gecko cao. Bản dựng chưa ký số có thể bị SmartScreen cảnh báo.

## License

Copyright (C) 2026 p1ndotdev. CamouManager được phát hành theo [GPL-3.0-only](LICENSE), không kèm bảo hành. Được phép dùng, sửa và bán; khi phân phối app hoặc bản phái sinh phải cung cấp mã nguồn tương ứng theo GPL-3.0. Dùng riêng không bắt buộc công khai mã nguồn. Thành phần bên thứ ba giữ license riêng.

Mã nguồn: https://github.com/p1ndotdev/CamouManager. Khi phát hành binary, cung cấp link mã nguồn đúng commit của bản đó cùng các hướng dẫn build.

## Ghi nhận

Dữ liệu Camoufox (MIT) và mô hình fpgen (Apache-2.0). Chi tiết trong [NOTICE](src-tauri/data/NOTICE), [LICENSE-CAMOUFOX](src-tauri/data/LICENSE-CAMOUFOX) và [LICENSE-FPGEN](src-tauri/data/LICENSE-FPGEN).
