# CamouManager

Ứng dụng quản lý hồ sơ trình duyệt [Camoufox](https://github.com/daijro/camoufox) trên Windows (x64), viết bằng Rust, Tauri 2 và React/TypeScript.

## Tính năng chính

- Tạo, nhân bản và chạy nhiều hồ sơ độc lập (fingerprint, cookie, tiện ích mở rộng, dấu trang).
- Quản lý proxy HTTP/HTTPS/SOCKS5, kiểm tra kết nối và tự động đồng bộ vị trí/múi giờ theo IP.
- Tải, cập nhật và đổi phiên bản Camoufox cho từng hồ sơ hoặc hàng loạt.
- Sao lưu và khôi phục dữ liệu hồ sơ có mã hóa mật khẩu (AES-GCM).
- Tự động kiểm tra và cập nhật ứng dụng từ GitHub.
- Hỗ trợ giao diện Tiếng Việt và Tiếng Anh.

## Cài đặt & Sử dụng

1. Tải bản cài đặt `CamouManager-Setup.exe` hoặc bản giải nén `CamouManager-Portable.zip` tại mục [Releases](https://github.com/p1ndotdev/CamouManager/releases).
2. Vào **Cài đặt → Phiên bản & Dữ liệu Fingerprint** để tải phiên bản trình duyệt Camoufox.
3. Vào **Hồ sơ → Tạo mới**, cấu hình hồ sơ và nhấn **Khởi chạy**.

Dữ liệu hồ sơ mặc định lưu tại `%LOCALAPPDATA%\CamouManagerRust` (có thể đổi bằng biến môi trường `CAMOUMANAGER_HOME`).

## Giấy phép

Phát hành theo giấy phép [GPL-3.0-only](LICENSE). Mã nguồn: https://github.com/p1ndotdev/CamouManager.
