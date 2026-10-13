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

### Cập nhật lên v1.0.2

Bản v1.0.2 sửa lỗi đồng bộ IP timeout khi mở lại profile dùng proxy: trước mỗi phiên, app làm mới riêng `browser/startupCache/webext.sc.lz4` để tiện ích monitor nạp cấu hình phiên hiện tại. Không xóa cookie, phiên đăng nhập hay cache khác; không đổi schema, thư mục dữ liệu hoặc fingerprint đã lưu. Bản v1.0.1 trước đó sửa lỗi phiên native khi SOCKS5 remote DNS làm Camoufox công bố BiDi bằng `localhost`.

Dừng các profile và đóng app trước khi cập nhật; nên tạo backup và lưu ra thư mục ngoài dữ liệu app trước. Cài setup mới đè lên bản cũ, hoặc giải nén portable mới và chạy `CamouManager.exe`. Dữ liệu vẫn ở `%LOCALAPPDATA%\CamouManagerRust`, không nằm cạnh executable. Nếu dùng `CAMOUMANAGER_HOME`, giữ nguyên biến này để mở đúng dữ liệu cũ.

Không cần gỡ bản cũ trước. Nếu setup hỏi cách xử lý bản cũ, chọn **Do not uninstall**. Nếu chọn **Uninstall before installing**, trình gỡ bản cũ có thể hiện checkbox **Delete the application data**: phải bỏ chọn để giữ dữ liệu. Chọn xóa dữ liệu khi gỡ cài đặt sẽ xóa toàn bộ dữ liệu mặc định, kể cả backup nằm trong đó. Không xóa thư mục dữ liệu hoặc đặt nó bên trong thư mục cài đặt/portable.

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

Smoke native cần binary Camoufox đã cài, chạy với hồ sơ/proxy kiểm thử riêng trong thư mục tạm:

```powershell
$env:CAMOUFOX_SMOKE_EXE = Join-Path $env:LOCALAPPDATA 'CamouManagerRust\versions\v156.0.1-beta.37\camoufox.exe'
cargo test --release --manifest-path src-tauri/Cargo.toml --all-targets -- --include-ignored --nocapture --test-threads=1
```

Smoke `smoke_real_browser_socks_localhost_bidi` kiểm tra BiDi khi SOCKS5 dùng remote DNS, cả chế độ headless và có cửa sổ. Camoufox có thể công bố `localhost` thay vì `127.0.0.1`; app giữ hostname này khi bắt tay WebSocket, chỉ kết nối loopback và xác minh PID thuộc profile.


Đóng gói installer và portable vào `dist/`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build.ps1
```

Script tạo lại `dist/CamouManager`; không để dữ liệu cá nhân trong thư mục này.

### Release trên GitHub

Workflow `.github/workflows/release.yml` build **Windows x64** bằng script ở trên. Push tag `v*` sẽ tự tạo GitHub Release với installer `.exe`, portable `.zip` (kèm license) và `SHA256SUMS.txt`; không cần tạo token riêng, workflow dùng `GITHUB_TOKEN` với quyền `contents: write`.

Trước mỗi release, cập nhật cùng version trong `package.json`, `package-lock.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` và bản ghi `camoumanager` trong `src-tauri/Cargo.lock`. Dùng `npm install --package-lock-only` và `cargo check --manifest-path src-tauri/Cargo.toml` để cập nhật lockfile sau khi sửa version. Tag phải đúng `v<version>`; lệch version sẽ dừng trước khi build.

Ví dụ phát hành version hiện tại, sau khi commit và push mã nguồn cùng workflow:

```powershell
git tag v1.0.2
git push origin v1.0.2
```

Để chỉ build thử, vào **Actions → Windows release → Run workflow** trên branch cần build. Tải kết quả ở **Artifacts** của lần chạy; artifact được giữ 7 ngày, không tạo Release khi chạy thủ công. Workflow phải có trên default branch để nút chạy thủ công xuất hiện. Mỗi bản phát hành dùng một tag mới; bước tạo Release sẽ báo lỗi nếu Release cho tag đó đã tồn tại.

Repo **public** dùng runner tiêu chuẩn `windows-2022` được miễn phí phút chạy theo [chính sách GitHub Actions](https://docs.github.com/en/billing/concepts/product-billing/github-actions). Không phải tài nguyên vô hạn: GitHub vẫn có [giới hạn thời gian, số job đồng thời và lưu trữ](https://docs.github.com/en/actions/reference/limits); larger runners vẫn tính phí. Bản dựng chưa ký số, Windows có thể cảnh báo SmartScreen.

## Dữ liệu & lưu ý

- Dữ liệu nằm tại `%LOCALAPPDATA%\CamouManagerRust`; có thể chọn thư mục khác bằng `CAMOUMANAGER_HOME`.
- Backup chứa cookie, phiên đăng nhập và thông tin proxy. Nên đặt mật khẩu; không chia sẻ profile hoặc backup với người không tin cậy. Mật khẩu chỉ mã hóa backup, không mã hóa dữ liệu hồ sơ/proxy đang lưu trong app.
- ZIP plaintext tạm của backup mã hóa dùng file handle tự xóa khi tiến trình đóng; app dọn file tạm legacy có tên/ID đúng định dạng khi mở dữ liệu.
- Tạo/khôi phục backup cùng áp dụng giới hạn: 4 GiB mỗi file, 20 GiB tổng dữ liệu giải nén, 100.000 entry, 10 MiB manifest và 4 MiB mỗi bản ghi JSON profile/proxy. Vượt giới hạn sẽ báo lỗi, không công bố backup thành công.
- Sao lưu tự động chỉ chạy khi app mở, chỉ chọn hồ sơ đã dừng; nếu tất cả đang chạy thì bỏ lượt đó, không cập nhật thời gian hoàn tất hay áp dụng retention. Mật khẩu phiên cần nhập lại sau mỗi lần mở app.
- Không hỗ trợ dữ liệu/backup của bản Python cũ. Gỡ cài đặt chỉ xóa dữ liệu mặc định khi chọn **Delete app data**; dữ liệu cũ và thư mục tùy chỉnh không bị xóa.
- Hồ sơ dùng proxy bật WebRTC ở chế độ **proxy-only + relay-only**: chỉ dùng TURN qua TCP/TLS và proxy đã gán; chặn STUN/UDP và ICE-TCP trực tiếp trước khi mở URL. Website phải cung cấp TURN tương thích và proxy phải cho phép tunnel tới TURN; không có đường đó thì kết nối thất bại, không fallback về mạng thật. Chuyển profile sang direct sẽ dùng kết nối thật.
- Chính sách ICE/proxy được ghi vào user.js và khóa trong phiên. Không spoof IP WebRTC trong cấu hình launch của profile proxy: ICE dùng địa chỉ relay thật, có thể khác IP HTTP của proxy; fingerprint đã lưu không bị tạo lại. Quyền micro/camera vẫn do người dùng cấp. Với Camoufox v156.0.1-beta.37, datachannel không có capture/quyền media có thể không kết nối do cơ chế chọn default interface của engine.
- Monitor cập nhật IP đang quan sát, kể cả proxy xoay IP; kiểm tra mỗi 10 giây, timeout request 15 giây. Lỗi mạng, phản hồi IP không hợp lệ hoặc monitor không tiến triển trong 45 giây được báo lỗi nhưng không đóng browser; giữ IP hợp lệ cuối cùng. Monitor tự thử lại, cập nhật IP và xóa lỗi khi phục hồi. Chính sách chặn đường ICE trực tiếp vẫn giữ nguyên trong lúc mất mạng và sau khi kết nối lại.
- Preflight vẫn chặn khởi động nếu proxy chưa dùng được. Vi phạm chính sách ICE/proxy đã khóa vẫn đóng phiên để bảo vệ định tuyến; không áp dụng việc đóng phiên này cho lỗi mạng hoặc IP thay đổi.
- SOCKS5 có credential bắt buộc xác thực username/password, không tự chuyển sang anonymous. Không còn fallback GeoIP HTTP khi dịch vụ HTTPS lỗi.
- Ưu tiên proxy sticky session. Không cam kết chống fingerprint hay khóa tài khoản; chỉ cài extension đáng tin cậy.
- Chỉ dùng phần mềm/tiện ích đáng tin cậy: cổng điều khiển BiDi nội bộ không có xác thực và tiện ích Experiment có quyền Gecko cao. Bản dựng chưa ký số có thể bị SmartScreen cảnh báo.

## License

Copyright (C) 2026 p1ndotdev. CamouManager được phát hành theo [GPL-3.0-only](LICENSE), không kèm bảo hành. Được phép dùng, sửa và bán; khi phân phối app hoặc bản phái sinh phải cung cấp mã nguồn tương ứng theo GPL-3.0. Dùng riêng không bắt buộc công khai mã nguồn. Thành phần bên thứ ba giữ license riêng.

Mã nguồn: https://github.com/p1ndotdev/CamouManager. Khi phát hành binary, cung cấp link mã nguồn đúng commit của bản đó cùng các hướng dẫn build.

## Ghi nhận

Dữ liệu Camoufox (MIT) và mô hình fpgen (Apache-2.0). Chi tiết trong [NOTICE](src-tauri/data/NOTICE), [LICENSE-CAMOUFOX](src-tauri/data/LICENSE-CAMOUFOX) và [LICENSE-FPGEN](src-tauri/data/LICENSE-FPGEN).
