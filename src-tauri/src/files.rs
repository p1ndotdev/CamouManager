use anyhow::{anyhow, bail, Context, Result};
use std::{collections::HashSet, fs, io::{Read, Write}, path::{Path, PathBuf}};

pub fn reject_link(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() { bail!("Không cho phép symlink: {}", path.display()); }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { bail!("Không cho phép junction/reparse point: {}", path.display()); }
    }
    Ok(())
}

pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    reject_link(from)?;
    reject_link(to)?;
    let metadata = fs::metadata(from)?;
    if metadata.is_dir() {
        fs::create_dir_all(to)?;
        for child in fs::read_dir(from)? {
            let child = child?;
            copy_tree(&child.path(), &to.join(child.file_name()))?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = to.parent() { fs::create_dir_all(parent)?; }
        fs::copy(from, to).with_context(|| format!("Không sao chép được {}", from.display()))?;
    } else { bail!("Loại file không được hỗ trợ: {}", from.display()); }
    Ok(())
}

fn archive_path(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('\\') || name.starts_with('/') || name.contains('\0') {
        bail!("Đường dẫn ZIP không hợp lệ");
    }
    let name = name.strip_suffix('/').unwrap_or(name);
    let mut relative = PathBuf::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.ends_with(['.', ' '])
            || part.chars().any(|c| c.is_control() || ":<>\"|?*".contains(c)) {
            bail!("Đường dẫn ZIP không an toàn: {name}");
        }
        let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if ["CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"].contains(&base.as_str()) {
            bail!("Tên file ZIP được Windows dành riêng");
        }
        relative.push(part);
    }
    Ok(relative)
}

pub fn extract_zip(archive: &Path, target: &Path, max_bytes: u64, cancel: Option<&dyn Fn() -> bool>) -> Result<bool> {
    reject_link(target)?;
    let mut zip = zip::ZipArchive::new(fs::File::open(archive)?)?;
    if zip.len() > 100_000 { bail!("ZIP vượt giới hạn số file an toàn"); }
    let mut declared = 0u64;
    let mut names = HashSet::with_capacity(zip.len());
    let mut paths = Vec::with_capacity(zip.len());
    for index in 0..zip.len() {
        if cancel.is_some_and(|check| check()) { return Ok(false); }
        let entry = zip.by_index(index)?;
        let relative = archive_path(entry.name())?;
        if !names.insert(relative.to_string_lossy().to_lowercase()) { bail!("ZIP chứa đường dẫn trùng lặp"); }
        if entry.unix_mode().is_some_and(|mode| mode & 0o170000 == 0o120000) { bail!("ZIP chứa symlink"); }
        declared = declared.checked_add(entry.size()).ok_or_else(|| anyhow!("ZIP quá lớn"))?;
        if declared > max_bytes { bail!("ZIP vượt giới hạn dung lượng giải nén"); }
        paths.push(relative);
    }
    fs::create_dir_all(target)?;
    let mut decoded = 0u64;
    let mut buffer = vec![0u8; 256 * 1024];
    for (index, relative) in paths.into_iter().enumerate() {
        if cancel.is_some_and(|check| check()) { return Ok(false); }
        let output = target.join(relative);
        for ancestor in output.ancestors().take_while(|path| path.starts_with(target)) { reject_link(ancestor)?; }
        let mut entry = zip.by_index(index)?;
        if entry.is_dir() { fs::create_dir_all(output)?; continue; }
        fs::create_dir_all(output.parent().ok_or_else(|| anyhow!("ZIP thiếu thư mục đích"))?)?;
        let mut file = fs::File::create(output)?;
        let mut written = 0u64;
        loop {
            if cancel.is_some_and(|check| check()) { return Ok(false); }
            let count = entry.read(&mut buffer)?;
            if count == 0 { break; }
            decoded = decoded.checked_add(count as u64).ok_or_else(|| anyhow!("ZIP quá lớn"))?;
            written += count as u64;
            if decoded > max_bytes || written > entry.size() { bail!("Dữ liệu ZIP vượt dung lượng đã khai báo"); }
            file.write_all(&buffer[..count])?;
        }
        if written != entry.size() { bail!("Dữ liệu ZIP bị thiếu"); }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;
    fn archive(root: &Path, names: &[&str]) -> PathBuf {
        let path = root.join("fixture.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        for name in names {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(b"contents").unwrap();
        }
        zip.finish().unwrap(); path
    }
    #[test]
    fn validates_all_entries_before_creating_files() {
        let root = tempfile::tempdir().unwrap(); let output = root.path().join("output");
        let path = archive(root.path(), &["valid.txt", "../escape.txt"]);
        assert!(extract_zip(&path, &output, 100, None).is_err());
        assert!(!output.exists()); assert!(!root.path().join("escape.txt").exists());
    }
    #[test]
    fn rejects_case_collisions_ads_and_windows_ambiguous_names() {
        for names in [&["Foo", "foo"][..], &["file:stream"][..], &["CON.txt"][..], &["file."][..], &["dir\\escape"][..]] {
            let root = tempfile::tempdir().unwrap(); let path = archive(root.path(), names);
            assert!(extract_zip(&path, &root.path().join("out"), 100, None).is_err());
        }
    }
    #[test]
    fn enforces_decoded_size_before_extraction() {
        let root = tempfile::tempdir().unwrap(); let path = archive(root.path(), &["data"]);
        assert!(extract_zip(&path, &root.path().join("out"), 2, None).is_err());
        assert!(!root.path().join("out").exists());
    }
    #[test]
    fn cancelling_inside_large_member_stops_write() {
        use std::cell::Cell;
        let root = tempfile::tempdir().unwrap(); let path = root.path().join("large.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        zip.start_file("large",SimpleFileOptions::default()).unwrap();zip.write_all(&vec![7;1024*1024]).unwrap();zip.finish().unwrap();
        let calls = Cell::new(0);
        let cancel = || { calls.set(calls.get()+1); calls.get()>3 };
        let out = root.path().join("out");
        assert!(!extract_zip(&path,&out,2*1024*1024,Some(&cancel)).unwrap());
        assert!(fs::metadata(out.join("large")).unwrap().len()<1024*1024);
    }
    #[cfg(unix)]
    #[test]
    fn copy_never_follows_symlinks() {
        let root = tempfile::tempdir().unwrap(); let outside = root.path().join("secret");
        fs::write(&outside,b"secret").unwrap();let from=root.path().join("from");fs::create_dir(&from).unwrap();
        std::os::unix::fs::symlink(&outside,from.join("link")).unwrap();
        assert!(copy_tree(&from,&root.path().join("out")).is_err());assert_eq!(fs::read(outside).unwrap(),b"secret");
    }
}
