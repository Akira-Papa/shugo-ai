//! Local storage guards. These reject final-component links and unsafe owners;
//! they are not a sandbox against a process with the same user's full authority.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
const STORAGE_ERROR: &str = "ローカル保存先の安全性を確認できません。";

fn check_parent(path: &Path) -> Result<&Path, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let m = fs::symlink_metadata(parent).map_err(|_| STORAGE_ERROR)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(STORAGE_ERROR.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
            return Err(STORAGE_ERROR.into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(STORAGE_ERROR.into());
        }
    }
    Ok(parent)
}
fn safe_options(write: bool) -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(0x00200000);
    }
    o
}
fn validate_handle(file: &File, original: &fs::Metadata) -> Result<(), String> {
    let m = file.metadata().map_err(|_| STORAGE_ERROR)?;
    if !m.is_file() || original.file_type().is_symlink() {
        return Err(STORAGE_ERROR.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if m.uid() != unsafe { libc::geteuid() }
            || m.nlink() != 1
            || original.dev() != m.dev()
            || original.ino() != m.ino()
        {
            return Err(STORAGE_ERROR.into());
        }
        // Change the verified handle, never chmod an unchecked pathname or directory.
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| STORAGE_ERROR)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(STORAGE_ERROR.into());
        }
    }
    Ok(())
}
fn checked_existing(path: &Path, write: bool) -> Result<File, String> {
    check_parent(path)?;
    let m = fs::symlink_metadata(path).map_err(|_| STORAGE_ERROR)?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(STORAGE_ERROR.into());
    }
    let f = safe_options(write).open(path).map_err(|_| STORAGE_ERROR)?;
    validate_handle(&f, &m)?;
    verify_path_identity(&f, path)?;
    Ok(f)
}
/// Compare a live handle with the current final pathname, without reading contents.
pub fn verify_path_identity(file: &File, path: &Path) -> Result<(), String> {
    let current = fs::symlink_metadata(path).map_err(|_| STORAGE_ERROR)?;
    let held = file.metadata().map_err(|_| STORAGE_ERROR)?;
    if !current.is_file() || current.file_type().is_symlink() || !held.is_file() {
        return Err(STORAGE_ERROR.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if held.dev() != current.dev() || held.ino() != current.ino() {
            return Err(STORAGE_ERROR.into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        if current.file_attributes() & 0x400 != 0 || held.file_attributes() & 0x400 != 0 {
            return Err(STORAGE_ERROR.into());
        }
        #[repr(C)]
        #[derive(Default)]
        struct Info {
            attributes: u32,
            creation: [u32; 2],
            access: [u32; 2],
            write: [u32; 2],
            volume: u32,
            size_high: u32,
            size_low: u32,
            links: u32,
            index_high: u32,
            index_low: u32,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut Info) -> i32;
        }
        let other = safe_options(false).open(path).map_err(|_| STORAGE_ERROR)?;
        let mut a = Info::default();
        let mut b = Info::default();
        // SAFETY: both handles remain live; Info follows BY_HANDLE_FILE_INFORMATION layout.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut a) } == 0
            || unsafe { GetFileInformationByHandle(other.as_raw_handle(), &mut b) } == 0
            || (a.volume, a.index_high, a.index_low) != (b.volume, b.index_high, b.index_low)
            || b.attributes & 0x400 != 0
        {
            return Err(STORAGE_ERROR.into());
        }
    }
    Ok(())
}
pub fn prepare_database(path: &Path) -> Result<(), String> {
    check_parent(path)?;
    let mut paths = vec![path.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut p = path.as_os_str().to_os_string();
        p.push(suffix);
        paths.push(PathBuf::from(p));
    }
    // Check every existing sidecar before SQLite can open or modify any of them.
    for p in &paths {
        match fs::symlink_metadata(p) {
            Ok(_) => {
                checked_existing(p, true)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(STORAGE_ERROR.into()),
        }
    }
    if fs::symlink_metadata(path).is_err() {
        safe_options(true)
            .create_new(true)
            .open(path)
            .map_err(|_| STORAGE_ERROR)?;
    }
    Ok(())
}
pub fn read_private_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = checked_existing(path, false)?;
    let before = file.metadata().map_err(|_| STORAGE_ERROR)?;
    if before.len() > limit as u64 {
        return Err(STORAGE_ERROR.into());
    }
    let mut bytes = Vec::with_capacity(limit.min(4096));
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| STORAGE_ERROR)?;
    if bytes.len() > limit {
        return Err(STORAGE_ERROR.into());
    }
    let after = fs::symlink_metadata(path).map_err(|_| STORAGE_ERROR)?;
    validate_handle(&file, &after)?;
    verify_path_identity(&file, path)?;
    let held_after = file.metadata().map_err(|_| STORAGE_ERROR)?;
    if before.len() != held_after.len()
        || before.modified().map_err(|_| STORAGE_ERROR)?
            != held_after.modified().map_err(|_| STORAGE_ERROR)?
    {
        return Err(STORAGE_ERROR.into());
    }
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AtomicStage {
    Write,
    Sync,
    Rename,
    DirectorySync,
}
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_private_atomic_checked(path, bytes, |_| Ok(()))
}
// Per-call hook: no global/environment state and no OS failure is required by tests.
pub(crate) fn write_private_atomic_checked(
    path: &Path,
    bytes: &[u8],
    mut before: impl FnMut(AtomicStage) -> Result<(), String>,
) -> Result<(), String> {
    let parent = check_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            checked_existing(path, false)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(STORAGE_ERROR.into()),
    }
    let tmp = parent.join(format!(".shugo-anchor-{}.tmp", uuid::Uuid::new_v4()));
    // Only clean up a temp file we successfully created ourselves.
    let mut f = safe_options(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|_| STORAGE_ERROR)?;
    let result = (|| {
        before(AtomicStage::Write)?;
        f.write_all(bytes).map_err(|_| STORAGE_ERROR)?;
        before(AtomicStage::Sync)?;
        f.sync_all().map_err(|_| STORAGE_ERROR)?;
        before(AtomicStage::Rename)?;
        fs::rename(&tmp, path).map_err(|_| STORAGE_ERROR)?;
        before(AtomicStage::DirectorySync)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| STORAGE_ERROR)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_roundtrip_is_bounded_and_private() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("anchor");
        write_private_atomic(&p, b"fixture").unwrap();
        assert_eq!(read_private_bounded(&p, 7).unwrap(), b"fixture");
        assert!(read_private_bounded(&p, 6).is_err());
        write_private_atomic(&p, b"next").unwrap();
        assert_eq!(read_private_bounded(&p, 7).unwrap(), b"next");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    #[cfg(unix)]
    #[test]
    fn links_and_fifo_are_rejected_without_touching_target() {
        let d = tempfile::tempdir().unwrap();
        let sentinel = d.path().join("sentinel");
        fs::write(&sentinel, b"preserve").unwrap();
        let db = d.path().join("db");
        std::os::unix::fs::symlink(&sentinel, &db).unwrap();
        assert!(prepare_database(&db).is_err());
        assert!(read_private_bounded(&db, 4096).is_err());
        assert!(write_private_atomic(&db, b"bad").is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
        fs::remove_file(&db).unwrap();
        fs::write(&db, b"").unwrap();
        let wal = d.path().join("db-wal");
        std::os::unix::fs::symlink(&sentinel, &wal).unwrap();
        assert!(prepare_database(&db).is_err());
        let fifo = d.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        assert!(read_private_bounded(&fifo, 4096).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_parent_and_hardlinks_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_database(&p).is_err());
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&p, b"preserve").unwrap();
        fs::hard_link(&p, d.path().join("alias")).unwrap();
        assert!(prepare_database(&p).is_err());
        assert_eq!(fs::read(p).unwrap(), b"preserve");
    }
}
