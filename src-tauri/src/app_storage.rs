//! Startup files are local app data, never arbitrary link targets.
use std::{fs, io, path::Path};

/// WebView may pre-create a readable app directory. Keep private state in a child,
/// but never silently abandon legacy data, anchors or partial database files.
pub fn desktop_data_dir(base: &Path) -> io::Result<std::path::PathBuf> {
    match fs::symlink_metadata(base) {
        Ok(meta) => {
            validate_directory(&meta)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o022 != 0 {
                    return Err(io::Error::other(
                        "アプリ保存先の親が他ユーザーから書込み可能です",
                    ));
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    for name in [
        "guardian.sqlite3",
        "guardian.sqlite3-wal",
        "guardian.sqlite3-shm",
        "guardian.sqlite3-journal",
        "guardian.budget-anchor.json",
        "instance.lock",
    ] {
        match fs::symlink_metadata(base.join(name)) {
            Ok(_) => return Ok(base.to_path_buf()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(base.join("private"))
}

pub fn prepare_data_dir(path: &Path) -> io::Result<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(meta) => {
            validate_directory(&meta)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::other("既存の保存先は所有者だけがアクセスできる専用フォルダにしてください。フォルダの権限は変更していません。"));
                }
            }
            false
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            true
        }
        Err(e) => return Err(e),
    };
    validate_directory(&fs::symlink_metadata(path)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)?;
        validate_directory(&dir.metadata()?)?;
        if created {
            dir.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    let _ = created;
    Ok(())
}

fn validate_directory(meta: &fs::Metadata) -> io::Result<()> {
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other(
            "保存先はリンクではない専用フォルダを指定してください",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments or side effects.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other("保存先の所有者を確認できません"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("再解析ポイントは保存先にできません"));
        }
    }
    Ok(())
}

pub fn open_instance_lock(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("起動ロックが通常ファイルではありません"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no pointer arguments or side effects.
        if meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 {
            return Err(io::Error::other("起動ロックの所有者・リンク数が不正です"));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("起動ロックの再解析ポイントを拒否しました"));
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desktop_webview_parent_uses_private_child_and_preserves_legacy_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("webview");
        fs::create_dir(&base).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let selected = desktop_data_dir(&base).unwrap();
        assert_eq!(selected, base.join("private"));
        prepare_data_dir(&selected).unwrap();
        for name in [
            "guardian.sqlite3",
            "guardian.sqlite3-wal",
            "guardian.sqlite3-shm",
            "guardian.sqlite3-journal",
            "guardian.budget-anchor.json",
            "instance.lock",
        ] {
            fs::write(base.join(name), "preserve").unwrap();
            assert_eq!(desktop_data_dir(&base).unwrap(), base);
            fs::remove_file(base.join(name)).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                fs::metadata(&base).unwrap().permissions().mode() & 0o777,
                0o755
            );
            let missing = base.join("guardian.sqlite3");
            symlink(base.join("absent"), &missing).unwrap();
            assert_eq!(desktop_data_dir(&base).unwrap(), base);
            assert!(prepare_data_dir(&base).is_err());
            fs::remove_file(missing).unwrap();
            fs::set_permissions(&selected, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(prepare_data_dir(&desktop_data_dir(&base).unwrap()).is_err());
            fs::remove_dir(&selected).unwrap();
            symlink(tmp.path(), &selected).unwrap();
            assert!(prepare_data_dir(&desktop_data_dir(&base).unwrap()).is_err());
            let alias = tmp.path().join("alias");
            symlink(&base, &alias).unwrap();
            assert!(desktop_data_dir(&alias).is_err());
            fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(desktop_data_dir(&base).is_err());
        }
    }
    #[test]
    fn private_directory_and_single_instance_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app-data");
        prepare_data_dir(&path).unwrap();
        let lock = open_instance_lock(&path.join("instance.lock")).unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        let second = open_instance_lock(&path.join("instance.lock")).unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&second).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(lock.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    #[cfg(unix)]
    #[test]
    fn linked_directory_and_lock_do_not_touch_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_data_dir(&target).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let alias = tmp.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert!(prepare_data_dir(&alias).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let data = target.join("data");
        fs::write(&data, "preserve").unwrap();
        let link = tmp.path().join("lock");
        symlink(&data, &link).unwrap();
        assert!(open_instance_lock(&link).is_err());
        let hardlink = tmp.path().join("hardlink");
        fs::hard_link(&data, &hardlink).unwrap();
        assert!(open_instance_lock(&hardlink).is_err());
        assert_eq!(fs::read_to_string(data).unwrap(), "preserve");
    }
}
