use crate::types::{Check, RegisteredFile};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub fn fixed_command(program: &str, args: &[&str], cancel: &AtomicBool) -> Result<String, String> {
    bounded_command(program, args, cancel, Duration::from_secs(3))
}

/// Read-only TCP inventory needs a larger, still bounded output budget.
/// Posture/CLI adapters retain fixed_command's original 16 KiB cap.
pub fn network_command(
    program: &str,
    args: &[&str],
    cancel: &AtomicBool,
) -> Result<String, String> {
    bounded_command_with_limit(program, args, cancel, Duration::from_secs(3), 128 * 1024)
}

// Read only bytes already available in the pipe. No detached blocking reader can survive
// cancellation, and the deadline covers both process exit and inherited stdout handles.
fn bounded_command(
    program: &str,
    args: &[&str],
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<String, String> {
    bounded_command_with_limit(program, args, cancel, timeout, 16 * 1024)
}
fn bounded_command_with_limit(
    program: &str,
    args: &[&str],
    cancel: &AtomicBool,
    timeout: Duration,
    output_limit: usize,
) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        if let Ok(root) = std::env::var("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| "検査コマンドを利用できません".to_string())?;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or("出力を取得できません")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: stdout owns this valid descriptor throughout the call.
            let fd = stdout.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err("出力の有界読取を設定できません".into());
            }
        }
        let start = Instant::now();
        let mut bytes = Vec::new();
        let mut status = None;
        let mut eof = false;
        loop {
            if cancel.load(Ordering::SeqCst) || start.elapsed() >= timeout {
                return Err("検査を中止、またはタイムアウトしました".into());
            }
            if status.is_none() {
                status = child.try_wait().map_err(|_| "検査の状態を取得できません")?;
            }
            let mut buffer = [0u8; 4096];
            #[cfg(windows)]
            let available = {
                use std::os::windows::io::AsRawHandle;
                #[link(name = "kernel32")]
                extern "system" {
                    fn PeekNamedPipe(
                        pipe: *mut std::ffi::c_void,
                        buffer: *mut std::ffi::c_void,
                        size: u32,
                        read: *mut u32,
                        available: *mut u32,
                        remaining: *mut u32,
                    ) -> i32;
                }
                let mut available = 0;
                // SAFETY: this is the live stdout pipe handle; null output buffers are supported.
                let ok = unsafe {
                    PeekNamedPipe(
                        stdout.as_raw_handle(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(109) {
                        eof = true;
                        0
                    } else {
                        return Err("出力取得失敗".into());
                    }
                } else {
                    available.min(buffer.len() as u32) as usize
                }
            };
            #[cfg(not(windows))]
            let available = buffer.len();
            if !eof && available > 0 {
                match stdout.read(&mut buffer[..available]) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        bytes.extend_from_slice(&buffer[..n]);
                        if bytes.len() > output_limit {
                            return Err("出力上限を超えました".into());
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err("出力取得失敗".into()),
                }
            }
            if let Some(exit) = status.filter(|_| eof) {
                if !exit.success() {
                    return Err("権限不足または取得不能です".into());
                }
                return String::from_utf8(bytes).map_err(|_| "不正な応答".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    #[cfg(unix)]
    {
        // SAFETY: the child's dedicated group was created above; no other app process belongs to it.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    // Windows currently has no process-tree guarantee: closing stdout and killing the direct
    // child bounds this collector. CLI adapters remain disabled until job containment is verified.
    let _ = child.kill();
    let reap_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < reap_deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    result
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn posture(
    id: &str,
    title: &str,
    program: &str,
    args: &[&str],
    yes: &str,
    no: &str,
    cancel: &AtomicBool,
) -> Check {
    match fixed_command(program, args, cancel) {
        Ok(text) if text.contains(yes) => Check::new(
            id,
            title,
            "保護設定",
            "ok",
            "この保護機能は有効です。",
            program,
        ),
        Ok(text) if text.contains(no) => Check::new(
            id,
            title,
            "保護設定",
            "attention",
            "この保護機能は無効です。OSの設定を確認してください。",
            program,
        ),
        _ => Check::new(
            id,
            title,
            "保護設定",
            "unavailable",
            "この環境では状態を確認できませんでした。",
            program,
        ),
    }
}
pub fn collect(files: &[RegisteredFile], cancel: Arc<AtomicBool>, mut emit: impl FnMut(Check)) {
    macro_rules! send {
        ($value:expr) => {
            if cancel.load(Ordering::SeqCst) {
                return;
            }
            emit($value);
        };
    }
    #[cfg(target_os = "macos")]
    {
        send!(posture(
            "gatekeeper",
            "Gatekeeper",
            "/usr/sbin/spctl",
            &["--status"],
            "assessments enabled",
            "assessments disabled",
            &cancel
        ));
        send!(posture(
            "sip",
            "システム整合性保護 (SIP)",
            "/usr/bin/csrutil",
            &["status"],
            "status: enabled",
            "status: disabled",
            &cancel
        ));
        send!(posture(
            "filevault",
            "ディスク暗号化 (FileVault)",
            "/usr/bin/fdesetup",
            &["status"],
            "FileVault is On",
            "FileVault is Off",
            &cancel
        ));
        send!(posture(
            "firewall",
            "アプリケーションファイアウォール",
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
            "State = 1",
            "State = 0",
            &cancel
        ));
    }
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let ps = format!(
            "{}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            root
        );
        send!(posture("defender","Microsoft Defender リアルタイム保護",&ps,&["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; try { $s=Get-MpComputerStatus -ErrorAction Stop; if ($null -eq $s -or $s.RealTimeProtectionEnabled -isnot [bool]) { exit 2 }; if ($s.RealTimeProtectionEnabled) { 'shugo_enabled' } else { 'shugo_disabled' } } catch { exit 2 }"],"shugo_enabled","shugo_disabled",&cancel));
        send!(posture("firewall","Windows ファイアウォール",&ps,&["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; try { $p=@(Get-NetFirewallProfile -ErrorAction Stop); if ($p.Count -ne 3 -or @($p | Where-Object { $null -eq $_.Enabled }).Count -gt 0) { exit 2 }; if (@($p | Where-Object { $_.Enabled -ne $true }).Count -eq 0) { 'shugo_enabled' } else { 'shugo_disabled' } } catch { exit 2 }"],"shugo_enabled","shugo_disabled",&cancel));
    }
    #[cfg(target_os = "linux")]
    {
        let apparmor = fs::read_to_string("/sys/module/apparmor/parameters/enabled").ok();
        let selinux = fs::read_to_string("/sys/fs/selinux/enforce").ok();
        let enabled = apparmor.as_deref().is_some_and(|x| x.trim() == "Y")
            || selinux.as_deref().is_some_and(|x| x.trim() == "1");
        send!(Check::new(
            "mandatory_access",
            "AppArmor / SELinux",
            "保護設定",
            if enabled { "ok" } else { "unavailable" },
            if enabled {
                "カーネルの制限機構が有効です。全プロセスの保護を保証するものではありません。"
            } else {
                "有効な制限機構を確認できません。権限や構成を確認してください。"
            },
            "sysfs"
        ));
        send!(Check::new(
            "firewall",
            "Linux ファイアウォール",
            "保護設定",
            "unavailable",
            "一般ユーザーで共通に検証できるAPIは未対応です。",
            "platform capability"
        ));
    }
    send!(Check::new(
        "av_alerts",
        "既存ウイルス対策の警告履歴",
        "既存警告",
        "unavailable",
        "警告履歴の読取アダプターはこの版では未対応です。標準セキュリティ画面で確認してください。",
        "platform capability"
    ));
    let sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let total = sys.total_memory();
    let used = sys.used_memory();
    if let Some(percent) = used.saturating_mul(100).checked_div(total) {
        send!(Check::new(
            "memory",
            "メモリの使用状況",
            "PCの状態",
            if percent >= 95 { "attention" } else { "ok" },
            &format!("使用率 {percent}%。単独では侵害の根拠になりません。"),
            "sysinfo"
        ));
    }
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let low = disks.iter().filter(|d| d.total_space() > 0).any(|d| {
        d.available_space() < d.total_space() / 20 || d.available_space() < 2 * 1024 * 1024 * 1024
    });
    send!(Check::new(
        "disk",
        "ディスクの空き容量",
        "PCの状態",
        if disks.is_empty() {
            "unavailable"
        } else if low {
            "attention"
        } else {
            "ok"
        },
        if low {
            "空き容量が少ないボリュームがあります。5%または2 GiB未満です。"
        } else {
            "確認できたボリュームに、空き容量5%または2 GiB未満のものはありません。"
        },
        "sysinfo"
    ));
    #[cfg(target_os = "macos")]
    {
        let mut dirs = vec![
            std::path::PathBuf::from("/Library/LaunchAgents"),
            std::path::PathBuf::from("/Library/LaunchDaemons"),
        ];
        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(std::path::PathBuf::from(home).join("Library/LaunchAgents"));
        }
        let mut entries = Vec::new();
        let mut readable = true;
        for dir in dirs {
            match fs::read_dir(&dir) {
                Ok(list) => {
                    for entry in list.take(101) {
                        if let Ok(e) = entry {
                            entries.push(format!("{}", e.path().display()));
                        } else {
                            readable = false;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => readable = false,
            }
        }
        entries.sort();
        let mut item=Check::new("startup","自動起動項目の一覧差分","変更検知","unverified","登録した3つのLaunchAgents/LaunchDaemons領域の項目名を比較します。内容の安全性は判定しません。","directory entries (names only)");
        if !readable || entries.len() > 100 {
            item.status = "unavailable".into();
            item.detail = "項目数上限または権限のため完全な比較ができません。".into();
        } else {
            item.digest = Some(format!(
                "{:x}",
                Sha256::digest(entries.join("\n").as_bytes())
            ));
        }
        send!(item);
    }
    #[cfg(not(target_os = "macos"))]
    send!(Check::new(
        "startup",
        "自動起動項目の一覧差分",
        "変更検知",
        "unavailable",
        "このOSの自動起動項目アダプターは未実装です。",
        "platform capability"
    ));
    let mut hash_budget = 32 * 1024 * 1024u64;
    for file in files {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let mut check = Check::new(
            &file.id,
            &file.label,
            "指定ファイル",
            "unverified",
            "登録したファイルのSHA-256を比較します。",
            "selected file / SHA-256",
        );
        match hash_file_with_budget(
            std::path::Path::new(&file.path),
            &cancel,
            &mut hash_budget,
            || {},
        ) {
            Ok(hash) => check.digest = Some(hash),
            Err(e) => {
                check.status = "unavailable".into();
                check.detail = e;
            }
        }
        emit(check);
    }
}
pub fn hash_file(path: &std::path::Path) -> Result<String, String> {
    hash_file_with_budget(
        path,
        &AtomicBool::new(false),
        &mut (16 * 1024 * 1024u64),
        || {},
    )
}
fn verify_read_identity(
    file: &fs::File,
    path: &std::path::Path,
    before: &fs::Metadata,
) -> Result<(), String> {
    let after = file.metadata().map_err(|_| "再確認に失敗しました")?;
    if before.len() != after.len()
        || before.modified().map_err(|_| "更新時刻を確認できません")?
            != after.modified().map_err(|_| "更新時刻を確認できません")?
    {
        return Err("読取中に変更されたため再検査が必要です".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
            return Err("読取中に変更されたため再検査が必要です".into());
        }
    }
    crate::storage_fs::verify_path_identity(file, path)
        .map_err(|_| "登録した対象が変更されました。再検査が必要です".into())
}
fn hash_file_with_budget(
    path: &std::path::Path,
    cancel: &AtomicBool,
    budget: &mut u64,
    after_read: impl FnOnce(),
) -> Result<String, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "ファイルを読み取れません")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 {
        return Err("通常ファイル（16 MiB以下）だけを登録できます".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options
        .open(path)
        .map_err(|_| "ファイルを安全に開けません")?;
    let before = file
        .metadata()
        .map_err(|_| "ファイル情報を確認できません")?;
    if !before.is_file() || before.len() > 16 * 1024 * 1024 {
        return Err("対象ファイルが変化しました".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != before.dev() || meta.ino() != before.ino() {
            return Err("対象が変更されました".into());
        }
    }
    crate::storage_fs::verify_path_identity(&file, path)?;
    if before.len() > *budget {
        return Err("今回のハッシュ読取上限32 MiBを超えました。".into());
    }
    let start = Instant::now();
    let mut reader = &file;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        if cancel.load(Ordering::SeqCst) || start.elapsed() >= Duration::from_secs(3) {
            return Err("検査を中止、または読取時間上限を超えました".into());
        }
        // Each actual byte consumes the shared patrol budget, including files rejected later.
        let read_limit = (*budget)
            .saturating_add(1)
            .min(
                (16 * 1024 * 1024u64)
                    .saturating_sub(total)
                    .saturating_add(1),
            )
            .min(buffer.len() as u64) as usize;
        let n = reader
            .read(&mut buffer[..read_limit])
            .map_err(|_| "ファイルを読み取れません")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        let remaining = *budget;
        *budget = budget.saturating_sub(n as u64);
        if n as u64 > remaining || total > 16 * 1024 * 1024 {
            return Err("ハッシュ読取上限を超えました".into());
        }
        hasher.update(&buffer[..n]);
    }
    after_read();
    if cancel.load(Ordering::SeqCst) || start.elapsed() >= Duration::from_secs(3) {
        return Err("検査を中止、または読取時間上限を超えました".into());
    }
    verify_read_identity(&file, path, &before)?;
    if total != before.len() {
        return Err("読取中に変更されたため再検査が必要です".into());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_changes_and_symlink_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("test");
        fs::write(&p, "before").unwrap();
        let a = hash_file(&p).unwrap();
        fs::write(&p, "after").unwrap();
        assert_ne!(a, hash_file(&p).unwrap());
        #[cfg(unix)]
        {
            let l = d.path().join("link");
            std::os::unix::fs::symlink(&p, &l).unwrap();
            assert!(hash_file(&l).is_err());
        }
    }
    #[test]
    fn oversized_file_is_not_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("large");
        let f = fs::File::create(&p).unwrap();
        f.set_len(16 * 1024 * 1024 + 1).unwrap();
        assert!(hash_file(&p).is_err());
    }
}

pub fn read_secret_file(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    read_secret_checked(path, || {})
}
fn read_secret_checked(
    path: &std::path::Path,
    before_open: impl FnOnce(),
) -> Result<zeroize::Zeroizing<String>, String> {
    read_secret_with_hooks(path, before_open, || {})
}
fn read_secret_with_hooks(
    path: &std::path::Path,
    before_open: impl FnOnce(),
    after_read: impl FnOnce(),
) -> Result<zeroize::Zeroizing<String>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "ファイルを確認できません")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8192 {
        return Err("8 KiB以下の通常ファイルを選んでください".into());
    }
    before_open();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path).map_err(|_| "キーを安全に開けません")?;
    let before = file
        .metadata()
        .map_err(|_| "ファイル情報を確認できません")?;
    if !before.is_file() || before.len() > 8192 {
        return Err("対象が変更されました".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.ino() != meta.ino() || before.dev() != meta.dev() {
            return Err("選択対象が変更されました".into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err("再解析ポイントは対象外です".into());
        }
    }
    let mut secret = zeroize::Zeroizing::new(String::new());
    (&file)
        .take(8193)
        .read_to_string(&mut secret)
        .map_err(|_| "キーを読み取れません")?;
    after_read();
    if secret.len() > 8192 || secret.len() as u64 != before.len() {
        return Err("読取中に変更されました".into());
    }
    verify_read_identity(&file, path, &before)?;
    Ok(secret)
}
#[cfg(all(test, unix))]
mod review1_tests {
    use super::*;
    #[test]
    fn credential_replacement_before_open_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("key");
        let other = d.path().join("other");
        fs::write(&p, "fixture-key-value-123").unwrap();
        fs::write(&other, "different-key-value-123").unwrap();
        assert!(read_secret_checked(&p, || {
            fs::remove_file(&p).unwrap();
            std::os::unix::fs::symlink(&other, &p).unwrap();
        })
        .is_err());
    }
    #[test]
    fn credential_fifo_replacement_does_not_block() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("key");
        fs::write(&p, "fixture-key-value-123").unwrap();
        let before = Instant::now();
        assert!(read_secret_checked(&p, || {
            fs::remove_file(&p).unwrap();
            let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        })
        .is_err());
        assert!(before.elapsed() < Duration::from_secs(1));
    }
}

#[cfg(all(test, unix))]
mod bounded_runner_tests {
    use super::*;
    #[test]
    fn inherited_stdout_cannot_outlive_deadline() {
        let start = Instant::now();
        let result = bounded_command(
            "/bin/sh",
            &["-c", "sleep 30 & exit 0"],
            &AtomicBool::new(false),
            Duration::from_millis(120),
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            fixed_command("/bin/sh", &["-c", "printf ready"], &AtomicBool::new(false)).unwrap(),
            "ready"
        );
    }
    #[test]
    fn cancellation_also_covers_inherited_stdout() {
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        assert!(bounded_command(
            "/bin/sh",
            &["-c", "sleep 30 & exit 0"],
            &cancel,
            Duration::from_secs(3)
        )
        .is_err());
        setter.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[cfg(all(test, unix))]
mod hardening_identity_tests {
    use super::*;
    #[test]
    fn pathname_replacement_after_read_never_returns_old_digest_or_secret() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("file");
        let replacement = d.path().join("replacement");
        fs::write(&p, b"old-fixture-key-123").unwrap();
        fs::write(&replacement, b"new-fixture-key-456").unwrap();
        assert!(
            hash_file_with_budget(&p, &AtomicBool::new(false), &mut 1024, || {
                fs::rename(&replacement, &p).unwrap();
            })
            .is_err()
        );
        fs::write(&replacement, b"old-fixture-key-123").unwrap();
        assert!(read_secret_with_hooks(
            &p,
            || {},
            || {
                fs::rename(&replacement, &p).unwrap();
            }
        )
        .is_err());
    }
    #[test]
    fn cancelled_hash_and_shared_budget_do_not_publish_digest() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("file");
        fs::write(&p, b"12345678").unwrap();
        let cancel = AtomicBool::new(true);
        assert!(hash_file_with_budget(&p, &cancel, &mut 100, || {}).is_err());
        cancel.store(false, Ordering::SeqCst);
        let mut budget = 12;
        assert!(hash_file_with_budget(&p, &cancel, &mut budget, || {}).is_ok());
        assert_eq!(budget, 4);
        assert!(hash_file_with_budget(&p, &cancel, &mut budget, || {}).is_err());
        assert_eq!(budget, 4);
        assert!(hash_file_with_budget(&p, &cancel, &mut 100, || {
            cancel.store(true, Ordering::SeqCst);
        })
        .is_err());
    }
}

#[cfg(all(test, unix))]
mod network_output_budget_tests {
    use super::*;
    #[test]
    fn posture_cap_is_unchanged_and_network_cap_stays_bounded() {
        let synthetic = "x".repeat(20_000);
        assert_eq!(
            fixed_command(
                "/usr/bin/printf",
                &["%s", &synthetic],
                &AtomicBool::new(false)
            )
            .unwrap_err(),
            "出力上限を超えました"
        );
        assert_eq!(
            network_command(
                "/usr/bin/printf",
                &["%s", &synthetic],
                &AtomicBool::new(false)
            )
            .unwrap()
            .len(),
            20_000
        );
        assert_eq!(
            network_command("/usr/bin/yes", &["fixture"], &AtomicBool::new(false)).unwrap_err(),
            "出力上限を超えました"
        );
    }
}
