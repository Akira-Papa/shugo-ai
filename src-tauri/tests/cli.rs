use shugo_core::{
    store::Store,
    types::{now_ms, Check, Run},
};
use std::{
    path::Path,
    process::{Command, Output},
};
fn invoke(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_shugo"))
        .arg("--data-dir")
        .arg(dir)
        .arg("--json")
        .args(args)
        .output()
        .unwrap()
}
fn value(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
#[test]
fn help_version_and_missing_permission_do_not_access_key_or_storage() {
    assert!(Command::new(env!("CARGO_BIN_EXE_shugo"))
        .arg("--help")
        .output()
        .unwrap()
        .status
        .success());
    let out = Command::new(env!("CARGO_BIN_EXE_shugo"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("shugo "));
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("new-data");
    let out = invoke(
        &data,
        &[
            "ai",
            "--role",
            "patrol",
            "--provider",
            "openai",
            "--model",
            "fixture",
            "--input-rate",
            "1000000",
            "--output-rate",
            "2000000",
            "--key-file",
            "/nonexistent-key",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-cloud"));
    assert!(!data.exists());
}
#[test]
fn models_roundtrip_files_duplicate_and_status_have_no_grant() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let out = invoke(
        &data,
        &[
            "models",
            "set",
            "--role",
            "patrol",
            "--provider",
            "openai",
            "--model",
            "fixture-model",
            "--input-rate",
            "1000000",
            "--output-rate",
            "2000000",
        ],
    );
    assert_eq!(value(&out)["patrol"]["model"], "fixture-model");
    let fixture = tmp.path().join("fixture.txt");
    std::fs::write(&fixture, "synthetic content").unwrap();
    let path = fixture.to_str().unwrap();
    assert_eq!(
        value(&invoke(&data, &["files", "add", path]))["registered"],
        true
    );
    assert!(!invoke(&data, &["files", "add", path]).status.success());
    let status = value(&invoke(&data, &["status"]));
    assert_eq!(status["cloudEnabled"], false);
    assert_eq!(status["files"].as_array().unwrap().len(), 1);
    assert_eq!(status["response"]["policy"]["mode"], "confirm");
}
#[test]
fn baseline_binds_exact_latest_observation_and_requires_yes() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    value(&invoke(&data, &["status"]));
    let now = now_ms();
    let mut check = Check::new(
        "fixture-check",
        "fixture",
        "指定ファイル",
        "unverified",
        "fixture",
        "fixture",
    );
    check.observed_at = now;
    check.digest = Some("fixture-digest".into());
    let run = Run {
        id: "fixture-run".into(),
        trigger: "manual".into(),
        status: "completed".into(),
        started_at: now,
        finished_at: Some(now),
        checks: vec![check],
    };
    {
        let mut store = Store::open(&data.join("guardian.sqlite3")).unwrap();
        store.save_run(&run).unwrap();
    }
    let stamp = now.to_string();
    let args = [
        "baseline",
        "--check-id",
        "fixture-check",
        "--run-id",
        "fixture-run",
        "--digest",
        "fixture-digest",
        "--observed-at",
        stamp.as_str(),
    ];
    assert!(!invoke(&data, &args).status.success());
    let mut yes = args.to_vec();
    yes.push("--yes");
    assert_eq!(value(&invoke(&data, &yes))["accepted"], true);
    yes[4] = "another-run";
    assert!(!invoke(&data, &yes).status.success());
    yes[4] = "fixture-run";
    yes[6] = "another-digest";
    assert!(!invoke(&data, &yes).status.success());
}
#[test]
fn finite_watch_emits_ndjson_with_real_check_statuses() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let out = invoke(&data, &["watch", "--interval", "1", "--count", "1"]);
    let run = value(&out);
    assert!(["completed", "partial"].contains(&run["status"].as_str().unwrap()));
    assert!(!run["checks"].as_array().unwrap().is_empty());
    assert!(
        !invoke(&data, &["watch", "--interval", "0", "--count", "1"])
            .status
            .success()
    );
}
#[test]
fn unsafe_storage_and_second_writer_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    value(&invoke(&data, &["status"]));
    let lock = shugo_core::app_storage::open_instance_lock(&data.join("instance.lock")).unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    assert!(!invoke(&data, &["status"]).status.success());
    drop(lock);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let unsafe_dir = tmp.path().join("public");
        std::fs::create_dir(&unsafe_dir).unwrap();
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!invoke(&unsafe_dir, &["status"]).status.success());
        let alias = tmp.path().join("alias");
        symlink(&data, &alias).unwrap();
        assert!(!invoke(&alias, &["status"]).status.success());
        let file = tmp.path().join("fixture.txt");
        std::fs::write(&file, "synthetic").unwrap();
        let link = tmp.path().join("fixture-link");
        symlink(&file, &link).unwrap();
        assert!(!invoke(&data, &["files", "add", link.to_str().unwrap()])
            .status
            .success());
    }
}
#[test]
fn explicit_access_log_fixture_and_missing_log_differ() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let log = tmp.path().join("access.log");
    std::fs::write(&log,"192.0.2.1 - - [08/Oct/2026:12:00:00 +0000] \"GET /secret?token=PRIVATE HTTP/1.1\" 404 12\n").unwrap();
    let out = invoke(&data, &["access-log", log.to_str().unwrap()]);
    let report = value(&out);
    assert_ne!(report["status"], "unavailable");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE"));
    assert!(!invoke(&data, &["access-log", "/nonexistent-fixture-log"])
        .status
        .success());
}

#[test]
fn human_scan_and_watch_attached_coverage_do_not_imply_safety() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let human = Command::new(env!("CARGO_BIN_EXE_shugo"))
        .arg("--data-dir")
        .arg(&data)
        .arg("scan")
        .output()
        .unwrap();
    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("観測時刻"));
    assert!(text.contains("未検査"));
    assert!(text.contains("保証しません"));
    let log = tmp.path().join("access.log");
    std::fs::write(
        &log,
        "192.0.2.1 - - [08/Oct/2026:12:00:00 +0000] \"GET /?token=PRIVATE HTTP/1.1\" 200 12\n",
    )
    .unwrap();
    let good = invoke(
        &data,
        &[
            "watch",
            "--count",
            "1",
            "--connections",
            "--access-log",
            log.to_str().unwrap(),
        ],
    );
    let event = value(&good);
    assert!(event["run"]["checks"].is_array());
    assert!(event["connections"]["status"].is_string());
    assert_eq!(event["accessLog"]["status"], "observed");
    assert!(!String::from_utf8_lossy(&good.stdout).contains("PRIVATE"));
    let missing = value(&invoke(
        &data,
        &[
            "watch",
            "--count",
            "1",
            "--access-log",
            "/nonexistent-fixture-log",
        ],
    ));
    assert_eq!(missing["coverage"], "partial");
    assert_eq!(missing["accessLog"]["status"], "unavailable");
    assert!(missing["accessLog"]["error"].is_string());
}
#[cfg(unix)]
#[test]
fn watch_interrupt_and_termination_exit_and_release_storage() {
    use std::{
        io::{BufRead, BufReader},
        time::{Duration, Instant},
    };
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let mut child = Command::new(env!("CARGO_BIN_EXE_shugo"))
            .arg("--data-dir")
            .arg(&data)
            .args(["--json", "watch", "--interval", "60"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Observe one completed persisted run before testing termination during the wait.
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        assert!(!first.is_empty());
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "signal {signal} must gracefully finish");
                break;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("signal handler did not stop watch")
            };
            std::thread::sleep(Duration::from_millis(30));
        }
        let status = value(&invoke(&data, &["status"]));
        assert_eq!(status["cloudEnabled"], false);
        assert!(status["active"].is_null());
        assert_eq!(status["runs"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn closed_stdout_returns_error_without_panic_and_releases_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let mut child = Command::new(env!("CARGO_BIN_EXE_shugo"))
        .arg("--data-dir")
        .arg(&data)
        .args(["--json", "status"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Output stream"));
    assert!(!err.contains("panicked"));
    value(&invoke(&data, &["status"]));
}
#[test]
fn invalid_ai_price_is_rejected_before_storage_or_key_read() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("untouched");
    let out = invoke(
        &data,
        &[
            "ai",
            "--role",
            "resolver",
            "--provider",
            "openai",
            "--model",
            "fixture",
            "--input-rate",
            "0",
            "--output-rate",
            "0",
            "--key-file",
            "/nonexistent-fixture-key",
            "--allow-cloud",
        ],
    );
    assert!(!out.status.success());
    assert!(!data.exists());
}
