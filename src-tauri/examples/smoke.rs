use shugo_core::{
    core::Core,
    types::{id, RegisteredFile},
};
use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
fn scan(c: &std::sync::Arc<Core>) -> shugo_core::types::Run {
    let request = id();
    let run = c.start(&request, &c.epoch, "manual").expect("scan start");
    assert_eq!(run, c.start(&request, &c.epoch, "manual").unwrap());
    let begin = Instant::now();
    while c.snapshot().unwrap().active.is_some() {
        assert!(begin.elapsed() < Duration::from_secs(30), "scan timed out");
        thread::sleep(Duration::from_millis(50));
    }
    c.snapshot().unwrap().runs[0].clone()
}
fn main() {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("explicit fresh test database path required");
    assert!(!path.exists(), "use a fresh database path");
    let c = Core::open(&path).expect("open core");
    let first = scan(&c);
    assert!(!first.checks.is_empty());
    let fixture = path.with_extension("synthetic-fixture.txt");
    assert!(!fixture.exists());
    std::fs::write(&fixture, "Shugo synthetic test version 1\n").unwrap();
    let file = RegisteredFile {
        id: id(),
        label: "Synthetic smoke fixture".into(),
        path: fixture.to_str().unwrap().into(),
    };
    {
        let mut inner = c.inner.lock().unwrap();
        let mut settings = inner.settings.clone();
        settings.revision += 1;
        inner
            .store
            .add_file_with_settings(&file, &settings)
            .unwrap();
        inner.settings = settings;
    }
    let check_id = file.id.clone();
    let observed = scan(&c);
    let check = observed
        .checks
        .iter()
        .find(|ch| ch.id == check_id)
        .expect("registered FIM result");
    assert_eq!(check.status, "unverified");
    // Test-only baseline for our generated fixture; no native approval or personal file is used.
    c.inner
        .lock()
        .unwrap()
        .store
        .accept_baseline(&check.id, check.digest.as_deref().unwrap())
        .unwrap();
    let unchanged = scan(&c);
    assert_eq!(
        unchanged
            .checks
            .iter()
            .find(|ch| ch.id == check_id)
            .unwrap()
            .status,
        "ok"
    );
    std::fs::write(&fixture, "Shugo synthetic test version 2\n").unwrap();
    let changed = scan(&c);
    assert_eq!(
        changed
            .checks
            .iter()
            .find(|ch| ch.id == check_id)
            .unwrap()
            .status,
        "attention"
    );
    let rev = c.snapshot().unwrap().settings.revision;
    c.pause(true, rev).unwrap();
    assert!(c.start(&id(), &c.epoch, "manual").is_err());
    c.pause(false, rev + 1).unwrap();
    let snap = c.snapshot().unwrap();
    assert!(!snap.cloud_enabled);
    assert_eq!(snap.budget.patrol_calls, 0);
    assert_eq!(snap.budget.resolver_calls, 0);
    assert_eq!(snap.findings.len(), 1);
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "os":snap.os,"realPostureChecks":first.checks.len(),"runs":snap.runs.len(),
        "manualScan":"pass","duplicateRequest":"same run", "syntheticFim":"unverified → ok → attention",
        "pauseResume":"pass","findings":snap.findings.len(),"aiCalls":0,
        "checks":first.checks.iter().map(|c|serde_json::json!({"id":c.id,"status":c.status})).collect::<Vec<_>>()
    })).unwrap());
}
