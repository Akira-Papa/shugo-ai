use crate::{
    collectors, providers,
    response::{ResponseAction, ResponseControl, ResponsePlan},
    store::Store,
    types::*,
};
use notify::Watcher;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct Core {
    pub inner: Mutex<Inner>,
    pub epoch: String,
}
pub struct Inner {
    pub store: Store,
    pub settings: Settings,
    pub active: Option<Run>,
    pub scan_cancel: Arc<AtomicBool>,
    pub cloud: bool,
    pub policy: u64,
    pub catalog_in_flight: bool,
    pub credentials: BTreeMap<String, Zeroizing<String>>,
    pub catalogs: BTreeMap<String, Vec<String>>,
    pub analysis_active: Option<String>,
    pub analysis_cancel: Arc<AtomicBool>,
    pub next_due: Option<Instant>,
    pub gap: Option<String>,
    pub watcher_status: String,
    pub settings_fault: bool,
    pub response_control: ResponseControl,
}
impl Core {
    pub fn open(path: &Path) -> Result<Arc<Self>, String> {
        let mut store = Store::open(path)?;
        store.cleanup_receipts()?;
        for mut r in store.runs()? {
            if r.status == "running" {
                r.status = "partial".into();
                r.finished_at = Some(now_ms());
                store.save_run(&r)?;
            }
        }
        let settings = store.settings()?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                store,
                settings,
                active: None,
                scan_cancel: Arc::new(AtomicBool::new(false)),
                cloud: false,
                policy: 1,
                catalog_in_flight: false,
                credentials: BTreeMap::new(),
                catalogs: BTreeMap::new(),
                analysis_active: None,
                analysis_cancel: Arc::new(AtomicBool::new(false)),
                next_due: None,
                gap: Some("アプリ起動前・睡眠中の状態は観測していません。".into()),
                watcher_status: "停止中".into(),
                settings_fault: false,
                response_control: ResponseControl::default(),
            }),
            epoch: id(),
        }))
    }
    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        let plans = s.store.response_plans()?;
        let response = s.response_control.snapshot(plans, now_ms(), Instant::now());
        Ok(Snapshot {
            version: env!("CARGO_PKG_VERSION").into(),
            os: std::env::consts::OS.into(),
            core_epoch: self.epoch.clone(),
            settings: s.settings.clone(),
            active: s.active.clone(),
            runs: s.store.runs()?,
            findings: s.store.findings()?,
            files: s
                .store
                .files()?
                .iter()
                .map(|f| FileDisplay {
                    id: f.id.clone(),
                    label: f.label.clone(),
                })
                .collect(),
            analyses: project_analyses(
                s.store.analyses()?,
                s.active.as_ref().map(|r| r.id.as_str()),
                &s.store.runs()?,
            ),
            cloud_enabled: s.cloud,
            credentials: ["openai", "anthropic"]
                .iter()
                .map(|p| (p.to_string(), s.credentials.contains_key(*p)))
                .collect(),
            catalogs: s.catalogs.clone(),
            budget: s.store.budget(now_ms())?,
            next_due: s
                .next_due
                .map(|t| now_ms() + t.saturating_duration_since(Instant::now()).as_millis() as u64),
            gap: s.gap.clone(),
            watcher_status: s.watcher_status.clone(),
            analysis_cancel_requested: s.analysis_active.is_some()
                && s.analysis_cancel.load(Ordering::SeqCst),
            catalog_in_flight: s.catalog_in_flight,
            ledger_blocked: s.store.ledger_blocked,
            response,
        })
    }
    pub fn start(
        self: &Arc<Self>,
        request: &str,
        epoch: &str,
        trigger: &str,
    ) -> Result<String, String> {
        self.start_guarded(request, epoch, trigger, None)
    }
    pub fn start_guarded(
        self: &Arc<Self>,
        request: &str,
        epoch: &str,
        trigger: &str,
        schedule_revision: Option<u64>,
    ) -> Result<String, String> {
        if epoch != self.epoch || uuid::Uuid::parse_str(request).is_err() {
            return Err("画面を再読み込みして操作してください。".into());
        }
        let (run, files, cancel) = {
            let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
            if s.settings.paused {
                return Err("巡回は一時停止中です。".into());
            }
            if trigger == "schedule"
                && (schedule_revision != Some(s.settings.revision)
                    || !s.settings.enabled
                    || s.settings.mode == "manual")
            {
                return Err("自動巡回設定が変更されました".into());
            }
            s.store.check_capacity()?;
            if let Some(r) = s.store.receipt(request, epoch)? {
                return Ok(r);
            }
            if let Some(r) = s.active.as_ref() {
                let id = r.id.clone();
                s.store.save_receipt(request, epoch, &id)?;
                return Ok(id);
            }
            let r = Run {
                id: id(),
                trigger: trigger.into(),
                status: "running".into(),
                started_at: now_ms(),
                finished_at: None,
                checks: Vec::new(),
            };
            let files = s.store.files()?;
            s.store.start_run_with_receipt(&r, request, epoch)?;
            s.scan_cancel = Arc::new(AtomicBool::new(false));
            s.active = Some(r.clone());
            (r, files, s.scan_cancel.clone())
        };
        let run_id = run.id.clone();
        let core = self.clone();
        thread::spawn(move || {
            let mut finished = run;
            collectors::collect(&files, cancel.clone(), |mut c| {
                if cancel.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(mut s) = core.inner.lock() {
                    if s.active.as_ref().is_none_or(|r| r.id != finished.id) {
                        return;
                    }
                    if let Some(hash) = &c.digest {
                        match s.store.baseline(&c.id) {
                            Ok(Some(b)) if b == *hash => {
                                c.status = "ok".into();
                                c.detail="本人が確認した基準から変更はありません。内容の安全性は別途確認が必要です。".into();
                            }
                            Ok(Some(_)) => {
                                c.status = "attention".into();
                                c.detail="本人が確認した基準から変更があります。変更内容を確認してください。".into();
                            }
                            Ok(None) => {
                                c.status = "unverified".into();
                                c.detail="比較基準が未確認です。内容を確認してから基準として登録してください。".into();
                            }
                            Err(_) => {
                                c.status = "unavailable".into();
                                c.detail = "比較基準を読み取れません。".into();
                            }
                        }
                    }
                    finished.checks.push(c);
                    if let Some(r) = s.active.as_mut() {
                        r.checks = finished.checks.clone();
                    }
                }
            });
            let mut should_analyze = false;
            if let Ok(mut s) = core.inner.lock() {
                if s.active.as_ref().is_some_and(|r| r.id == finished.id) {
                    finished.status = if cancel.load(Ordering::SeqCst) {
                        "cancelled"
                    } else if finished.checks.iter().any(|c| c.status == "unavailable") {
                        "partial"
                    } else {
                        "completed"
                    }
                    .into();
                    finished.finished_at = Some(now_ms());
                    let changed = patrol_due(&s.store, &finished);
                    match s.store.save_run(&finished) {
                        Ok(()) => {
                            should_analyze = changed && !cancel.load(Ordering::SeqCst) && s.cloud;
                        }
                        Err(_) => {
                            s.cloud = false;
                            s.gap = Some(
                                "結果の保存に失敗しました。クラウド解析を停止しました。".into(),
                            );
                        }
                    }
                    s.active = None;
                }
            }
            if should_analyze {
                let _ = core.analyze("patrol", &finished.id);
            }
        });
        Ok(run_id)
    }
    pub fn pause(&self, paused: bool, revision: u64) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        if !paused && (s.settings_fault || revision != s.settings.revision) {
            return Err("設定が更新されました。最新画面で再開してください。".into());
        }
        let mut candidate = s.settings.clone();
        candidate.paused = paused;
        candidate.revision += 1;
        if !paused {
            s.store.save_settings(&candidate)?;
            s.settings = candidate;
            return Ok(());
        }
        s.settings = candidate;
        if paused {
            s.response_control.invalidate();
            s.scan_cancel.store(true, Ordering::SeqCst);
            s.analysis_cancel.store(true, Ordering::SeqCst);
            s.policy += 1;
            s.next_due = None;
            s.watcher_status = "停止要求中".into();
        }
        if let Err(e) = s.store.save_settings(&s.settings) {
            s.settings_fault = true;
            s.cloud = false;
            s.gap = Some("停止設定の保存に失敗しました。再開を保留します。".into());
            return Err(e);
        }
        Ok(())
    }
    pub fn schedule(&self, mode: &str, enabled: bool, revision: u64) -> Result<(), String> {
        if !["manual", "quarter", "hourly", "continuous"].contains(&mode) {
            return Err("巡回間隔が不正です".into());
        }
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        if revision != s.settings.revision {
            return Err("設定が更新されました。再操作してください。".into());
        }
        let mut candidate = s.settings.clone();
        candidate.mode = mode.into();
        candidate.enabled = enabled && mode != "manual";
        candidate.revision += 1;
        if !candidate.enabled {
            s.settings = candidate;
            s.next_due = None;
            if let Err(e) = s.store.save_settings(&s.settings) {
                s.settings_fault = true;
                s.cloud = false;
                return Err(e);
            }
            return Ok(());
        }
        s.store.save_settings(&candidate)?;
        s.settings = candidate;
        s.next_due = None;
        Ok(())
    }
    pub fn models(
        &self,
        patrol: ModelChoice,
        resolver: ModelChoice,
        revision: u64,
    ) -> Result<(), String> {
        patrol.validate()?;
        resolver.validate()?;
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        if revision != s.settings.revision {
            return Err("設定が更新されました".into());
        }
        let mut candidate = s.settings.clone();
        candidate.patrol = patrol;
        candidate.resolver = resolver;
        candidate.revision += 1;
        s.store.save_settings(&candidate)?;
        s.settings = candidate;
        s.response_control.invalidate();
        s.cloud = false;
        s.policy += 1;
        s.analysis_cancel.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn commit_credential(
        &self,
        provider: &str,
        secret: Zeroizing<String>,
        policy: u64,
    ) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        if s.policy != policy || s.settings.paused || !["openai", "anthropic"].contains(&provider) {
            return Err("接続設定が変わりました。キーは読み込み直してください".into());
        }
        s.credentials.insert(provider.into(), secret);
        s.catalogs.remove(provider);
        s.response_control.invalidate();
        s.cloud = false;
        s.policy += 1;
        s.analysis_cancel.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn commit_catalog(&self, provider: &str, policy: u64) -> Result<Zeroizing<String>, String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        if s.policy != policy || s.settings.paused || s.catalog_in_flight {
            return Err("接続設定が変わったか一時停止中、または確認中です".into());
        }
        if !["openai", "anthropic"].contains(&provider) {
            return Err("未対応の接続方式です".into());
        }
        let key = s
            .credentials
            .get(provider)
            .ok_or("APIキーを先に設定してください")?
            .clone();
        s.catalog_in_flight = true;
        Ok(key)
    }
    pub fn cancel_scan(&self) -> Result<(), String> {
        let s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        s.scan_cancel.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn disable_cloud(&self) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        s.response_control.invalidate();
        s.cloud = false;
        s.policy += 1;
        s.analysis_cancel.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn cancel_analysis(&self) -> Result<(), String> {
        let s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        s.analysis_cancel.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn analyze(self: &Arc<Self>, role: &str, run_id: &str) -> Result<String, String> {
        self.analyze_guarded(role, run_id, None)
    }
    pub fn analyze_guarded(
        self: &Arc<Self>,
        role: &str,
        run_id: &str,
        escalation_revision: Option<u64>,
    ) -> Result<String, String> {
        if !["patrol", "resolver"].contains(&role) {
            return Err("解析の役割が不正です".into());
        }
        let (a, model, prepared, checks, cancel, reserved, attempt, response_revision) = {
            let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
            if s.settings.paused || !s.cloud {
                return Err("クラウド解析は停止中です。接続設定で送信を許可してください。".into());
            }
            let response_policy = s.response_control.policy(now_ms(), Instant::now());
            if escalation_revision.is_some_and(|rev| {
                rev != response_policy.revision
                    || !response_policy.auto_escalate
                    || response_policy.expires_at.is_none()
            }) {
                return Err("自動引継ぎの許可が失効しました".into());
            }
            if s.active.is_some() {
                return Err("検査完了後の最新結果を使用してください".into());
            }
            if let Some(id) = &s.analysis_active {
                return Err(format!("別の解析が実行中です ({})", &id[..8]));
            }
            let model = if role == "patrol" {
                s.settings.patrol.clone()
            } else {
                s.settings.resolver.clone()
            };
            let key = s
                .credentials
                .get(&model.provider)
                .ok_or("APIキーが未設定です")?
                .clone();
            if !s
                .catalogs
                .get(&model.provider)
                .is_some_and(|xs| xs.contains(&model.model))
            {
                return Err("モデル一覧を取得して利用候補を確認してください".into());
            }
            let run = s
                .store
                .runs()?
                .into_iter()
                .find(|r| r.id == run_id)
                .ok_or("検査結果が見つかりません")?;
            if !s.store.runs()?.first().is_some_and(|r| r.id == run_id)
                || run.status == "running"
                || run.status == "cancelled"
                || !evidence_fresh(run.finished_at.unwrap_or(0), now_ms())
                || run.checks.is_empty()
                || run
                    .checks
                    .iter()
                    .any(|c| !evidence_fresh(c.observed_at, now_ms()))
            {
                return Err("新しい検査結果が必要です。再巡回してください。".into());
            }
            if s.store.analyses()?.iter().any(|a| {
                a.run_id == run_id
                    && a.role == role
                    && a.model == model.model
                    && a.provider == model.provider
            }) {
                return Err("この結果は解析済み、または解析を試行済みです。再巡回してから精査してください。".into());
            }
            let prepared = providers::prepare_for_role(&model, &key, &run.checks, role)?;
            let reserved = providers::reservation(&model)?;
            let a = Analysis {
                id: id(),
                role: role.into(),
                run_id: run.id.clone(),
                provider: model.provider.clone(),
                model: model.model.clone(),
                status: "running".into(),
                text: String::new(),
                created_at: now_ms(),
                cost_status: "reserved".into(),
            };
            let attempt = s.store.reserve(&a, reserved, now_ms())?;
            // Reservation and dispatch commitment are serialized with revoke. After this point it is in flight.
            s.analysis_active = Some(a.id.clone());
            s.analysis_cancel = Arc::new(AtomicBool::new(false));
            (
                a,
                model,
                prepared,
                run.checks,
                s.analysis_cancel.clone(),
                reserved,
                attempt,
                response_policy.revision,
            )
        };
        let analysis_id = a.id.clone();
        let core = self.clone();
        thread::spawn(move || {
            let result =
                providers::analyze_prepared_guarded(&model, prepared, checks.len(), &cancel);
            let mut follow_up = None;
            if let Ok(mut s) = core.inner.lock() {
                let mut done = a;
                let actual = result.actual;
                if actual.is_none_or(|v| v > reserved) {
                    s.cloud = false;
                }
                done.cost_status = if actual.is_some() {
                    "settled"
                } else {
                    "unknown"
                }
                .into();
                if cancel.load(Ordering::SeqCst) {
                    done.status = "cancelled".into();
                    done.text =
                        "アプリ内の解析を中止しました。送信済みの情報と費用は取り消せません。"
                            .into();
                } else {
                    match result.advice {
                        Ok(text) => {
                            let stale = s.active.as_ref().is_some_and(|r| r.id != done.run_id)
                                || s.store
                                    .runs()
                                    .ok()
                                    .and_then(|rs| rs.into_iter().find(|r| r.status != "running"))
                                    .is_none_or(|r| {
                                        r.id != done.run_id
                                            || signature(&r.checks) != signature(&checks)
                                    });
                            done.status = if stale { "stale" } else { "succeeded" }.into();
                            done.text = text;
                        }
                        Err(error) => {
                            done.status = "failed".into();
                            done.text = error;
                        }
                    }
                }
                if s.store.finish_analysis(&done, &attempt, actual).is_err() {
                    s.cloud = false;
                    s.store.ledger_blocked = true;
                    s.gap = Some(
                        "解析・費用の確定保存に失敗しました。予約を保持しクラウドを停止しました。"
                            .into(),
                    );
                }
                s.analysis_active = None;
                if !s.store.ledger_blocked {
                    match ingest_response(&mut s, &done, response_revision) {
                        Ok(next) => follow_up = next,
                        Err(_) => {
                            s.response_control.invalidate();
                            s.gap = Some(
                                "対策計画の検証・記録に失敗しました。自動対策を停止しています。"
                                    .into(),
                            );
                        }
                    }
                }
            }
            if let Some((run_id, revision)) = follow_up {
                if let Err(e) = core.analyze_guarded("resolver", &run_id, Some(revision)) {
                    if let Ok(mut s) = core.inner.lock() {
                        s.gap = Some(format!("対策モデルへの自動引継ぎを実行できません: {e}"));
                    }
                }
            }
        });
        Ok(analysis_id)
    }
    pub fn revoke_response_policy(&self) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        s.response_control.invalidate();
        Ok(())
    }
    pub fn execute_response(&self, plan_id: &str, revision: u64) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        execute_plan(&mut s, plan_id, revision, false)
    }
    pub fn emergency_lock(&self) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| "エンジンエラー")?;
        lock_cloud(&mut s);
        // Stop is independent of database health; never delay revocation for an audit write.
        let policy = s.response_control.policy(now_ms(), Instant::now());
        let plan = ResponsePlan::new("user-emergency".into(),id(),ResponseAction::PauseCloud,
            "本人が緊急送信停止を実行。守護AIの新規送信停止とメモリ内キー破棄。PC全体の通信は変更していません。".into(),
            vec!["user-command".into()],policy.revision,now_ms());
        let recorded = (|| {
            s.store.add_response_plan(&plan)?;
            s.store
                .begin_response_action(&plan.id, policy.revision, now_ms())?;
            s.store.finish_response_action(&plan.id, true)
        })();
        if recorded.is_err() {
            s.gap = Some("緊急送信停止を適用しましたが、操作記録の保存に失敗しました。".into());
            return Err(
                "送信停止・アプリ内キー破棄は適用済みです。操作記録を保存できませんでした。".into(),
            );
        }
        Ok(())
    }
    pub fn spawn_scheduler(self: &Arc<Self>) {
        let core = Arc::downgrade(self);
        thread::spawn(move || {
            let mut last = Instant::now();
            let mut last_wall = now_ms();
            let mut revision = 0;
            let mut watcher: Option<notify::RecommendedWatcher> = None;
            let mut event = Arc::new(AtomicBool::new(false));
            let mut watch_error = Arc::new(AtomicBool::new(false));
            let mut gate = EventGate::default();
            loop {
                thread::sleep(Duration::from_millis(500));
                let Some(core) = core.upgrade() else { break };
                let now = Instant::now();
                let wall = now_ms();
                let mut trigger = None;
                if let Ok(mut s) = core.inner.lock() {
                    let gap = now.duration_since(last) > Duration::from_secs(10)
                        || wall.saturating_sub(last_wall) > 10_000
                        || wall < last_wall;
                    if gap {
                        s.gap =
                            Some("睡眠・時刻変更・エンジン停止による観測空白があります。".into());
                        if wall < last_wall || wall.saturating_sub(last_wall) > 10_000 {
                            s.cloud = false;
                            s.policy += 1;
                            s.response_control.invalidate();
                        }
                        if s.settings.enabled && !s.settings.paused {
                            s.next_due = Some(now);
                        }
                    }
                    if revision != s.settings.revision {
                        revision = s.settings.revision;
                        watcher = None;
                        event = Arc::new(AtomicBool::new(false));
                        watch_error = Arc::new(AtomicBool::new(false));
                        gate.dirty = false;
                        s.watcher_status = "停止中".into();
                        s.next_due = None;
                        if s.settings.enabled && !s.settings.paused {
                            s.next_due = Some(
                                now + Duration::from_secs(if s.settings.mode == "continuous" {
                                    0
                                } else {
                                    interval(&s.settings.mode)
                                }),
                            );
                            if s.settings.mode == "continuous" {
                                let signal = event.clone();
                                let error = watch_error.clone();
                                match s.store.files() {
                                    Err(_) => {
                                        s.watcher_status =
                                            "対象一覧の読取失敗。イベント未監視・60秒照合のみ"
                                                .into();
                                        s.gap = Some(
                                            "監視対象を読み取れない観測空白があります。".into(),
                                        );
                                    }
                                    Ok(files) => {
                                        let paths: Vec<_> = files
                                            .iter()
                                            .map(|f| std::path::PathBuf::from(&f.path))
                                            .collect();
                                        let watched_paths = watch_targets(&paths);
                                        match notify::recommended_watcher(
                                            move |result: Result<notify::Event, notify::Error>| {
                                                match result {
                                                    Ok(e) if e.need_rescan() => {
                                                        error.store(true, Ordering::SeqCst);
                                                        signal.store(true, Ordering::SeqCst);
                                                    }
                                                    Ok(e)
                                                        if event_matches(
                                                            &watched_paths,
                                                            &e.paths,
                                                        ) =>
                                                    {
                                                        signal.store(true, Ordering::SeqCst);
                                                    }
                                                    Err(_) => {
                                                        error.store(true, Ordering::SeqCst);
                                                        signal.store(true, Ordering::SeqCst);
                                                    }
                                                    _ => {}
                                                }
                                            },
                                        ) {
                                            Ok(mut w) => {
                                                let parents: std::collections::BTreeSet<_> = paths
                                                    .iter()
                                                    .filter_map(|p| {
                                                        p.parent().map(|v| v.to_path_buf())
                                                    })
                                                    .collect();
                                                let successful: std::collections::BTreeSet<_> =
                                                    parents
                                                        .into_iter()
                                                        .filter(|p| {
                                                            w.watch(
                                                                p,
                                                                notify::RecursiveMode::NonRecursive,
                                                            )
                                                            .is_ok()
                                                        })
                                                        .collect();
                                                let count = paths
                                                    .iter()
                                                    .filter(|p| {
                                                        p.parent()
                                                            .is_some_and(|v| successful.contains(v))
                                                    })
                                                    .count();
                                                s.watcher_status = format!("登録 {} 件中 {count} 件のイベント監視＋60秒照合。イベント巡回は最短30秒（OS警告購読は未対応）", paths.len());
                                                if count < paths.len() {
                                                    s.gap = Some("一部ファイルはイベント未監視です。60秒ごとの照合で補います。".into());
                                                }
                                                watcher = Some(w);
                                            }
                                            Err(_) => {
                                                s.watcher_status =
                                                    "イベント監視を開始できません。60秒照合のみ。"
                                                        .into();
                                                s.gap = Some("イベント監視が利用できない観測空白があります。".into());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if watch_error.swap(false, Ordering::SeqCst) {
                        s.watcher_status =
                            "イベント欠落・監視エラーを検出。60秒照合を併用中".into();
                        s.gap = Some("イベント監視で欠落またはエラーがありました。変更の即時検知は未保証です。".into());
                    }
                    gate.dirty |= event.swap(false, Ordering::SeqCst);
                    if s.settings.enabled
                        && !s.settings.paused
                        && s.active.is_none()
                        && gate.ready(
                            now,
                            s.next_due.is_some_and(|t| t <= now),
                            s.settings.mode == "continuous",
                        )
                    {
                        trigger = Some(s.settings.revision);
                        gate.dispatched(now);
                        s.next_due = Some(now + Duration::from_secs(interval(&s.settings.mode)));
                    }
                }
                last = now;
                last_wall = wall;
                if let Some(rev) = trigger {
                    let _ = core.start_guarded(&id(), &core.epoch, "schedule", Some(rev));
                }
                // Keep the OS subscription alive only while enabled; the watcher is dropped on disable/pause.
                let _ = &watcher;
            }
        });
    }
}

fn lock_cloud(s: &mut Inner) {
    s.cloud = false;
    s.policy += 1;
    s.analysis_cancel.store(true, Ordering::SeqCst);
    s.credentials.clear();
    s.catalogs.clear();
    s.response_control.invalidate();
}
fn response_context(s: &Inner, analysis: &Analysis, refs: &[String]) -> Result<Run, String> {
    if s.settings.paused || s.active.is_some() || analysis.status != "succeeded" || refs.is_empty()
    {
        return Err("対策の根拠が有効ではありません".into());
    }
    let run = s
        .store
        .runs()?
        .into_iter()
        .next()
        .ok_or("根拠がありません")?;
    if run.id != analysis.run_id
        || !["completed", "partial"].contains(&run.status.as_str())
        || !evidence_fresh(run.finished_at.unwrap_or(0), now_ms())
    {
        return Err("新しい検査結果が必要です".into());
    }
    let linked: Vec<_> = refs
        .iter()
        .map(|r| {
            r.strip_prefix('e')
                .and_then(|i| i.parse::<usize>().ok())
                .and_then(|i| run.checks.get(i))
        })
        .collect();
    if linked
        .iter()
        .any(|c| c.is_none_or(|c| !evidence_fresh(c.observed_at, now_ms())))
        || !linked.iter().flatten().any(|c| c.status == "attention")
    {
        return Err("要確認の観測根拠が不足しています".into());
    }
    Ok(run)
}
fn execute_plan(
    s: &mut Inner,
    plan_id: &str,
    revision: u64,
    automatic: bool,
) -> Result<(), String> {
    let p = s
        .store
        .response_plans()?
        .into_iter()
        .find(|p| p.id == plan_id)
        .ok_or("対策計画がありません")?;
    let a = s
        .store
        .analyses()?
        .into_iter()
        .find(|a| a.id == p.analysis_id)
        .ok_or("AI根拠がありません")?;
    response_context(s, &a, &p.evidence_ids)?;
    let advice: providers::Advice = serde_json::from_str(&providers::validate_advice(
        &a.text,
        s.store.runs()?.first().map_or(0, |r| r.checks.len()),
    )?)
    .map_err(|_| "対策形式が不正です")?;
    if a.role != "resolver"
        || p.run_id != a.run_id
        || p.evidence_ids != advice.evidence_ids
        || !advice.actions.contains(&p.action)
        || (automatic && advice.assessment != providers::Assessment::Urgent)
    {
        return Err("許可された提案と根拠が一致しません".into());
    }
    s.response_control
        .validate(p.action, revision, automatic, now_ms(), Instant::now())?;
    // Persist the single-use intent before any effect, under the same lock as revocation.
    s.store.begin_response_action(&p.id, revision, now_ms())?;
    match p.action {
        ResponseAction::PauseCloud => lock_cloud(s),
        _ => return Err("未対応の操作です".into()),
    }
    if s.store.finish_response_action(&p.id, true).is_err() {
        s.gap =
            Some("送信停止は適用済みですが、対策の結果記録に失敗しました。再実行しません。".into());
        return Err("送信停止適用済み・結果の保存失敗".into());
    }
    Ok(())
}
fn ingest_response(
    s: &mut Inner,
    done: &Analysis,
    expected_revision: u64,
) -> Result<Option<(String, u64)>, String> {
    if done.status != "succeeded" {
        return Ok(None);
    }
    let policy = s.response_control.policy(now_ms(), Instant::now());
    if policy.revision != expected_revision {
        return Ok(None);
    }
    let advice: providers::Advice =
        serde_json::from_str(&done.text).map_err(|_| "対策形式が不正です")?;
    if response_context(s, done, &advice.evidence_ids).is_err() {
        return Ok(None);
    }
    for action in advice.actions.iter().filter(|_| done.role == "resolver") {
        let plan = ResponsePlan::new(
            done.run_id.clone(),
            done.id.clone(),
            *action,
            "AIによる対策候補です。現在の観測根拠・許可・対応能力を確認して実行します。".into(),
            advice.evidence_ids.clone(),
            policy.revision,
            now_ms(),
        );
        s.store.add_response_plan(&plan)?;
        if *action == ResponseAction::PauseCloud
            && advice.assessment == providers::Assessment::Urgent
            && policy.mode == "automatic"
        {
            execute_plan(s, &plan.id, policy.revision, true)?;
            return Ok(None);
        }
    }
    if done.role == "patrol"
        && advice.needs_response
        && policy.auto_escalate
        && policy.expires_at.is_some()
        && s.cloud
    {
        return Ok(Some((done.run_id.clone(), policy.revision)));
    }
    Ok(None)
}
/// Compare against the latest run that was actually sent to the patrol model (any non-cancelled
/// attempt). Cancelled/truncated local runs never become the comparison base, and local-only
/// history before cloud consent does not suppress the first patrol. Read failures fail closed
/// (no paid request).
fn patrol_due(store: &Store, finished: &Run) -> bool {
    let (Ok(analyses), Ok(runs)) = (store.analyses(), store.runs()) else {
        return false;
    };
    let tried: std::collections::BTreeSet<&str> = analyses
        .iter()
        .filter(|a| a.role == "patrol" && a.status != "cancelled")
        .map(|a| a.run_id.as_str())
        .collect();
    let previous = runs
        .iter()
        .find(|r| r.id != finished.id && tried.contains(r.id.as_str()));
    should_patrol(finished, previous)
}
/// FSEvents reports resolved paths (e.g. /private/var/...); match both the stored and canonical form.
fn watch_targets(paths: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
    let mut targets = paths.to_vec();
    targets.extend(paths.iter().filter_map(|p| std::fs::canonicalize(p).ok()));
    targets.sort();
    targets.dedup();
    targets
}
fn event_matches(targets: &[std::path::PathBuf], events: &[std::path::PathBuf]) -> bool {
    events.iter().any(|p| {
        targets.contains(p) || std::fs::canonicalize(p).is_ok_and(|c| targets.contains(&c))
    })
}
fn should_patrol(run: &Run, previous: Option<&Run>) -> bool {
    run.status != "cancelled"
        && !run.checks.is_empty()
        && previous.is_none_or(|p| signature(&p.checks) != signature(&run.checks))
}
#[derive(Default)]
struct EventGate {
    dirty: bool,
    last: Option<Instant>,
}
impl EventGate {
    fn ready(&self, now: Instant, due: bool, continuous: bool) -> bool {
        (due || (continuous && self.dirty))
            && self
                .last
                .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(30))
    }
    fn dispatched(&mut self, now: Instant) {
        self.last = Some(now);
        self.dirty = false;
    }
}
fn project_analyses(
    analyses: Vec<Analysis>,
    active_id: Option<&str>,
    runs: &[Run],
) -> Vec<Analysis> {
    project_analyses_at(analyses, active_id, runs, now_ms())
}
fn project_analyses_at(
    mut analyses: Vec<Analysis>,
    active_id: Option<&str>,
    runs: &[Run],
    now: u64,
) -> Vec<Analysis> {
    let latest = active_id.or_else(|| runs.first().map(|r| r.id.as_str()));
    for a in &mut analyses {
        let fresh = runs.first().is_some_and(|r| {
            r.id == a.run_id
                && ["completed", "partial"].contains(&r.status.as_str())
                && evidence_fresh(r.finished_at.unwrap_or(0), now)
                && !r.checks.is_empty()
                && r.checks.iter().all(|c| evidence_fresh(c.observed_at, now))
        });
        if a.status == "succeeded"
            && (latest != Some(a.run_id.as_str()) || !fresh || !evidence_fresh(a.created_at, now))
        {
            a.status = "stale".into();
        }
    }
    analyses
}

pub fn interval(mode: &str) -> u64 {
    match mode {
        "quarter" => 900,
        "hourly" => 3600,
        "continuous" => 60,
        _ => 3600,
    }
}
fn signature(checks: &[Check]) -> Vec<(String, String, Option<String>)> {
    checks
        .iter()
        .map(|c| (c.id.clone(), c.status.clone(), c.digest.clone()))
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pause_blocks_work_and_stale_resume() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        c.pause(true, 0).unwrap();
        assert!(c.start(&id(), &c.epoch, "manual").is_err());
        assert!(c.pause(false, 1).is_err());
        assert!(c.pause(false, 2).is_ok());
    }
    #[test]
    fn manual_cannot_enable_and_model_change_revokes() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        c.schedule("manual", true, 1).unwrap();
        assert!(!c.snapshot().unwrap().settings.enabled);
        assert!(c.schedule("other", true, 2).is_err());
    }
    #[test]
    fn old_epoch_and_invalid_request_rejected() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        assert!(c.start(&id(), "old", "manual").is_err());
        assert!(c.start("abc", &c.epoch, "manual").is_err());
        assert!(c.analyze("resolver", "missing").is_err());
    }
}
#[cfg(test)]
mod review1_tests {
    use super::*;
    #[test]
    fn scheduler_trigger_cannot_cross_off() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        c.schedule("continuous", true, 1).unwrap();
        let rev = c.snapshot().unwrap().settings.revision;
        c.schedule("manual", false, rev).unwrap();
        assert!(c
            .start_guarded(&id(), &c.epoch, "schedule", Some(rev))
            .is_err());
        assert!(c.snapshot().unwrap().runs.is_empty());
    }
    #[test]
    fn catalog_revoke_before_commit_rejects() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        let policy = c.inner.lock().unwrap().policy;
        c.disable_cloud().unwrap();
        assert!(c.commit_catalog("openai", policy).is_err());
        assert!(!c.snapshot().unwrap().catalog_in_flight);
    }
    #[test]
    fn catalog_acquires_secret_only_after_valid_confirmation_epoch() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        let initial = c.inner.lock().unwrap().policy;
        assert!(c.commit_catalog("openai", initial).is_err());
        assert!(!c.snapshot().unwrap().catalog_in_flight);
        c.commit_credential(
            "anthropic",
            Zeroizing::new("fixture-original".into()),
            initial,
        )
        .unwrap();
        let confirmed = c.inner.lock().unwrap().policy;
        assert!(c.commit_catalog("unsupported", confirmed).is_err());
        assert_eq!(
            &*c.commit_catalog("anthropic", confirmed).unwrap(),
            "fixture-original"
        );
        assert!(c.commit_catalog("anthropic", confirmed).is_err());
        c.emergency_lock().unwrap();
        assert!(c.commit_catalog("anthropic", confirmed).is_err());
        assert!(c.inner.lock().unwrap().credentials.is_empty());
    }
    #[test]
    fn settings_write_failure_cannot_enable_schedule() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        c.inner.lock().unwrap().store.db.execute_batch("CREATE TRIGGER fail_settings BEFORE INSERT ON settings BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(c.schedule("continuous", true, 1).is_err());
        assert!(!c.snapshot().unwrap().settings.enabled);
        assert!(c.pause(true, 1).is_err());
        assert!(c.snapshot().unwrap().settings.paused);
        assert!(c.pause(false, 2).is_err());
    }
}

#[cfg(test)]
mod review2_tests {
    use super::*;
    #[test]
    fn event_flood_is_bounded_and_last_change_retained() {
        let base = Instant::now();
        let mut gate = EventGate::default();
        let mut count = 0;
        for ms in (0..120_000).step_by(10) {
            gate.dirty = true;
            let now = base + Duration::from_millis(ms);
            if gate.ready(now, false, true) {
                count += 1;
                gate.dispatched(now);
            }
        }
        assert_eq!(count, 4);
        assert!(gate.dirty);
        assert!(gate.ready(base + Duration::from_secs(120), false, true));
    }
    #[test]
    fn budget_corruption_does_not_block_local_resume() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        c.pause(true, 1).unwrap();
        c.inner.lock().unwrap().store.ledger_blocked = true;
        c.pause(false, 2).unwrap();
        assert!(!c.snapshot().unwrap().settings.paused);
        assert!(!c.snapshot().unwrap().cloud_enabled);
    }
    #[test]
    fn older_ai_is_stale_during_and_after_new_scan() {
        let a = Analysis {
            id: id(),
            role: "resolver".into(),
            run_id: "old".into(),
            provider: "openai".into(),
            model: "test".into(),
            status: "succeeded".into(),
            text: "ok".into(),
            created_at: 1,
            cost_status: "settled".into(),
        };
        assert_eq!(
            project_analyses(vec![a.clone()], Some("new"), &[])[0].status,
            "stale"
        );
        let r = Run {
            id: "new".into(),
            trigger: "manual".into(),
            status: "completed".into(),
            started_at: 2,
            finished_at: Some(3),
            checks: vec![],
        };
        assert_eq!(project_analyses(vec![a], None, &[r])[0].status, "stale");
    }
}

#[cfg(test)]
mod response_integration_tests {
    use super::*;
    fn fixture(
        status: &str,
        action: ResponseAction,
        mode: &str,
    ) -> (tempfile::TempDir, Arc<Core>, Analysis, u64) {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        let mut s = c.inner.lock().unwrap();
        s.cloud = true;
        s.credentials.insert(
            "openai".into(),
            Zeroizing::new("artificial-test-secret".into()),
        );
        if mode == "automatic" {
            s.response_control
                .grant(mode, true, 1, now_ms(), Instant::now())
                .unwrap();
        }
        let rev = s.response_control.policy(now_ms(), Instant::now()).revision;
        let r = Run {
            id: id(),
            trigger: "fixture".into(),
            status: "completed".into(),
            started_at: now_ms(),
            finished_at: Some(now_ms()),
            checks: vec![Check::new(
                "firewall",
                "Firewall",
                "保護設定",
                status,
                "fixture",
                "fixture",
            )],
        };
        s.store.save_run(&r).unwrap();
        let advice = providers::Advice {
            summary: "人工的な緊急推定fixture".into(),
            evidence_ids: vec!["e0".into()],
            next_steps: vec![],
            assessment: providers::Assessment::Urgent,
            needs_response: true,
            actions: vec![action],
        };
        let a = Analysis {
            id: id(),
            role: "resolver".into(),
            run_id: r.id,
            provider: "fixture".into(),
            model: "fixture".into(),
            status: "succeeded".into(),
            text: serde_json::to_string(&advice).unwrap(),
            created_at: now_ms(),
            cost_status: "settled".into(),
        };
        s.store.save_analysis(&a).unwrap();
        drop(s);
        (d, c, a, rev)
    }
    #[test]
    fn authorized_emergency_cuts_only_our_authority_and_never_replays() {
        let (_d, c, a, rev) = fixture("attention", ResponseAction::PauseCloud, "automatic");
        let mut s = c.inner.lock().unwrap();
        assert!(ingest_response(&mut s, &a, rev).unwrap().is_none());
        assert!(!s.cloud);
        assert!(s.credentials.is_empty());
        assert!(s.catalogs.is_empty());
        assert!(!s.settings.paused);
        let plans = s.store.response_plans().unwrap();
        assert_eq!(plans[0].status, "succeeded");
        assert!(execute_plan(&mut s, &plans[0].id, rev, true).is_err());
        assert_eq!(s.store.response_plans().unwrap().len(), 1);
    }
    #[test]
    fn severity_alone_and_revoked_or_stale_result_cannot_act() {
        let (_d, c, a, rev) = fixture("ok", ResponseAction::PauseCloud, "automatic");
        {
            let mut s = c.inner.lock().unwrap();
            ingest_response(&mut s, &a, rev).unwrap();
            assert!(s.cloud);
            assert!(s.store.response_plans().unwrap().is_empty());
        }
        let (_d, c, a, rev) = fixture("attention", ResponseAction::PauseCloud, "automatic");
        c.revoke_response_policy().unwrap();
        let mut s = c.inner.lock().unwrap();
        ingest_response(&mut s, &a, rev).unwrap();
        assert!(s.cloud);
        assert!(s.store.response_plans().unwrap().is_empty());
        let (_d, c, a, rev) = fixture("attention", ResponseAction::PauseCloud, "automatic");
        let mut s = c.inner.lock().unwrap();
        s.active = Some(Run {
            id: id(),
            trigger: "fixture".into(),
            status: "running".into(),
            started_at: now_ms(),
            finished_at: None,
            checks: vec![],
        });
        ingest_response(&mut s, &a, rev).unwrap();
        assert!(s.cloud);
        assert!(s.store.response_plans().unwrap().is_empty());
    }
    #[test]
    fn unsupported_action_is_only_a_proposal() {
        let (_d, c, a, rev) = fixture("attention", ResponseAction::BlockConnection, "automatic");
        let mut s = c.inner.lock().unwrap();
        let next = ingest_response(&mut s, &a, rev).unwrap();
        assert!(next.is_none());
        let p = s.store.response_plans().unwrap()[0].clone();
        assert_eq!(p.status, "unsupported");
        assert!(execute_plan(&mut s, &p.id, rev, true).is_err());
        assert!(s.cloud);
        assert_eq!(s.credentials.len(), 1);
    }
    #[test]
    fn confirm_mode_waits_for_native_approval_commit() {
        let (_d, c, a, rev) = fixture("attention", ResponseAction::PauseCloud, "confirm");
        let mut s = c.inner.lock().unwrap();
        assert!(ingest_response(&mut s, &a, rev).unwrap().is_none());
        assert!(s.cloud);
        let p = s.store.response_plans().unwrap()[0].clone();
        assert!(execute_plan(&mut s, &p.id, rev, true).is_err());
        assert!(s.cloud);
        // This internal call represents the native confirmation commit, never exposed raw over IPC.
        execute_plan(&mut s, &p.id, rev, false).unwrap();
        assert!(!s.cloud);
    }
    #[test]
    fn failed_intent_has_no_side_effect_but_emergency_stop_ignores_log_failure() {
        let (_d, c, a, rev) = fixture("attention", ResponseAction::PauseCloud, "automatic");
        {
            let mut s = c.inner.lock().unwrap();
            s.store.db.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON response_events WHEN NEW.kind='intent' BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
            assert!(ingest_response(&mut s, &a, rev).is_err());
            assert!(s.cloud);
            assert_eq!(s.credentials.len(), 1);
        }
        assert!(c.emergency_lock().is_err());
        let s = c.inner.lock().unwrap();
        assert!(!s.cloud);
        assert!(s.credentials.is_empty());
    }
    #[test]
    fn escalation_revocation_is_checked_before_any_model_request_or_reservation() {
        let (_d, c, mut a, rev) =
            fixture("attention", ResponseAction::BlockConnection, "automatic");
        a.role = "patrol".into();
        let next = {
            let mut s = c.inner.lock().unwrap();
            let next = ingest_response(&mut s, &a, rev).unwrap().unwrap();
            assert!(s.store.response_plans().unwrap().is_empty());
            assert!(s.cloud);
            next
        };
        c.revoke_response_policy().unwrap();
        assert!(c
            .analyze_guarded("resolver", &next.0, Some(next.1))
            .is_err());
        assert_eq!(c.snapshot().unwrap().budget.resolver_calls, 0);
    }
    #[test]
    fn pending_key_picker_cannot_restore_credentials_after_emergency_stop() {
        let (_d, c, _, _) = fixture("attention", ResponseAction::PauseCloud, "confirm");
        let epoch = c.inner.lock().unwrap().policy;
        c.emergency_lock().unwrap();
        assert!(c
            .commit_credential("openai", Zeroizing::new("test-only-key".into()), epoch)
            .is_err());
        assert!(c.inner.lock().unwrap().credentials.is_empty());
        assert!(!c.snapshot().unwrap().cloud_enabled);
    }
    #[test]
    fn patrol_classifies_first_and_changed_observations_without_repeat_spend() {
        let r = Run {
            id: id(),
            trigger: "fixture".into(),
            status: "completed".into(),
            started_at: now_ms(),
            finished_at: Some(now_ms()),
            checks: vec![Check::new("firewall", "", "保護設定", "ok", "", "")],
        };
        assert!(should_patrol(&r, None));
        assert!(!should_patrol(&r, Some(&r)));
        let mut changed = r.clone();
        changed.checks[0].status = "attention".into();
        assert!(should_patrol(&changed, Some(&r)));
        changed.status = "cancelled".into();
        assert!(!should_patrol(&changed, Some(&r)));
    }
}

#[cfg(test)]
mod opus_review_tests {
    use super::*;
    fn run(status: &str, checks: Vec<Check>) -> Run {
        Run {
            id: id(),
            trigger: "fixture".into(),
            status: status.into(),
            started_at: now_ms(),
            finished_at: Some(now_ms()),
            checks,
        }
    }
    fn full() -> Vec<Check> {
        vec![
            Check::new("firewall", "", "保護設定", "ok", "", ""),
            Check::new("disk", "", "PCの状態", "ok", "", ""),
        ]
    }
    fn patrol_analysis(run_id: &str, status: &str) -> Analysis {
        Analysis {
            id: id(),
            role: "patrol".into(),
            run_id: run_id.into(),
            provider: "fixture".into(),
            model: "fixture".into(),
            status: status.into(),
            text: String::new(),
            created_at: now_ms(),
            cost_status: "settled".into(),
        }
    }
    /// G-01: a cancelled (truncated) run between two identical runs must not cause a repeat paid patrol.
    #[test]
    fn cancelled_run_does_not_trigger_repeat_patrol_spend() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        let mut s = c.inner.lock().unwrap();
        let first = run("partial", full());
        s.store.save_run(&first).unwrap();
        s.store
            .save_analysis(&patrol_analysis(&first.id, "succeeded"))
            .unwrap();
        thread::sleep(Duration::from_millis(3));
        let cancelled = run("cancelled", full()[..1].to_vec());
        s.store.save_run(&cancelled).unwrap();
        thread::sleep(Duration::from_millis(3));
        let same = run("partial", full());
        s.store.save_run(&same).unwrap();
        // Legacy selection compared with the newest other run (the cancelled one) and spent again.
        assert!(should_patrol(&same, Some(&cancelled)));
        assert!(!patrol_due(&s.store, &same));
        let mut changed = run("partial", full());
        changed.checks[1].status = "attention".into();
        s.store.save_run(&changed).unwrap();
        assert!(patrol_due(&s.store, &changed));
    }
    /// G-02: enabling cloud after local-only scans must still allow the first patrol.
    #[test]
    fn first_patrol_after_local_only_history_is_allowed_once() {
        let d = tempfile::tempdir().unwrap();
        let c = Core::open(&d.path().join("db")).unwrap();
        let mut s = c.inner.lock().unwrap();
        let local = run("partial", full());
        s.store.save_run(&local).unwrap();
        thread::sleep(Duration::from_millis(3));
        let next = run("partial", full());
        s.store.save_run(&next).unwrap();
        // Legacy rule: identical to the previous local-only run, so AI patrol never happened.
        assert!(!should_patrol(&next, Some(&local)));
        assert!(patrol_due(&s.store, &next));
        s.store
            .save_analysis(&patrol_analysis(&next.id, "failed"))
            .unwrap();
        thread::sleep(Duration::from_millis(3));
        let again = run("partial", full());
        s.store.save_run(&again).unwrap();
        // A failed paid attempt is not retried on unchanged evidence; a cancelled one may be.
        assert!(!patrol_due(&s.store, &again));
    }
    /// R-01: FSEvents reports canonical paths (/private/var/...) for files registered via /var/...
    #[cfg(target_os = "macos")]
    #[test]
    fn canonical_event_path_matches_registered_alias() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("watched.txt");
        std::fs::write(&p, "fixture").unwrap();
        let canonical = std::fs::canonicalize(&p).unwrap();
        assert_ne!(canonical, p, "fixture expects /var -> /private/var alias");
        let targets = watch_targets(std::slice::from_ref(&p));
        assert!(event_matches(&targets, &[canonical]));
        assert!(!event_matches(&targets, &[d.path().join("other.txt")]));
    }
}

#[cfg(test)]
mod hardening_projection_tests {
    use super::*;
    #[test]
    fn same_run_expired_future_and_missing_observations_are_not_current_ai_advice() {
        let now = 1_000_000;
        let mut check = Check::new("fixture", "fixture", "保護設定", "attention", "", "");
        check.observed_at = now - 1000;
        let mut run = Run {
            id: "run".into(),
            trigger: "manual".into(),
            status: "completed".into(),
            started_at: now - 1000,
            finished_at: Some(now - 500),
            checks: vec![check],
        };
        let analysis = Analysis {
            id: "analysis".into(),
            role: "resolver".into(),
            run_id: "run".into(),
            provider: "openai".into(),
            model: "fixture".into(),
            status: "succeeded".into(),
            text: "fixture".into(),
            created_at: now - 100,
            cost_status: "settled".into(),
        };
        let projected = |r: &Run, time| {
            project_analyses_at(vec![analysis.clone()], None, std::slice::from_ref(r), time)[0]
                .status
                .clone()
        };
        assert_eq!(projected(&run, now), "succeeded");
        assert_eq!(projected(&run, now + 300_001), "stale");
        assert_eq!(projected(&run, now - 2000), "stale");
        assert_eq!(analysis.status, "succeeded"); // Projection does not rewrite persisted evidence.
        run.checks[0].observed_at = now - 300_001;
        assert_eq!(projected(&run, now), "stale");
        run.checks.clear();
        assert_eq!(projected(&run, now), "stale");
    }
}

#[cfg(test)]
mod hardening_preflight_freshness_tests {
    use super::*;
    #[test]
    fn fresh_completion_does_not_allow_spend_on_old_future_or_empty_observations() {
        for case in ["old", "future", "empty"] {
            let dir = tempfile::tempdir().unwrap();
            let core = Core::open(&dir.path().join("db")).unwrap();
            let now = now_ms();
            let mut check = Check::new("fixture", "fixture", "保護設定", "attention", "", "");
            check.observed_at = if case == "future" {
                now + 60_000
            } else {
                now - 300_001
            };
            let run = Run {
                id: id(),
                trigger: "manual".into(),
                status: "completed".into(),
                started_at: now - 400_000,
                finished_at: Some(now),
                checks: if case == "empty" { vec![] } else { vec![check] },
            };
            {
                let mut s = core.inner.lock().unwrap();
                s.store.save_run(&run).unwrap();
                s.settings.patrol = ModelChoice {
                    provider: "openai".into(),
                    model: "fixture".into(),
                    input_rate: 1_000_000,
                    output_rate: 1_000_000,
                };
                s.credentials.insert(
                    "openai".into(),
                    Zeroizing::new("artificial-never-sent".into()),
                );
                s.catalogs.insert("openai".into(), vec!["fixture".into()]);
                s.cloud = true;
            }
            let error = core.analyze("patrol", &run.id).unwrap_err();
            assert!(error.contains("新しい検査結果"));
            let s = core.inner.lock().unwrap();
            assert!(s.store.analyses().unwrap().is_empty());
            let budget = s.store.budget(now_ms()).unwrap();
            assert_eq!(budget.patrol_calls, 0);
            assert_eq!(budget.reserved, 0);
            assert!(s.analysis_active.is_none());
        }
    }
}
