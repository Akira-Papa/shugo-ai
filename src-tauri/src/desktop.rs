use crate::core::Core;
use crate::types::*;
use crate::{app_storage, baseline, collectors, providers};
use std::{fs, sync::Arc};
use tauri::{Manager, State};
use zeroize::Zeroizing;

type AppCore = Arc<Core>;
fn confirm(title: &str, text: &str) -> bool {
    matches!(
        rfd::MessageDialog::new()
            .set_title(title)
            .set_description(text)
            .set_level(rfd::MessageLevel::Info)
            .set_buttons(rfd::MessageButtons::OkCancel)
            .show(),
        rfd::MessageDialogResult::Ok
    )
}
#[tauri::command]
fn snapshot(core: State<AppCore>) -> Result<Snapshot, String> {
    core.snapshot()
}
#[tauri::command]
fn scan_start(core: State<AppCore>, request_id: String, epoch: String) -> Result<String, String> {
    core.start(&request_id, &epoch, "manual")
}
#[tauri::command]
fn scan_cancel(core: State<AppCore>) -> Result<(), String> {
    core.cancel_scan()
}
#[tauri::command]
fn set_schedule(
    core: State<AppCore>,
    mode: String,
    enabled: bool,
    revision: u64,
) -> Result<(), String> {
    core.schedule(&mode, enabled, revision)
}
#[tauri::command]
fn set_paused(core: State<AppCore>, paused: bool, revision: u64) -> Result<(), String> {
    core.pause(paused, revision)
}
#[tauri::command]
fn set_models(
    core: State<AppCore>,
    patrol: ModelChoice,
    resolver: ModelChoice,
    revision: u64,
) -> Result<(), String> {
    core.models(patrol, resolver, revision)
}
#[tauri::command]
fn register_file(core: State<AppCore>) -> Result<MutationOutcome, String> {
    let Some(path) = rfd::FileDialog::new()
        .set_title("変更を見守るファイルを選ぶ（16 MiB以下）")
        .pick_file()
    else {
        return Ok(MutationOutcome::Cancelled);
    };
    collectors::hash_file(&path)?;
    let mut s = core.inner.lock().map_err(|_| "エンジンエラー")?;
    let files = s.store.files()?;
    if files.len() >= 100 {
        return Err("登録上限100件です。".into());
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("ファイル名を読み取れません")?
        .chars()
        .take(160)
        .collect::<String>();
    let path = path.to_str().ok_or("このパスは利用できません")?.to_string();
    if files.iter().any(|f| f.path == path) {
        return Err("このファイルは登録済みです。".into());
    }
    let mut candidate = s.settings.clone();
    candidate.revision += 1;
    s.store.add_file_with_settings(
        &RegisteredFile {
            id: id(),
            label: name,
            path,
        },
        &candidate,
    )?;
    s.settings = candidate;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
fn accept_baseline(
    core: State<AppCore>,
    run_id: String,
    check_id: String,
    digest: String,
    observed_at: u64,
) -> Result<MutationOutcome, String> {
    let selection = baseline::BaselineSelection {
        run_id: &run_id,
        check_id: &check_id,
        digest: &digest,
        observed_at,
    };
    let (check, revision, policy) = {
        let s = core.inner.lock().map_err(|_| "エンジンエラー")?;
        if s.active.is_some() {
            return Err("検査完了後に確認してください".into());
        }
        if s.settings.paused {
            return Err("一時停止中です".into());
        }
        let runs = s.store.runs()?;
        let run = runs.first().ok_or("新しい検査結果が必要です")?;
        let check = baseline::selected_check(run, &selection, now_ms())?;
        (check, s.settings.revision, s.policy)
    };
    if !evidence_fresh(check.observed_at, now_ms()) || check.digest.is_none() {
        return Err("再巡回して最新の根拠を確認してください".into());
    }
    if !confirm("比較基準の確認",&format!("「{}」の画面で選択した観測を比較基準にします。\n観測識別: {} / {}\nSHA-256: {}\n内容が安全だという判定ではありません。自分が行った変更であることを確認しましたか？",check.title,run_id,observed_at,digest)){return Ok(MutationOutcome::Cancelled)}
    let s = core.inner.lock().map_err(|_| "エンジンエラー")?;
    if !evidence_fresh(check.observed_at, now_ms())
        || s.settings.paused
        || s.policy != policy
        || s.settings.revision != revision
        || s.active.is_some()
        || !s
            .store
            .runs()?
            .first()
            .is_some_and(|r| baseline::selected_check(r, &selection, now_ms()).is_ok())
    {
        return Err("根拠が変わりました。再確認してください".into());
    }
    s.store
        .accept_baseline(&check.id, check.digest.as_deref().unwrap_or_default())?;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
fn import_credential(core: State<AppCore>, provider: String) -> Result<MutationOutcome, String> {
    if !["openai", "anthropic"].contains(&provider.as_str()) {
        return Err("未対応の接続方式です".into());
    }
    let policy = {
        let s = core.inner.lock().map_err(|_| "エンジンエラー")?;
        if s.settings.paused {
            return Err("一時停止中です".into());
        }
        s.policy
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("APIキーだけを記載したファイルを選択（メモリ内のみ利用）")
        .pick_file()
    else {
        return Ok(MutationOutcome::Cancelled);
    };
    let value = collectors::read_secret_file(&path)?;
    let secret = value.trim();
    if secret.len() < 16 || secret.len() > 8192 || !secret.bytes().all(|c| c.is_ascii_graphic()) {
        return Err("ファイルにはAPIキー1つだけを記載してください".into());
    }
    core.commit_credential(&provider, Zeroizing::new(secret.to_owned()), policy)?;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
async fn catalog_refresh(
    core: State<'_, AppCore>,
    provider: String,
) -> Result<Vec<String>, String> {
    let core = core.inner().clone();
    tauri::async_runtime::spawn_blocking(move||{
  // Do not retain a secret while the native confirmation is open.
  let policy={let s=core.inner.lock().map_err(|_|"エンジンエラー")?;
    if !s.credentials.contains_key(&provider){return Err("APIキーを先に設定してください".into());}
    s.policy};
  if !confirm("接続先のモデル一覧を確認",&format!("{}の公式APIへ接続し、モデルID一覧を取得します。PCの観測結果は送信しません。解析や自動巡回の送信許可とは別です。",provider)){return Err("接続確認を中止しました".into());}
  let key=core.commit_catalog(&provider,policy)?;
  // Dispatch is committed under the same mutex as revoke. Later cancellation is in-flight.
  let result=providers::catalog(&provider,&key);
  let mut s=core.inner.lock().map_err(|_|"エンジンエラー")?;s.catalog_in_flight=false;if s.policy!=policy{return Err("接続設定が変わりました。送信済み確認の結果は採用しません。".into());}let models=result?;s.catalogs.insert(provider,models.clone());Ok(models)
 }).await.map_err(|_|"モデル一覧取得に失敗しました")?
}
#[tauri::command]
fn cloud_enable(core: State<AppCore>) -> Result<MutationOutcome, String> {
    let (settings, policy) = {
        let s = core.inner.lock().map_err(|_| "エンジンエラー")?;
        if s.settings.paused {
            return Err("先に巡回の一時停止を解除してください".into());
        }
        let models = [&s.settings.patrol, &s.settings.resolver];
        let active: Vec<_> = models
            .into_iter()
            .filter(|m| m.provider != "none")
            .collect();
        if active.is_empty() {
            return Err("巡回または対策モデルにAPIモデルを設定してください".into());
        }
        for m in active {
            providers::reservation(m)?;
            if !s.credentials.contains_key(&m.provider)
                || !s
                    .catalogs
                    .get(&m.provider)
                    .is_some_and(|xs| xs.contains(&m.model))
            {
                return Err("APIキー・モデル一覧・単価を先に設定してください".into());
            }
        }
        (s.settings.clone(), s.policy)
    };
    let text=format!("送信先: 巡回 {}/{}、対策モデル {}/{}\n送信内容: OS種別、検査カテゴリ、状態、根拠の連番のみ。ファイル名・内容・パス・生ログは送りません。\n日次 USD 0.25、30日 USD 5.00。設定単価による予約で、実請求の上限保証ではありません。巡回24回、対策モデル4回/日。\n初回と変化した検査結果を巡回モデルへ送信。対策モデルはボタン操作、または別途許可した自動引継ぎ時だけ。\nこの起動セッションで許可しますか？",settings.patrol.provider,settings.patrol.model,settings.resolver.provider,settings.resolver.model);
    if !confirm("クラウド解析の送信許可", &text) {
        return Ok(MutationOutcome::Cancelled);
    }
    let mut s = core.inner.lock().map_err(|_| "エンジンエラー")?;
    if s.policy != policy || s.settings.revision != settings.revision || s.settings.paused {
        return Err("設定が変わりました。再確認してください".into());
    }
    s.store.check_anchor(now_ms())?;
    if s.store.budget(now_ms())?.unknown > 0 {
        return Err("未確定費用があるため送信できません".into());
    }
    s.response_control.invalidate();
    s.cloud = true;
    s.policy += 1;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
fn cloud_disable(core: State<AppCore>) -> Result<(), String> {
    core.disable_cloud()
}
#[tauri::command]
fn analyze(core: State<AppCore>, role: String, run_id: String) -> Result<String, String> {
    core.analyze(&role, &run_id)
}
#[tauri::command]
fn analysis_cancel(core: State<AppCore>) -> Result<(), String> {
    core.cancel_analysis()
}
#[tauri::command]
fn set_response_policy(
    core: State<AppCore>,
    mode: String,
    auto_escalate: bool,
    revision: u64,
) -> Result<MutationOutcome, String> {
    if !["confirm", "automatic"].contains(&mode.as_str()) {
        return Err("対策方針が不正です".into());
    }
    let (settings_revision, cloud_policy) = {
        let mut s = core.inner.lock().map_err(|_| "エンジンエラー")?;
        let p = s
            .response_control
            .policy(now_ms(), std::time::Instant::now());
        if p.revision != revision || s.settings.paused {
            return Err("一時停止中、または対策許可が変更されています".into());
        }
        if auto_escalate && (!s.cloud || s.settings.resolver.provider == "none") {
            return Err("対策モデルの接続・送信許可を先に設定してください".into());
        }
        (s.settings.revision, s.policy)
    };
    let description=format!("有効期限はこの起動中の1時間。停止・モデル変更・許可取消・再起動で失効します。\n\n方式: {}\n巡回AIから対策モデルへ自動引継ぎ: {}（既存の予算・回数上限内）\n\n自動実行できる操作は『守護AIの新規クラウド送信停止とアプリ内キー破棄』だけです。AIの緊急推定に加え、最新の要確認観測が必要です。\nPC全体の通信遮断・ファイル隔離は未対応です。\n送信済みの情報・費用は取り戻せません。復旧はAPI接続と送信許可を改めて設定します。",if mode=="automatic"{"事前許可した操作のみ自動"}else{"実行ごとに確認"},if auto_escalate{"許可する"}else{"行わない"});
    if !confirm("限定対策の事前許可", &description) {
        return Ok(MutationOutcome::Cancelled);
    }
    let mut s = core.inner.lock().map_err(|_| "エンジンエラー")?;
    if s.policy != cloud_policy || s.settings.revision != settings_revision || s.settings.paused {
        return Err("確認中に設定が変わりました。再確認してください".into());
    }
    s.response_control
        .policy(now_ms(), std::time::Instant::now());
    s.response_control.grant(
        &mode,
        auto_escalate,
        revision,
        now_ms(),
        std::time::Instant::now(),
    )?;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
fn revoke_response_policy(core: State<AppCore>) -> Result<(), String> {
    core.revoke_response_policy()
}
#[tauri::command]
fn execute_response(
    core: State<AppCore>,
    plan_id: String,
    revision: u64,
) -> Result<MutationOutcome, String> {
    {
        let mut s = core.inner.lock().map_err(|_| "エンジンエラー")?;
        let p = s
            .store
            .response_plans()?
            .into_iter()
            .find(|p| p.id == plan_id)
            .ok_or("対策計画がありません")?;
        if !p.action.available() || p.status != "proposed" || p.policy_revision != revision {
            return Err("この対策は現在実行できません".into());
        }
        s.response_control.validate(
            p.action,
            revision,
            false,
            now_ms(),
            std::time::Instant::now(),
        )?;
    }
    if !confirm("守護AIの送信を停止", "この提案に基づき、守護AIの新規クラウド送信を停止してメモリ内のAPIキーを破棄します。PC全体の通信は遮断しません。送信済み要求は取り戻せません。再利用には接続と送信許可を再設定します。実行しますか？") {return Ok(MutationOutcome::Cancelled);}
    core.execute_response(&plan_id, revision)?;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
fn emergency_lock(core: State<AppCore>) -> Result<(), String> {
    core.emergency_lock()
}
#[tauri::command]
fn acknowledge(core: State<AppCore>, finding_id: String) -> Result<(), String> {
    core.inner
        .lock()
        .map_err(|_| "エンジンエラー")?
        .store
        .acknowledge(&finding_id)
}
#[tauri::command]
fn export_report(core: State<AppCore>) -> Result<MutationOutcome, String> {
    let data = {
        let s = core.inner.lock().map_err(|_| "エンジンエラー")?;
        let mut runs = s.store.runs()?;
        for r in &mut runs {
            for (i, c) in r.checks.iter_mut().enumerate() {
                if c.category == "指定ファイル" {
                    c.title = format!("登録ファイル {}", i + 1);
                    c.id = format!("file-{}", i + 1);
                }
                c.digest = None;
            }
        }
        serde_json::to_vec_pretty(&serde_json::json!({"formatVersion":1,"scope":"Local observations; not proof of absence of compromise","runs":runs})).map_err(|_|"レポートを作れません")?
    };
    let Some(path) = rfd::FileDialog::new()
        .set_file_name("shugo-report.json")
        .add_filter("JSON", &["json"])
        .save_file()
    else {
        return Ok(MutationOutcome::Cancelled);
    };
    fs::write(path, data).map_err(|_| "レポートを保存できません")?;
    Ok(MutationOutcome::Applied)
}
#[tauri::command]
fn delete_history(core: State<AppCore>) -> Result<MutationOutcome, String> {
    if !confirm("検査履歴を削除", "未解決案件がない場合に、検査結果と解析文を削除します。予算台帳・比較基準・設定は保持します。この操作は元に戻せません。") {return Ok(MutationOutcome::Cancelled)}
    let s = core.inner.lock().map_err(|_| "エンジンエラー")?;
    if s.active.is_some() || s.analysis_active.is_some() {
        return Err("検査・解析の終了後に操作してください".into());
    }
    s.store.delete_history()?;
    Ok(MutationOutcome::Applied)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data = match std::env::var_os("SHUGO_DATA_DIR") {
                Some(p) => std::path::PathBuf::from(p),
                None => app_storage::desktop_data_dir(&app.path().app_local_data_dir()?)?,
            };
            app_storage::prepare_data_dir(&data)?;
            let lock = app_storage::open_instance_lock(&data.join("instance.lock"))?;
            fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| "守護AIはすでに起動しています")?;
            app.manage(lock);
            let core = Core::open(&data.join("guardian.sqlite3")).map_err(std::io::Error::other)?;
            core.spawn_scheduler();
            app.manage(core);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            scan_start,
            scan_cancel,
            set_schedule,
            set_paused,
            set_models,
            register_file,
            accept_baseline,
            import_credential,
            catalog_refresh,
            cloud_enable,
            cloud_disable,
            analyze,
            analysis_cancel,
            export_report,
            acknowledge,
            delete_history,
            set_response_policy,
            revoke_response_policy,
            execute_response,
            emergency_lock
        ])
        .run(tauri::generate_context!())
        .expect("守護AIを起動できませんでした");
}
