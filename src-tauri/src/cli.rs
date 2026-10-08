//! Headless commands. No shell execution, daemon installation or automatic grants.
use crate::{app_storage, baseline, collectors, core::Core, providers, types::*};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fs2::FileExt;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(
    name = "shugo",
    version,
    about = "Shugo: bounded read-only PC/VPS inspection (alpha)"
)]
pub struct Cli {
    /// Private CLI-only storage directory (existing Unix directories must be mode 0700).
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    /// Machine-readable JSON. Watch emits one JSON object per line.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Read-only local inspection. Unavailable checks are not a safety verdict.
    Scan,
    Status,
    History,
    /// Foreground monitoring; no AI transmission or background daemon installation.
    Watch {
        #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u64).range(1..=86400))]
        interval: u64,
        #[arg(long, value_parser=clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        /// Attach bounded local TCP observations to each watch event.
        #[arg(long)]
        connections: bool,
        /// Attach local aggregation of this explicitly selected access log.
        #[arg(long)]
        access_log: Option<PathBuf>,
    },
    Files {
        #[command(subcommand)]
        command: FileCommand,
    },
    /// Confirm exactly one observed file digest as comparison baseline, not as safe content.
    Baseline {
        #[arg(long)]
        check_id: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        digest: String,
        #[arg(long)]
        observed_at: u64,
        #[arg(long)]
        yes: bool,
    },
    Models {
        #[command(subcommand)]
        command: Option<ModelCommand>,
    },
    /// One explicit API analysis of the latest fresh inspection, plus a model-list request.
    Ai {
        #[command(flatten)]
        model: ModelArgs,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        allow_cloud: bool,
    },
    /// List observed connections, without blocking traffic.
    Connections,
    /// Summarize a user-selected access log locally; raw lines are never sent to AI.
    AccessLog {
        path: PathBuf,
    },
}
#[derive(Subcommand, Debug)]
pub enum FileCommand {
    Add { path: PathBuf },
}
#[derive(Subcommand, Debug)]
pub enum ModelCommand {
    Set {
        #[command(flatten)]
        model: ModelArgs,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Role {
    Patrol,
    Resolver,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Patrol => "patrol",
            Self::Resolver => "resolver",
        }
    }
}
#[derive(Args, Debug)]
pub struct ModelArgs {
    #[arg(long, value_enum)]
    pub role: Role,
    #[arg(long,value_parser=["none","openai","anthropic"])]
    pub provider: String,
    #[arg(long)]
    pub model: String,
    /// Integer microUSD per million input tokens. 1000000 means USD 1.00 / million.
    #[arg(long)]
    pub input_rate: u64,
    /// Integer microUSD per million output tokens. 5000000 means USD 5.00 / million.
    #[arg(long)]
    pub output_rate: u64,
}
impl ModelArgs {
    fn choice(&self) -> ModelChoice {
        ModelChoice {
            provider: self.provider.clone(),
            model: self.model.clone(),
            input_rate: self.input_rate,
            output_rate: self.output_rate,
        }
    }
}

fn terminal_text(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}
fn write_stdout(text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|_| out.write_all(b"\n"))
        .and_then(|_| out.flush())
        .map_err(|_| "Output stream closed or unavailable".into())
}
fn output_run(run: &Run, json: bool) -> Result<(), String> {
    if json {
        return output(run, true);
    }
    let mut text = format!(
        "観測時刻 (Unix ms): {} / 終了: {:?} / run: {}\n検査状態: {} / {} 項目\n",
        run.started_at,
        run.finished_at,
        terminal_text(&run.id),
        terminal_text(&run.status),
        run.checks.len()
    );
    for check in &run.checks {
        text.push_str(&format!(
            "[{}] {} — {}\n",
            terminal_text(&check.status),
            terminal_text(&check.title),
            terminal_text(&check.detail)
        ));
    }
    text.push_str("観測範囲は限定的です。unavailable は未検査、partial は不完全。空結果や ok は侵入なし/内容の安全を保証しません。停止中・睡眠中・短命イベントは観測しません。");
    write_stdout(&text)
}

pub fn default_data_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("LOCALAPPDATA is unavailable; specify --data-dir")?;
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|v| PathBuf::from(v).join("Library/Application Support"))
        .ok_or("HOME is unavailable; specify --data-dir")?;
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/state")))
        .ok_or("HOME is unavailable; specify --data-dir")?;
    if !base.is_absolute() {
        return Err("Storage base must be absolute; specify --data-dir".into());
    }
    Ok(base.join("shugo-cli"))
}
fn output<T: Serialize>(value: &T, json: bool) -> Result<(), String> {
    let text = if json {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    }
    .map_err(|_| "Cannot serialize result")?;
    write_stdout(&text)
}
pub fn execute(cli: Cli, cancel: Arc<AtomicBool>) -> Result<(), String> {
    // Permission validation precedes any file or database access.
    if let Command::Ai {
        model, allow_cloud, ..
    } = &cli.command
    {
        if !allow_cloud {
            return Err(
                "AI requires --allow-cloud for this one invocation. No key was read.".into(),
            );
        }
        model.choice().validate()?;
        providers::reservation(&model.choice())?;
    }
    let data = match cli.data_dir {
        Some(p) => p,
        None => default_data_dir()?,
    };
    if !data.is_absolute() {
        return Err("--data-dir must be an absolute dedicated directory".into());
    }
    app_storage::prepare_data_dir(&data).map_err(|_| {
        "Storage directory is unsafe or inaccessible (Unix: use a dedicated mode 0700 directory)"
    })?;
    let lock = app_storage::open_instance_lock(&data.join("instance.lock"))
        .map_err(|_| "Cannot safely open storage lock")?;
    lock.try_lock_exclusive()
        .map_err(|_| "This storage directory is already in use")?;
    let core = Core::open(&data.join("guardian.sqlite3"))?;
    match cli.command {
        Command::Scan => output_run(&scan(&core, &cancel)?, cli.json),
        Command::Status => output(&core.snapshot()?, cli.json),
        Command::History => output(&core.snapshot()?.runs, cli.json),
        Command::Watch {
            interval,
            count,
            connections,
            access_log,
        } => {
            let mut completed = 0u64;
            while !cancel.load(Ordering::SeqCst) {
                let run = scan(&core, &cancel)?;
                if connections || access_log.is_some() {
                    let tcp = if connections && !cancel.load(Ordering::SeqCst) {
                        Some(crate::network::collect_connections())
                    } else {
                        None
                    };
                    let log=access_log.as_ref().map(|path| {
                        if cancel.load(Ordering::SeqCst) {serde_json::json!({"status":"unavailable","error":"cancelled before access-log read"})}
                        else {match crate::network::access_log(path) {Ok(report)=>serde_json::to_value(report).unwrap_or_else(|_|serde_json::json!({"status":"unavailable","error":"serialization failure"})),Err(error)=>serde_json::json!({"status":"unavailable","error":error})}}
                    });
                    let coverage = if run.status != "completed"
                        || run.checks.is_empty()
                        || (connections && tcp.as_ref().is_none_or(|v| v.status != "observed"))
                        || log.as_ref().is_some_and(|v| v["status"] != "observed")
                    {
                        "partial"
                    } else {
                        "observed"
                    };
                    if cli.json {
                        output(
                            &serde_json::json!({"run":run,"connections":tcp,"accessLog":log,"coverage":coverage}),
                            true,
                        )?;
                    } else {
                        output_run(&run, false)?;
                        write_stdout(&format!(
                            "追加観測 coverage: {coverage}（攻撃判定ではありません）"
                        ))?;
                        if let Some(report) = tcp {
                            output(&report, false)?;
                        } else if connections {
                            write_stdout("TCP: unavailable / cancelled")?;
                        }
                        if let Some(report) = log {
                            output(&report, false)?;
                        }
                    }
                } else {
                    output_run(&run, cli.json)?;
                }
                completed += 1;
                if cancel.load(Ordering::SeqCst) || count.is_some_and(|n| completed >= n) {
                    break;
                }
                let until = Instant::now() + Duration::from_secs(interval);
                while Instant::now() < until && !cancel.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(50));
                }
            }
            Ok(())
        }
        Command::Files {
            command: FileCommand::Add { path },
        } => {
            let absolute = if path.is_absolute() {
                path
            } else {
                std::env::current_dir()
                    .map_err(|_| "Current directory unavailable")?
                    .join(path)
            };
            // Check the submitted name before canonicalizing, so symlinks cannot be silently accepted.
            collectors::hash_file(&absolute)?;
            let canonical = absolute
                .canonicalize()
                .map_err(|_| "Cannot resolve selected file")?;
            collectors::hash_file(&canonical)?;
            let path = canonical
                .to_str()
                .ok_or("File path must be valid UTF-8")?
                .to_string();
            let label = canonical
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("Invalid file name")?
                .chars()
                .take(160)
                .collect();
            let mut s = core.inner.lock().map_err(|_| "Engine lock failed")?;
            let files = s.store.files()?;
            if files.len() >= 100 {
                return Err("File registration limit is 100".into());
            }
            if files.iter().any(|f| f.path == path) {
                return Err("File is already registered".into());
            }
            let file = RegisteredFile {
                id: id(),
                label,
                path,
            };
            let mut settings = s.settings.clone();
            settings.revision += 1;
            s.store.add_file_with_settings(&file, &settings)?;
            s.settings = settings;
            output(
                &serde_json::json!({"id":file.id,"label":file.label,"registered":true}),
                cli.json,
            )
        }
        Command::Baseline {
            check_id,
            run_id,
            digest,
            observed_at,
            yes,
        } => {
            if !yes {
                return Err("Baseline needs --yes after inspecting the exact observed content; it is not a safety approval".into());
            }
            let s = core.inner.lock().map_err(|_| "Engine lock failed")?;
            let runs = s.store.runs()?;
            let latest = runs.first().ok_or("No inspection exists")?;
            let selected = baseline::BaselineSelection {
                run_id: &run_id,
                check_id: &check_id,
                digest: &digest,
                observed_at,
            };
            let check = baseline::selected_check(latest, &selected, now_ms())?;
            s.store
                .accept_baseline(&check.id, check.digest.as_deref().ok_or("Missing digest")?)?;
            output(
                &serde_json::json!({"checkId":check.id,"runId":run_id,"accepted":true,"contentSafety":"not_assessed"}),
                cli.json,
            )
        }
        Command::Models { command } => {
            if let Some(ModelCommand::Set { model }) = command {
                set_model(&core, &model)?;
            }
            let settings = core.snapshot()?.settings;
            output(
                &serde_json::json!({"patrol":settings.patrol,"resolver":settings.resolver,"ratesUnit":"microUSD_per_million_tokens","cloudEnabled":false}),
                cli.json,
            )
        }
        Command::Ai {
            model, key_file, ..
        } => ai(&core, &cancel, &model, &key_file, cli.json),
        Command::Connections => {
            let report = crate::network::collect_connections();
            output(&report, cli.json)?;
            if report.status == "unavailable" {
                Err("TCP observations unavailable; no safety verdict".into())
            } else {
                Ok(())
            }
        }
        Command::AccessLog { path } => output(&crate::network::access_log(&path)?, cli.json),
    }
}
fn set_model(core: &Arc<Core>, model: &ModelArgs) -> Result<(), String> {
    let settings = core.snapshot()?.settings;
    let mut patrol = settings.patrol;
    let mut resolver = settings.resolver;
    match model.role {
        Role::Patrol => patrol = model.choice(),
        Role::Resolver => resolver = model.choice(),
    }
    core.models(patrol, resolver, settings.revision)
}
fn scan(core: &Arc<Core>, cancel: &AtomicBool) -> Result<Run, String> {
    if cancel.load(Ordering::SeqCst) {
        return Err("Cancelled before inspection".into());
    }
    let run_id = core.start(&id(), &core.epoch, "manual")?;
    let limit = Instant::now() + Duration::from_secs(120);
    loop {
        if cancel.load(Ordering::SeqCst) || Instant::now() >= limit {
            core.cancel_scan()?;
        }
        let snapshot = core.snapshot()?;
        if snapshot.active.is_none() {
            return snapshot
                .runs
                .into_iter()
                .find(|r| r.id == run_id)
                .ok_or("Inspection result was not saved".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}
fn ai(
    core: &Arc<Core>,
    cancel: &AtomicBool,
    model: &ModelArgs,
    key_file: &std::path::Path,
    json: bool,
) -> Result<(), String> {
    // Reject stale/missing results before reading the explicitly selected secret.
    let snapshot = core.snapshot()?;
    let run = snapshot.runs.first().ok_or("Run scan before AI analysis")?;
    if run.checks.is_empty()
        || !["completed", "partial"].contains(&run.status.as_str())
        || !evidence_fresh(run.finished_at.unwrap_or(0), now_ms())
        || run
            .checks
            .iter()
            .any(|c| !evidence_fresh(c.observed_at, now_ms()))
    {
        return Err("A fresh completed inspection is required; run scan again".into());
    }
    if snapshot.settings.paused {
        return Err("Inspection is paused".into());
    }
    let run_id = run.id.clone();
    set_model(core, model)?;
    if cancel.load(Ordering::SeqCst) {
        return Err("Cancelled before key read".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(key_file)
            .map_err(|_| "Key file unavailable (value hidden)")?;
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(
                "Key file must be owned by this user, private (mode 0600), and not hard-linked"
                    .into(),
            );
        }
    }
    let source_secret = collectors::read_secret_file(key_file)?;
    let secret = zeroize::Zeroizing::new(source_secret.trim().to_string());
    drop(source_secret);
    if !(16..=8192).contains(&secret.len()) || !secret.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("Key file has invalid format (value hidden)".into());
    }
    let policy = core.inner.lock().map_err(|_| "Engine lock failed")?.policy;
    core.commit_credential(&model.provider, secret, policy)?;
    let policy = core.inner.lock().map_err(|_| "Engine lock failed")?.policy;
    let key = core.commit_catalog(&model.provider, policy)?;
    if cancel.load(Ordering::SeqCst) {
        core.inner
            .lock()
            .map_err(|_| "Engine lock failed")?
            .catalog_in_flight = false;
        return Err("Cancelled before model-list request".into());
    }
    let catalog = providers::catalog(&model.provider, &key);
    drop(key);
    {
        let mut s = core.inner.lock().map_err(|_| "Engine lock failed")?;
        s.catalog_in_flight = false;
        // Do not surface network errors which could contain credentials or response body.
        let models = catalog.map_err(|_| "Model-list request failed (remote details hidden)")?;
        if s.policy != policy || cancel.load(Ordering::SeqCst) {
            return Err("Model-list result cancelled".into());
        }
        if !models.contains(&model.model) {
            return Err("Selected model was not returned by the provider".into());
        }
        s.catalogs.insert(model.provider.clone(), models);
        s.store.check_anchor(now_ms())?;
        if s.store.budget(now_ms())?.unknown > 0 {
            return Err("Unsettled costs prevent another transmission".into());
        }
        s.cloud = true;
        s.policy += 1;
    }
    let result = (|| {
        if cancel.load(Ordering::SeqCst) {
            return Err("Cancelled before analysis request".into());
        }
        let analysis_id = core.analyze(model.role.name(), &run_id)?;
        loop {
            if cancel.load(Ordering::SeqCst) {
                core.cancel_analysis()?;
            }
            let running = core
                .inner
                .lock()
                .map_err(|_| "Engine lock failed")?
                .analysis_active
                .is_some();
            if !running {
                // Completion and settlement are committed before analysis_active is cleared.
                // Read the result only after observing that committed state, never an older running snapshot.
                let snapshot = core.snapshot()?;
                let analysis = snapshot
                    .analyses
                    .into_iter()
                    .find(|a| a.id == analysis_id)
                    .ok_or("Analysis result was not saved")?;
                output(&analysis, json)?;
                return analysis_completed(&analysis);
            }
            thread::sleep(Duration::from_millis(50));
        }
    })();
    core.emergency_lock()?;
    result
}

fn analysis_completed(analysis: &Analysis) -> Result<(), String> {
    if analysis.status == "succeeded" && analysis.cost_status == "settled" {
        Ok(())
    } else {
        Err("Analysis did not complete with settled costs; inspect status and cost ledger before retry".into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_success_contract_requires_succeeded_and_settled() {
        let mut a = Analysis {
            id: "fixture".into(),
            role: "patrol".into(),
            run_id: "r".into(),
            provider: "openai".into(),
            model: "fixture".into(),
            status: "succeeded".into(),
            text: "synthetic".into(),
            created_at: 1,
            cost_status: "settled".into(),
        };
        assert!(analysis_completed(&a).is_ok());
        for status in ["running", "completed", "failed", "cancelled", "stale"] {
            a.status = status.into();
            assert!(analysis_completed(&a).is_err());
        }
        a.status = "succeeded".into();
        a.cost_status = "unknown".into();
        assert!(analysis_completed(&a).is_err());
    }
}
