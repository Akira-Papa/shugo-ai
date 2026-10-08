use crate::response::ResponsePlan;
use crate::types::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
pub struct Store {
    pub db: Connection,
    pub ledger_blocked: bool,
    anchor: PathBuf,
}
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct Anchor {
    generation: String,
    sequence: u64,
    highwater: u64,
}
fn err(_: impl std::fmt::Display) -> String {
    "ローカルデータベースの処理に失敗しました。".into()
}
impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        let existed = path.exists();
        let anchor = path.with_extension("budget-anchor.json");
        let anchor_existed = anchor.exists();
        crate::storage_fs::prepare_database(path)?;
        let db = Connection::open(path).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(err)?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )
        .map_err(err)?;
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(err)?;
        if version > 2 {
            return Err("新しいバージョンのデータです。新しいアプリで開いてください。".into());
        }
        db.execute_batch("BEGIN; CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS baselines(check_id TEXT PRIMARY KEY,digest TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,created_at INTEGER NOT NULL,value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,check_id TEXT NOT NULL UNIQUE,value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY,created_at INTEGER NOT NULL,value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,analysis_id TEXT NOT NULL,role TEXT NOT NULL,created_at INTEGER NOT NULL,state TEXT NOT NULL,reserved INTEGER NOT NULL,actual INTEGER);
   CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,epoch TEXT NOT NULL,run_id TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY CHECK(id=1),generation TEXT NOT NULL,sequence INTEGER NOT NULL,highwater INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS response_plans(id TEXT PRIMARY KEY,analysis_id TEXT NOT NULL,action TEXT NOT NULL,state TEXT NOT NULL,value TEXT NOT NULL,UNIQUE(analysis_id,action));
   CREATE TABLE IF NOT EXISTS response_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,plan_id TEXT NOT NULL REFERENCES response_plans(id),kind TEXT NOT NULL,created_at INTEGER NOT NULL);
   PRAGMA user_version=2; COMMIT;").map_err(err)?;
        db.execute(
            "UPDATE attempts SET state='unknown' WHERE state='dispatched'",
            [],
        )
        .map_err(err)?;
        let mut store = Self {
            db,
            ledger_blocked: false,
            anchor,
        };
        let ledger: Option<String> = store
            .db
            .query_row("SELECT generation FROM ledger WHERE id=1", [], |r| r.get(0))
            .optional()
            .map_err(err)?;
        if ledger.is_none() {
            let generation = id();
            store
                .db
                .execute(
                    "INSERT INTO ledger VALUES(1,?1,0,?2)",
                    params![generation, now_ms()],
                )
                .map_err(err)?;
            if !existed && !anchor_existed {
                store.write_anchor()?;
            } else {
                store.ledger_blocked = true;
            }
        }
        if store.check_anchor(now_ms()).is_err() {
            store.ledger_blocked = true;
        }
        for mut a in store.analyses()? {
            if a.status == "running" {
                a.status = "interrupted".into();
                a.text = "前回の解析は中断しました。請求額は未確定です。".into();
                a.cost_status = "unknown".into();
                store.save_analysis(&a)?;
            }
        }
        store.interrupt_response_actions()?;
        Ok(store)
    }
    pub fn settings(&self) -> Result<Settings, String> {
        let data: Option<String> = self
            .db
            .query_row("SELECT value FROM settings WHERE id=1", [], |r| r.get(0))
            .optional()
            .map_err(err)?;
        match data {
            Some(s) => serde_json::from_str(&s).map_err(err),
            None => Ok(Settings::default()),
        }
    }
    pub fn response_plans(&self) -> Result<Vec<ResponsePlan>, String> {
        self.list("SELECT value FROM response_plans ORDER BY rowid DESC LIMIT 500")
    }
    pub fn add_response_plan(&mut self, p: &ResponsePlan) -> Result<(), String> {
        p.validate_new()?;
        self.check_capacity()?;
        let tx = self.db.transaction().map_err(err)?;
        let count: u64 = tx
            .query_row("SELECT count(*) FROM response_plans", [], |r| r.get(0))
            .map_err(err)?;
        if count >= 500 {
            return Err("対策計画の保存上限です。新しい対策を開始しません。".into());
        }
        tx.execute(
            "INSERT INTO response_plans VALUES(?1,?2,?3,?4,?5)",
            params![
                p.id,
                p.analysis_id,
                p.action.as_str(),
                p.status,
                serde_json::to_string(p).map_err(err)?
            ],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO response_events(plan_id,kind,created_at) VALUES(?1,'proposal',?2)",
            params![p.id, p.created_at],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    /// Must complete before the core performs an effect. The core separately
    /// checks current session authorization and evidence while holding its lock.
    pub fn begin_response_action(
        &mut self,
        id: &str,
        policy_revision: u64,
        now: u64,
    ) -> Result<ResponsePlan, String> {
        self.check_capacity()?;
        let tx = self.db.transaction().map_err(err)?;
        let (state, value): (String, String) = tx
            .query_row(
                "SELECT state,value FROM response_plans WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        let mut p: ResponsePlan = serde_json::from_str(&value).map_err(err)?;
        if state != "proposed"
            || p.status != state
            || !p.action.available()
            || p.policy_revision != policy_revision
            || now < p.created_at
            || now >= p.expires_at
        {
            return Err("対策計画が古い・実行済み・未対応です。再実行しません。".into());
        }
        p.status = "executing".into();
        let n = tx.execute("UPDATE response_plans SET state='executing',value=?1 WHERE id=?2 AND state='proposed'",params![serde_json::to_string(&p).map_err(err)?,id]).map_err(err)?;
        if n != 1 {
            return Err("対策計画が変更されています。".into());
        }
        tx.execute(
            "INSERT INTO response_events(plan_id,kind,created_at) VALUES(?1,'intent',?2)",
            params![id, now],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(p)
    }
    /// `success` means the core independently verified its own send gate closed.
    pub fn finish_response_action(&mut self, id: &str, success: bool) -> Result<(), String> {
        let tx = self.db.transaction().map_err(err)?;
        let (state, value): (String, String) = tx
            .query_row(
                "SELECT state,value FROM response_plans WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        let mut p: ResponsePlan = serde_json::from_str(&value).map_err(err)?;
        if state != "executing" || p.status != state {
            return Err("対策結果を保存する状態が不正です。".into());
        }
        p.status = if success { "succeeded" } else { "failed" }.into();
        tx.execute(
            "UPDATE response_plans SET state=?1,value=?2 WHERE id=?3 AND state='executing'",
            params![p.status, serde_json::to_string(&p).map_err(err)?, id],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO response_events(plan_id,kind,created_at) VALUES(?1,?2,?3)",
            params![id, p.status, now_ms()],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    fn interrupt_response_actions(&mut self) -> Result<(), String> {
        let tx = self.db.transaction().map_err(err)?;
        let values = {
            let mut query = tx
                .prepare("SELECT value FROM response_plans WHERE state IN ('executing','proposed')")
                .map_err(err)?;
            let rows = query
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(err)?
        };
        for value in values {
            let mut p: ResponsePlan = serde_json::from_str(&value).map_err(err)?;
            p.status = if p.status == "executing" {
                "interrupted"
            } else {
                "expired"
            }
            .into();
            tx.execute(
                "UPDATE response_plans SET state=?1,value=?2 WHERE id=?3",
                params![p.status, serde_json::to_string(&p).map_err(err)?, p.id],
            )
            .map_err(err)?;
            tx.execute(
                "INSERT INTO response_events(plan_id,kind,created_at) VALUES(?1,?2,?3)",
                params![p.id, p.status, now_ms()],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)
    }
    pub fn save_settings(&self, s: &Settings) -> Result<(), String> {
        self.db.execute("INSERT INTO settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET value=excluded.value",[serde_json::to_string(s).map_err(err)?]).map_err(err)?;
        Ok(())
    }
    pub fn files(&self) -> Result<Vec<RegisteredFile>, String> {
        self.list("SELECT value FROM files ORDER BY id LIMIT 100")
    }
    pub fn add_file_with_settings(
        &mut self,
        f: &RegisteredFile,
        s: &Settings,
    ) -> Result<(), String> {
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "INSERT INTO files VALUES(?1,?2)",
            params![f.id, serde_json::to_string(f).map_err(err)?],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
            [serde_json::to_string(s).map_err(err)?],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    fn list<T: serde::de::DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>, String> {
        let mut st = self.db.prepare(sql).map_err(err)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
        rows.map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
            .collect()
    }
    pub fn runs(&self) -> Result<Vec<Run>, String> {
        self.list("SELECT value FROM runs ORDER BY created_at DESC LIMIT 100")
    }
    pub fn findings(&self) -> Result<Vec<Finding>, String> {
        self.list("SELECT value FROM findings ORDER BY rowid DESC LIMIT 1000")
    }
    pub fn analyses(&self) -> Result<Vec<Analysis>, String> {
        self.list("SELECT value FROM analyses ORDER BY created_at DESC LIMIT 100")
    }
    pub fn baseline(&self, id: &str) -> Result<Option<String>, String> {
        self.db
            .query_row(
                "SELECT digest FROM baselines WHERE check_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)
    }
    pub fn accept_baseline(&self, id: &str, digest: &str) -> Result<(), String> {
        self.db.execute("INSERT INTO baselines VALUES(?1,?2) ON CONFLICT(check_id) DO UPDATE SET digest=excluded.digest",params![id,digest]).map_err(err)?;
        Ok(())
    }
    pub fn save_run(&mut self, r: &Run) -> Result<(), String> {
        self.save_run_at(r, now_ms())
    }
    fn save_run_at(&mut self, r: &Run, retention_now: u64) -> Result<(), String> {
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "INSERT INTO runs VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
            params![r.id, r.started_at, serde_json::to_string(r).map_err(err)?],
        )
        .map_err(err)?;
        for c in &r.checks {
            if c.status == "attention" {
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT value FROM findings WHERE check_id=?1",
                        [&c.id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(err)?;
                let mut f = if let Some(s) = existing {
                    serde_json::from_str::<Finding>(&s).map_err(err)?
                } else {
                    Finding {
                        id: id(),
                        check_id: c.id.clone(),
                        title: c.title.clone(),
                        detail: c.detail.clone(),
                        status: "open".into(),
                        first_seen: c.observed_at,
                        last_seen: c.observed_at,
                        evidence: Some(c.clone()),
                    }
                };
                f.last_seen = c.observed_at;
                f.detail = c.detail.clone();
                f.evidence = Some(c.clone());
                tx.execute("INSERT INTO findings VALUES(?1,?2,?3) ON CONFLICT(check_id) DO UPDATE SET value=excluded.value",params![f.id,f.check_id,serde_json::to_string(&f).map_err(err)?]).map_err(err)?;
            }
        }
        tx.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY created_at DESC LIMIT -1 OFFSET 100) AND id NOT IN (SELECT json_extract(value,'$.runId') FROM response_plans)",[]).map_err(err)?;
        tx.execute("DELETE FROM analyses WHERE created_at<?1 AND json_extract(value,'$.status') NOT IN ('running','cancelling') AND id NOT IN (SELECT analysis_id FROM response_plans)",[retention_now.saturating_sub(7*86_400_000)]).map_err(err)?;
        // Preserve all billing receipts in this alpha. A forward wall-clock jump
        // must not erase costs which become in-window again after clock recovery.
        tx.commit().map_err(err)
    }
    /// Publish a new run and its idempotency receipt as one durable operation.
    /// A failed receipt must never leave an orphaned running run.
    pub fn start_run_with_receipt(
        &mut self,
        r: &Run,
        request: &str,
        epoch: &str,
    ) -> Result<(), String> {
        if r.status != "running" || !r.checks.is_empty() {
            return Err("新規検査の状態が不正です".into());
        }
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "INSERT INTO runs VALUES(?1,?2,?3)",
            params![r.id, r.started_at, serde_json::to_string(r).map_err(err)?],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO receipts VALUES(?1,?2,?3)",
            params![request, epoch, r.id],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub fn acknowledge(&self, id: &str) -> Result<(), String> {
        let mut f = self
            .findings()?
            .into_iter()
            .find(|f| f.id == id)
            .ok_or("案件が見つかりません")?;
        f.status = "acknowledged".into();
        self.db
            .execute(
                "UPDATE findings SET value=?1 WHERE id=?2",
                params![serde_json::to_string(&f).map_err(err)?, id],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn save_analysis(&self, a: &Analysis) -> Result<(), String> {
        self.db.execute("INSERT INTO analyses VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET value=excluded.value",params![a.id,a.created_at,serde_json::to_string(a).map_err(err)?]).map_err(err)?;
        Ok(())
    }
    pub fn budget(&self, now: u64) -> Result<Budget, String> {
        let day = now / 86_400_000 * 86_400_000;
        let month = now.saturating_sub(30 * 86_400_000);
        let sum = |sql: &str, time: u64| -> Result<u64, String> {
            self.db
                .query_row(sql, [time], |r| r.get::<_, u64>(0))
                .map_err(err)
        };
        Ok(Budget{used_today:sum("SELECT coalesce(sum(coalesce(actual,reserved)),0) FROM attempts WHERE created_at>=?1 OR state IN ('unknown','dispatched')",day)?,reserved:sum("SELECT coalesce(sum(reserved),0) FROM attempts WHERE state IN ('unknown','dispatched') AND created_at>=0 AND ?1>=0",0)?,used_30_days:sum("SELECT coalesce(sum(coalesce(actual,reserved)),0) FROM attempts WHERE created_at>=?1 OR state IN ('unknown','dispatched')",month)?,patrol_calls:sum("SELECT count(*) FROM attempts WHERE role='patrol' AND created_at>=?1",day)?,resolver_calls:sum("SELECT count(*) FROM attempts WHERE role='resolver' AND created_at>=?1",day)?,unknown:sum("SELECT count(*) FROM attempts WHERE state='unknown' AND ?1>=0",0)?})
    }
    pub fn reserve(&mut self, a: &Analysis, reserved: u64, now: u64) -> Result<String, String> {
        self.reserve_checked(a, reserved, now, |s| s.write_anchor())
    }
    fn reserve_checked(
        &mut self,
        a: &Analysis,
        reserved: u64,
        now: u64,
        save_anchor: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<String, String> {
        self.check_anchor(now)?;
        self.check_capacity()?;
        let b = self.budget(now)?;
        if b.unknown > 0 {
            return Err("未確定の請求があります。新規クラウド解析を停止しています。".into());
        }
        if b.used_today.saturating_add(reserved) > 250_000
            || b.used_30_days.saturating_add(reserved) > 5_000_000
            || (a.role == "patrol" && b.patrol_calls >= 24)
            || (a.role == "resolver" && b.resolver_calls >= 4)
        {
            return Err("予算または回数上限に達しました。ローカル検査は続けられます。".into());
        }
        let attempt = id();
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "INSERT INTO analyses VALUES(?1,?2,?3)",
            params![a.id, a.created_at, serde_json::to_string(a).map_err(err)?],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO attempts VALUES(?1,?2,?3,?4,'dispatched',?5,NULL)",
            params![attempt, a.id, a.role, now, reserved],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE ledger SET sequence=sequence+1,highwater=max(highwater,?1) WHERE id=1",
            [now],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        if save_anchor(self).is_err() {
            self.ledger_blocked = true;
            return Err("予算参照の保存に失敗しました。送信を停止します。".into());
        }
        Ok(attempt)
    }
    pub fn check_capacity(&self) -> Result<(), String> {
        let pages: u64 = self
            .db
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(err)?;
        let size: u64 = self
            .db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(err)?;
        let free: u64 = self
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))
            .map_err(err)?;
        if pages.saturating_sub(free).saturating_mul(size) > 64 * 1024 * 1024 {
            return Err(
                "保存容量の上限です。新規検査とAIを停止します。根拠は保持しています。".into(),
            );
        }
        Ok(())
    }
    fn anchor_value(&self) -> Result<Anchor, String> {
        self.db
            .query_row(
                "SELECT generation,sequence,highwater FROM ledger WHERE id=1",
                [],
                |r| {
                    Ok(Anchor {
                        generation: r.get(0)?,
                        sequence: r.get(1)?,
                        highwater: r.get(2)?,
                    })
                },
            )
            .map_err(err)
    }
    fn write_anchor(&self) -> Result<(), String> {
        crate::storage_fs::write_private_atomic(
            &self.anchor,
            &serde_json::to_vec(&self.anchor_value()?).map_err(err)?,
        )
    }
    pub fn check_anchor(&self, now: u64) -> Result<(), String> {
        if self.ledger_blocked {
            return Err("予算台帳の整合性を確認できません。クラウドは停止中です。".into());
        }
        let actual: Anchor = serde_json::from_slice(&crate::storage_fs::read_private_bounded(
            &self.anchor,
            4096,
        )?)
        .map_err(err)?;
        let expected = self.anchor_value()?;
        if actual != expected || now.saturating_add(1000) < expected.highwater {
            return Err(
                "時計逆行・台帳復元・データ欠損を検出しました。請求の照合が必要です。".into(),
            );
        }
        Ok(())
    }
    pub fn finish_analysis(
        &mut self,
        a: &Analysis,
        attempt: &str,
        actual: Option<u64>,
    ) -> Result<(), String> {
        let tx = self.db.transaction().map_err(err)?;
        let count = tx
            .execute(
                "UPDATE attempts SET state=?1,actual=?2 WHERE id=?3 AND state='dispatched'",
                params![
                    if actual.is_some() {
                        "settled"
                    } else {
                        "unknown"
                    },
                    actual,
                    attempt
                ],
            )
            .map_err(err)?;
        if count != 1 {
            return Err("費用台帳の状態が競合しました".into());
        }
        tx.execute(
            "UPDATE analyses SET value=?1 WHERE id=?2",
            params![serde_json::to_string(a).map_err(err)?, a.id],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub fn settle(&self, id: &str, actual: Option<u64>) -> Result<(), String> {
        self.db
            .execute(
                "UPDATE attempts SET state=?1, actual=?2 WHERE id=?3 AND state='dispatched'",
                params![
                    if actual.is_some() {
                        "settled"
                    } else {
                        "unknown"
                    },
                    actual,
                    id
                ],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn receipt(&self, request: &str, epoch: &str) -> Result<Option<String>, String> {
        self.db
            .query_row(
                "SELECT run_id FROM receipts WHERE id=?1 AND epoch=?2",
                params![request, epoch],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)
    }
    pub fn save_receipt(&self, request: &str, epoch: &str, run: &str) -> Result<(), String> {
        self.db
            .execute(
                "INSERT INTO receipts VALUES(?1,?2,?3)",
                params![request, epoch, run],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn cleanup_receipts(&self) -> Result<(), String> {
        self.db.execute("DELETE FROM receipts", []).map_err(err)?;
        Ok(())
    }
    pub fn delete_history(&self) -> Result<(), String> {
        if !self.findings()?.is_empty() {
            return Err("未解決案件の根拠を保護しています。この版では履歴削除できません。".into());
        }
        let plans: u64 = self
            .db
            .query_row("SELECT count(*) FROM response_plans", [], |r| r.get(0))
            .map_err(err)?;
        if plans > 0 {
            return Err(
                "対策計画の根拠と監査を保護しています。この版では履歴削除できません。".into(),
            );
        }
        // A failed DELETE inside execute_batch("BEGIN; ...") left the transaction open and
        // wedged every later write; a scoped transaction rolls back on drop.
        let tx = self.db.unchecked_transaction().map_err(err)?;
        tx.execute_batch("DELETE FROM runs; DELETE FROM analyses;")
            .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub fn baselines(&self) -> Result<BTreeMap<String, String>, String> {
        let mut s = self
            .db
            .prepare("SELECT check_id,digest FROM baselines")
            .map_err(err)?;
        let rows = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(err)?;
        rows.map(|r| r.map_err(err)).collect()
    }
}
#[cfg(test)]
mod response_tests {
    use super::*;
    use crate::response::{ResponseAction, ResponsePlan};
    fn plan(action: ResponseAction) -> ResponsePlan {
        ResponsePlan::new(
            id(),
            id(),
            action,
            "人工fixture".into(),
            vec!["evidence-1".into()],
            2,
            now_ms(),
        )
    }
    #[test]
    fn intent_failure_rolls_back_and_duplicate_or_unsupported_never_execute() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        let p = plan(ResponseAction::PauseCloud);
        s.add_response_plan(&p).unwrap();
        assert!(s.add_response_plan(&p).is_err());
        let mut duplicate = p.clone();
        duplicate.id = id();
        assert!(s.add_response_plan(&duplicate).is_err());
        s.db.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON response_events WHEN NEW.kind='intent' BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(s.begin_response_action(&p.id, 2, now_ms()).is_err());
        assert_eq!(s.response_plans().unwrap()[0].status, "proposed");
        s.db.execute_batch("DROP TRIGGER fail_intent;").unwrap();
        assert!(s.begin_response_action(&p.id, 1, now_ms()).is_err());
        assert!(s.begin_response_action(&p.id, 2, p.expires_at).is_err());
        s.begin_response_action(&p.id, 2, now_ms()).unwrap();
        assert!(s.begin_response_action(&p.id, 2, now_ms()).is_err());
        s.finish_response_action(&p.id, true).unwrap();
        assert!(s.finish_response_action(&p.id, true).is_err());
        let unsupported = plan(ResponseAction::BlockConnection);
        s.add_response_plan(&unsupported).unwrap();
        assert!(s
            .begin_response_action(&unsupported.id, 2, now_ms())
            .is_err());
    }
    #[test]
    fn result_failure_and_restart_preserve_uncertainty_and_block_replay() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let mut s = Store::open(&path).unwrap();
        let p = plan(ResponseAction::PauseCloud);
        s.add_response_plan(&p).unwrap();
        s.begin_response_action(&p.id, 2, now_ms()).unwrap();
        s.db.execute_batch("CREATE TRIGGER fail_result BEFORE INSERT ON response_events WHEN NEW.kind='succeeded' BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(s.finish_response_action(&p.id, true).is_err());
        assert_eq!(s.response_plans().unwrap()[0].status, "executing");
        drop(s);
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.response_plans().unwrap()[0].status, "interrupted");
        assert!(s.begin_response_action(&p.id, 2, now_ms()).is_err());
        let kinds: String = s.db.query_row("SELECT group_concat(kind,',') FROM (SELECT kind FROM response_events ORDER BY sequence)", [], |r| r.get(0)).unwrap();
        assert_eq!(kinds, "proposal,intent,interrupted");
        assert!(s.delete_history().is_err());
    }
    #[test]
    fn session_restart_expires_unexecuted_plan_and_upgrade_preserves_existing_data() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let mut s = Store::open(&path).unwrap();
        let p = plan(ResponseAction::PauseCloud);
        s.add_response_plan(&p).unwrap();
        let mut settings = Settings::default();
        settings.revision += 1;
        s.save_settings(&settings).unwrap();
        drop(s);
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.settings().unwrap().revision, settings.revision);
        let version: u64 =
            s.db.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 2);
        assert_eq!(s.response_plans().unwrap()[0].status, "expired");
        assert!(s.begin_response_action(&p.id, 2, now_ms()).is_err());
        // Reconstruct the pre-response v1 schema, which has no response tables.
        s.db.execute_batch(
            "DROP TABLE response_events; DROP TABLE response_plans; PRAGMA user_version=1;",
        )
        .unwrap();
        drop(s);
        let s = Store::open(&path).unwrap();
        assert_eq!(s.settings().unwrap().revision, settings.revision);
        assert!(s.response_plans().unwrap().is_empty());
        let version: u64 =
            s.db.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 2);
    }
    #[test]
    fn plan_cap_is_fail_closed_and_audited_evidence_survives_retention() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        let p = plan(ResponseAction::PauseCloud);
        let a = Analysis {
            id: p.analysis_id.clone(),
            role: "resolver".into(),
            run_id: p.run_id.clone(),
            provider: "fixture".into(),
            model: "fixture".into(),
            status: "succeeded".into(),
            text: "fixture".into(),
            created_at: 1,
            cost_status: "settled".into(),
        };
        s.save_analysis(&a).unwrap();
        s.save_run(&Run {
            id: p.run_id.clone(),
            trigger: "manual".into(),
            status: "completed".into(),
            started_at: 1,
            finished_at: Some(1),
            checks: vec![],
        })
        .unwrap();
        s.add_response_plan(&p).unwrap();
        // Re-save old analysis after its first unpinned retention pass.
        s.save_analysis(&a).unwrap();
        for i in 0..101 {
            s.save_run(&Run {
                id: id(),
                trigger: "manual".into(),
                status: "completed".into(),
                started_at: 100 + i,
                finished_at: Some(100 + i),
                checks: vec![],
            })
            .unwrap();
        }
        let pinned: u64 =
            s.db.query_row("SELECT count(*) FROM runs WHERE id=?1", [&p.run_id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(pinned, 1);
        assert!(s.analyses().unwrap().iter().any(|a| a.id == p.analysis_id));
        for _ in 1..500 {
            s.add_response_plan(&plan(ResponseAction::PauseCloud))
                .unwrap();
        }
        assert!(s
            .add_response_plan(&plan(ResponseAction::PauseCloud))
            .is_err());
        assert_eq!(s.response_plans().unwrap().len(), 500);
    }
}

#[cfg(test)]
mod review3_tests {
    use super::*;

    #[test]
    fn failed_registration_rolls_back_file_and_settings() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        let original = Settings::default();
        s.save_settings(&original).unwrap();
        let mut candidate = original.clone();
        candidate.revision += 1;
        let file = RegisteredFile {
            id: id(),
            label: "fixture".into(),
            path: "/fixture".into(),
        };
        s.db.execute_batch("CREATE TRIGGER fail_settings BEFORE INSERT ON settings BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(s.add_file_with_settings(&file, &candidate).is_err());
        assert!(s.files().unwrap().is_empty());
        assert_eq!(s.settings().unwrap().revision, original.revision);
        s.db.execute_batch("DROP TRIGGER fail_settings;").unwrap();
        s.add_file_with_settings(&file, &candidate).unwrap();
        assert_eq!(s.files().unwrap().len(), 1);
        assert_eq!(s.settings().unwrap().revision, candidate.revision);
    }

    #[test]
    fn freed_pages_allow_capacity_recovery_and_reuse() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("db")).unwrap();
        s.db.execute_batch("CREATE TABLE capacity_fixture(value BLOB); INSERT INTO capacity_fixture VALUES(zeroblob(68157440));").unwrap();
        assert!(s.check_capacity().is_err());
        s.db.execute("DELETE FROM capacity_fixture", []).unwrap();
        // DELETE leaves the physical pages allocated but reusable by SQLite.
        let allocated: u64 =
            s.db.query_row("PRAGMA page_count", [], |r| r.get(0))
                .unwrap();
        let page_size: u64 =
            s.db.query_row("PRAGMA page_size", [], |r| r.get(0))
                .unwrap();
        assert!(allocated * page_size > 64 * 1024 * 1024);
        s.check_capacity().unwrap();
        s.db.execute("INSERT INTO capacity_fixture VALUES(zeroblob(1048576))", [])
            .unwrap();
        s.check_capacity().unwrap();
        let reused: u64 =
            s.db.query_row("PRAGMA page_count", [], |r| r.get(0))
                .unwrap();
        assert_eq!(allocated, reused);
    }

    #[test]
    fn future_run_retention_preserves_settled_cost_after_clock_recovery() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let mut s = Store::open(&path).unwrap();
        let now = now_ms();
        let mut a = Analysis {
            id: id(),
            role: "resolver".into(),
            run_id: "r".into(),
            provider: "openai".into(),
            model: "m".into(),
            status: "running".into(),
            text: String::new(),
            created_at: now,
            cost_status: "reserved".into(),
        };
        let attempt = s.reserve(&a, 1000, now).unwrap();
        a.status = "succeeded".into();
        a.cost_status = "settled".into();
        s.finish_analysis(&a, &attempt, Some(100)).unwrap();
        let future = now + 31 * 86_400_000;
        let run = Run {
            id: id(),
            trigger: "manual".into(),
            status: "completed".into(),
            started_at: future,
            finished_at: Some(future),
            checks: vec![],
        };
        s.save_run_at(&run, future).unwrap();
        assert!(s.analyses().unwrap().is_empty());
        assert_eq!(s.budget(now).unwrap().used_today, 100);
        s.delete_history().unwrap();
        drop(s);
        let s = Store::open(&path).unwrap();
        s.check_anchor(now_ms()).unwrap();
        assert_eq!(s.budget(now).unwrap().used_today, 100);
        assert_eq!(s.budget(now).unwrap().used_30_days, 100);
    }
}

#[cfg(test)]
mod review2_tests {
    use super::*;
    #[test]
    fn failed_receipt_rolls_back_run_and_retry_commits_both() {
        let d = tempfile::tempdir().unwrap();
        let mut store = Store::open(&d.path().join("db")).unwrap();
        let run = Run {
            id: id(),
            trigger: "manual".into(),
            status: "running".into(),
            started_at: now_ms(),
            finished_at: None,
            checks: vec![],
        };
        let request = id();
        store.db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(store
            .start_run_with_receipt(&run, &request, "epoch")
            .is_err());
        assert!(store.runs().unwrap().is_empty());
        assert!(store.receipt(&request, "epoch").unwrap().is_none());
        store
            .db
            .execute_batch("DROP TRIGGER fail_receipt;")
            .unwrap();
        store
            .start_run_with_receipt(&run, &request, "epoch")
            .unwrap();
        assert_eq!(store.runs().unwrap().len(), 1);
        assert_eq!(
            store.receipt(&request, "epoch").unwrap(),
            Some(run.id.clone())
        );
        assert!(store
            .start_run_with_receipt(&run, &request, "epoch")
            .is_err());
        assert_eq!(store.runs().unwrap().len(), 1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_reservation_survives_history_delete_and_restart() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        let mut s = Store::open(&p).unwrap();
        let a = Analysis {
            id: id(),
            role: "resolver".into(),
            run_id: "r".into(),
            provider: "openai".into(),
            model: "m".into(),
            status: "running".into(),
            text: "".into(),
            created_at: now_ms(),
            cost_status: "reserved".into(),
        };
        s.reserve(&a, 1000, now_ms()).unwrap();
        drop(s);
        let mut s = Store::open(&p).unwrap();
        assert_eq!(s.budget(now_ms()).unwrap().unknown, 1);
        s.delete_history().unwrap();
        assert_eq!(s.budget(now_ms()).unwrap().reserved, 1000);
        assert!(s.reserve(&a, 1000, now_ms()).is_err());
    }
    #[test]
    fn budget_reservation_is_conservative() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        let a = Analysis {
            id: id(),
            role: "resolver".into(),
            run_id: "r".into(),
            provider: "openai".into(),
            model: "m".into(),
            status: "running".into(),
            text: "".into(),
            created_at: now_ms(),
            cost_status: "reserved".into(),
        };
        assert!(s.reserve(&a, 250001, now_ms()).is_err());
        let at = s.reserve(&a, 1000, now_ms()).unwrap();
        s.settle(&at, Some(100)).unwrap();
        s.settle(&at, Some(900)).unwrap();
        assert_eq!(s.budget(now_ms()).unwrap().used_today, 100);
    }
}
#[cfg(test)]
mod review1_tests {
    use super::*;
    fn analysis() -> Analysis {
        Analysis {
            id: id(),
            role: "resolver".into(),
            run_id: "r".into(),
            provider: "openai".into(),
            model: "m".into(),
            status: "running".into(),
            text: String::new(),
            created_at: now_ms(),
            cost_status: "reserved".into(),
        }
    }
    #[test]
    fn unresolved_evidence_survives_101_runs() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        for i in 0..101 {
            let mut c = Check::new(
                &format!("check-{i}"),
                "fixture",
                "fixture",
                "attention",
                "fixture detail",
                "fixture",
            );
            c.digest = Some(format!("hash{i}"));
            s.save_run(&Run {
                id: id(),
                trigger: "manual".into(),
                status: "completed".into(),
                started_at: i,
                finished_at: Some(i),
                checks: vec![c],
            })
            .unwrap();
        }
        assert_eq!(s.runs().unwrap().len(), 100);
        assert_eq!(s.findings().unwrap().len(), 101);
        assert_eq!(
            s.findings()
                .unwrap()
                .iter()
                .find(|f| f.check_id == "check-0")
                .unwrap()
                .evidence
                .as_ref()
                .unwrap()
                .digest
                .as_deref(),
            Some("hash0")
        );
    }
    #[test]
    fn settle_failure_rolls_back_content_and_cost() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        let mut a = analysis();
        let at = s.reserve(&a, 1000, now_ms()).unwrap();
        s.db.execute_batch("CREATE TRIGGER fail_settle BEFORE UPDATE ON attempts BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        a.status = "succeeded".into();
        a.cost_status = "settled".into();
        assert!(s.finish_analysis(&a, &at, Some(100)).is_err());
        assert_eq!(s.analyses().unwrap()[0].status, "running");
        assert_eq!(s.budget(now_ms()).unwrap().reserved, 1000);
    }
    #[test]
    fn missing_db_and_clock_rollback_block_cloud() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        let mut s = Store::open(&p).unwrap();
        let a = analysis();
        s.reserve(&a, 1000, now_ms()).unwrap();
        assert!(s.check_anchor(now_ms() - 10_000).is_err());
        drop(s);
        std::fs::remove_file(&p).unwrap();
        let s = Store::open(&p).unwrap();
        assert!(s.ledger_blocked);
    }
}

#[cfg(test)]
mod opus_review_tests {
    use super::*;
    /// T-01: a failed history delete must not leave an open transaction that wedges every later write.
    #[test]
    fn failed_history_delete_rolls_back_and_later_writes_work() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("db")).unwrap();
        let r = Run {
            id: id(),
            trigger: "fixture".into(),
            status: "completed".into(),
            started_at: now_ms(),
            finished_at: Some(now_ms()),
            checks: vec![],
        };
        s.save_run(&r).unwrap();
        s.db.execute_batch("CREATE TRIGGER fail_delete BEFORE DELETE ON analyses BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        s.save_analysis(&Analysis {
            id: id(),
            role: "patrol".into(),
            run_id: r.id.clone(),
            provider: "fixture".into(),
            model: "fixture".into(),
            status: "succeeded".into(),
            text: String::new(),
            created_at: now_ms(),
            cost_status: "settled".into(),
        })
        .unwrap();
        assert!(s.delete_history().is_err());
        assert!(s.db.is_autocommit(), "transaction must not stay open");
        assert_eq!(s.runs().unwrap().len(), 1, "partial delete must roll back");
        let mut r2 = r.clone();
        r2.id = id();
        s.save_run(&r2).unwrap();
    }
}

#[cfg(all(test, unix))]
mod hardening_storage_tests {
    use super::*;
    #[test]
    fn old_fixed_temp_symlink_is_ignored_and_anchor_remains_private() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        let sentinel = d.path().join("sentinel");
        std::fs::write(&sentinel, b"preserve").unwrap();
        std::os::unix::fs::symlink(&sentinel, p.with_extension("budget-anchor.tmp")).unwrap();
        let mut s = Store::open(&p).unwrap();
        let a = Analysis {
            id: id(),
            role: "patrol".into(),
            run_id: "r".into(),
            provider: "fixture".into(),
            model: "fixture".into(),
            status: "running".into(),
            text: String::new(),
            created_at: now_ms(),
            cost_status: "reserved".into(),
        };
        s.reserve(&a, 1000, now_ms()).unwrap();
        s.check_anchor(now_ms()).unwrap();
        assert_eq!(std::fs::read(sentinel).unwrap(), b"preserve");
        assert!(!d.path().read_dir().unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".shugo-anchor-")));
    }
    #[test]
    fn huge_or_linked_anchor_blocks_reservation_without_erasing_receipts() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        let mut s = Store::open(&p).unwrap();
        let a = Analysis {
            id: id(),
            role: "patrol".into(),
            run_id: "r".into(),
            provider: "fixture".into(),
            model: "fixture".into(),
            status: "running".into(),
            text: String::new(),
            created_at: now_ms(),
            cost_status: "reserved".into(),
        };
        s.reserve(&a, 1000, now_ms()).unwrap();
        let anchor = p.with_extension("budget-anchor.json");
        std::fs::write(&anchor, vec![b' '; 4097]).unwrap();
        assert!(s.check_anchor(now_ms()).is_err());
        assert!(s.reserve(&a, 1000, now_ms()).is_err());
        assert_eq!(s.budget(now_ms()).unwrap().reserved, 1000);
        drop(s);
        let s = Store::open(&p).unwrap();
        assert!(s.ledger_blocked);
        assert_eq!(s.budget(now_ms()).unwrap().reserved, 1000);
        drop(s);
        std::fs::remove_file(&anchor).unwrap();
        let target = d.path().join("target");
        std::fs::write(&target, b"preserve").unwrap();
        std::os::unix::fs::symlink(&target, &anchor).unwrap();
        let s = Store::open(&p).unwrap();
        assert!(s.ledger_blocked);
        assert_eq!(std::fs::read(target).unwrap(), b"preserve");
    }
}

#[cfg(all(test, unix))]
mod hardening_round2_tests {
    use super::*;
    use crate::storage_fs::{write_private_atomic_checked, AtomicStage};
    fn analysis() -> Analysis {
        Analysis {
            id: id(),
            role: "patrol".into(),
            run_id: "r".into(),
            provider: "fixture".into(),
            model: "fixture".into(),
            status: "running".into(),
            text: String::new(),
            created_at: now_ms(),
            cost_status: "reserved".into(),
        }
    }
    #[test]
    fn atomic_save_failure_never_authorizes_dispatch_and_keeps_costs() {
        for phase in [
            AtomicStage::Write,
            AtomicStage::Sync,
            AtomicStage::Rename,
            AtomicStage::DirectorySync,
        ] {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("db");
            let mut s = Store::open(&path).unwrap();
            let old = std::fs::read(&s.anchor).unwrap();
            let a = analysis();
            let mut dispatches = 0;
            let result = s.reserve_checked(&a, 1000, now_ms(), |s| {
                let bytes = serde_json::to_vec(&s.anchor_value()?).map_err(err)?;
                write_private_atomic_checked(&s.anchor, &bytes, |stage| {
                    if stage == phase {
                        Err("fixture fault".into())
                    } else {
                        Ok(())
                    }
                })
            });
            if result.is_ok() {
                dispatches += 1;
            }
            assert_eq!(dispatches, 0, "phase {phase:?}");
            assert!(s.ledger_blocked);
            assert_eq!(s.budget(now_ms()).unwrap().reserved, 1000);
            if phase != AtomicStage::DirectorySync {
                assert_eq!(std::fs::read(&s.anchor).unwrap(), old);
            }
            assert!(!d.path().read_dir().unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".shugo-anchor-")));
            drop(s);
            let s = Store::open(&path).unwrap();
            assert_eq!(s.budget(now_ms()).unwrap().reserved, 1000);
            assert_eq!(s.budget(now_ms()).unwrap().unknown, 1);
            if phase != AtomicStage::DirectorySync {
                assert!(s.ledger_blocked);
            } else {
                assert!(!s.ledger_blocked);
            }
            // Even a matching post-rename anchor cannot erase the unknown committed attempt.
            assert_eq!(
                s.db.query_row("SELECT count(*) FROM attempts", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                1
            );
        }
    }
    #[test]
    fn legacy_0644_database_anchor_and_real_wal_reopen_preserve_data() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let mut s = Store::open(&path).unwrap();
        s.db.execute_batch("PRAGMA wal_autocheckpoint=0;").unwrap();
        let settings = Settings {
            revision: 42,
            ..Settings::default()
        };
        s.save_settings(&settings).unwrap();
        s.accept_baseline("fixture-check", "fixture-digest")
            .unwrap();
        let mut c = Check::new(
            "fixture-check",
            "fixture",
            "fixture",
            "attention",
            "preserved evidence",
            "fixture",
        );
        c.digest = Some("changed".into());
        let run = Run {
            id: "r".into(),
            trigger: "manual".into(),
            status: "completed".into(),
            started_at: now_ms(),
            finished_at: Some(now_ms()),
            checks: vec![c],
        };
        s.save_run(&run).unwrap();
        let a = analysis();
        s.reserve(&a, 1000, now_ms()).unwrap();
        let plan = ResponsePlan::new(
            "r".into(),
            a.id.clone(),
            crate::response::ResponseAction::PauseCloud,
            "preserved plan".into(),
            vec!["fixture-check".into()],
            2,
            now_ms(),
        );
        s.add_response_plan(&plan).unwrap();
        let wal = d.path().join("db-wal");
        assert!(std::fs::metadata(&wal).unwrap().len() > 32);
        for p in [&path, &s.anchor, &wal, &d.path().join("db-shm")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // Keep original connection live: SQLite cannot remove/checkpoint WAL on final close.
        let reopened = Store::open(&path).unwrap();
        assert!(!reopened.ledger_blocked);
        let plans = reopened.response_plans().unwrap();
        assert_eq!(plans[0].id, plan.id);
        assert_eq!(plans[0].reason, "preserved plan");
        assert_eq!(plans[0].status, "expired"); // Restart invalidates authorization, not evidence.
        assert_eq!(
            reopened
                .db
                .query_row(
                    "SELECT count(*) FROM response_events WHERE plan_id=?1",
                    [&plan.id],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(reopened.settings().unwrap().revision, 42);
        assert_eq!(
            reopened.baseline("fixture-check").unwrap().as_deref(),
            Some("fixture-digest")
        );
        assert_eq!(
            reopened.findings().unwrap()[0]
                .evidence
                .as_ref()
                .unwrap()
                .digest
                .as_deref(),
            Some("changed")
        );
        assert_eq!(reopened.runs().unwrap()[0].id, "r");
        assert_eq!(reopened.budget(now_ms()).unwrap().reserved, 1000);
        assert_eq!(reopened.budget(now_ms()).unwrap().unknown, 1);
        assert_eq!(
            reopened
                .db
                .query_row("PRAGMA user_version", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            2
        );
        for p in [&path, &reopened.anchor, &wal, &d.path().join("db-shm")] {
            assert_eq!(
                std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
