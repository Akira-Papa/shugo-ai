use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelChoice {
    pub provider: String,
    pub model: String,
    pub input_rate: u64,
    pub output_rate: u64,
}
impl ModelChoice {
    pub fn validate(&self) -> Result<(), String> {
        if !["none", "openai", "anthropic", "codex", "claude_code"]
            .contains(&self.provider.as_str())
            || self.model.len() > 100
            || !self
                .model
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c))
            || self.input_rate > 1_000_000_000
            || self.output_rate > 1_000_000_000
        {
            return Err("モデル設定の形式が不正です".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub revision: u64,
    pub mode: String,
    pub enabled: bool,
    pub paused: bool,
    pub patrol: ModelChoice,
    pub resolver: ModelChoice,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            revision: 1,
            mode: "hourly".into(),
            enabled: false,
            paused: false,
            patrol: ModelChoice {
                provider: "none".into(),
                model: "gpt-6-luna".into(),
                input_rate: 0,
                output_rate: 0,
            },
            resolver: ModelChoice {
                provider: "none".into(),
                model: "gpt-6.1-sol".into(),
                input_rate: 0,
                output_rate: 0,
            },
        }
    }
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub id: String,
    pub title: String,
    pub category: String,
    pub status: String,
    pub detail: String,
    pub source: String,
    pub observed_at: u64,
    pub digest: Option<String>,
}
impl Check {
    pub fn new(
        id: &str,
        title: &str,
        category: &str,
        status: &str,
        detail: &str,
        source: &str,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            category: category.into(),
            status: status.into(),
            detail: detail.into(),
            source: source.into(),
            observed_at: now_ms(),
            digest: None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: String,
    pub trigger: String,
    pub status: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub checks: Vec<Check>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub check_id: String,
    pub title: String,
    pub detail: String,
    pub status: String,
    pub first_seen: u64,
    pub last_seen: u64,
    #[serde(default)]
    pub evidence: Option<Check>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredFile {
    pub id: String,
    pub label: String,
    pub path: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub id: String,
    pub role: String,
    pub run_id: String,
    pub provider: String,
    pub model: String,
    pub status: String,
    pub text: String,
    pub created_at: u64,
    pub cost_status: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Budget {
    pub used_today: u64,
    pub reserved: u64,
    pub used_30_days: u64,
    pub patrol_calls: u64,
    pub resolver_calls: u64,
    pub unknown: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub version: String,
    pub os: String,
    pub core_epoch: String,
    pub settings: Settings,
    pub active: Option<Run>,
    pub runs: Vec<Run>,
    pub findings: Vec<Finding>,
    pub files: Vec<FileDisplay>,
    pub analyses: Vec<Analysis>,
    pub cloud_enabled: bool,
    pub credentials: BTreeMap<String, bool>,
    pub catalogs: BTreeMap<String, Vec<String>>,
    pub budget: Budget,
    pub next_due: Option<u64>,
    pub gap: Option<String>,
    pub watcher_status: String,
    pub analysis_cancel_requested: bool,
    pub catalog_in_flight: bool,
    pub ledger_blocked: bool,
    pub response: crate::response::ResponseSnapshot,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDisplay {
    pub id: String,
    pub label: String,
}
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    Applied,
    Cancelled,
}

/// An approval is bound to a recent observation, including at the final commit.
pub fn evidence_fresh(observed: u64, now: u64) -> bool {
    now >= observed && now - observed <= 300_000
}
#[cfg(test)]
mod approval_tests {
    use super::*;
    #[test]
    fn approval_dialog_does_not_extend_evidence_lifetime() {
        assert!(evidence_fresh(1_000, 2_000));
        assert!(!evidence_fresh(1_000, 301_001));
        assert!(!evidence_fresh(2_000, 1_000));
    }
}
