//! Session-scoped authorization and typed plans. No OS commands live here.
use crate::types::id;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const GRANT_TTL: u64 = 3_600_000;
const PLAN_TTL: u64 = 300_000;
pub const MAX_EVIDENCE_IDS: usize = 100;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    PauseCloud,
    QuarantineFile,
    BlockConnection,
}
impl ResponseAction {
    pub fn available(self) -> bool {
        self == Self::PauseCloud
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PauseCloud => "pause_cloud",
            Self::QuarantineFile => "quarantine_file",
            Self::BlockConnection => "block_connection",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponsePolicy {
    pub revision: u64,
    pub mode: String,
    pub auto_escalate: bool,
    pub expires_at: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ResponseCapability {
    pub action: ResponseAction,
    pub available: bool,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponsePlan {
    pub id: String,
    pub run_id: String,
    pub analysis_id: String,
    pub action: ResponseAction,
    pub status: String,
    pub reason: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy_revision: u64,
    pub evidence_ids: Vec<String>,
}
impl ResponsePlan {
    pub fn new(
        run_id: String,
        analysis_id: String,
        action: ResponseAction,
        reason: String,
        evidence_ids: Vec<String>,
        policy_revision: u64,
        now: u64,
    ) -> Self {
        Self {
            id: id(),
            run_id,
            analysis_id,
            action,
            status: if action.available() {
                "proposed"
            } else {
                "unsupported"
            }
            .into(),
            reason,
            created_at: now,
            expires_at: now.saturating_add(PLAN_TTL),
            policy_revision,
            evidence_ids,
        }
    }
    pub fn validate_new(&self) -> Result<(), String> {
        let valid_id = |s: &str| !s.is_empty() && s.len() <= 160;
        if !valid_id(&self.id)
            || !valid_id(&self.run_id)
            || !valid_id(&self.analysis_id)
            || self.reason.len() > 4096
            || self.evidence_ids.is_empty()
            || self.evidence_ids.len() > MAX_EVIDENCE_IDS
            || self
                .evidence_ids
                .iter()
                .enumerate()
                .any(|(i, id)| self.evidence_ids[..i].contains(id))
            || self.evidence_ids.iter().any(|s| !valid_id(s))
            || self.expires_at <= self.created_at
            || self.expires_at.saturating_sub(self.created_at) > PLAN_TTL
            || self.status
                != if self.action.available() {
                    "proposed"
                } else {
                    "unsupported"
                }
        {
            return Err("対策計画の形式が不正です。".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponseSnapshot {
    pub policy: ResponsePolicy,
    pub capabilities: Vec<ResponseCapability>,
    pub plans: Vec<ResponsePlan>,
}

pub struct ResponseControl {
    policy: ResponsePolicy,
    granted_wall: Option<u64>,
    deadline: Option<Instant>,
}
impl Default for ResponseControl {
    fn default() -> Self {
        Self {
            policy: ResponsePolicy {
                revision: 1,
                mode: "confirm".into(),
                auto_escalate: false,
                expires_at: None,
            },
            granted_wall: None,
            deadline: None,
        }
    }
}
impl ResponseControl {
    /// Call only after the core has validated the native approval and its epoch.
    pub fn grant(
        &mut self,
        mode: &str,
        auto_escalate: bool,
        expected_revision: u64,
        now: u64,
        monotonic: Instant,
    ) -> Result<(), String> {
        if !["confirm", "automatic"].contains(&mode) || expected_revision != self.policy.revision {
            return Err("対策許可が変更されています。再確認してください。".into());
        }
        self.policy.revision += 1;
        self.policy.mode = mode.into();
        self.policy.auto_escalate = auto_escalate;
        self.policy.expires_at = Some(now.saturating_add(GRANT_TTL));
        self.granted_wall = Some(now);
        self.deadline = Some(monotonic + Duration::from_millis(GRANT_TTL));
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.policy.revision += 1;
        self.policy.mode = "confirm".into();
        self.policy.auto_escalate = false;
        self.policy.expires_at = None;
        self.granted_wall = None;
        self.deadline = None;
    }
    fn live(&self, now: u64, monotonic: Instant) -> bool {
        matches!((self.granted_wall,self.policy.expires_at,self.deadline), (Some(start),Some(end),Some(deadline)) if now >= start && now < end && monotonic < deadline)
    }
    pub fn policy(&mut self, now: u64, monotonic: Instant) -> ResponsePolicy {
        if self.deadline.is_some() && !self.live(now, monotonic) {
            self.invalidate();
        }
        self.policy.clone()
    }
    pub fn validate(
        &mut self,
        action: ResponseAction,
        policy_revision: u64,
        automatic: bool,
        now: u64,
        monotonic: Instant,
    ) -> Result<(), String> {
        self.policy(now, monotonic);
        if !action.available() {
            return Err("この対策は未対応です。PC設定は変更しません。".into());
        }
        if policy_revision != self.policy.revision
            || (automatic && (!self.live(now, monotonic) || self.policy.mode != "automatic"))
        {
            return Err("対策許可が無効・期限切れです。再確認してください。".into());
        }
        Ok(())
    }
    pub fn snapshot(
        &mut self,
        mut plans: Vec<ResponsePlan>,
        now: u64,
        monotonic: Instant,
    ) -> ResponseSnapshot {
        let policy = self.policy(now, monotonic);
        for plan in &mut plans {
            if plan.status == "proposed" {
                if now < plan.created_at || now >= plan.expires_at {
                    plan.status = "expired".into();
                } else if plan.policy_revision != policy.revision {
                    plan.status = "revoked".into();
                }
            }
        }
        ResponseSnapshot {
            policy,
            capabilities: vec![
                ResponseCapability {
                    action: ResponseAction::PauseCloud,
                    available: true,
                    reason: "守護AIの新規クラウド送信だけを停止。送信済み情報・料金は戻せません。"
                        .into(),
                },
                ResponseCapability {
                    action: ResponseAction::QuarantineFile,
                    available: false,
                    reason: "ファイル隔離adapter・対象証明・復元は未実装。計画のみ。".into(),
                },
                ResponseCapability {
                    action: ResponseAction::BlockConnection,
                    available: false,
                    reason: "OS通信隔離helper・認可・復元は未実装。計画のみ。".into(),
                },
            ],
            plans,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_expires_revokes_and_never_survives_restart() {
        let t = Instant::now();
        let mut c = ResponseControl::default();
        assert!(c
            .validate(ResponseAction::PauseCloud, 1, true, 1000, t)
            .is_err());
        c.grant("automatic", true, 1, 1000, t).unwrap();
        c.validate(ResponseAction::PauseCloud, 2, true, 1001, t)
            .unwrap();
        assert!(c
            .validate(ResponseAction::PauseCloud, 2, true, 1000 + GRANT_TTL, t)
            .is_err());
        assert!(c
            .validate(
                ResponseAction::PauseCloud,
                2,
                true,
                1001,
                t + Duration::from_millis(GRANT_TTL)
            )
            .is_err());
        assert!(c
            .validate(ResponseAction::PauseCloud, 2, true, 999, t)
            .is_err());
        assert!(c
            .validate(ResponseAction::QuarantineFile, 2, true, 1001, t)
            .is_err());
        c.invalidate();
        assert!(c
            .validate(ResponseAction::PauseCloud, 2, false, 1001, t)
            .is_err());
        assert!(ResponseControl::default()
            .validate(ResponseAction::PauseCloud, 2, false, 1001, t)
            .is_err());
    }
    #[test]
    fn invalid_grants_and_confirm_mode_cannot_authorize_automatic_action() {
        let t = Instant::now();
        let mut c = ResponseControl::default();
        // A current native approval in the core authorizes a manual action,
        // without requiring an additional session automatic grant.
        c.validate(ResponseAction::PauseCloud, 1, false, 1000, t)
            .unwrap();
        assert!(c.grant("shell", true, 1, 1000, t).is_err());
        assert!(c.grant("automatic", true, 9, 1000, t).is_err());
        c.grant("confirm", false, 1, 1000, t).unwrap();
        assert!(c
            .validate(ResponseAction::PauseCloud, 2, true, 1001, t)
            .is_err());
        c.validate(ResponseAction::PauseCloud, 2, false, 1001, t)
            .unwrap();
        let p = c.policy(1000 + GRANT_TTL, t);
        assert_eq!(p.revision, 3);
        assert!(p.expires_at.is_none());
        assert!(c.grant("automatic", true, 2, 1000, t).is_err());
    }
    #[test]
    fn each_clock_limit_independently_revokes_and_snapshot_projects_unexecutable_plans() {
        let t = Instant::now();
        for (wall, mono) in [
            (999, t),
            (1000 + GRANT_TTL, t),
            (1001, t + Duration::from_millis(GRANT_TTL)),
        ] {
            let mut c = ResponseControl::default();
            c.grant("automatic", true, 1, 1000, t).unwrap();
            assert!(c
                .validate(ResponseAction::PauseCloud, 2, true, wall, mono)
                .is_err());
            // Returning to the old wall time must not revive the grant.
            assert!(c
                .validate(ResponseAction::PauseCloud, 2, true, 1001, t)
                .is_err());
        }
        let mut c = ResponseControl::default();
        let p = ResponsePlan::new(
            "r".into(),
            "a".into(),
            ResponseAction::PauseCloud,
            "fixture".into(),
            vec!["e".into()],
            1,
            1000,
        );
        assert_eq!(
            c.snapshot(vec![p.clone()], 1000 + PLAN_TTL, t).plans[0].status,
            "expired"
        );
        c.invalidate();
        assert_eq!(c.snapshot(vec![p], 1001, t).plans[0].status, "revoked");
    }
}
