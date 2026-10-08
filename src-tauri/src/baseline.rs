use crate::types::{evidence_fresh, Check, Run};

/// Bind approval to precisely the observation displayed by the caller.
pub struct BaselineSelection<'a> {
    pub run_id: &'a str,
    pub check_id: &'a str,
    pub digest: &'a str,
    pub observed_at: u64,
}
pub fn selected_check(
    run: &Run,
    selected: &BaselineSelection<'_>,
    now: u64,
) -> Result<Check, String> {
    if run.id != selected.run_id || !["completed", "partial"].contains(&run.status.as_str()) {
        return Err(
            "選択した観測は最新の完了検査ではありません。詳細を開き直してください。".into(),
        );
    }
    let check = run
        .checks
        .iter()
        .find(|c| c.id == selected.check_id)
        .ok_or("選択した観測がありません。詳細を開き直してください。")?;
    if selected.digest.is_empty()
        || check.digest.as_deref() != Some(selected.digest)
        || check.observed_at != selected.observed_at
        || !evidence_fresh(check.observed_at, now)
        || !["ok", "attention", "unverified"].contains(&check.status.as_str())
    {
        return Err(
            "選択した観測が古いか変更されています。再巡回して詳細を開き直してください。".into(),
        );
    }
    Ok(check.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(id: &str, digest: &str, observed: u64) -> Run {
        let mut c = Check::new(
            "file-1",
            "fixture",
            "指定ファイル",
            "unverified",
            "fixture",
            "fixture",
        );
        c.digest = Some(digest.into());
        c.observed_at = observed;
        Run {
            id: id.into(),
            trigger: "manual".into(),
            status: "completed".into(),
            started_at: observed,
            finished_at: Some(observed),
            checks: vec![c],
        }
    }
    #[test]
    fn exact_displayed_observation_is_required_before_and_after_confirmation() {
        let selected = BaselineSelection {
            run_id: "a",
            check_id: "file-1",
            digest: "A",
            observed_at: 1000,
        };
        selected_check(&run("a", "A", 1000), &selected, 1100).unwrap();
        // A is on screen; the latest run/observation becomes B before approval.
        assert!(selected_check(&run("b", "B", 1100), &selected, 1200).is_err());
        // Even if a run ID is retained, changed contents or time cannot replace A.
        assert!(selected_check(&run("a", "B", 1000), &selected, 1200).is_err());
        assert!(selected_check(&run("a", "A", 1100), &selected, 1200).is_err());
    }
    #[test]
    fn stale_future_missing_and_incomplete_observations_are_rejected() {
        let selected = BaselineSelection {
            run_id: "a",
            check_id: "file-1",
            digest: "A",
            observed_at: 1000,
        };
        assert!(selected_check(&run("a", "A", 1000), &selected, 301001).is_err());
        assert!(selected_check(&run("a", "A", 1000), &selected, 999).is_err());
        for status in ["running", "cancelled"] {
            let mut r = run("a", "A", 1000);
            r.status = status.into();
            assert!(selected_check(&r, &selected, 1100).is_err());
        }
        let mut r = run("a", "A", 1000);
        r.checks[0].digest = None;
        assert!(selected_check(&r, &selected, 1100).is_err());
        r.checks.clear();
        assert!(selected_check(&r, &selected, 1100).is_err());
    }
}
