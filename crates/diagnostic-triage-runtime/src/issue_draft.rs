//! Typed, deterministic bug issue-draft projection.

use diagnostic_triage_contracts::{
    AdapterId, Fingerprint, Language, ObjectId, Sha256Digest,
    model::{
        AdapterKind, DecisionAction, EvidenceSource, ExecutionStatus, Finding, Location, Position,
        Severity, Taxonomy, Tool, Verdict, WaivedAction,
    },
};

use crate::{
    issue_draft_sanitize::{
        SanitizeError, SanitizedText, sanitize_external_text, sanitize_repository_path_text,
    },
    reporters::{MAX_REPORT_OUTPUT_BYTES, ValidatedSessionReport},
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

macro_rules! draft_type {
    ($visibility:vis $name:ident { $($field:ident: $kind:ty),+ $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        $visibility struct $name { $( $field: $kind, )+ }
    };
}
macro_rules! record {
    ($name:ident { $($field:ident = $value:expr),+ $(,)? }) => {
        $name { $( $field: $value, )+ }
    };
}

draft_type!(pub(crate) BugIssueDraftV1 { session_id: ObjectId, contract_sha256: Sha256Digest, policy_digest: Sha256Digest, verdict: Verdict, findings: Vec<BugFindingV1>, decisions: Vec<BugDecisionV1>, evidence: Vec<BugEvidenceRefV1>, executions: Vec<BugExecutionV1> });
draft_type!(BugToolV1 { name: SanitizedText, version: SanitizedText, rule_id: Option<SanitizedText> });
draft_type!(BugLocationV1 { path: SanitizedText, start: Position, end: Option<Position> });
draft_type!(BugFindingV1 { finding_id: ObjectId, fingerprint: Fingerprint, observation_ids: Vec<ObjectId>, tool: BugToolV1, language: Language, severity: Severity, taxonomy: Taxonomy, message: SanitizedText, location: Option<BugLocationV1>, symbol: Option<SanitizedText>, expected: Option<SanitizedText>, observed: Option<SanitizedText>, evidence_ids: Vec<ObjectId> });
#[rustfmt::skip]
draft_type!(BugWaiverV1 { fingerprint: Fingerprint, waived_action: WaivedAction, reason: SanitizedText, owner: SanitizedText, expires_at: SanitizedText });
#[rustfmt::skip]
draft_type!(BugDecisionV1 { decision_id: ObjectId, finding_id: ObjectId, action: DecisionAction, evaluated_at: SanitizedText, matched_rule_id: SanitizedText, waiver: Option<BugWaiverV1> });
draft_type!(BugEvidenceRefV1 { evidence_id: ObjectId, execution_id: Option<ObjectId>, source: EvidenceSource, sha256: Sha256Digest, relative_path: Option<SanitizedText> });
draft_type!(BugExecutionV1 { execution_id: ObjectId, adapter_id: AdapterId, adapter_kind: AdapterKind, tool: BugToolV1, required: bool, status: ExecutionStatus, exit_code: Option<u8>, message: Option<SanitizedText> });

impl BugIssueDraftV1 {
    pub(crate) fn project(report: &ValidatedSessionReport) -> Result<Self, SanitizeError> {
        // Sources: schemas/v1/session-report.schema.json and https://doc.rust-lang.org/std/primitive.slice.html#method.sort_by.
        let report = report.as_report();
        let mut findings = report
            .findings
            .iter()
            .map(project_finding)
            .collect::<Result<Vec<_>, _>>()?;
        let mut decisions = report
            .decisions
            .iter()
            .map(|value| Ok(record!(BugDecisionV1 { decision_id = value.decision_id.clone(), finding_id = value.finding_id.clone(), action = value.action.clone(), evaluated_at = text(&value.evaluated_at)?, matched_rule_id = text(&value.matched_rule_id)?, waiver = value.waiver.as_ref().map(|waiver| Ok(record!(BugWaiverV1 { fingerprint = waiver.fingerprint.clone(), waived_action = waiver.waived_action.clone(), reason = text(&waiver.reason)?, owner = text(&waiver.owner)?, expires_at = text(&waiver.expires_at)? }))).transpose()? })))
            .collect::<Result<Vec<_>, SanitizeError>>()?;
        let mut evidence = report
            .evidence
            .iter()
            .map(|value| Ok(record!(BugEvidenceRefV1 { evidence_id = value.evidence_id.clone(), execution_id = value.execution_id.clone(), source = value.source.clone(), sha256 = value.sha256.clone(), relative_path = value.relative_path.as_ref().map(|path| sanitize_repository_path_text(path, MAX_REPORT_OUTPUT_BYTES)).transpose()? })))
            .collect::<Result<Vec<_>, SanitizeError>>()?;
        let mut executions = report
            .executions
            .iter()
            .map(|value| Ok(record!(BugExecutionV1 { execution_id = value.execution_id.clone(), adapter_id = value.adapter_id.clone(), adapter_kind = value.adapter_kind.clone(), tool = project_tool(&value.tool)?, required = value.required, status = value.status.clone(), exit_code = value.exit_code.0, message = optional_text(value.message.as_deref())? })))
            .collect::<Result<Vec<_>, SanitizeError>>()?;
        findings.sort_by(|a, b| {
            a.fingerprint
                .cmp(&b.fingerprint)
                .then(a.finding_id.cmp(&b.finding_id))
        });
        decisions.sort_by(|a, b| {
            a.finding_id
                .cmp(&b.finding_id)
                .then(a.decision_id.cmp(&b.decision_id))
        });
        evidence.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
        executions.sort_by(|a, b| a.execution_id.cmp(&b.execution_id));
        Ok(
            record!(BugIssueDraftV1 { session_id = report.session_id.clone(), contract_sha256 = report.contract_sha256.clone(), policy_digest = report.policy_digest.clone(), verdict = report.verdict.clone(), findings = findings, decisions = decisions, evidence = evidence, executions = executions }),
        )
    }
}

fn project_finding(value: &Finding) -> Result<BugFindingV1, SanitizeError> {
    Ok(
        record!(BugFindingV1 { finding_id = value.finding_id.clone(), fingerprint = value.fingerprint.clone(), observation_ids = sorted_ids(&value.observation_ids), tool = project_tool(&value.tool)?, language = value.language.clone(), severity = value.severity.clone(), taxonomy = value.classification.clone(), message = text(&value.message)?, location = value.location.as_ref().map(project_location).transpose()?, symbol = optional_text(value.symbol.as_deref())?, expected = optional_text(value.expected.as_deref())?, observed = optional_text(value.observed.as_deref())?, evidence_ids = sorted_ids(&value.evidence_ids) }),
    )
}

fn project_location(value: &Location) -> Result<BugLocationV1, SanitizeError> {
    Ok(
        record!(BugLocationV1 { path = sanitize_repository_path_text(&value.path, MAX_REPORT_OUTPUT_BYTES)?, start = value.start.clone(), end = value.end.clone() }),
    )
}

fn project_tool(value: &Tool) -> Result<BugToolV1, SanitizeError> {
    Ok(
        record!(BugToolV1 { name = text(&value.name)?, version = text(&value.version)?, rule_id = optional_text(value.rule_id.as_deref())? }),
    )
}

fn text(value: &str) -> Result<SanitizedText, SanitizeError> {
    sanitize_external_text(value, MAX_REPORT_OUTPUT_BYTES)
}

fn optional_text(value: Option<&str>) -> Result<Option<SanitizedText>, SanitizeError> {
    value.map(text).transpose()
}

fn sorted_ids(value: &[ObjectId]) -> Vec<ObjectId> {
    let mut value = value.to_vec();
    value.sort();
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostic_triage_contracts::model::{DecisionAction, ExecutionStatus, SessionReport};

    const VALID: &[u8] = include_bytes!("../../../tests/fixtures/v1/valid-report.json");
    const UNSUPPORTED: &[u8] =
        include_bytes!("../../../tests/fixtures/v1/valid-unsupported-report.json");
    const VERIFIED: &[u8] = include_bytes!("../../../tests/fixtures/v1/valid-verified-report.json");
    fn report(bytes: &[u8]) -> SessionReport {
        ValidatedSessionReport::from_json(bytes)
            .unwrap()
            .into_report()
    }
    fn project(report: SessionReport) -> BugIssueDraftV1 {
        BugIssueDraftV1::project(&ValidatedSessionReport::new(report).unwrap()).unwrap()
    }

    #[test]
    fn projects_all_verdicts_and_omits_unlisted_material() {
        let mut pass = report(VALID);
        pass.decisions[0].action = DecisionAction::Waive;
        pass.decisions[0].waiver = Some(diagnostic_triage_contracts::model::Waiver {
            fingerprint: pass.findings[0].fingerprint.clone(),
            waived_action: WaivedAction::Block,
            reason: "token=hidden".into(),
            owner: "maintainers".into(),
            expires_at: "2026-08-20T00:00:00Z".into(),
        });
        pass.verdict = Verdict::Pass;
        let mut incomplete = report(UNSUPPORTED);
        incomplete.executions[0].status = ExecutionStatus::Incomplete;
        incomplete.verdict = Verdict::Incomplete;
        assert_eq!(project(report(VALID)).verdict, Verdict::PolicyFail);
        assert_eq!(project(incomplete).verdict, Verdict::Incomplete);
        assert_eq!(project(report(UNSUPPORTED)).verdict, Verdict::Unsupported);
        pass.observations[0].location = None;
        pass.findings[0].location = None;
        pass.observations[0].expected = Some("token=hidden".into());
        pass.findings[0].expected = pass.observations[0].expected.clone();
        pass.observations[0].observed = Some("observed".into());
        pass.findings[0].observed = pass.observations[0].observed.clone();
        let session_id = pass.session_id.clone();
        let evidence_sha256 = pass.evidence[0].sha256.clone();
        let draft = project(pass);
        let debug = format!("{draft:?}");
        assert_eq!(draft.session_id, session_id);
        assert_eq!(draft.verdict, Verdict::Pass);
        assert!(draft.findings[0].location.is_none());
        let finding = &draft.findings[0];
        let expected = finding.expected.as_ref().unwrap().as_str();
        assert_eq!(expected, "token=[REDACTED_SECRET]");
        assert_eq!(finding.observed.as_ref().unwrap().as_str(), "observed");
        assert_eq!(finding.tool.rule_id.as_ref().unwrap().as_str(), "F821");
        assert_eq!(draft.evidence[0].sha256, evidence_sha256);
        let waiver = draft.decisions[0].waiver.as_ref().unwrap();
        assert_eq!(waiver.reason.as_str(), "token=[REDACTED_SECRET]");
        assert_eq!(draft.executions[0].status, ExecutionStatus::Complete);
        assert!(debug.contains("Type") && debug.contains("UnresolvedSymbol"));
        assert!(!debug.contains("content") && !debug.contains("runner"));
        let verified = format!("{:?}", project(report(VERIFIED)));
        assert!(!verified.contains("--- a/") && !verified.contains("tree_sha256"));
    }

    #[test]
    fn multiple_findings_are_permutation_stable() {
        let mut report = report(VALID);
        let mut finding = report.findings[0].clone();
        finding.finding_id = "019f7e95-0000-7000-8000-000000000120".parse().unwrap();
        finding.fingerprint = format!("dtfp1:{}", "a".repeat(64)).parse().unwrap();
        let mut decision = report.decisions[0].clone();
        decision.decision_id = "019f7e95-0000-7000-8000-000000000121".parse().unwrap();
        decision.finding_id = finding.finding_id.clone();
        report.findings.push(finding);
        report.decisions.push(decision);
        let expected = project(report.clone());
        report.findings.reverse();
        report.decisions.reverse();
        assert_eq!(project(report), expected);
    }
}
