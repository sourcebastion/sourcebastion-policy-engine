//! Typed rule-set aggregate evaluation. Hosts authenticate policy resolution;
//! this offline profile cannot attest account, assignment or provider identity.
use crate::{
    rule_sets::{self, Document, Effect},
    v2, Bundle, PolicySource, ResultRecord, Status, SEVERITIES,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const PROFILE: &str = "scan-rule-sets.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: u32,
    pub schema_version: u32,
    pub profile: String,
    pub document: Document,
    pub snapshot: Option<v2::Snapshot>,
}

#[derive(Debug, Serialize)]
pub struct RuleResult {
    pub set_id: String,
    pub revision: u64,
    pub rule_id: String,
    pub name: String,
    pub effect: Effect,
    pub outcome: &'static str,
    pub observed_new: Option<i64>,
    pub observed_existing: Option<i64>,
    pub max_new: Option<i64>,
    pub max_existing: Option<i64>,
    pub diagnostic_codes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Result {
    pub protocol_version: u32,
    pub schema_version: u32,
    pub profile: &'static str,
    pub engine_version: &'static str,
    pub status: &'static str,
    pub diagnostic_codes: Vec<&'static str>,
    pub snapshot_digest: Option<String>,
    pub document_digest: Option<String>,
    pub rules: Vec<RuleResult>,
}

impl Result {
    pub fn error(code: &'static str) -> Self {
        Self {
            protocol_version: 1,
            schema_version: 2,
            profile: PROFILE,
            engine_version: env!("CARGO_PKG_VERSION"),
            status: "unevaluable",
            diagnostic_codes: vec![code],
            snapshot_digest: None,
            document_digest: None,
            rules: vec![],
        }
    }
    pub fn exit_code(&self) -> i32 {
        match self.status {
            "passed" | "passed_with_warnings" | "gating_disabled" => 0,
            "blocked" => 1,
            _ => 2,
        }
    }
}

pub fn evaluate_bytes(bytes: &[u8]) -> Result {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Result::error("RESOURCE_LIMIT");
    }
    // Direct typed parsing rejects duplicate document keys.
    match serde_json::from_slice::<Request>(bytes) {
        Ok(request) => evaluate(&request),
        Err(_) => Result::error("INVALID_REQUEST"),
    }
}

pub fn evaluate(request: &Request) -> Result {
    if request.protocol_version != 1 || request.schema_version != 2 || request.profile != PROFILE {
        return Result::error("INVALID_REQUEST");
    }
    let compiled = match rule_sets::compile(&request.document, &SEVERITIES) {
        Ok(rules) => rules,
        Err(rule_sets::Error::ResourceLimit) => return Result::error("RESOURCE_LIMIT"),
        Err(_) => return Result::error("INVALID_RULE_SETS"),
    };
    if request.document.sets.is_empty() || request.document.sets.iter().any(|s| s.rules.is_empty())
    {
        return Result::error("POLICY_NOT_CONFIGURED");
    }
    let mut canonical = request.document.clone();
    canonical.sets.sort_by(|a, b| a.set_id.cmp(&b.set_id));
    for set in &mut canonical.sets {
        set.rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        for rule in &mut set.rules {
            rule.condition.severities.sort();
        }
    }
    let mut result = Result::error("INTERNAL_ERROR");
    result.document_digest = crate::digest_value(&json!(canonical));
    result.diagnostic_codes.clear();
    for set in &canonical.sets {
        for rule in &set.rules {
            result.rules.push(RuleResult {
                set_id: set.set_id.clone(),
                revision: set.revision,
                rule_id: rule.rule_id.clone(),
                name: rule.name.clone(),
                effect: rule.effect,
                outcome: if set.enabled && rule.enabled {
                    "unevaluable"
                } else {
                    "disabled"
                },
                observed_new: None,
                observed_existing: None,
                max_new: rule.condition.max_new,
                max_existing: rule.condition.max_existing,
                diagnostic_codes: vec![],
            });
        }
    }
    if compiled.is_empty() {
        result.status = "gating_disabled";
        return result;
    }
    let snapshot = match request.snapshot.as_ref() {
        Some(snapshot) => snapshot,
        None => {
            result.diagnostic_codes.push("INCOMPLETE_SNAPSHOT");
            return result;
        }
    };
    match v2::validate_snapshot(snapshot) {
        Ok(digest) => result.snapshot_digest = Some(digest),
        Err(code) => {
            result.diagnostic_codes.push(code);
            return result;
        }
    }
    if snapshot.baseline.kind != "target_ref" && snapshot.baseline.kind != "prior_ref" {
        result.diagnostic_codes.push("MISSING_BASELINE");
        return result;
    }
    // Only compiler-owned finding_count expressions enter Cedar. Counts have
    // already been validated and their total fits MAX_SAFE_COUNT, so their
    // subset sums cannot overflow or access missing attributes. No arbitrary
    // user Cedar or future error-producing rule types are accepted here.
    let mut policies = vec![];
    for (index, rule) in compiled.iter().enumerate() {
        for source in &rule.policies {
            policies.push(PolicySource {
                id: format!("r{index}_{}", source.id),
                source: source.source.clone(),
            });
        }
    }
    let schema = match v2::build_schema() {
        Some(schema) => schema,
        None => return Result::error("INTERNAL_ERROR"),
    };
    let evaluated = crate::evaluate_bundles_with_limit(
        &[Bundle {
            id: "rules".into(),
            policies,
        }],
        ResultRecord::new_for(Status::Error, PROFILE, 2),
        schema,
        json!({"finding_count":snapshot.finding_count,"by_category":snapshot.by_category}),
        2000,
    );
    if evaluated.status == Status::Error {
        result.diagnostic_codes = evaluated.diagnostic_codes;
        return result;
    }
    let mut blocked = false;
    let mut warned = false;
    for (index, compiled_rule) in compiled.iter().enumerate() {
        let row = result
            .rules
            .iter_mut()
            .find(|r| r.set_id == compiled_rule.set_id && r.rule_id == compiled_rule.rule_id)
            .unwrap();
        let set = canonical
            .sets
            .iter()
            .find(|s| s.set_id == row.set_id)
            .unwrap();
        let condition = &set
            .rules
            .iter()
            .find(|r| r.rule_id == row.rule_id)
            .unwrap()
            .condition;
        let count = |cohort: &str| {
            condition
                .severities
                .iter()
                .map(|s| snapshot.by_category[&condition.category][cohort][s])
                .sum::<i64>()
        };
        row.observed_new = Some(count("new"));
        row.observed_existing = Some(count("existing"));
        let reasons = if row.effect == Effect::Block {
            &evaluated.determining_policy_ids
        } else {
            &evaluated.warning_policy_ids
        };
        let failed = ["new", "existing"]
            .iter()
            .any(|cohort| reasons.contains(&format!("rules/r{index}_{cohort}")));
        row.outcome = if failed { "failed" } else { "passed" };
        blocked |= failed && row.effect == Effect::Block;
        warned |= failed && row.effect == Effect::Warn;
    }
    result.status = if blocked {
        "blocked"
    } else if warned {
        "passed_with_warnings"
    } else {
        "passed"
    };
    result
}
