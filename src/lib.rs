//! Offline, scanner-independent `scan-gate.v1` Cedar engine.
//!
//! Consumers supply a complete normalized summary and every policy bundle they
//! intend to enforce. A digest identifies bytes, not completeness or provenance.

use cedar_policy::{
    ActionConstraint, Authorizer, Context, Decision, Effect, Entities, EntityUid, Policy, PolicyId,
    PolicySet, PrincipalConstraint, Request as CedarRequest, ResourceConstraint, Schema,
    ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

pub mod migration;

pub const PROTOCOL_VERSION: u32 = 1;
pub const SCHEMA_VERSION: u32 = 1;
pub const PROFILE: &str = "scan-gate.v1";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_BUNDLES: usize = 16;
pub const MAX_POLICIES: usize = 256;
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_POLICY_TOTAL_BYTES: usize = 1024 * 1024;
pub const MAX_SAFE_COUNT: i64 = 9_007_199_254_740_991;
pub const SEVERITIES: [&str; 6] = ["critical", "high", "medium", "low", "info", "unknown"];
pub const CATEGORIES: [&str; 6] = [
    "secrets",
    "sast",
    "iac",
    "cve",
    "dependency_scanning",
    "other",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: u32,
    pub schema_version: u32,
    pub profile: String,
    pub snapshot: Snapshot,
    pub bundles: Vec<Bundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub kind: String,
    pub complete: bool,
    pub suppression_basis: String,
    pub finding_count: i64,
    pub severity: BTreeMap<String, i64>,
    pub category: BTreeMap<String, i64>,
    pub by_category: BTreeMap<String, BTreeMap<String, i64>>,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub id: String,
    pub policies: Vec<PolicySource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySource {
    pub id: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Passed,
    Failed,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultRecord {
    pub protocol_version: u32,
    pub profile: &'static str,
    pub schema_version: u32,
    pub engine_version: &'static str,
    pub status: Status,
    pub determining_policy_ids: Vec<String>,
    pub warning_policy_ids: Vec<String>,
    pub diagnostic_codes: Vec<&'static str>,
    pub snapshot_digest: Option<String>,
    pub bundle_digest: Option<String>,
}

impl ResultRecord {
    fn new(status: Status) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            profile: PROFILE,
            schema_version: SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION"),
            status,
            determining_policy_ids: Vec::new(),
            warning_policy_ids: Vec::new(),
            diagnostic_codes: Vec::new(),
            snapshot_digest: None,
            bundle_digest: None,
        }
    }

    pub fn error(code: &'static str) -> Self {
        let mut record = Self::new(Status::Error);
        record.diagnostic_codes.push(code);
        record
    }

    pub fn exit_code(&self) -> i32 {
        match self.status {
            Status::Passed => 0,
            Status::Failed => 1,
            Status::Error => 2,
        }
    }
}

/// SHA-256 over RFC 8785 canonical JSON of the snapshot without its digest.
pub fn canonical_snapshot_digest(snapshot: &Snapshot) -> Option<String> {
    let mut value = serde_json::to_value(snapshot).ok()?;
    value.as_object_mut()?.remove("digest")?;
    digest_value(&value)
}

fn digest_value(value: &Value) -> Option<String> {
    let bytes = serde_jcs::to_vec(value).ok()?;
    Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

/// Strictly parse and evaluate one protocol request; never returns a green result
/// for malformed or oversized input.
pub fn evaluate_bytes(input: &[u8]) -> ResultRecord {
    if input.len() > MAX_INPUT_BYTES {
        return ResultRecord::error("RESOURCE_LIMIT");
    }
    let value: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => return ResultRecord::error("INVALID_REQUEST"),
    };
    if value
        .as_object()
        .is_some_and(|object| !object.contains_key("bundles"))
    {
        return ResultRecord::error("MISSING_BUNDLE");
    }
    let request: Request = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(_) => return ResultRecord::error("INVALID_REQUEST"),
    };
    evaluate(&request)
}

/// Evaluate an already decoded request. Callers must still treat both `Failed`
/// and `Error` as non-green and verify the reported digest provenance themselves.
pub fn evaluate(request: &Request) -> ResultRecord {
    if request.protocol_version != PROTOCOL_VERSION
        || request.schema_version != SCHEMA_VERSION
        || request.profile != PROFILE
    {
        return ResultRecord::error("INVALID_REQUEST");
    }
    let calculated_snapshot_digest = match validate_snapshot(&request.snapshot) {
        Ok(digest) => digest,
        Err(code) => return ResultRecord::error(code),
    };
    let mut result = ResultRecord::new(Status::Error);
    result.snapshot_digest = Some(calculated_snapshot_digest);
    if request.bundles.len() > MAX_BUNDLES {
        result.diagnostic_codes.push("RESOURCE_LIMIT");
        return result;
    }
    let mut sorted_bundles = request.bundles.clone();
    sorted_bundles.sort_by(|a, b| a.id.cmp(&b.id));
    let mut seen_bundles = BTreeSet::new();
    let mut policy_count = 0usize;
    let mut policy_bytes = 0usize;
    for bundle in &mut sorted_bundles {
        if !valid_id(&bundle.id) || !seen_bundles.insert(bundle.id.clone()) {
            result.diagnostic_codes.push("INVALID_REQUEST");
            return result;
        }
        bundle.policies.sort_by(|a, b| a.id.cmp(&b.id));
        let mut seen_policies = BTreeSet::new();
        for policy in &bundle.policies {
            if !valid_id(&policy.id) || !seen_policies.insert(policy.id.clone()) {
                result.diagnostic_codes.push("INVALID_REQUEST");
                return result;
            }
            policy_count += 1;
            policy_bytes = policy_bytes.saturating_add(policy.source.len());
            if policy_count > MAX_POLICIES
                || policy.source.len() > MAX_POLICY_BYTES
                || policy_bytes > MAX_POLICY_TOTAL_BYTES
            {
                result.diagnostic_codes.push("RESOURCE_LIMIT");
                return result;
            }
        }
    }
    result.bundle_digest =
        digest_value(&serde_json::to_value(&sorted_bundles).unwrap_or(Value::Null));
    let schema = match build_schema() {
        Some(schema) => schema,
        None => {
            result.diagnostic_codes.push("INTERNAL_ERROR");
            return result;
        }
    };
    let principal = match EntityUid::from_str("Scanner::\"local\"") {
        Ok(uid) => uid,
        Err(_) => return internal_error(result),
    };
    let resource = match EntityUid::from_str("Scan::\"current\"") {
        Ok(uid) => uid,
        Err(_) => return internal_error(result),
    };
    let pass_action = match EntityUid::from_str("Action::\"passScan\"") {
        Ok(uid) => uid,
        Err(_) => return internal_error(result),
    };
    let warn_action = match EntityUid::from_str("Action::\"warnScan\"") {
        Ok(uid) => uid,
        Err(_) => return internal_error(result),
    };
    let mut policies = PolicySet::new();
    let base_id = PolicyId::new("_engine_base_pass");
    let base = match Policy::parse(
        Some(base_id.clone()),
        "permit(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\");",
    ) {
        Ok(policy) => policy,
        Err(_) => return internal_error(result),
    };
    if policies.add(base).is_err() {
        return internal_error(result);
    }
    for bundle in &sorted_bundles {
        for source in &bundle.policies {
            let policy_id = PolicyId::new(format!("{}/{}", bundle.id, source.id));
            let policy = match Policy::parse(Some(policy_id), &source.source) {
                Ok(policy) => policy,
                Err(_) => {
                    result.diagnostic_codes.push("INVALID_POLICY");
                    return result;
                }
            };
            let action_shape = match policy.effect() {
                Effect::Forbid => ActionConstraint::Eq(pass_action.clone()),
                Effect::Permit => ActionConstraint::Eq(warn_action.clone()),
            };
            if !policy.is_static()
                || policy.action_constraint() != action_shape
                || policy.principal_constraint() != PrincipalConstraint::Eq(principal.clone())
                || policy.resource_constraint() != ResourceConstraint::Eq(resource.clone())
            {
                result.diagnostic_codes.push("INVALID_POLICY_SHAPE");
                return result;
            }
            if policies.add(policy).is_err() {
                result.diagnostic_codes.push("INVALID_POLICY");
                return result;
            }
        }
    }
    let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    if !validation.validation_passed() {
        result.diagnostic_codes.push("INVALID_POLICY");
        return result;
    }
    let context = json!({
        "finding_count": request.snapshot.finding_count,
        "severity": request.snapshot.severity,
        "category": request.snapshot.category,
        "by_category": request.snapshot.by_category,
    });
    let pass_context =
        match Context::from_json_value(context.clone(), Some((&schema, &pass_action))) {
            Ok(context) => context,
            Err(_) => return internal_error(result),
        };
    let warn_context = match Context::from_json_value(context, Some((&schema, &warn_action))) {
        Ok(context) => context,
        Err(_) => return internal_error(result),
    };
    let pass_request = match CedarRequest::new(
        principal.clone(),
        pass_action,
        resource.clone(),
        pass_context,
        Some(&schema),
    ) {
        Ok(request) => request,
        Err(_) => return internal_error(result),
    };
    let warn_request = match CedarRequest::new(
        principal,
        warn_action,
        resource,
        warn_context,
        Some(&schema),
    ) {
        Ok(request) => request,
        Err(_) => return internal_error(result),
    };
    let authorizer = Authorizer::new();
    let entities = Entities::empty();
    let pass = authorizer.is_authorized(&pass_request, &policies, &entities);
    let warn = authorizer.is_authorized(&warn_request, &policies, &entities);
    if pass.diagnostics().errors().next().is_some() || warn.diagnostics().errors().next().is_some()
    {
        result.diagnostic_codes.push("CEDAR_EVALUATION_ERROR");
        return result;
    }
    let mut pass_reasons: Vec<String> = pass
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    pass_reasons.sort();
    let mut warnings: Vec<String> = warn
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    warnings.sort();
    warnings.dedup();
    if warn.decision() == Decision::Allow && warnings.is_empty() {
        result.diagnostic_codes.push("INTERNAL_ERROR");
        return result;
    }
    result.warning_policy_ids = warnings;
    match pass.decision() {
        Decision::Allow => {
            if !pass_reasons.contains(&base_id.to_string()) {
                result.warning_policy_ids.clear();
                result.diagnostic_codes.push("IMPLICIT_DENY");
                return result;
            }
            result.status = Status::Passed;
        }
        Decision::Deny => {
            if pass_reasons.is_empty() || pass_reasons.iter().any(|id| id == &base_id.to_string()) {
                result.warning_policy_ids.clear();
                result.diagnostic_codes.push("IMPLICIT_DENY");
                return result;
            }
            result.determining_policy_ids = pass_reasons;
            result.status = Status::Failed;
        }
    }
    result
}

fn internal_error(mut result: ResultRecord) -> ResultRecord {
    result.diagnostic_codes.push("INTERNAL_ERROR");
    result
}

fn valid_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<String, &'static str> {
    if snapshot.kind != "full" || !snapshot.complete || snapshot.suppression_basis != "post-ignore"
    {
        return Err("INCOMPLETE_SNAPSHOT");
    }
    if !(0..=MAX_SAFE_COUNT).contains(&snapshot.finding_count)
        || snapshot.severity.len() != SEVERITIES.len()
        || snapshot.category.len() != CATEGORIES.len()
        || snapshot.by_category.len() != CATEGORIES.len()
    {
        return Err("INVALID_REQUEST");
    }
    let mut severity_sums = BTreeMap::new();
    let mut category_sum = 0i64;
    for severity in SEVERITIES {
        let total = *snapshot.severity.get(severity).ok_or("INVALID_REQUEST")?;
        if !(0..=MAX_SAFE_COUNT).contains(&total) {
            return Err("INVALID_REQUEST");
        }
        severity_sums.insert(severity, 0i64);
    }
    for category in CATEGORIES {
        let total = *snapshot.category.get(category).ok_or("INVALID_REQUEST")?;
        let row = snapshot
            .by_category
            .get(category)
            .ok_or("INVALID_REQUEST")?;
        if !(0..=MAX_SAFE_COUNT).contains(&total) || row.len() != SEVERITIES.len() {
            return Err("INVALID_REQUEST");
        }
        let mut row_sum = 0i64;
        for severity in SEVERITIES {
            let cell = *row.get(severity).ok_or("INVALID_REQUEST")?;
            if !(0..=MAX_SAFE_COUNT).contains(&cell) {
                return Err("INVALID_REQUEST");
            }
            row_sum = row_sum.checked_add(cell).ok_or("INVALID_REQUEST")?;
            let column = severity_sums.get_mut(severity).ok_or("INVALID_REQUEST")?;
            *column = column.checked_add(cell).ok_or("INVALID_REQUEST")?;
        }
        if row_sum != total {
            return Err("INVALID_REQUEST");
        }
        category_sum = category_sum.checked_add(total).ok_or("INVALID_REQUEST")?;
    }
    if category_sum != snapshot.finding_count
        || SEVERITIES
            .iter()
            .any(|severity| severity_sums[severity] != snapshot.severity[*severity])
    {
        return Err("INVALID_REQUEST");
    }
    let digest = canonical_snapshot_digest(snapshot).ok_or("INVALID_REQUEST")?;
    if digest != snapshot.digest {
        return Err("DIGEST_MISMATCH");
    }
    Ok(digest)
}

fn build_schema() -> Option<Schema> {
    let count_attributes: serde_json::Map<String, Value> = SEVERITIES
        .iter()
        .map(|severity| (severity.to_string(), json!({"type": "Long"})))
        .collect();
    let category_attributes: serde_json::Map<String, Value> = CATEGORIES
        .iter()
        .map(|category| (category.to_string(), json!({"type": "Long"})))
        .collect();
    let by_category_attributes: serde_json::Map<String, Value> = CATEGORIES
        .iter()
        .map(|category| {
            (
                category.to_string(),
                json!({"type": "Record", "attributes": count_attributes}),
            )
        })
        .collect();
    let context = json!({
        "type": "Record",
        "attributes": {
            "finding_count": {"type": "Long"},
            "severity": {"type": "Record", "attributes": count_attributes},
            "category": {"type": "Record", "attributes": category_attributes},
            "by_category": {"type": "Record", "attributes": by_category_attributes}
        }
    });
    let action = |context: Value| {
        json!({
            "appliesTo": {"principalTypes": ["Scanner"], "resourceTypes": ["Scan"], "context": context}
        })
    };
    let schema_json = json!({"": {
        "entityTypes": {"Scanner": {}, "Scan": {}},
        "actions": {"passScan": action(context.clone()), "warnScan": action(context)}
    }});
    Schema::from_json_value(schema_json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(policies: Vec<PolicySource>) -> Request {
        let mut snapshot = Snapshot {
            kind: "full".into(),
            complete: true,
            suppression_basis: "post-ignore".into(),
            finding_count: 0,
            severity: SEVERITIES.iter().map(|key| (key.to_string(), 0)).collect(),
            category: CATEGORIES.iter().map(|key| (key.to_string(), 0)).collect(),
            by_category: CATEGORIES
                .iter()
                .map(|category| {
                    (
                        category.to_string(),
                        SEVERITIES
                            .iter()
                            .map(|severity| (severity.to_string(), 0))
                            .collect(),
                    )
                })
                .collect(),
            digest: String::new(),
        };
        snapshot.digest = canonical_snapshot_digest(&snapshot).unwrap();
        Request {
            protocol_version: 1,
            schema_version: 1,
            profile: PROFILE.into(),
            snapshot,
            bundles: vec![Bundle {
                id: "repository".into(),
                policies,
            }],
        }
    }

    fn policy(id: &str, source: &str) -> PolicySource {
        PolicySource {
            id: id.into(),
            source: source.into(),
        }
    }

    #[test]
    fn empty_snapshot_passes() {
        let result = evaluate(&request_with(vec![]));
        assert_eq!(
            result.status,
            Status::Passed,
            "{:?}",
            result.diagnostic_codes
        );
        assert_eq!(result.exit_code(), 0);
    }

    #[test]
    fn matching_forbid_fails() {
        let mut request = request_with(vec![policy("block", "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when { context.severity.critical > 0 };")]);
        request.snapshot.severity.insert("critical".into(), 1);
        request.snapshot.category.insert("secrets".into(), 1);
        request
            .snapshot
            .by_category
            .get_mut("secrets")
            .unwrap()
            .insert("critical".into(), 1);
        request.snapshot.finding_count = 1;
        request.snapshot.digest = canonical_snapshot_digest(&request.snapshot).unwrap();
        let result = evaluate(&request);
        assert_eq!(
            result.status,
            Status::Failed,
            "{:?}",
            result.diagnostic_codes
        );
        assert_eq!(result.determining_policy_ids, ["repository/block"]);
        assert_eq!(result.exit_code(), 1);
    }

    #[test]
    fn warning_does_not_fail() {
        let result = evaluate(&request_with(vec![policy("notice", "permit(principal == Scanner::\"local\", action == Action::\"warnScan\", resource == Scan::\"current\");")]));
        assert_eq!(
            result.status,
            Status::Passed,
            "{:?}",
            result.diagnostic_codes
        );
        assert_eq!(result.warning_policy_ids, ["repository/notice"]);
    }

    #[test]
    fn consumer_pass_permit_is_rejected() {
        let result = evaluate(&request_with(vec![policy("override", "permit(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\");")]));
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INVALID_POLICY_SHAPE"]);
    }

    #[test]
    fn mismatched_digest_is_rejected() {
        let mut request = request_with(vec![]);
        request.snapshot.digest = "sha256:bad".into();
        let result = evaluate(&request);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["DIGEST_MISMATCH"]);
    }

    #[test]
    fn incomplete_snapshot_is_rejected() {
        let mut request = request_with(vec![]);
        request.snapshot.complete = false;
        let result = evaluate(&request);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INCOMPLETE_SNAPSHOT"]);
    }

    #[test]
    fn cedar_evaluation_error_cannot_pass() {
        let mut request = request_with(vec![policy("overflow", "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when { context.severity.critical + 9223372036854775807 > 0 };")]);
        request.snapshot.severity.insert("critical".into(), 1);
        request.snapshot.category.insert("secrets".into(), 1);
        request
            .snapshot
            .by_category
            .get_mut("secrets")
            .unwrap()
            .insert("critical".into(), 1);
        request.snapshot.finding_count = 1;
        request.snapshot.digest = canonical_snapshot_digest(&request.snapshot).unwrap();
        let result = evaluate(&request);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["CEDAR_EVALUATION_ERROR"]);
        assert_eq!(result.exit_code(), 2);
    }

    #[test]
    fn malformed_policy_cannot_pass() {
        let result = evaluate(&request_with(vec![policy("broken", "not cedar")]));
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INVALID_POLICY"]);
    }

    #[test]
    fn unknown_request_field_cannot_pass() {
        let request = request_with(vec![]);
        let mut value = serde_json::to_value(request).unwrap();
        value["raw_findings"] = json!([{"secret": "must never enter engine"}]);
        let result = evaluate_bytes(&serde_json::to_vec(&value).unwrap());
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INVALID_REQUEST"]);
    }

    #[test]
    fn missing_or_unknown_schema_version_cannot_pass() {
        let mut value = serde_json::to_value(request_with(vec![])).unwrap();
        value.as_object_mut().unwrap().remove("schema_version");
        let missing = evaluate_bytes(&serde_json::to_vec(&value).unwrap());
        assert_eq!(missing.status, Status::Error);
        assert_eq!(missing.diagnostic_codes, ["INVALID_REQUEST"]);

        let mut request = request_with(vec![]);
        request.schema_version = 2;
        let unknown = evaluate(&request);
        assert_eq!(unknown.status, Status::Error);
        assert_eq!(unknown.diagnostic_codes, ["INVALID_REQUEST"]);
    }

    #[test]
    fn versioned_clean_example_passes() {
        let request: Request = serde_json::from_slice(include_bytes!("../examples/clean.json"))
            .expect("versioned example parses");
        let result = evaluate(&request);
        assert_eq!(
            result.status,
            Status::Passed,
            "{:?}",
            result.diagnostic_codes
        );
        let bytes_result = evaluate_bytes(include_bytes!("../examples/clean.json"));
        assert_eq!(
            bytes_result.status,
            Status::Passed,
            "{:?}",
            bytes_result.diagnostic_codes
        );
    }

    #[test]
    fn inconsistent_intersection_cannot_pass() {
        let mut request = request_with(vec![]);
        request
            .snapshot
            .by_category
            .get_mut("secrets")
            .unwrap()
            .insert("critical".into(), 1);
        request.snapshot.digest = canonical_snapshot_digest(&request.snapshot).unwrap();
        let result = evaluate(&request);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INVALID_REQUEST"]);
    }

    #[test]
    fn missing_bundle_is_error() {
        let mut value = serde_json::to_value(request_with(vec![])).unwrap();
        value.as_object_mut().unwrap().remove("bundles");
        let result = evaluate_bytes(&serde_json::to_vec(&value).unwrap());
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.exit_code(), 2);
        assert_eq!(result.diagnostic_codes, ["MISSING_BUNDLE"]);
    }

    #[test]
    fn warning_evaluation_error_cannot_be_silent() {
        let mut request = request_with(vec![policy(
            "overflow_warning",
            "permit(principal == Scanner::\"local\", action == Action::\"warnScan\", resource == Scan::\"current\") when { context.severity.critical + 9223372036854775807 > 0 };",
        )]);
        request.snapshot.severity.insert("critical".into(), 1);
        request.snapshot.category.insert("secrets".into(), 1);
        request
            .snapshot
            .by_category
            .get_mut("secrets")
            .unwrap()
            .insert("critical".into(), 1);
        request.snapshot.finding_count = 1;
        request.snapshot.digest = canonical_snapshot_digest(&request.snapshot).unwrap();
        let result = evaluate(&request);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["CEDAR_EVALUATION_ERROR"]);
        assert!(result.warning_policy_ids.is_empty());
    }

    #[test]
    fn schema_rejects_unknown_policy_attribute() {
        let result = evaluate(&request_with(vec![policy(
            "bad_attribute",
            "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when { context.severity.not_a_level > 0 };",
        )]));
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INVALID_POLICY"]);
    }

    #[test]
    fn bundle_and_policy_order_do_not_change_result_bytes() {
        let mut request = request_with(vec![policy(
            "later",
            "permit(principal == Scanner::\"local\", action == Action::\"warnScan\", resource == Scan::\"current\");",
        )]);
        request.bundles.push(Bundle {
            id: "another".into(),
            policies: vec![policy(
                "earlier",
                "permit(principal == Scanner::\"local\", action == Action::\"warnScan\", resource == Scan::\"current\");",
            )],
        });
        let first = serde_json::to_vec(&evaluate(&request)).unwrap();
        request.bundles.reverse();
        let second = serde_json::to_vec(&evaluate(&request)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn oversized_input_is_structured_error() {
        let result = evaluate_bytes(&vec![b' '; MAX_INPUT_BYTES + 1]);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["RESOURCE_LIMIT"]);
        assert_eq!(result.exit_code(), 2);
    }

    #[test]
    fn cedar_without_base_permit_is_implicit_deny() {
        let schema = build_schema().unwrap();
        let principal = EntityUid::from_str("Scanner::\"local\"").unwrap();
        let action = EntityUid::from_str("Action::\"passScan\"").unwrap();
        let resource = EntityUid::from_str("Scan::\"current\"").unwrap();
        let context = json!({
            "finding_count": 0,
            "severity": request_with(vec![]).snapshot.severity,
            "category": request_with(vec![]).snapshot.category,
            "by_category": request_with(vec![]).snapshot.by_category,
        });
        let context = Context::from_json_value(context, Some((&schema, &action))).unwrap();
        let request =
            CedarRequest::new(principal, action, resource, context, Some(&schema)).unwrap();
        let response =
            Authorizer::new().is_authorized(&request, &PolicySet::new(), &Entities::empty());
        assert_eq!(response.decision(), Decision::Deny);
        assert_eq!(response.diagnostics().reason().count(), 0);
    }
}
