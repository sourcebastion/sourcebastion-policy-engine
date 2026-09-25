//! Complete category/cohort scan gate. Consumers own finding and baseline provenance.

use crate::{
    digest_value, evaluate_bundles, Bundle, ResultRecord, Status, MAX_SAFE_COUNT, PROTOCOL_VERSION,
    SEVERITIES,
};
use cedar_policy::Schema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const PROFILE: &str = "scan-gate.v2";
pub const SCHEMA_VERSION: u32 = 2;
pub const CATEGORIES: [&str; 7] = [
    "secrets",
    "sast",
    "iac",
    "cve",
    "dependency_scanning",
    "container_images",
    "other",
];
pub const COHORTS: [&str; 2] = ["new", "existing"];

type Counts = BTreeMap<String, BTreeMap<String, BTreeMap<String, i64>>>;

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
    pub baseline: Baseline,
    pub finding_count: i64,
    pub by_category: Counts,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub kind: String,
    pub digest: Option<String>,
}

pub fn canonical_snapshot_digest(snapshot: &Snapshot) -> Option<String> {
    let mut value = serde_json::to_value(snapshot).ok()?;
    value.as_object_mut()?.remove("digest")?;
    digest_value(&value)
}

pub(crate) fn evaluate_value(value: Value) -> ResultRecord {
    if value
        .as_object()
        .is_some_and(|object| !object.contains_key("bundles"))
    {
        return error("MISSING_BUNDLE");
    }
    let request: Request = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(_) => return error("INVALID_REQUEST"),
    };
    evaluate(&request)
}

pub fn evaluate(request: &Request) -> ResultRecord {
    if request.protocol_version != PROTOCOL_VERSION
        || request.schema_version != SCHEMA_VERSION
        || request.profile != PROFILE
    {
        return error("INVALID_REQUEST");
    }
    if request.bundles.is_empty() {
        return error("MISSING_BUNDLE");
    }
    let digest = match validate_snapshot(&request.snapshot) {
        Ok(digest) => digest,
        Err(code) => return error(code),
    };
    let schema = match build_schema() {
        Some(schema) => schema,
        None => return error("INTERNAL_ERROR"),
    };
    let context = json!({
        "finding_count": request.snapshot.finding_count,
        "by_category": request.snapshot.by_category,
    });
    let mut result = ResultRecord::new_for(Status::Error, PROFILE, SCHEMA_VERSION);
    result.snapshot_digest = Some(digest);
    evaluate_bundles(&request.bundles, result, schema, context)
}

fn error(code: &'static str) -> ResultRecord {
    ResultRecord::error_for(code, PROFILE, SCHEMA_VERSION)
}

fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<String, &'static str> {
    if snapshot.kind != "full" || !snapshot.complete || snapshot.suppression_basis != "post-ignore"
    {
        return Err("INCOMPLETE_SNAPSHOT");
    }
    if !(0..=MAX_SAFE_COUNT).contains(&snapshot.finding_count)
        || snapshot.by_category.len() != CATEGORIES.len()
    {
        return Err("INVALID_REQUEST");
    }
    match snapshot.baseline.kind.as_str() {
        "none" if snapshot.baseline.digest.is_none() => {}
        "target_ref" | "prior_ref"
            if snapshot
                .baseline
                .digest
                .as_deref()
                .is_some_and(valid_digest) => {}
        _ => return Err("INVALID_REQUEST"),
    }
    let mut total = 0i64;
    for category in CATEGORIES {
        let cohorts = snapshot
            .by_category
            .get(category)
            .ok_or("INVALID_REQUEST")?;
        if cohorts.len() != COHORTS.len() {
            return Err("INVALID_REQUEST");
        }
        for cohort in COHORTS {
            let severities = cohorts.get(cohort).ok_or("INVALID_REQUEST")?;
            if severities.len() != SEVERITIES.len() {
                return Err("INVALID_REQUEST");
            }
            for severity in SEVERITIES {
                let count = *severities.get(severity).ok_or("INVALID_REQUEST")?;
                if !(0..=MAX_SAFE_COUNT).contains(&count)
                    || (snapshot.baseline.kind == "none" && cohort == "existing" && count != 0)
                {
                    return Err("INVALID_REQUEST");
                }
                total = total.checked_add(count).ok_or("INVALID_REQUEST")?;
            }
        }
    }
    if total != snapshot.finding_count {
        return Err("INVALID_REQUEST");
    }
    let digest = canonical_snapshot_digest(snapshot).ok_or("INVALID_REQUEST")?;
    if digest != snapshot.digest {
        return Err("DIGEST_MISMATCH");
    }
    Ok(digest)
}

fn build_schema() -> Option<Schema> {
    let severity_attrs: serde_json::Map<String, Value> = SEVERITIES
        .iter()
        .map(|severity| (severity.to_string(), json!({"type": "Long"})))
        .collect();
    let cohort_attrs: serde_json::Map<String, Value> = COHORTS
        .iter()
        .map(|cohort| {
            (
                cohort.to_string(),
                json!({"type": "Record", "attributes": severity_attrs}),
            )
        })
        .collect();
    let category_attrs: serde_json::Map<String, Value> = CATEGORIES
        .iter()
        .map(|category| {
            (
                category.to_string(),
                json!({"type": "Record", "attributes": cohort_attrs}),
            )
        })
        .collect();
    let context = json!({
        "type": "Record",
        "attributes": {
            "finding_count": {"type": "Long"},
            "by_category": {"type": "Record", "attributes": category_attrs},
        }
    });
    let action = |context: Value| {
        json!({
            "appliesTo": {"principalTypes": ["Scanner"], "resourceTypes": ["Scan"], "context": context}
        })
    };
    Schema::from_json_value(json!({"": {
        "entityTypes": {"Scanner": {}, "Scan": {}},
        "actions": {"passScan": action(context.clone()), "warnScan": action(context)}
    }}))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evaluate_bytes, PolicySource};

    fn request_with(policies: Vec<PolicySource>) -> Request {
        let mut snapshot = Snapshot {
            kind: "full".into(),
            complete: true,
            suppression_basis: "post-ignore".into(),
            baseline: Baseline {
                kind: "none".into(),
                digest: None,
            },
            finding_count: 0,
            by_category: CATEGORIES
                .iter()
                .map(|category| {
                    (
                        category.to_string(),
                        COHORTS
                            .iter()
                            .map(|cohort| {
                                (
                                    cohort.to_string(),
                                    SEVERITIES
                                        .iter()
                                        .map(|severity| (severity.to_string(), 0))
                                        .collect(),
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
            digest: String::new(),
        };
        snapshot.digest = canonical_snapshot_digest(&snapshot).unwrap();
        Request {
            protocol_version: PROTOCOL_VERSION,
            schema_version: SCHEMA_VERSION,
            profile: PROFILE.into(),
            snapshot,
            bundles: vec![Bundle {
                id: "project".into(),
                policies,
            }],
        }
    }

    fn forbid(category: &str, cohort: &str, severity: &str) -> PolicySource {
        PolicySource {
            id: format!("{category}_{cohort}_{severity}"),
            source: format!(
                "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when {{ context.by_category.{category}.{cohort}.{severity} > 0 }};"
            ),
        }
    }

    fn add_finding(request: &mut Request, category: &str, cohort: &str, severity: &str) {
        *request
            .snapshot
            .by_category
            .get_mut(category)
            .unwrap()
            .get_mut(cohort)
            .unwrap()
            .get_mut(severity)
            .unwrap() += 1;
        request.snapshot.finding_count += 1;
        request.snapshot.digest = canonical_snapshot_digest(&request.snapshot).unwrap();
    }

    #[test]
    fn clean_v2_request_passes_via_bytes_and_preserves_version() {
        let request = request_with(vec![forbid("secrets", "new", "critical")]);
        let result = evaluate_bytes(&serde_json::to_vec(&request).unwrap());
        assert_eq!(
            result.status,
            Status::Passed,
            "{:?}",
            result.diagnostic_codes
        );
        assert_eq!(result.profile, PROFILE);
        assert_eq!(result.schema_version, SCHEMA_VERSION);
        assert_eq!(result.exit_code(), 0);
    }

    #[test]
    fn new_and_existing_findings_fail_their_own_rules() {
        let mut request = request_with(vec![
            forbid("secrets", "new", "critical"),
            forbid("container_images", "existing", "high"),
        ]);
        add_finding(&mut request, "secrets", "new", "critical");
        let new_result = evaluate(&request);
        assert_eq!(
            new_result.status,
            Status::Failed,
            "{:?}",
            new_result.diagnostic_codes
        );
        assert_eq!(
            new_result.determining_policy_ids,
            ["project/secrets_new_critical"]
        );

        request.snapshot.baseline = Baseline {
            kind: "target_ref".into(),
            digest: Some(format!("sha256:{}", "a".repeat(64))),
        };
        add_finding(&mut request, "container_images", "existing", "high");
        let both = evaluate_bytes(&serde_json::to_vec(&request).unwrap());
        assert_eq!(both.status, Status::Failed, "{:?}", both.diagnostic_codes);
        assert_eq!(both.determining_policy_ids.len(), 2);
    }

    #[test]
    fn first_scan_cannot_claim_existing_findings() {
        let mut request = request_with(vec![]);
        add_finding(&mut request, "other", "existing", "low");
        let result = evaluate(&request);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["INVALID_REQUEST"]);
    }

    #[test]
    fn missing_category_and_bad_digest_are_errors() {
        let mut request = request_with(vec![]);
        request.snapshot.by_category.remove("other");
        assert_eq!(evaluate(&request).diagnostic_codes, ["INVALID_REQUEST"]);

        let mut request = request_with(vec![]);
        request.snapshot.digest = "sha256:bad".into();
        assert_eq!(evaluate(&request).diagnostic_codes, ["DIGEST_MISMATCH"]);
    }

    #[test]
    fn v2_rejects_unscoped_permits_and_incomplete_snapshots() {
        let mut request = request_with(vec![PolicySource {
            id: "bad".into(),
            source: "permit(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\");".into(),
        }]);
        assert_eq!(
            evaluate(&request).diagnostic_codes,
            ["INVALID_POLICY_SHAPE"]
        );

        request.bundles[0].policies.clear();
        request.snapshot.complete = false;
        assert_eq!(evaluate(&request).diagnostic_codes, ["INCOMPLETE_SNAPSHOT"]);
    }

    #[test]
    fn v2_missing_bundle_is_not_a_passing_policy() {
        let mut request = request_with(vec![]);
        assert_eq!(evaluate(&request).status, Status::Passed);
        request.bundles.clear();
        let result = evaluate_bytes(&serde_json::to_vec(&request).unwrap());
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.diagnostic_codes, ["MISSING_BUNDLE"]);
        assert_eq!(result.exit_code(), 2);
    }
}
