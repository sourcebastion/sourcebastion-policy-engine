use serde_json::{json, Value};
use sourcebastion_policy_engine::{
    canonical_snapshot_digest, gate_settings::GateSettings, v2, Snapshot, CATEGORIES, SEVERITIES,
};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn request(critical_secrets: i64, policies: Value) -> Value {
    let mut severity = serde_json::Map::new();
    let mut category = serde_json::Map::new();
    let mut by_category = serde_json::Map::new();
    for name in SEVERITIES {
        severity.insert(
            name.into(),
            json!(if name == "critical" {
                critical_secrets
            } else {
                0
            }),
        );
    }
    for name in CATEGORIES {
        category.insert(
            name.into(),
            json!(if name == "secrets" {
                critical_secrets
            } else {
                0
            }),
        );
        let mut row = serde_json::Map::new();
        for level in SEVERITIES {
            row.insert(
                level.into(),
                json!(if name == "secrets" && level == "critical" {
                    critical_secrets
                } else {
                    0
                }),
            );
        }
        by_category.insert(name.into(), Value::Object(row));
    }
    let mut snapshot: Snapshot = serde_json::from_value(json!({
        "kind": "full", "complete": true, "suppression_basis": "post-ignore",
        "finding_count": critical_secrets, "severity": severity,
        "category": category, "by_category": by_category, "digest": ""
    }))
    .unwrap();
    snapshot.digest = canonical_snapshot_digest(&snapshot).unwrap();
    json!({"protocol_version": 1, "schema_version": 1, "profile": "scan-gate.v1", "snapshot": snapshot,
        "bundles": [{"id": "repository", "policies": policies}]})
}

fn invoke(args: &[&str], input: &Value) -> Output {
    let executable = env!("CARGO_BIN_EXE_sourcebastion-policy");
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn supervised_cli_pass_fail_error_and_warning() {
    let clean = invoke(&[], &request(0, json!([])));
    assert_eq!(clean.status.code(), Some(0));
    let clean_json: Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(clean_json["status"], "passed");

    let policies = json!([
        {"id": "block", "source": "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when { context.by_category.secrets.critical > 0 };"},
        {"id": "warn", "source": "permit(principal == Scanner::\"local\", action == Action::\"warnScan\", resource == Scan::\"current\") when { context.severity.critical > 0 };"}
    ]);
    let blocked = invoke(&["evaluate"], &request(1, policies));
    assert_eq!(blocked.status.code(), Some(1));
    let blocked_json: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked_json["status"], "failed");
    assert_eq!(
        blocked_json["determining_policy_ids"],
        json!(["repository/block"])
    );
    assert_eq!(
        blocked_json["warning_policy_ids"],
        json!(["repository/warn"])
    );

    let mut incomplete = request(0, json!([]));
    incomplete["snapshot"]["kind"] = json!("delta");
    let error = invoke(&[], &incomplete);
    assert_eq!(error.status.code(), Some(2));
    let error_json: Value = serde_json::from_slice(&error.stdout).unwrap();
    assert_eq!(error_json["status"], "error");
    assert_eq!(
        error_json["diagnostic_codes"],
        json!(["INCOMPLETE_SNAPSHOT"])
    );

    let mut unversioned = request(0, json!([]));
    unversioned
        .as_object_mut()
        .unwrap()
        .remove("schema_version");
    let error = invoke(&["evaluate"], &unversioned);
    assert_eq!(error.status.code(), Some(2));
    let error_json: Value = serde_json::from_slice(&error.stdout).unwrap();
    assert_eq!(error_json["status"], "error");
    assert_eq!(error_json["diagnostic_codes"], json!(["INVALID_REQUEST"]));
}

#[test]
fn converter_emits_evaluable_bundle() {
    let converted = invoke(
        &["convert-plan09"],
        &json!([
            {"severity": "critical", "category": "secrets", "max_count": 0},
            {"category": "secrets", "max_count": 0, "action": "warn"},
            {"action": "ignore"}
        ]),
    );
    assert_eq!(converted.status.code(), Some(0));
    let conversion: Value = serde_json::from_slice(&converted.stdout).unwrap();
    assert_eq!(conversion["skipped_rule_ids"], json!(["plan09_rule_0003"]));
    let mut scan_request = request(1, json!([]));
    scan_request["bundles"] = json!([conversion["bundle"]]);
    let evaluated = invoke(&[], &scan_request);
    assert_eq!(evaluated.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&evaluated.stdout).unwrap();
    assert_eq!(
        result["determining_policy_ids"],
        json!(["plan09/plan09_rule_0001"])
    );
    assert_eq!(
        result["warning_policy_ids"],
        json!(["plan09/plan09_rule_0002"])
    );
}

#[test]
fn compiled_category_gate_blocks_v2_cli_request() {
    let settings = serde_json::to_value(GateSettings::default_high()).unwrap();
    let compiled = invoke(&["compile-gate"], &settings);
    assert_eq!(compiled.status.code(), Some(0));
    let bundle: Value = serde_json::from_slice(&compiled.stdout).unwrap();
    assert_eq!(
        bundle["bundles"][0]["policies"].as_array().unwrap().len(),
        14
    );

    let mut by_category = serde_json::Map::new();
    for category in v2::CATEGORIES {
        let mut cohorts = serde_json::Map::new();
        for cohort in v2::COHORTS {
            let mut levels = serde_json::Map::new();
            for severity in SEVERITIES {
                let count =
                    i64::from(category == "secrets" && cohort == "new" && severity == "high");
                levels.insert(severity.into(), json!(count));
            }
            cohorts.insert(cohort.into(), Value::Object(levels));
        }
        by_category.insert(category.into(), Value::Object(cohorts));
    }
    let mut snapshot: v2::Snapshot = serde_json::from_value(json!({
        "kind": "full", "complete": true, "suppression_basis": "post-ignore",
        "baseline": {"kind": "target_ref", "digest": format!("sha256:{}", "a".repeat(64))},
        "finding_count": 1, "by_category": by_category, "digest": ""
    }))
    .unwrap();
    snapshot.digest = v2::canonical_snapshot_digest(&snapshot).unwrap();
    let request = json!({
        "protocol_version": 1, "schema_version": 2, "profile": "scan-gate.v2",
        "snapshot": snapshot, "bundles": bundle["bundles"],
    });
    let evaluated = invoke(&["evaluate"], &request);
    assert_eq!(evaluated.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&evaluated.stdout).unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(result["profile"], "scan-gate.v2");
    assert_eq!(
        result["determining_policy_ids"],
        json!(["project/secrets_new"])
    );

    let invalid = invoke(&["compile-gate"], &json!({"version": 1}));
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&invalid.stdout).unwrap()["error_code"],
        "INVALID_GATE_SETTINGS"
    );
}

#[test]
fn nearly_full_request_does_not_hang_on_worker_input() {
    let mut request = request(0, json!([]));
    request["raw_findings"] = json!("x".repeat(900_000));
    let output = invoke(&[], &request);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "error");
    assert_eq!(result["diagnostic_codes"], json!(["INVALID_REQUEST"]));
}

#[test]
fn maximum_matching_policies_do_not_hang_on_worker_output() {
    let source = "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\");";
    let policies: Vec<Value> = (0..256)
        .map(|index| {
            json!({
                "id": format!("rule_{index:04}_{}", "x".repeat(54)),
                "source": source,
            })
        })
        .collect();
    let output = invoke(&["evaluate"], &request(0, json!(policies)));
    assert_eq!(output.status.code(), Some(1), "{:?}", output);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(
        result["determining_policy_ids"].as_array().unwrap().len(),
        256
    );
}
