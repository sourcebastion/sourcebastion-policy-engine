use serde_json::{json, Value};
use sourcebastion_policy_engine::{canonical_snapshot_digest, Snapshot, CATEGORIES, SEVERITIES};
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
    json!({"protocol_version": 1, "profile": "scan-gate.v1", "snapshot": snapshot,
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
