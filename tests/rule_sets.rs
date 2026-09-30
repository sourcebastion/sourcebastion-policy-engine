use serde_json::{json, Value};
use sourcebastion_policy_engine::{rule_sets, v2, Bundle, Status, SEVERITIES};

#[test]
fn shared_rule_set_cases_execute_in_cedar() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/rule-set-cases.json")).unwrap();
    for case in fixtures["cases"].as_array().unwrap() {
        let sets: Vec<Value> = case["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let mut condition = json!({"kind":"finding_count", "category":"sast",
                "severities": r.get("severities").cloned().unwrap_or(json!(["high"])),
                "max_new":r["max_new"]});
                if let Some(value) = r.get("max_existing") {
                    condition["max_existing"] = value.clone();
                }
                json!({"set_id":r["set_id"],"revision":1,"name":"Fixture set",
                "enabled":r.get("set_enabled").cloned().unwrap_or(json!(true)),
                "rules":[{"rule_id":r["rule_id"],"name":"Fixture rule",
                    "enabled":r.get("rule_enabled").cloned().unwrap_or(json!(true)),
                    "effect":r["effect"],"condition":condition}]})
            })
            .collect();
        let document = json!({"schema_version":2,"sets":sets});
        let compiled =
            rule_sets::compile_bytes(&serde_json::to_vec(&document).unwrap(), &SEVERITIES).unwrap();
        let mut counts = json!({});
        for category in v2::CATEGORIES {
            for cohort in v2::COHORTS {
                for severity in SEVERITIES {
                    counts[category][cohort][severity] = json!(0);
                }
            }
        }
        let new_high = case["new_high"].as_i64().unwrap();
        let new_unknown = case["new_unknown"].as_i64().unwrap_or(0);
        let new_critical = case["new_critical"].as_i64().unwrap_or(0);
        let existing_high = case["existing_high"].as_i64().unwrap_or(0);
        counts["sast"]["new"]["high"] = json!(new_high);
        counts["sast"]["new"]["unknown"] = json!(new_unknown);
        counts["sast"]["new"]["critical"] = json!(new_critical);
        counts["sast"]["existing"]["high"] = json!(existing_high);
        let mut snapshot: v2::Snapshot = serde_json::from_value(json!({
            "kind":"full","complete":true,"suppression_basis":"post-ignore",
            "baseline":{"kind":"target_ref","digest":format!("sha256:{}", "a".repeat(64))},
            "finding_count":new_high+new_critical+existing_high+new_unknown,"by_category":counts,"digest":""
        }))
        .unwrap();
        snapshot.digest = v2::canonical_snapshot_digest(&snapshot).unwrap();
        let aggregate_request = json!({
            "protocol_version":1,"schema_version":2,"profile":"scan-rule-sets.v1",
            "document":document,"snapshot":snapshot,
        });
        let aggregate = sourcebastion_policy_engine::rule_set_evaluation::evaluate_bytes(
            &serde_json::to_vec(&aggregate_request).unwrap(),
        );
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(env!("CARGO_BIN_EXE_sourcebastion-policy"))
            .arg("evaluate-rule-sets")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&aggregate_request).unwrap())
            .unwrap();
        let cli = child.wait_with_output().unwrap();
        assert_eq!(
            cli.status.code(),
            Some(aggregate.exit_code()),
            "{}",
            case["id"]
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&cli.stdout).unwrap(),
            serde_json::to_value(&aggregate).unwrap()
        );
        assert_eq!(
            json!(aggregate.status),
            case["expected"],
            "{}: {:?}",
            case["id"],
            aggregate
        );
        assert_eq!(
            aggregate.rules.len(),
            case["rules"].as_array().unwrap().len()
        );
        let mut invalid_snapshot = aggregate_request.clone();
        invalid_snapshot["snapshot"] = Value::Null;
        let invalid = sourcebastion_policy_engine::rule_set_evaluation::evaluate_bytes(
            &serde_json::to_vec(&invalid_snapshot).unwrap(),
        );
        assert_eq!(
            invalid.status,
            if compiled.is_empty() {
                "gating_disabled"
            } else {
                "unevaluable"
            }
        );
        if compiled.is_empty() {
            assert!(invalid.snapshot_digest.is_none());
        }
        let mut blocked = Vec::new();
        let mut warnings = Vec::new();
        for rule in &compiled {
            let result = v2::evaluate(&v2::Request {
                protocol_version: 1,
                schema_version: 2,
                profile: v2::PROFILE.into(),
                snapshot: snapshot.clone(),
                bundles: vec![Bundle {
                    id: "project".into(),
                    policies: rule.policies.clone(),
                }],
            });
            assert_ne!(
                result.status,
                Status::Error,
                "{}: {:?}",
                case["id"],
                result.diagnostic_codes
            );
            let id = format!("{}/{}", rule.set_id, rule.rule_id);
            if result.status == Status::Failed {
                blocked.push(id.clone());
            }
            if !result.warning_policy_ids.is_empty() {
                warnings.push(id);
            }
        }
        let status = if compiled.is_empty() {
            "gating_disabled"
        } else if !blocked.is_empty() {
            "blocked"
        } else if !warnings.is_empty() {
            "passed_with_warnings"
        } else {
            "passed"
        };
        assert_eq!(json!(status), case["expected"], "{}", case["id"]);
        assert_eq!(json!(blocked), case["blocked"], "{}", case["id"]);
        assert_eq!(json!(warnings), case["warnings"], "{}", case["id"]);
    }
}

#[test]
fn absent_policy_is_not_disabled_and_duplicate_keys_are_rejected() {
    use sourcebastion_policy_engine::rule_set_evaluation::evaluate_bytes;
    let missing = evaluate_bytes(br#"{"protocol_version":1,"schema_version":2,"profile":"scan-rule-sets.v1","document":{"schema_version":2,"sets":[]},"snapshot":null}"#);
    assert_eq!(missing.status, "unevaluable");
    assert_eq!(missing.diagnostic_codes, ["POLICY_NOT_CONFIGURED"]);
    let duplicate = evaluate_bytes(br#"{"protocol_version":1,"protocol_version":1,"schema_version":2,"profile":"scan-rule-sets.v1","document":{"schema_version":2,"sets":[]},"snapshot":null}"#);
    assert_eq!(duplicate.status, "unevaluable");
    assert_eq!(duplicate.diagnostic_codes, ["INVALID_REQUEST"]);
}
