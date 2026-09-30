//! Experimental typed rule-set compiler; not wired into a released CLI profile.
//!
//! The host resolves assignments and authenticates revisions before compilation.
//! Disabled documents are still validated. Empty output is not merge permission:
//! only the host can distinguish authenticated disablement from missing policy.

use crate::{v2::CATEGORIES, PolicySource, MAX_INPUT_BYTES, MAX_SAFE_COUNT, SEVERITIES};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema_version: u32,
    pub sets: Vec<RuleSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub set_id: String,
    pub revision: u64,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub rule_id: String,
    pub name: String,
    pub enabled: bool,
    pub effect: Effect,
    pub condition: FindingCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Block,
    Warn,
}

// A closed shape intentionally rejects future metric/check rules until their
// evidence and evaluation contracts are supported by an engine profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingCount {
    pub kind: String,
    pub category: String,
    pub severities: Vec<String>,
    #[serde(
        default,
        deserialize_with = "present_count",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_new: Option<i64>,
    #[serde(
        default,
        deserialize_with = "present_count",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_existing: Option<i64>,
}

fn present_count<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    // Missing is unconstrained, whereas explicit null is invalid.
    i64::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidDocument,
    UnsupportedSeverity,
    ResourceLimit,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompiledRule {
    pub set_id: String,
    pub revision: u64,
    pub rule_id: String,
    pub effect: Effect,
    pub policies: Vec<PolicySource>,
}

fn name_valid(name: &str) -> bool {
    let size = name.chars().count();
    (1..=120).contains(&size) && name == name.trim() && !name.chars().any(char::is_control)
}

/// Parse directly into structs so duplicate keys cannot disappear in a Value.
pub fn compile_bytes(
    input: &[u8],
    supported_severities: &[&str],
) -> Result<Vec<CompiledRule>, Error> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Error::ResourceLimit);
    }
    let document: Document = serde_json::from_slice(input).map_err(|_| Error::InvalidDocument)?;
    compile(&document, supported_severities)
}

pub fn compile(
    document: &Document,
    supported_severities: &[&str],
) -> Result<Vec<CompiledRule>, Error> {
    if document.schema_version != 2 {
        return Err(Error::InvalidDocument);
    }
    if document.sets.len() > 50 {
        return Err(Error::ResourceLimit);
    }
    let mut set_ids = BTreeSet::new();
    let mut active_count = 0;
    let mut policy_bytes = 0usize;
    let mut output = Vec::new();
    for set in &document.sets {
        if !crate::valid_id(&set.set_id)
            || !set_ids.insert(&set.set_id)
            || set.revision == 0
            || set.revision > MAX_SAFE_COUNT as u64
            || !name_valid(&set.name)
            || set.description.chars().count() > 2000
        {
            return Err(Error::InvalidDocument);
        }
        if set.rules.len() > 100
            || serde_json::to_vec(set)
                .map_err(|_| Error::InvalidDocument)?
                .len()
                > 65536
        {
            return Err(Error::ResourceLimit);
        }
        let mut rule_ids = BTreeSet::new();
        for rule in &set.rules {
            let c = &rule.condition;
            let severities: BTreeSet<_> = c.severities.iter().collect();
            if !crate::valid_id(&rule.rule_id)
                || !rule_ids.insert(&rule.rule_id)
                || !name_valid(&rule.name)
                || c.kind != "finding_count"
                || !CATEGORIES.contains(&c.category.as_str())
                || severities.is_empty()
                || severities.len() != c.severities.len()
                || c.max_new.is_none() && c.max_existing.is_none()
                || [c.max_new, c.max_existing]
                    .into_iter()
                    .flatten()
                    .any(|n| !(0..=MAX_SAFE_COUNT).contains(&n))
            {
                return Err(Error::InvalidDocument);
            }
            for severity in &c.severities {
                if !SEVERITIES.contains(&severity.as_str()) {
                    return Err(Error::InvalidDocument);
                }
                if !supported_severities.contains(&severity.as_str()) {
                    return Err(Error::UnsupportedSeverity);
                }
            }
            if !set.enabled || !rule.enabled {
                continue;
            }
            active_count += 1;
            if active_count > 1000 {
                return Err(Error::ResourceLimit);
            }
            let (effect, action) = match rule.effect {
                Effect::Block => ("forbid", "passScan"),
                Effect::Warn => ("permit", "warnScan"),
            };
            let mut policies = Vec::new();
            for (cohort, limit) in [("new", c.max_new), ("existing", c.max_existing)] {
                if let Some(limit) = limit {
                    let count = severities
                        .iter()
                        .map(|s| format!("context.by_category.{}.{cohort}.{s}", c.category))
                        .collect::<Vec<_>>()
                        .join(" + ");
                    policies.push(PolicySource {
                        // Per-rule policies are evaluated in their own namespace;
                        // host IDs remain separate fields, never concatenated.
                        id: cohort.into(),
                        source: format!("{effect}(principal == Scanner::\"local\", action == Action::\"{action}\", resource == Scan::\"current\") when {{ {count} > {limit} }};"),
                    });
                }
            }
            policy_bytes += policies.iter().map(|p| p.source.len()).sum::<usize>();
            if policy_bytes > crate::MAX_POLICY_TOTAL_BYTES {
                return Err(Error::ResourceLimit);
            }
            output.push(CompiledRule {
                set_id: set.set_id.clone(),
                revision: set.revision,
                rule_id: rule.rule_id.clone(),
                effect: rule.effect,
                policies,
            });
        }
    }
    output.sort_by(|a, b| (&a.set_id, &a.rule_id).cmp(&(&b.set_id, &b.rule_id)));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> serde_json::Value {
        json!({"schema_version":2,"sets":[{"set_id":"release","revision":1,"name":"Release","enabled":true,"rules":[{
            "rule_id":"sast_high","name":"SAST high","enabled":true,"effect":"block",
            "condition":{"kind":"finding_count","category":"sast","severities":["high"],"max_new":2}
        }]}]})
    }

    #[test]
    fn invalid_documents_fail_even_when_disabled() {
        for invalid in [
            json!(null),
            json!(true),
            json!(-1),
            json!(1.5),
            json!(MAX_SAFE_COUNT + 1),
        ] {
            let mut d = document();
            d["sets"][0]["enabled"] = json!(false);
            d["sets"][0]["rules"][0]["condition"]["max_new"] = invalid;
            assert_eq!(
                compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap_err(),
                Error::InvalidDocument
            );
        }
    }

    #[test]
    fn duplicate_keys_and_ids_are_rejected() {
        assert_eq!(
            compile_bytes(
                br#"{"schema_version":2,"schema_version":2,"sets":[]}"#,
                &SEVERITIES
            )
            .unwrap_err(),
            Error::InvalidDocument
        );
        let mut d = document();
        let duplicate = d["sets"][0].clone();
        d["sets"].as_array_mut().unwrap().push(duplicate);
        assert_eq!(
            compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap_err(),
            Error::InvalidDocument
        );
    }

    #[test]
    fn unknown_severity_requires_explicit_capability() {
        let mut d = document();
        d["sets"][0]["rules"][0]["condition"]["severities"] = json!(["unknown"]);
        let bytes = serde_json::to_vec(&d).unwrap();
        assert_eq!(
            compile_bytes(&bytes, &SEVERITIES[..5]).unwrap_err(),
            Error::UnsupportedSeverity
        );
        assert!(compile_bytes(&bytes, &SEVERITIES).is_ok());
    }

    #[test]
    fn compilation_preserves_cohorts_effects_and_disabling() {
        let mut d = document();
        let first = compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap();
        assert_eq!(first[0].policies.len(), 1);
        assert!(first[0].policies[0].source.starts_with("forbid("));
        d["sets"][0]["rules"][0]["effect"] = json!("warn");
        let warn = compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap();
        assert!(warn[0].policies[0].source.contains("Action::\"warnScan\""));
        d["sets"][0]["enabled"] = json!(false);
        assert!(compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn disabled_rules_reject_unsupported_shapes_and_selectors() {
        for (field, value) in [
            ("kind", json!("metric")),
            ("category", json!("not_a_category")),
            ("severities", json!([])),
            ("severities", json!(["high", "high"])),
            ("severities", json!(["invented"])),
            ("unexpected", json!(true)),
        ] {
            let mut d = document();
            d["sets"][0]["rules"][0]["enabled"] = json!(false);
            d["sets"][0]["rules"][0]["condition"][field] = value;
            assert_eq!(
                compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap_err(),
                Error::InvalidDocument
            );
        }
    }

    #[test]
    fn severity_order_does_not_change_compiled_policy() {
        let mut d = document();
        d["sets"][0]["rules"][0]["condition"]["severities"] = json!(["high", "critical"]);
        let first = compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap();
        d["sets"][0]["rules"][0]["condition"]["severities"] = json!(["critical", "high"]);
        let second = compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap();
        assert_eq!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(second).unwrap()
        );
    }

    #[test]
    fn authoring_limits_also_apply_to_disabled_sets() {
        let mut d = document();
        d["sets"][0]["enabled"] = json!(false);
        let rule = d["sets"][0]["rules"][0].clone();
        d["sets"][0]["rules"] = json!(vec![rule; 101]);
        assert_eq!(
            compile_bytes(&serde_json::to_vec(&d).unwrap(), &SEVERITIES).unwrap_err(),
            Error::ResourceLimit
        );
        assert_eq!(
            compile_bytes(&vec![b' '; MAX_INPUT_BYTES + 1], &SEVERITIES).unwrap_err(),
            Error::ResourceLimit
        );
    }
}
