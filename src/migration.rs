//! Deterministic conversion of supported PLAN-09 rule data.
//!
//! This module consumes plain JSON rules, never scanner internals. Legacy
//! behavior stays the default in the scanner and this conversion is explicit.

use crate::{Bundle, PolicySource, CATEGORIES, MAX_SAFE_COUNT, SEVERITIES};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRule {
    pub severity: Option<String>,
    pub category: Option<String>,
    #[serde(default)]
    pub max_count: i64,
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_action() -> String {
    "fail".to_owned()
}

#[derive(Debug, Serialize)]
pub struct Conversion {
    pub bundle: Bundle,
    pub skipped_rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionError {
    InvalidInput,
    UnsupportedRule,
    ResourceLimit,
}

impl ConversionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_PLAN09_INPUT",
            Self::UnsupportedRule => "UNSUPPORTED_PLAN09_RULE",
            Self::ResourceLimit => "RESOURCE_LIMIT",
        }
    }
}

pub fn convert_bytes(input: &[u8]) -> Result<Conversion, ConversionError> {
    if input.len() > crate::MAX_INPUT_BYTES {
        return Err(ConversionError::ResourceLimit);
    }
    let rules: Vec<LegacyRule> =
        serde_json::from_slice(input).map_err(|_| ConversionError::InvalidInput)?;
    convert(rules)
}

pub fn convert(rules: Vec<LegacyRule>) -> Result<Conversion, ConversionError> {
    if rules.len() > crate::MAX_POLICIES {
        return Err(ConversionError::ResourceLimit);
    }
    let mut policies = Vec::new();
    let mut skipped_rule_ids = Vec::new();
    for (index, rule) in rules.into_iter().enumerate() {
        if !(0..=MAX_SAFE_COUNT).contains(&rule.max_count)
            || rule
                .severity
                .as_deref()
                .is_some_and(|value| !SEVERITIES[..4].contains(&value))
            || rule
                .category
                .as_deref()
                .is_some_and(|value| !CATEGORIES[..5].contains(&value))
            || !matches!(rule.action.as_str(), "fail" | "warn" | "ignore")
        {
            return Err(ConversionError::UnsupportedRule);
        }
        let id = format!("plan09_rule_{:04}", index + 1);
        if rule.action == "ignore" {
            skipped_rule_ids.push(id);
            continue;
        }
        let count = match (rule.category.as_deref(), rule.severity.as_deref()) {
            (Some(category), Some(severity)) => {
                format!("context.by_category.{category}.{severity}")
            }
            (Some(category), None) => format!("context.category.{category}"),
            (None, Some(severity)) => format!("context.severity.{severity}"),
            (None, None) => "context.finding_count".to_owned(),
        };
        let (effect, action) = if rule.action == "fail" {
            ("forbid", "passScan")
        } else {
            ("permit", "warnScan")
        };
        policies.push(PolicySource {
            id,
            source: format!(
                "{effect}(principal == Scanner::\"local\", action == Action::\"{action}\", resource == Scan::\"current\") when {{ {count} > {} }};",
                rule.max_count
            ),
        });
    }
    Ok(Conversion {
        bundle: Bundle {
            id: "plan09".into(),
            policies,
        },
        skipped_rule_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_all_supported_shapes() {
        let rules = br#"[
            {"severity":"critical","max_count":0},
            {"category":"secrets","max_count":1,"action":"warn"},
            {"severity":"high","category":"sast","max_count":2},
            {"max_count":3},
            {"action":"ignore"}
        ]"#;
        let output = convert_bytes(rules).unwrap();
        assert_eq!(output.bundle.policies.len(), 4);
        assert_eq!(output.skipped_rule_ids, ["plan09_rule_0005"]);
        assert!(output.bundle.policies[2]
            .source
            .contains("context.by_category.sast.high > 2"));
        assert!(output.bundle.policies[1].source.starts_with("permit"));
    }

    #[test]
    fn rejects_negative_and_unknown_filters() {
        assert_eq!(
            convert_bytes(br#"[{"max_count":-1}]"#).unwrap_err(),
            ConversionError::UnsupportedRule
        );
        assert_eq!(
            convert_bytes(br#"[{"severity":"unknown"}]"#).unwrap_err(),
            ConversionError::UnsupportedRule
        );
        assert_eq!(
            convert_bytes(br#"[{"category":"OTHER"}]"#).unwrap_err(),
            ConversionError::UnsupportedRule
        );
    }

    #[test]
    fn rejects_unknown_keys_instead_of_discarding_them() {
        assert_eq!(
            convert_bytes(br#"[{"max_count":0,"oops":true}]"#).unwrap_err(),
            ConversionError::InvalidInput
        );
    }
}
