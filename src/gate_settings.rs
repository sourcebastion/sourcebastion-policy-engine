//! Deterministic compiler for effective category threshold settings.
//!
//! Consumers merge and authenticate organization, dashboard and repository
//! sources before calling this compiler. It does not authenticate provenance.

use crate::{v2::CATEGORIES, Bundle, PolicySource, MAX_INPUT_BYTES, MAX_SAFE_COUNT, SEVERITIES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SETTINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSettings {
    pub version: u32,
    pub minimum_severity: String,
    pub categories: BTreeMap<String, CategoryGate>,
}

impl GateSettings {
    /// Project default matching the existing high/critical gate.
    pub fn default_high() -> Self {
        Self {
            version: SETTINGS_VERSION,
            minimum_severity: "high".into(),
            categories: CATEGORIES
                .iter()
                .map(|category| {
                    (
                        category.to_string(),
                        CategoryGate {
                            enabled: true,
                            max_new: 0,
                            max_existing: 0,
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryGate {
    pub enabled: bool,
    pub max_new: i64,
    pub max_existing: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileError {
    InvalidSettings,
    ResourceLimit,
}

impl CompileError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidSettings => "INVALID_GATE_SETTINGS",
            Self::ResourceLimit => "RESOURCE_LIMIT",
        }
    }
}

pub fn compile_bytes(input: &[u8]) -> Result<Bundle, CompileError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(CompileError::ResourceLimit);
    }
    let settings: GateSettings =
        serde_json::from_slice(input).map_err(|_| CompileError::InvalidSettings)?;
    compile(&settings)
}

pub fn compile(settings: &GateSettings) -> Result<Bundle, CompileError> {
    let severity_index = SEVERITIES[..5]
        .iter()
        .position(|severity| *severity == settings.minimum_severity)
        .ok_or(CompileError::InvalidSettings)?;
    if settings.version != SETTINGS_VERSION || settings.categories.len() != CATEGORIES.len() {
        return Err(CompileError::InvalidSettings);
    }
    let severities = &SEVERITIES[..=severity_index];
    let mut policies = Vec::new();
    for category in CATEGORIES {
        let row = settings
            .categories
            .get(category)
            .ok_or(CompileError::InvalidSettings)?;
        if !(0..=MAX_SAFE_COUNT).contains(&row.max_new)
            || !(0..=MAX_SAFE_COUNT).contains(&row.max_existing)
        {
            return Err(CompileError::InvalidSettings);
        }
        if !row.enabled {
            continue;
        }
        for (cohort, max_count) in [("new", row.max_new), ("existing", row.max_existing)] {
            let count = severities
                .iter()
                .map(|severity| format!("context.by_category.{category}.{cohort}.{severity}"))
                .collect::<Vec<_>>()
                .join(" + ");
            policies.push(PolicySource {
                id: format!("{category}_{cohort}"),
                source: format!(
                    "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when {{ {count} > {max_count} }};"
                ),
            });
        }
    }
    Ok(Bundle {
        id: "project".into(),
        policies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evaluate_bytes, v2, Status};

    fn settings() -> GateSettings {
        GateSettings::default_high()
    }

    fn result_for(settings: &GateSettings, category: &str, cohort: &str, severity: &str) -> Status {
        let by_category = CATEGORIES
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    v2::COHORTS
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
            .collect();
        let mut snapshot = v2::Snapshot {
            kind: "full".into(),
            complete: true,
            suppression_basis: "post-ignore".into(),
            baseline: v2::Baseline {
                kind: "target_ref".into(),
                digest: Some(format!("sha256:{}", "a".repeat(64))),
            },
            finding_count: 1,
            by_category,
            digest: String::new(),
        };
        *snapshot
            .by_category
            .get_mut(category)
            .unwrap()
            .get_mut(cohort)
            .unwrap()
            .get_mut(severity)
            .unwrap() = 1;
        snapshot.digest = v2::canonical_snapshot_digest(&snapshot).unwrap();
        let request = v2::Request {
            protocol_version: 1,
            schema_version: v2::SCHEMA_VERSION,
            profile: v2::PROFILE.into(),
            snapshot,
            bundles: vec![compile(settings).unwrap()],
        };
        evaluate_bytes(&serde_json::to_vec(&request).unwrap()).status
    }

    #[test]
    fn default_high_threshold_blocks_new_and_existing_high_not_medium() {
        let settings = settings();
        assert_eq!(
            result_for(&settings, "secrets", "new", "high"),
            Status::Failed
        );
        assert_eq!(
            result_for(&settings, "sast", "existing", "critical"),
            Status::Failed
        );
        assert_eq!(
            result_for(&settings, "sast", "new", "medium"),
            Status::Passed
        );
    }

    #[test]
    fn disabled_category_is_still_counted_but_does_not_block() {
        let mut settings = settings();
        settings
            .categories
            .get_mut("container_images")
            .unwrap()
            .enabled = false;
        let bundle = compile(&settings).unwrap();
        assert!(!bundle
            .policies
            .iter()
            .any(|policy| policy.id.starts_with("container_images")));
        assert_eq!(
            result_for(&settings, "container_images", "new", "critical"),
            Status::Passed
        );
        assert_eq!(
            result_for(&settings, "secrets", "new", "critical"),
            Status::Failed
        );
    }

    #[test]
    fn limits_and_invalid_shapes_are_rejected() {
        let mut settings = settings();
        settings.categories.get_mut("secrets").unwrap().max_new = 1;
        assert_eq!(
            result_for(&settings, "secrets", "new", "high"),
            Status::Passed
        );
        settings.categories.get_mut("secrets").unwrap().max_new = -1;
        assert_eq!(
            compile(&settings).unwrap_err(),
            CompileError::InvalidSettings
        );
        settings.categories.get_mut("secrets").unwrap().max_new = 0;
        settings.categories.remove("other");
        assert_eq!(
            compile(&settings).unwrap_err(),
            CompileError::InvalidSettings
        );
        settings.categories.insert(
            "unknown_type".into(),
            CategoryGate {
                enabled: true,
                max_new: 0,
                max_existing: 0,
            },
        );
        assert_eq!(
            compile(&settings).unwrap_err(),
            CompileError::InvalidSettings
        );
        assert_eq!(
            compile_bytes(
                br#"{"version":1,"minimum_severity":"high","categories":{},"extra":true}"#
            )
            .unwrap_err(),
            CompileError::InvalidSettings
        );
        settings = GateSettings::default_high();
        settings.minimum_severity = "unknown".into();
        assert_eq!(
            compile(&settings).unwrap_err(),
            CompileError::InvalidSettings
        );
    }

    #[test]
    fn compilation_is_byte_deterministic() {
        let settings = settings();
        let first = serde_json::to_vec(&compile(&settings).unwrap()).unwrap();
        let second =
            serde_json::to_vec(&compile_bytes(&serde_json::to_vec(&settings).unwrap()).unwrap())
                .unwrap();
        assert_eq!(first, second);
    }
}
