# `scan-gate.v1` contract

Protocol version 1 is JSON-in/JSON-out. Unknown fields and missing required fields are errors. A request describes one complete, post-ignore-suppression scan summary before display-only severity filtering, plus explicit policy bundles. The engine validates internal consistency; it cannot establish that the consumer included all findings.

```json
{
  "protocol_version": 1,
  "profile": "scan-gate.v1",
  "snapshot": {
    "kind": "full", "complete": true, "suppression_basis": "post-ignore",
    "finding_count": 0,
    "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
    "category": {"secrets": 0, "sast": 0, "iac": 0, "cve": 0, "dependency_scanning": 0, "other": 0},
    "by_category": {
      "secrets": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
      "sast": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
      "iac": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
      "cve": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
      "dependency_scanning": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
      "other": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    },
    "digest": "sha256:<64 lowercase hex digits>"
  },
  "bundles": [{"id": "repository", "policies": []}]
}
```

The shown digest is a placeholder. `snapshot.digest` is SHA-256 of the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical UTF-8 serialization of the snapshot excluding `digest`. It identifies this normalized summary, not the raw finding set or its provenance. The engine recalculates it. `bundle_digest` identifies an ordered canonical representation of bundle/policy IDs and exact policy bytes, not authenticated origin. A missing `bundles` field is an error; an explicit empty policy list is valid.

Accepted severity keys are `critical`, `high`, `medium`, `low`, `info`, `unknown`; category keys are `secrets`, `sast`, `iac`, `cve`, `dependency_scanning`, `other`. Missing/unrecognized values in consumer findings normalize to `unknown`/`other`. Every count is an integer from 0 through 9,007,199,254,740,991 (the JSON interoperable integer ceiling). Category rows sum to category totals; severity columns sum to severity totals; both sets sum to `finding_count`. Reject missing/extra cells, overflow, contradictory counts, `complete: false`, and a kind other than `full`. Bundle and policy IDs are unique ASCII `[a-z][a-z0-9_-]{0,63}`; duplicate legacy rules receive separate IDs.

The Cedar principal is `Scanner::"local"`, the resource is `Scan::"current"`, and actions are `Action::"passScan"` and `Action::"warnScan"`. Context contains validated counts. The engine installs a sealed base `permit` for `passScan`. Consumers may supply only `forbid` policies scoped exactly to `passScan` and `permit` policies scoped exactly to `warnScan`. Reject wildcard/broader action scopes, consumer `permit passScan`, `forbid warnScan`, templates, arbitrary entities and unsupported effects, in addition to Cedar schema validation. Matching forbids override the base permit; matching warning permits emit warning IDs without altering the gate.

Cedar [skips policies that error](https://docs.cedarpolicy.com/auth/authorization.html). Therefore evaluation diagnostics from either action make the whole result `error`, even if the pass request returned Allow. A Deny with no determining forbid is an unexpected implicit deny and also `error`. Policy text must pass Cedar [schema validation](https://docs.cedarpolicy.com/policies/validation.html).

The result has `protocol_version`, `profile`, `schema_version`, `engine_version`, `status` (`passed|failed|error`), sorted `determining_policy_ids`, sorted `warning_policy_ids`, sorted safe `diagnostic_codes`, `snapshot_digest` and `bundle_digest`. The base permit is not reported as a determining ID. On error both policy-ID arrays are empty to avoid a misleading partial verdict; unavailable digests are null. Diagnostics are fixed codes and never echo request values, policy source, paths, or secrets. stdout is one JSON object and newline; process exits 0 for pass, 1 for intentional fail, 2 for unevaluable. An unrecoverable process failure without JSON is unevaluable to the consumer.

Implementation limits: input ≤1 MiB, ≤16 bundles, ≤256 policies, ≤64 KiB per policy, total policy text ≤1 MiB, ≤16 diagnostics, and bounded runtime/memory. The implementation must prove these limits, not merely document them. Identical canonical summary, bundle and engine release should produce byte-identical results on Linux amd64 and arm64.
