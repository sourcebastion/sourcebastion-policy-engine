# PLAN-09 parity report — M042 release-candidate proof

Measured with the `v0.1.0-rc1` engine code and the scanner adapter's [`test_cedar_plan09_parity_live.py`](https://github.com/sourcebastion/sourcebastion-scanner/pull/38), using the real release-mode Rust binary. The test converts plain PLAN-09 rule JSON, runs the existing Python `PolicyEngine` on the same post-suppression finding list, evaluates Cedar through the scanner adapter, and compares status, exact fail IDs and warning IDs. All 14 supported cases matched. This is local amd64 proof; native arm64 parity requires its own CI run before closure.

| Case | Legacy / Cedar status | Determining fail IDs | Warning IDs | Match |
| --- | --- | --- | --- | --- |
| No rules, empty scan | passed / passed | — | — | yes |
| `max_count: 0`, zero matches | passed / passed | — | — | yes |
| `max_count: 0`, one match | failed / failed | `plan09/plan09_rule_0001` | — | yes |
| Category threshold, count exactly 2 | passed / passed | — | — | yes |
| Category threshold, count 3 | failed / failed | `plan09/plan09_rule_0001` | — | yes |
| Case-normalized severity | failed / failed | `plan09/plan09_rule_0001` | — | yes |
| Category fallback via `type` | failed / failed | `plan09/plan09_rule_0001` | — | yes |
| Category fallback via `scanner` | failed / failed | `plan09/plan09_rule_0001` | — | yes |
| Combined severity/category intersection | failed / failed | `plan09/plan09_rule_0001` | — | yes |
| Warning-only rule | passed / passed | — | `plan09/plan09_rule_0001` | yes |
| `ignore` rule | passed / passed | — | — | yes |
| Unknown severity/category against named filters | passed / passed | — | — | yes |
| Duplicate matching fail rules | failed / failed | `plan09/plan09_rule_0001`, `plan09/plan09_rule_0002` | — | yes |
| Post-suppression empty input | passed / passed | — | — | yes |

Unsupported negative `max_count` returns converter exit 2 and `UNSUPPORTED_PLAN09_RULE`; it is deliberately not clamped to zero. Unknown rule keys and unsupported filter/action values are rejected rather than silently dropped. The scanner's `shadow` mode is non-enforcing and preserves the legacy exit status even on a Cedar error; explicit `cedar` mode maps engine `passed|failed|error` to 0|1|2. Switching back to `policy_mode: legacy` is the rollback path.

The scanner adapter's live artifact test also exercised complete clean, blocked critical-secret and warning-only scans through `SecurityScanner`, read the versioned sibling policy artifact, and confirmed status/warning behavior. Existing `vulnerabilities.json` readers are unchanged. The public Action and hosted platform remain on separate gates.
