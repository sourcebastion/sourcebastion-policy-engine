# Conformance and PLAN-09 parity

The `tests/cli.rs` corpus invokes the built binary, verifies JSON status and process exit code, and covers clean, blocked, warning, malformed/incomplete and converted PLAN-09 cases. The `src/lib.rs` tests cover Cedar evaluation errors, malformed policies, unknown request fields, digest and count inconsistencies, and disallowed consumer permits. The scanner adapter's tests cover category fallback, no raw-finding leakage, pin mismatch, shadow error visibility and its versioned policy artifact. These tests do not by themselves prove arm64 behavior or a release artifact; the release matrix must run the same corpus natively on both architectures.

| Rule shape / case | Legacy PLAN-09 | Cedar migration |
| --- | --- | --- |
| Severity-only `max_count` | Exact lowercased severity, triggers when `count > max_count` | `context.severity.<name> > max_count` |
| Category-only | `category` → `type` → `scanner` fallback, lowercased | Adapter uses same fallback, then `context.category.<name>` |
| Both filters | Intersection | `context.by_category.<category>.<severity>` |
| No filters | All findings | `context.finding_count` |
| `fail` | Blocks | `forbid passScan` |
| `warn` | Advisory only | `permit warnScan` |
| `ignore` | Skipped | No emitted policy; converter reports skipped rule ID |
| Empty rule set / empty scan | Pass | Explicit empty bundle / sealed base permit |
| Duplicate rule | Separate violations | Separate stable IDs, one per rule index |
| Unknown severity/category | Does not match named filter | `unknown`/`other` bucket, named filter still does not match |
| Negative `max_count` | May trigger on an empty scan | Rejected as unsupported; no silent clamping |
| Unsupported field/value | Legacy parser behavior varies | Converter rejects with a reviewable code |

PLAN-09 evaluates after ignore suppression and before the display severity filter. The adapter captures exactly that in-memory list. A stored `vulnerabilities.json` may already be display-filtered and does not persist PLAN-09 policy fields; it is not a safe substitute for the complete input. `<output filename>.policy-result.json` is an additive, versioned adapter artifact.

Shadow comparison is non-enforcing: PLAN-09 controls exit status while Cedar result/error and mismatched IDs are recorded. In explicit Cedar mode, policy failure exits 1 and evaluation/configuration error exits 2. Rollback is `policy_mode: legacy`. The public Action and hosted platform remain on their own gates until separate integrations and acceptance.

Open conformance gaps before closing M042: static golden results for all adversarial cases; native arm64 run and cross-architecture byte comparison; scanner packaged-path proof; reviewer acceptance of the binary/SBOM/license record and rollback demonstration.
