# Conformance and PLAN-09 parity

The [measured PLAN-09 parity report](plan09-parity-report.md) records exact IDs and outcomes from the scanner adapter's live cross-project corpus.

The `tests/cli.rs` corpus invokes the built binary, verifies JSON status and process exit code, and covers clean, blocked, warning, malformed/incomplete, converted PLAN-09, near-limit input and maximum-policy output cases. A CLI unit test forces the worker timeout branch and checks that it returns an unevaluable exit-2 error. `tests/golden.rs` compares exact output bytes and exit codes against checked-in blocked, warning, malformed, incomplete and conflicting-policy fixtures; the clean fixture is additionally compared in CI. The `src/lib.rs` tests cover Cedar evaluation errors, malformed policies, unknown request fields, digest and count inconsistencies, and disallowed consumer permits. The scanner adapter's tests cover category fallback, no raw-finding leakage, pin mismatch, shadow error visibility and its versioned policy artifact. Native amd64 and arm64 CI compare the same golden result bytes.

| Fixture case | Executable evidence | Expected status / exit |
| --- | --- | --- |
| Clean and empty scan | `examples/clean.json`, `empty_snapshot_passes` | `passed` / 0 |
| Critical-secret block | `tests/fixtures/blocked.request.json` | `failed` / 1 |
| Warning only | `tests/fixtures/warning.request.json` | `passed` / 0 with warning ID |
| Malformed policy | `tests/fixtures/malformed.request.json` | `error` / 2, `INVALID_POLICY` |
| Incomplete or delta summary | `tests/fixtures/incomplete.request.json`, CLI delta case | `error` / 2, `INCOMPLETE_SNAPSHOT` |
| Conflicting consumer pass permit | `tests/fixtures/conflicting.request.json` | `error` / 2, `INVALID_POLICY_SHAPE` |
| Post-suppression empty input | scanner parity corpus `suppressed_input` | `passed` / 0 |
| Unknown severity/category | scanner parity corpus `unknown` | `passed` / 0 for named filters |
| Category fallback and threshold boundaries | scanner parity corpus | matching legacy status and exact rule IDs |

The checked-in expected JSON files and process exit codes are compared on both native release architectures; no architecture-specific normalization is permitted.

M043 adds `tests/fixtures/m043-consumer-cases.json`, a shared v2 consumer
corpus also checked into the platform repository. The CLI and hosted platform
run the same twelve cases: clean first scan, image-only new finding,
target-baseline existing finding, disabled-but-visible row, mandatory account
floor over a disabled project row, allowance boundary and breach, severity
filter, other-category fallback, incomplete scan, bad digest, and invalid
first-scan existing count. Both compare status, determining policy IDs, and
diagnostic codes; the CLI also checks process exit status. This proves the
engine and hosted consumer agree on the fixture decisions, but does not yet
prove GitLab or Action delivery semantics or a production release pin.

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

The [scanner packaged-adapter workflow](https://github.com/sourcebastion/sourcebastion-scanner/actions/workflows/cedar-adapter.yml) proves clean, blocked, warning, malformed-policy, shadow-mismatch and legacy-rollback artifacts plus the 14-case PLAN-09 parity corpus on native Linux amd64 and arm64. The remaining release gate is independent reviewer acceptance of the binary/SBOM/license record, adapter demonstration and rollback evidence; the candidate stays draft until that review.
