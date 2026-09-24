# Consumer boundaries and trust

The existing gates are distinct:

| Consumer | Current behavior | Cedar ownership |
| --- | --- | --- |
| Scanner CLI | PLAN-09 Python `max_count` rules after ignore suppression, before display severity filtering. `fail` blocks, `warn` reports, `ignore` is a no-op. Policy fields are returned in memory but not written into `vulnerabilities.json`. | Build a complete summary at that same point. Keep PLAN-09 as default; shadow cannot change its exit status. |
| Public GitHub Action | Own severity-threshold gate, exit 0/1/2 for pass/violation/unevaluable. Does not call PLAN-09. | Separate future integration and cutover. |
| Hosted platform | Own high/critical check after ingest and persists `passed`/`failed`. | Server evaluates a trusted, complete snapshot, including reconstructed incremental state; it authenticates bundles and owns the verdict. |

The engine evaluates the bundles it receives. A bundle digest establishes identity, not provenance. An organization guardrail must be supplied and protected by the consumer. A repository-controlled workflow can omit it; the engine cannot detect that without an authenticated external binding. An included guardrail's `forbid passScan` cannot be overridden by another bundle because consumer `permit passScan` policies are disallowed.

The engine cannot prove that a caller's summary contains every finding. The consumer must attest completeness, choose suppression and branch scope, and ensure the workflow honors exit 1 or 2. The hosted platform must never trust a customer-supplied `passed` value. Raw findings, source text, secret matches, credentials and personal data do not enter the engine request.

M042's original implementation dependency is the [rebrand compatibility audit](https://github.com/sourcebastion/sourcebastion-platform/issues/192). That audit remains open. On 2026-09-23 the project owner explicitly approved beginning engine code before it closes; this exception does not close or waive the platform audit itself.
