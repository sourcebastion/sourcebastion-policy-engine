# Rule-set compiler and evaluator candidate

This is an experimental implementation of the platform rule-set contract, stacked
on the M043 v2 engine work (PR #11, revision `24f6c52`). It does not introduce a
new production evaluation profile or change existing `evaluate`/`compile-gate`
semantics. No deployment or migration is implied.

`compile-rule-sets-preview` accepts a JSON document with `schema_version: 2`
and `sets`. Each set has `set_id`, positive `revision`, `name`, `enabled`,
optional `description`, and `rules`. Each rule has `rule_id`, `name`, `enabled`,
`effect` (`block` or `warn`), and `condition` containing:

- `kind: finding_count`, a v2 `category`, and nonempty unique `severities`;
- optional `max_new` and `max_existing`, at least one present;
- maxima are safe nonnegative integers; omitted means unconstrained, not zero.

Explicit nulls, duplicate keys/identities, unsupported kinds, unknown fields,
and malformed disabled rules are rejected. Output is deterministic by set and
rule identity. Names must be trimmed, 1–120 characters, with no control
characters. Unknown severity is an explicitly advertised capability; this
compiler does not choose which severities any default policy selects.

Generated Cedar is separated by rule and effect. Block rules forbid `passScan`;
Warn rules permit `warnScan`. Grouped severity counts remain grouped, and new
and existing limits remain independent. The caller must retain the separate
set/revision/rule identity fields, not combine all generated policies into one
bundle (their local cohort policy IDs intentionally repeat across rules).

## Verification and limits

`cargo test --locked` runs the shared fixture through real Cedar evaluation.
`tests/fixtures/rule-set-cases.json` is mirrored by platform
`tests/fixtures/policy-rule-sets/cases.json`; both copies must remain identical.
The cases cover strictest Block, independent Warn, combined violations,
inclusive limits, disabled sets/rules, grouped severities, and cohorts.

The preview compiler bounds input to 1 MiB, 50 sets, 64 KiB serialized per set,
100 rules per set, and 1,000 enabled rules overall. These are authoring limits,
**not a claim that v2 can evaluate that many rules in one request**. Existing
v2 request limits still apply. Preview compilation is not the bounded worker
evaluation command and its output is not a gate verdict.

## Aggregate candidate profile

`evaluate-rule-sets` accepts `protocol_version: 1`, `schema_version: 2`,
`profile: scan-rule-sets.v1`, `document` (the typed compiler input), and a v2
`snapshot` or null. It returns all rule identities, names, effects, outcomes,
observations, limits, document digest and snapshot digest. JSON input is parsed
directly into types so duplicate object fields cannot silently replace values.

Active rules require a complete, consistent, digest-verified full snapshot and
a target/prior baseline. Shared input failure is `unevaluable`, including for
warn-only sets. Valid finding-count expressions cannot overflow: every count
is a nonnegative subset of a validated safe-integer total. Arbitrary Cedar,
future metrics and checks are not accepted by this profile.

Statuses and process exits: `passed`, `passed_with_warnings`, and
`gating_disabled` exit 0; `blocked` exits 1; `unevaluable` exits 2. Missing sets
or sets without any configured rules fail with `POLICY_NOT_CONFIGURED`.
Explicitly disabled configured sets return disabled rule outcomes without
inventing snapshot observations. Host resolution and mandatory-floor inclusion
remain trusted caller responsibilities; the engine cannot authenticate them.

The new command uses the existing 5-second wall, 3-second CPU and 512 MiB worker
limits, with a separately bounded 4 MiB output. Generated policy source is also
bounded to 1 MiB before evaluation. The old v1/v2 command limits are unchanged.
A local debug CLI probe of 1,000 enabled single-cohort rules completed in 2.2 s;
this is not release-hardware or worst-case benchmark evidence.

Unknown is explicitly selectable; legacy exclusions remain unchanged. The host
must reject activation until policy is configured. Removing configuration is
not equivalent to explicitly disabling a configured policy.

## Not implemented here

- Host assignment resolution, mandatory floors, immutable publication, and
  atomic invalidation of previously passing provider checks.
- Release approval and a pinned production aggregate artifact; future rule-local
  runtime errors need their own evaluation semantics before new kinds ship.
- Proving explicit disabled configuration: empty compiler output must never
  itself authorize merging, especially for missing/unconfigured policy.
- UI, persistent models, repository policy overrides, rollout or migration.

Do not wire the preview directly into merge enforcement. Final profile,
resource budgets, trusted resolution, and cross-repository CI conformance must
be established before activation.
