# Proposed `scan-gate.v2` contract (M043 S01)

Status: design draft. This document is not an implemented profile or a release
promise. [`scan-gate.v1`](scan-gate-v1.md) remains the current engine contract.

## Purpose and boundary

M043 gives the SourceBastion Policy tab, GitHub PR gates, and GitLab MR gates
one decision model. The engine still receives counts only; consumers assemble
the complete findings, authenticate policy and baseline sources, and enforce
the result. The engine cannot prove that a caller included every finding.

No gate runs before all configured scanners finish, including container-image
scanning. Only open findings remaining after *authorized* suppression enter the
gate snapshot. A scanner failure, missing component, partial/delta-only result,
untrusted baseline, or policy-source failure is unevaluable, not a pass. A
display filter must not change the snapshot. Every finding maps to exactly one
canonical category and one cohort; the `other` category catches unknowns.

## Canonical categories and cohorts

Use stable policy categories rather than product/tool names:

| Key | Policy tab label | Typical source |
| --- | --- | --- |
| `secrets` | Secrets | Credential and secret detection |
| `sast` | SAST | Static application analysis |
| `iac` | IaC | Infrastructure-as-code analysis |
| `cve` | CVEs | Vulnerability findings not assigned below |
| `dependency_scanning` | Dependency scanning | Package/dependency findings |
| `container_images` | Container images | Image and OS-package findings |
| `other` | Other / Unknown | All unmapped findings |

The mapping is a consumer conformance contract, not an inference from a tool
name. A scanner can emit more than one category. The mapping must be tested
for each supported finding shape; unknowns are counted in `other`, never
dropped. Source text, file paths, secret values, and credentials do not enter
the engine request.

`new` means the stable finding identity is absent from the relevant trusted
baseline. `existing` means that identity is present and still open. For a
PR/MR, the baseline is the target protected branch; for a dashboard branch
scan, it is the preceding applied complete scan of that ref. A missing first
baseline classifies **all** current findings as `new` and none as `existing`.
The consumer records and verifies the baseline identity. Resolved findings
are not current findings and do not count. Dismissed or suppressed findings
count only after their authorization semantics are decided and recorded by
the consumer; an untrusted repository ignore rule cannot silently bypass an
organization floor.

## Request sketch

The wire request retains the M042 JSON-in/JSON-out envelope and explicit
`protocol_version`, `schema_version`, `profile`, `snapshot`, and `bundles`.
The next schema version and profile are intentionally distinct from v1:

```json
{
  "protocol_version": 1,
  "schema_version": 2,
  "profile": "scan-gate.v2",
  "snapshot": {
    "kind": "full",
    "complete": true,
    "suppression_basis": "post-ignore",
    "baseline": {"kind": "target_ref", "digest": "sha256:<64 lowercase hex digits>"},
    "finding_count": 1,
    "by_category": {
      "secrets": {"new": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}},
      "sast": {"new": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}},
      "iac": {"new": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}},
      "cve": {"new": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}},
      "dependency_scanning": {"new": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}},
      "container_images": {"new": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}},
      "other": {"new": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}, "existing": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}}
    },
    "digest": "sha256:<64 lowercase hex digits>"
  },
  "bundles": [{"id": "project", "policies": [{"id": "secrets_new", "source": "forbid(principal == Scanner::\"local\", action == Action::\"passScan\", resource == Scan::\"current\") when { context.by_category.secrets.new.critical + context.by_category.secrets.new.high > 0 };"}]}]
}
```

The digest placeholders above are explanatory, not valid values. For
`baseline.kind = "none"`, `baseline.digest` is null and every `existing`
cell must be zero. `none` is allowed only when the consumer has verified that
this is the first scan; a baseline fetch failure is an error, not `none`.
`target_ref` and `prior_ref` require a well-formed digest,
but the consuming platform must authenticate what it identifies. Snapshot
digest is RFC 8785 canonical SHA-256 over the snapshot without `digest`.

The engine validates exact category/cohort/severity keys, non-negative safe
integers, the sum of all cells equals `finding_count`, resource bounds,
declared completeness, suppression basis, baseline shape, versions, and
digest. Unknown or missing fields are errors. Equal v2 request, policy and
engine release must produce byte-identical results on Linux amd64/arm64.

## Policy tab and repository file

One project setting row per category has `enabled`, `max_new`, and
`max_existing`; a global `minimum_severity` selects the lowest counted
severity. The default is `high`; all rows start enabled with both maxima zero
to preserve today's high/critical gate. Values are non-negative integers.

The repository override is a declarative, versioned file, not arbitrary Cedar
source. Proposed location and shape:

```yaml
# .sourcebastion/policy/gate.yaml
version: 1
minimum_severity: high
categories:
  secrets: {enabled: true, max_new: 0, max_existing: 0}
  container_images: {enabled: true, max_new: 0, max_existing: 5}
```

Unspecified rows inherit dashboard project defaults. An approved repository
file can replace project defaults within administrator-defined organization
limits, but cannot weaken or omit a mandatory organization guardrail. A
disabled project row still scans, stores, displays and tracks its findings;
it simply contributes no project-level failure rule. An organization-mandated
row is locked in the Policy tab. An untrusted PR/MR head policy change is
preview-only; the gate uses the protected target-ref policy until the change
is approved and merged. File parsing rejects duplicates, unknown categories,
negative/unbounded limits, and unrecognized versions rather than silently
ignoring them.

The table/file settings compile deterministically into Cedar `forbid
passScan` policies. Each enabled row fails when the sum of counts at or above
`minimum_severity` in `new` exceeds `max_new`, or the equivalent `existing`
sum exceeds `max_existing`. One rule per row and cohort yields stable,
explainable policy IDs. Consumer policies still cannot `permit passScan` or
override an included organization `forbid`. The engine does not authenticate
bundle origin; the server/CI consumer resolves and binds provenance before
evaluation.

## Result and merge enforcement

Keep `passed`, `failed`, `error`, stable determining/warning IDs, profile,
schema and engine versions, snapshot and bundle digests, and 0/1/2 exit
mapping. Add the baseline digest to the persisted consumer record alongside
the effective policy version and source. The dashboard displays the server's
own verdict, not a value supplied by a scan client. A failing or unevaluable
result is non-green in CI; the check is bound to the current PR/MR commit.
Provider-side required-check settings remain repository-owner configuration.

## Open implementation checkpoints

1. Confirm the mapping for every scanner output, especially package CVEs
   versus image CVEs; `container_images` takes precedence for image origin.
2. Decide how an authorized suppression is proved and represented without
   allowing a PR to suppress its own organization-blocking finding.
3. Decide whether a policy-file edit requires a dedicated policy owner review
   on top of protected-ref activation. A preview must never be authoritative.
4. Publish consumer conformance fixtures before any Action or platform
   cutover. Include image-only, clean, new, existing, first-baseline,
   disabled-but-visible, guardrail, malformed and partial-scan cases.
