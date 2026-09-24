# SourceBastion Policy Engine

Independent, offline Cedar policy engine for application-security scan gates. The project owns the policy library, CLI and protocol; scanners and other consumers own finding normalization, trusted policy delivery and enforcement.

[M042 milestone](https://github.com/sourcebastion/sourcebastion-policy-engine/milestone/1) · [Contract](docs/scan-gate-v1.md) · [Consumer boundaries](docs/consumers.md) · [Conformance](docs/conformance.md)

The legacy scanner PLAN-09 gate remains the default. The public Action and hosted platform are separate consumers and are not switched by this project.

Build and evaluate the checked-in clean example:

```sh
cargo build --release --locked
target/release/sourcebastion-policy evaluate < examples/clean.json
```

The second command needs no network, account or scanner package. It emits one JSON result and exits `0` for pass, `1` for intentional policy failure or `2` for unevaluable input/policy. The first `cargo build` downloads pinned dependencies on a fresh installation; subsequent `cargo build --offline --locked` and evaluation work without network. `examples/bundle.json` contains a critical-secret gate, a high-SAST warning, and a category threshold.

To convert the supported PLAN-09 rule vocabulary from plain JSON (without scanner imports):

```sh
printf '[{"severity":"critical","category":"secrets","max_count":0,"action":"fail"}]' | target/release/sourcebastion-policy convert-plan09
```

The converter reports unsupported rules as a nonzero error and never changes a scanner default. For scanner `shadow` and opt-in `cedar` modes, see the [consumer adapter](https://github.com/sourcebastion/sourcebastion-scanner/issues/37). The CLI's evaluator runs in a constrained worker with a 512 MiB address-space cap, a 3-second CPU cap and a 5-second wall-clock cap; an uncompleted worker becomes a structured `error` result. Embedding callers must supply equivalent resource bounds.

## Compatibility

Version `0.1.0` implements protocol `1`, schema `1` and profile `scan-gate.v1`. Consumers should pin the exact engine binary and verify all three fields plus `engine_version` and the process exit code before accepting a result. An unknown version or profile is unevaluable, not a pass. Future profile changes require a new profile name or schema version; this pre-1.0 release does not promise that unpinned future binaries preserve the same contract. Release-candidate tags remain drafts until artifact review and publication.
