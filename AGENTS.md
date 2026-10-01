# AGENTS.md — conformance

Public. The shared CBP contract: WIT interfaces + conformance vectors + certifier.
See `README.md`; the architecture is frozen in `../core/specs/SPEC-0012` and
`../core/specs/SPEC-0013`.

## Hard laws

- **Law 11** — no in-place edits; whole-file atomic replace via `tools/safe-replace.sh`.
- **Law 12** — the agent may run any tests; operator/CI is the record.
- **Law 13** — commit and push continuously; never `--no-verify`.

## Invariants

- The vectors are **language-agnostic** and **versioned**; a host is certified,
  not assumed.
- A runtime and the verifier/compiler/reducer toolchain are part of the TCB:
  pinned, signed, version-recorded.
- Nothing here may encode an implementation detail of any single language or
  runtime.

## Next

Layer 0: write `contracts/*.wit` (the ABI) and the first `vectors/` fixtures;
stub `certifier/` to run them against a host.
