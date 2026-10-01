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
- A data-plane packet travels under a **granted, canonical encoding**; encoding
  equivalence is proven by the vectors, never assumed.

## Status / Next

**Layer 0 delivered** (frozen `component-abi.v1` in `contracts/`, the v1 vectors
in `vectors/`, and the `certifier/` that runs them — 17/17 on the reference
host). Validate the WIT with the pinned `wasm-tools` recorded in
`contracts/ABI.lock.v1.json`; certify with `python3 certifier/certify.py`.

**Layer 1:** a Rust host + signed WASM components over this ABI, certified by
these same vectors (see `../pro/`). Then the Python reflection host, same ABI.
