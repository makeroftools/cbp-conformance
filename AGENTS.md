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

**Layers 0/1a/1b/1c delivered.** `contracts/` freezes `component-abi.v1`
(revision 3: the data-plane `transport.send-on` / `receive-on`; validated with the
pinned `wasm-tools` in `ABI.lock.v1.json`); `vectors/` holds the shared suite
(**31/31** on the Python reference host and the Rust host) and the WASM
execution suite (**8/8**, run against `artifacts/{identity,abi-identity}.wasm` by
the Rust host — including a full `component-abi.v1` guest). Certify with
`certifier/certify.py`; `../pro/scripts/certify.sh` runs both suites.

**Next:** artifact signing/provenance (accept/refuse vectors over content
addressing), then Layer 2 (content-addressed network execution).
