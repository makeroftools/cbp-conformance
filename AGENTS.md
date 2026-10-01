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
execution suite (**10/10**, run against `artifacts/{identity,abi-identity}.wasm`
by the Rust host — a full `component-abi.v1` guest, plus detached **Ed25519**
artifact-signing accept/refuse). The trust root is host configuration carried in
`wasm.lock.v1.json`, never fixture data. Certify with `certifier/certify.py`;
`../pro/scripts/certify.sh` runs all three suites.

**Layer 2 delivered (`network.v1` revision 2).** `contracts/network-v1.md` freezes
`network.v1`: a component network pinned (content-addressed) before it runs,
every edge type-checked at instantiation, and a deterministic replayable
trajectory that includes the pin. A `planner`-provenanced (generated) network
re-runs its deterministic planner and must reproduce the pin (`plan-mismatch`
otherwise). `vectors/network-{fixtures,suite,lock}.v1.json` (**14 cases**) pass on
**both** the Python reference host and the Rust host.

**Next:** Layer 3 (read-only web diagram from the pinned network document).
