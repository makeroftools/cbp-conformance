# conformance — the shared CBP contract

This repository is the **single source of truth** for the CBP component contract
and the proof of cross-runtime equivalence. It is **public** (it is the
whitepaper's evidence and the trust proof); the Pro/Enterprise moat is
optimization and enterprise components, not the contract.

## Contents

- `contracts/` — the **WIT** interface for the component ABI (SPEC-0012):
  `component-abi-v1.wit` (`init` / `run` / `kill`, identity, capabilities,
  channels/tasks, the framed transport unit), the normative `ABI.md`, and the
  content address `ABI.lock.v1.json`.
- `vectors/` — the **language-agnostic conformance vectors** (SPEC-0013):
  `fixtures.v1.json` + `suite.v1.json`, content-addressed by
  `vectors.lock.v1.json`, covering pure-function semantics, lifecycle, transport,
  determinism, capability bounds, and the data-plane encodings (`json` / pinned
  canonical `msgpack`).
- `certifier/` — the tool that runs the vectors against a host/runtime and emits
  a deterministic **certification record**; `reference_host.py` is the test
  double, `PROTOCOL.md` is the language-neutral host protocol.

## The rule

**Equivalence is proven by the vectors, never assumed.** A realization of a
component — by translation/compilation (canonically WASM) or by native-runtime
invocation (language-server protocol, dialed-up JIT runtime) — is trusted only
after it passes the same vectors. Translation is a *generation* act; its output
is untrusted until verified.

Both `core/` (Python reflection) and `pro/` (Rust) pin this repo and must pass
its vectors; that is what lets the Python reflection stand in for Rust without
divergence.

## Certify (Layer 0, offline)

```sh
# offline, against the in-process reference host
python3 certifier/certify.py

# an external host over the cbp.conformance-host.v1 protocol
python3 certifier/certify.py --host-cmd "python3 certifier/reference_host.py"
```

Exit `0` certified · `1` a case failed/nondeterministic · `2` the suite, lock, or
contract drifted (refused before running).

## Status

**Layer 0 delivered:** the `component-abi.v1` contract and the v1 vectors are
frozen and content-addressed; the certifier runs them (17/17 on the reference
host). **Next (Layer 1):** a Rust host that loads signed WASM components over the
ABI and passes these same vectors — hence `pro/`.
