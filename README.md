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

**Layers 0/1a/1b/1c delivered:** the `component-abi.v1` contract (revision 3,
adding the data-plane `transport.send-on` / `receive-on`) and the v1 vectors are
frozen and content-addressed. The certifier runs the shared suite **31/31** on the
Python reference host (in-process and over the protocol) and on the Rust host
(`pro/cbp-host`), and the **WASM execution suite 10/10** — including a real
`component-abi.v1` WASM guest that announces channels/tasks and exchanges
Information Packets over the transport. Artifacts are **signed**: a detached
**Ed25519** signature must verify against the host trust root in
`wasm.lock.v1.json` before anything executes (unsigned/bad-signature refused).
**Next:** Layer 2 (content-addressed network execution).
