# conformance — the shared CBP contract

This repository is the **single source of truth** for the CBP component contract
and the proof of cross-runtime equivalence. It is **public** (it is the
whitepaper's evidence and the trust proof); the Pro/Enterprise moat is
optimization and enterprise components, not the contract.

## Contents

- `contracts/` — the **WIT** interface definitions for the component ABI
  (SPEC-0012): `init(boot_config)` / `run(event_loop)` / `kill()`, typed
  inputs/outputs, channels/ports and tasks announced over the initial channels.
- `vectors/` — the **language-agnostic conformance vectors** (SPEC-0013):
  versioned contract + golden cases covering pure-function semantics, lifecycle,
  transport, determinism, and capability bounds.
- `certifier/` — the tool that runs the vectors against a host/runtime and
  certifies it.

## The rule

**Equivalence is proven by the vectors, never assumed.** A realization of a
component — by translation/compilation (canonically WASM) or by native-runtime
invocation (language-server protocol, dialed-up JIT runtime) — is trusted only
after it passes the same vectors. Translation is a *generation* act; its output
is untrusted until verified.

Both `core/` (Python reflection) and `pro/` (Rust) pin this repo and must pass
its vectors; that is what lets the Python reflection stand in for Rust without
divergence.
