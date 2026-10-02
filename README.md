# conformance — the shared CBP contract

Public. This repository is the **single shared contract** that proves the Python
reflection (`../core`), the Rust host (`../pro`), and WASM execution are
equivalent (SPEC-0013). It holds the frozen WIT/ABI, the conformance vectors, the
certifier, and the content-addressed WASM fixtures. Nothing here encodes an
implementation detail of any one language or runtime.

See [`AGENTS.md`](AGENTS.md) for the hard laws and invariants; the architecture is
frozen in `../core/specs/SPEC-0012` (component ABI) and
`../core/specs/SPEC-0013` (cross-runtime realization and conformance vectors).

## Layout

| path | what |
| --- | --- |
| [`contracts/`](contracts/README.md) | The frozen contracts: `component-abi.v1` (WIT + normative `ABI.md` + `ABI.lock.v1.json`), `network.v1`, `appointed.v1`, `ui.v1`. |
| [`vectors/`](vectors/README.md) | The language-agnostic conformance cases and their content addresses: the shared ABI suite (**31**), `network.v1` (**14**), `appointed.v1` (**8**), and the WASM execution suite (**10**). |
| [`certifier/`](certifier/README.md) | `certify.py` (stdlib only) and `reference_host.py`; the `cbp.conformance-host.v1` protocol. |
| [`artifacts/`](artifacts/README.md) | The signed, content-addressed WASM fixtures (`identity.wasm`, `abi-identity.wasm`). |
| [`tools/`](tools/) | `safe-replace.sh` (Law 11). |

## Frozen contracts

- **`component-abi.v1`** (revision 3) — the abstract component contract:
  `init` / `run` / `kill`, a ZeroMQ control plane, canonical-JSON control plus a
  granted data-plane encoding, and the additive `transport.send-on` /
  `receive-on` data-plane transport.
- **`network.v1`** (revision 2) — a component network pinned (content-addressed)
  before it runs, every edge type-checked at instantiation, and a deterministic
  replayable trajectory; a generated (`planner`) network re-runs its
  deterministic planner and must reproduce the pin.
- **`appointed.v1`** (revision 1) — the allowlisted appointment gate: a
  host-configured source allowlist plus a detached Ed25519 signature over the
  exact bytes, A0 containment, and a recorded Assurance Label.

The contracts are **additive-only**: `component-abi.v1` is consumed, so any change
is `component-abi.v2` (see [`contracts/README.md`](contracts/README.md)).

## Certify a host

```sh
# Python reference host, in-process and over the external protocol
python3 certifier/certify.py
python3 certifier/certify.py --host-cmd "python3 certifier/reference_host.py"

# network.v1 / appointed.v1
python3 certifier/certify.py --suite vectors/network-suite.v1.json \
  --fixtures vectors/network-fixtures.v1.json --lock vectors/network.lock.v1.json \
  --contract-lock contracts/ABI.lock.v1.json
python3 certifier/certify.py --suite vectors/appointed-suite.v1.json \
  --fixtures vectors/appointed-fixtures.v1.json --lock vectors/appointed.lock.v1.json \
  --contract-lock contracts/ABI.lock.v1.json --artifacts-dir artifacts

# all four suites against the Rust host (builds it first)
../pro/scripts/certify.sh
```

Exit codes: `0` certified · `1` a case failed or was nondeterministic ·
`2` suite, lock, or contract drifted (refused before running). A certification
record is **deterministic** (no wall-clock) and records the host's pinned
identity/version (SPEC-0013).

## Boundary

Public origins only. The contract is runtime-neutral by construction; a runtime
and the verifier/compiler toolchain are part of the TCB — pinned, signed, and
version-recorded.
