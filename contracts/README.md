# contracts/ — the frozen CBP contracts

The versioned, additive-only contracts certified by [`../vectors/`](../vectors/)
and implemented by every host. Each is content-addressed in a `*.lock.v1.json`.

| file | what |
| --- | --- |
| [`component-abi-v1.wit`](component-abi-v1.wit) | The machine-checkable **WIT** surface of `component-abi.v1`, validated with the pinned `wasm-tools` recorded in `ABI.lock.v1.json`. |
| [`ABI.md`](ABI.md) | The **normative prose** of `component-abi.v1`: lifecycle, transport, the initial hard-coded channels, and the announcement rule. Hashed by `abi_md_sha256` in the lock. |
| [`ABI.lock.v1.json`](ABI.lock.v1.json) | The **content address** of the ABI (`contract_sha256`, revision 3) and of `ABI.md`, plus the pinned `wasm-tools`. |
| [`network-v1.md`](network-v1.md) | `network.v1` (revision 2): pinned-before-run networks, typed edges, deterministic replayable trajectories, and generated-network pin reproduction. |
| [`appointed-v1.md`](appointed-v1.md) | `appointed.v1` (revision 1): the allowlisted appointment gate, ordered fail-closed admission, A0 containment, and a recorded Assurance Label. |
| [`ui-v1.wit`](ui-v1.wit) | The machine-checkable **WIT** surface of `ui.v1` — the target-agnostic **UI world** (`cbp:ui@1.0.0`), validated with the pinned `wasm-tools` in `ui.lock.v1.json`. |
| [`UI-ABI.md`](UI-ABI.md) | The **normative prose** of `ui.v1`: targets, the projection/directive boundary, mandatory sandboxing, and assembly. Hashed by `ui_md_sha256`. |
| [`ui.lock.v1.json`](ui.lock.v1.json) | The **content address** of the UI ABI and of `UI-ABI.md`, plus the pinned `wasm-tools`. |

`component-abi-v1.wit` and `ABI.md` are **one contract**, versioned together as
`component-abi.v1`; if they disagree, the WIT is the machine-checkable surface and
`ABI.md` is the normative prose. `component-abi.v1` is **consumed** — a full WASM
guest and both hosts implement it — so changes are **additive-only**; anything
else is `component-abi.v2`.
`ui-v1.wit` and `UI-ABI.md` are **one contract**, `ui.v1`; it is additive and
extends `component-abi.v1` (no new node kind). A `ui.v1` conformance suite is
future (SPEC-0022).
