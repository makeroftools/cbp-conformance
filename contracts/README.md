# contracts/ — the frozen component ABI (WIT)

The frozen ABI is the **language- and runtime-agnostic** component contract
(SPEC-0012). Nothing language-specific lives here.

| file | what |
| --- | --- |
| [`component-abi-v1.wit`](component-abi-v1.wit) | The typed surface: `init` / `run` / `kill`, the pre-init boot config, identity, capabilities, channels/tasks, and the framed transport unit. Validated with the pinned resolver. |
| [`ABI.md`](ABI.md) | The **normative prose**: lifecycle ordering, the ZeroMQ event loop, the initial hard-coded channels, the announcement rule, identity, registry sources, least privilege, and fail-closed rejection. Read together with the WIT. |
| [`ABI.lock.v1.json`](ABI.lock.v1.json) | The **content address** of the contract: `source_sha256` (the abstract identity anchor) and `resolved_sha256` (the semantics-only check), plus the pinned resolver. |
| [`network-v1.md`](network-v1.md) | The **normative** `network.v1` contract: the orthogonal wiring layer, the pin (content address) rule, typed enforcement at instantiation, and the replayable trajectory (SPEC-0014, Layer 2 static). |

## Validate

```sh
wasm-tools component wit component-abi-v1.wit      # pinned: see ABI.lock.v1.json
```

`component-abi.v1` is frozen and additive-only; an incompatible change is
`component-abi.v2` with a new `contract-hash`. Revision 3 added the additive
data-plane transport (`transport.send-on` / `transport.receive-on`), keyed by the
announced channel endpoint; the control plane (`send` / `receive`) is unchanged.
