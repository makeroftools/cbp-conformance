# artifacts/ — content-addressed WASM fixtures

Committed WASM **components** used by the execution suite
([`../vectors/wasm-suite.v1.json`](../vectors/wasm-suite.v1.json)). They are
**language-agnostic build outputs**: a host loads one only after its bytes match
the declared `sha256` in the fixture descriptor (fail-closed), then executes it.

| artifact | sha256 | what |
| --- | --- | --- |
| `identity.wasm` | see the fixture descriptor / `wasm.lock.v1.json` | A WASM component exporting `init`/`run`/`kill` over the narrow `cbp:fixture` task world; `run` echoes its canonical-JSON input (Layer 1b substrate). |
| `abi-identity.wasm` | see the fixture descriptor / `wasm.lock.v1.json` | A full **`component-abi.v1`** WASM guest (Layer 1c): it exports the ABI world, announces its channels/task over the control channel, and exchanges Information Packets on its data channels via the host-mediated `transport`. |

Source: [`pro/fixtures/`](https://github.com/makeroftools/cbp-pro)
(`identity/`, `abi-identity/`; Rust, built with the pinned `cargo-component`
against `../contracts/component-abi-v1.wit`). The component ABI
(`component-abi.v1`) is the runtime contract for `abi-identity.wasm`; the
`identity.wasm` fixture world proves the content-addressed execution substrate.
