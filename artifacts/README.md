# artifacts/ — content-addressed WASM fixtures

Committed WASM **components** used by the execution suite
([`../vectors/wasm-suite.v1.json`](../vectors/wasm-suite.v1.json)). They are
**language-agnostic build outputs**: a host loads one only after its bytes match
the declared `sha256` in the fixture descriptor (fail-closed), then executes it.

| artifact | sha256 | what |
| --- | --- | --- |
| `identity.wasm` | see the fixture descriptor / `wasm.lock.v1.json` | A WASM component exporting `init`/`run`/`kill` over the `cbp:fixture` task world; `run` echoes its canonical-JSON input. |

Source: [`pro/fixtures/identity/`](https://github.com/makeroftools/cbp-pro)
(Rust; built with the pinned `cargo-component`). The component ABI
(`component-abi.v1`) remains the runtime contract; this is a *fixture* world that
proves signed WASM execution.
