# certifier ⇄ host protocol — `cbp.conformance-host.v1`

The **live** interface between the certifier (client) and a **host under test**.
It is language-neutral: any host — the Python reference host, the Rust host, a
WASM runtime, a native-runtime adapter — implements it and can be certified.

## Transport

JSON Lines over the host process's **stdin / stdout**. The certifier launches
the host (``--host-cmd``) and exchanges one compact JSON object per line. Any
extra logging goes to the host's **stderr**, never stdout.

## Handshake

```
→ {"protocol":"cbp.conformance-host.v1","op":"configure","fixtures":{...},"abi_sha256":"<hex>"}
← {"protocol":"cbp.conformance-host.v1","op":"configure","ok":true,
   "runtime":{"name":"...","version":"...","sha256":"<hex>"}}
```

- `fixtures` is the parsed [`fixtures.v1.json`](../vectors/fixtures.v1.json).
- `abi_sha256` is the frozen contract hash (`contracts/ABI.lock.v1.json`), so the
  host binds the same contract the vectors were built against.
- `runtime` is the **pinned identity** of the host/runtime: name, version, and
  the content hash of the runtime artifact. It is recorded in the certification
  record (SPEC-0013: the runtime is part of the trusted computing base).

## Run a case

```
→ {"protocol":"cbp.conformance-host.v1","op":"run","id":"<case id>","case":{...}}
← {"protocol":"cbp.conformance-host.v1","op":"run","id":"<case id>","result":{...}}
```

`case` is one entry of [`suite.v1.json`](../vectors/suite.v1.json). `result` is
the **normalized observation** (see [`../vectors/README.md`](../vectors/README.md)):
`lifecycle`, `announcements`, `packets_out`, `error`. Dynamic endpoints and
free-text messages are dropped in normalization; only `error.kind` is
contractual.

## Shutdown

```
→ {"protocol":"cbp.conformance-host.v1","op":"shutdown"}
← {"protocol":"cbp.conformance-host.v1","op":"shutdown","ok":true}
```

## Fail-closed

The certifier **refuses to certify** (exit 2) on a protocol mismatch, a missing
`protocol` field, or a host that closes the stream without a response. A run
that fails any case, or that is not byte-identical across `determinism.runs`
repetitions, yields `passed:false` (exit 1). There is no partial pass.

## Reference implementation

[`reference_host.py`](reference_host.py) is the deterministic reference host. Run
it directly to speak this protocol on stdio:

```sh
python3 certifier/certify.py --host-cmd "python3 certifier/reference_host.py"
```
