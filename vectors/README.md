# vectors/ — language-agnostic conformance vectors

Versioned golden cases that any host/runtime must pass to be certified
(SPEC-0013). The vectors are **data**, not code: an implementation detail of any
single language or runtime is forbidden here.

| file | what |
| --- | --- |
| [`fixtures.v1.json`](fixtures.v1.json) | The reference component **fixtures**: declared channels (ports, direction, coarse `port_type`), tasks, behavior, and grant. A host implements each fixture id once. |
| [`suite.v1.json`](suite.v1.json) | The **cases**: fixture + scenario + expected normalized observation. |
| [`vectors.lock.v1.json`](vectors.lock.v1.json) | The **content address** of the suite and fixtures, plus the ABI `contract_sha256` they certify. |
| [`network-fixtures.v1.json`](network-fixtures.v1.json) | The **network fixtures**: the component fixtures a network instantiates plus the pinned `network.v1` documents. |
| [`network-suite.v1.json`](network-suite.v1.json) | The **network cases**: a pinned network + scenario + expected trajectory/outputs (Layer 2). |
| [`network.lock.v1.json`](network.lock.v1.json) | The content address of the network suite/fixtures and the `network.v1` contract document. |

## Categories (SPEC-0013)

- **semantics** — pure-function typed inputs to typed outputs, including edge and
  error cases.
- **lifecycle** — `init` / `run` / `kill` ordering, pre-init handling,
  deterministic teardown.
- **transport** — channel/task announcement over the initial hard-coded
  channels, the `ready` close, packet ordering.
- **determinism** — identical vectors yield identical outputs and ordering across
  runs (`determinism.runs`).
- **capability** — a component cannot exceed its granted capabilities or envelope;
  escape attempts fail closed.
- **encoding** — the data plane renders the *same typed value* deterministically
  under the granted encoding (`json` baseline, pinned canonical `msgpack`),
  cross-encoding equivalence holds, and non-canonical bytes are rejected
  fail-closed (see `contracts/ABI.md` §2a–§2b).
- **network** — a `network.v1` document is content-addressed (pinned) before it
  runs; every edge is type-checked at instantiation; execution is a deterministic
  topological order whose trajectory (including the pin) is replayable (see
  `contracts/network-v1.md`).

## Canonical form (content addressing)

Both JSON files are stored in canonical form so their sha256 is stable:

```
UTF-8, keys sorted, separators "," and ":", json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=False) + one trailing newline
```

The certifier refuses to run unless each file re-serializes byte-for-byte to its
canonical form **and** matches `vectors.lock.v1.json`, and unless
`contract_sha256` matches `contracts/ABI.lock.v1.json`.

## Scenario

```json
{"lifecycle": ["init","run","kill"],   // entrypoints to invoke, in order (default)
 "encoding": "json",                   // the data-plane encoding the host grants ("json"|"msgpack")
 "declared_contract_mismatch": false,  // force a boot-config contract mismatch
 "packets": [{"port":"in","type":"int","value":42}],              // typed inputs
 "raw_packets": [{"port":"in","encoding":"msgpack","hex":"2a"}]}  // pre-encoded bytes (strict decode)
```

An input may be given **typed** (`packets`) or **pre-encoded** (`raw_packets`).
A raw packet is decoded under its declared encoding and its bytes must be in
**canonical form**; any non-canonical, non-conformant, or trailing byte sequence
is rejected as `encoding-violation`.

## Normalized observation

A host reports, per case:

```json
{"lifecycle": ["init","run","kill"],
 "announcements": [{"kind":"channel","name":"in","direction":"in","port_type":"any"},
                   {"kind":"task","name":"identity","input-ports":["in"],"output-ports":["out"]},
                   {"kind":"ready"}],
 "packets_out": [{"port":"out","type":"int","value":42}],
 "encoded": [{"port":"out","encoding":"msgpack","hex":"2a"}],
 "error": null}
```

Dynamic endpoints and free-text error messages are **dropped** in normalization:
endpoints are runtime-specific and must not affect conformance, and only
`error.kind` is contractual.

## Comparison rule

- `error` (its `kind`, or `null`) is always compared.
- `lifecycle` is compared when present in the expected observation.
- When the expected `error` is `null`, `announcements`, `packets_out`, and — when
  present — `encoded` are compared exactly (ordered).
- `network_sha256` and `trajectory` are compared when present in the expected
  observation (network cases).

Fixtures must be deterministic and runtime-neutral. Certification is defined in
[`../certifier/`](../certifier/).
