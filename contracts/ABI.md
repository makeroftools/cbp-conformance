# CBP Component ABI v1 — the language- and runtime-agnostic component contract

**Status:** Layer 0, frozen. **Authority:** `core/specs/SPEC-0012` (component ABI)
and `core/specs/SPEC-0013` (cross-runtime realization). **Classification:**
mission-critical. This document and `component-abi-v1.wit` are **one contract**,
versioned together as `component-abi.v1`; if they disagree, the WIT is the
machine-checkable surface and this document is the normative prose. Both defer to
`core/PRINCIPLES.md` (Laws 1, 2, 5, 8, 11).

The typed surface is frozen in [`component-abi-v1.wit`](component-abi-v1.wit).
This document states the rules that WIT cannot express: the lifecycle, the
transport, the initial hard-coded channels, and the announcement rule.

## 0. The model

A component is a **special abstract object**. It is **virtual and blank at
rest**: it carries a typed interface contract and a language/runtime
requirement, but the concrete **task it invokes is loaded dynamically**. A
component therefore depends only on **its language and its runtime** — never on
a baked-in implementation.

A component is realized as a module exporting exactly three entrypoints:
`init`, `run`, `kill`. The ABI is deliberately minimal so a host can execute
components it was never built against.

## 1. Lifecycle (normative)

| entrypoint | when | receives | effect |
| --- | --- | --- | --- |
| `init(boot_config)` | once, **before anything else** | the typed pre-init boot config (identity, declared contract, environment) | one-time setup only |
| `run(event_loop)` | after `init`, long-lived | the initial channels; **all body data arrives over the loop** | announces channels/tasks, then processes packets |
| `kill()` | last | nothing | deterministic teardown |

- **Pre-init / body split is hard.** Everything the component needs *before*
  the loop opens is in `boot_config` and is delivered **only** to `init`.
  Everything *during* the loop is delivered over the loop. `run` receives
  **everything except the pre-init already given to `init`**; it is not handed
  the boot config again.
- **Ordering is fixed:** `init` → `run` → `kill`, once each. Missing any of the
  three, calling `run` before `init`, or re-entering after `kill` is
  `malformed-module` (fail-closed).
- **`declared-contract` must equal `identity.contract`.** A mismatch is refused
  fail-closed: a host may never pin one contract and receive another.
- **Teardown is deterministic.** After `kill` no channel, task, or state handle
  is live; a host that observes continued activity fails closed.

## 2. Transport (normative)

**Transport is ZeroMQ.** The event loop is a ZeroMQ socket loop; channels are
ZeroMQ endpoints. The transport is a property of the channel, not the protocol:
the same frame is identical over `inproc://`, `ipc://`, and `tcp://`.

A frame is a sequence of ZeroMQ parts:

```
[identity?]   [correlation-id]   [kind]   [body]
```

- `identity` — the sender's routing identity, prepended by a ROUTER; absent on a
  DEALER.
- `correlation-id` — its own part, echoed on every ack/response. This is what
  makes asynchronous matching deterministic and idempotency checkable.
- `kind` — `directive` | `ack` | `response` | `announcement` | `packet`.
- `body` — the `frame-body` from the WIT: a structured `announcement`, a
  structured `packet` (`packet-value`), or canonical JSON (`control`).

A host mediates every send and receive through the imported `transport`
interface (`send` / `receive`): a WASM or otherwise sandboxed component cannot
open a socket itself.

### The control plane and the data plane (encodings)

The frame body is split by plane:

- **Control plane** — `announcement` bodies and lifecycle `control` bodies
  (directive / ack / response): **always canonical JSON**. They are small,
  stable, and human-auditable; an operator can read a lifecycle trace without a
  decoder.
- **Data plane** — `packet` bodies: a `packet-value` (`declared-type` + `data`)
  rendered under the **one encoding the host grants for the session**
  (`event-loop.encoding`). Using an un-granted encoding is refused.

`json` is the **mandatory baseline** encoding. `msgpack` is admitted only under
the pinned canonical profile in §2b; a runtime is trusted with it only after it
passes the encoding vectors. Equivalence between encodings is **proven by the
vectors, never assumed** (SPEC-0013): the same typed value must decode
identically under both, and each must produce its canonical bytes.

If the session encoding for a host is `msgpack`, the *semantic* record is
unchanged; only the data-plane rendering differs.

### Canonical JSON (the `json` encoding, and all control-plane bodies)

To keep the wire language-neutral and deterministic, JSON is canonical:

- UTF-8, no BOM.
- Object keys sorted by Unicode code point; no insignificant whitespace
  (separators `,` and `:`).
- Numbers are **integers only** (signed 64-bit). Non-integer IEEE-754 binary64
  numbers are **not representable** in canonical JSON: a float value MUST be
  carried under a binary encoding (`msgpack`, float64). NaN and infinity are
  forbidden in every encoding.
- `true` / `false` / `null` lowercase; minimal string escaping.

This is exactly `json.dumps(obj, sort_keys=True, separators=(",", ":"))` in the
reference control plane, and mirrors its hand-off type vocabulary
(`str`/`int`/`float`/`bool`/`dict`/`list`/`null`/`any`).

### Canonical MessagePack (the `msgpack` encoding) — pinned profile

MessagePack has **no standardized canonical form**. To use it without
reintroducing nondeterminism, `component-abi.v1` pins this profile; a runtime
that emits any other form is non-conformant:

- **Integers** — signed 64-bit only, in the **shortest** form. Positive fixint
  `0x00`–`0x7f`; negative fixint `0xe0`–`0xff`; otherwise minimal
  `int8`/`int16`/`int32`/`int64` (negative) or `uint8`/`uint16`/`uint32`/`uint64`
  (non-negative). An integer MUST NOT be encoded as a float.
- **Floats** — **float64 (`0xcb`) only**, finite. NaN and infinity are forbidden;
  float32 (`0xca`) is not permitted (it would silently lose precision).
- **Strings** — UTF-8; fixstr for length ≤ 31, else minimal `str8`/`str16`/`str32`.
- **Binary** — minimal `bin8`/`bin16`/`bin32`.
- **Arrays** — fixarray for length ≤ 15, else minimal `array16`/`array32`.
- **Maps** — string keys only, **sorted ascending by UTF-8 byte order**;
  duplicate keys forbidden; fixmap for length ≤ 15, else minimal `map16`/`map32`.
- **Nil / booleans** — `0xc0` / `0xc2` / `0xc3`.
- No ext, timestamp, or reserved types; **no trailing bytes**; nesting depth
  bounded (32). A decoder MUST reject any non-canonical or non-conformant input
  as `encoding-violation` (fail-closed).

`json` remains the mandatory baseline. MessagePack is a **performance** rendering
of the *same* typed value; it never changes semantics. CBOR with RFC 8949 §4.2
deterministic encoding is the preferred *standardized* binary encoding and may be
added additively in a future revision.

## 3. Initial hard-coded channels (normative)

At the moment `run` begins, **exactly two channels exist** — the **initial
hard-coded channels** — and their endpoints are handed to `run` in the
`event-loop` record:

| channel | field | carries |
| --- | --- | --- |
| control | `control-endpoint` | lifecycle directives **in**; all announcements **out** |
| data | `data-endpoint` | Information Packets (**in**) |

No other channel exists until it is announced. Any send or receive on an
unannounced channel — or a receive on a channel the peer has not bound — is
`announcement-violation`, fail-closed.

## 4. The announcement rule (normative)

**All channels (ports) and all tasks are announced over the initial, hard-coded
channels — never over an ad-hoc one.**

In `run`, before any packet flows, the component sends, on the **control**
channel:

1. one `announcement.channel` per named port (direction, declared `port-type`,
   endpoint), then
2. one `announcement.task` per task (its input and output port names), then
3. exactly one `announcement.ready`, closing the set.

Rules:

- Announcements are **ordered**; `ready` is last.
- A packet before `ready`, a second `ready`, an announcement after `ready`, or an
  announcement sent on the data channel is `announcement-violation`.
- Ports are **dynamic runtime endpoints instantiated from the contract**. They
  are **never identity**.
- **At rest, a component has no edges.** A `component.v1` manifest carries no
  wiring; dependency exists only in a network document (`SPEC-0014`), never in
  the component.

## 5. Identity (normative)

Identity is **two-level** and is **never** the ports:

- **Abstract component** = the hash of its typed interface contract. This is
  language- and runtime-agnostic and is what a network binds against. It is
  carried as `interface-ref.contract-hash`: the lowercase sha256 (64-hex) of the
  exact bytes of the frozen contract document, recorded in
  [`ABI.lock.v1.json`](ABI.lock.v1.json).
- **Concrete task** = its signed **content hash** plus `provenance`
  (`artifact-ref`). This is the artifact that executes.
- Ports are dynamic endpoints (above); they are not identity.
- **At rest, a component has no edges** (above).

## 6. Registry sources (normative)

A component's registry entry may point to an **open, extensible** set of
sources — a git repo, a directory, a binary, … — anything content-addressable.
The **source kind never changes identity**: the resolved artifact is always
content-hashed and signed (`tree-sha256`, `content-hash`, `signature`).

## 7. Least privilege (normative)

A component receives only the capabilities and envelope it was granted
(`grant`). The envelope (`timeout-ms`, `step-limit`, `state-bytes`) is **not
advisory**; exceeding it fails closed. A capability not granted is
`capability-denied`. A component runs only what its grant permits.

## 8. Fail-closed rejection

A host rejects a module, fail-closed, when any of these holds:

- it does not match the `component-abi-v1` world (a missing/extra entrypoint, or
  a mismatched signature) — `malformed-module`;
- `declared-contract` disagrees with `identity.contract` — `malformed-module`;
- it announces off the initial channels, announces a channel/task after `ready`,
  or emits a packet before `ready` — `announcement-violation`;
- a packet violates its declared `port-type` — `type-violation`;
- a packet's bytes are not in the granted encoding's canonical form —
  `encoding-violation`;
- it uses a capability or exceeds the envelope it was not granted —
  `capability-denied` / `failed`.

There is **no third state**: a component either completes with a verified
outcome or ends in an explicit, contained, audited `abi-error`.

## 9. Versioning

The ABI is **additive-only**. `component-abi.v1` is frozen; any incompatible
change is `component-abi.v2` with a new `contract-hash`. The legacy
in-process/args path is untouched until cross-runtime equivalence is proven by
the conformance vectors (`SPEC-0013`, `SPEC-0002` §13).

## 10. Realization paths (SPEC-0013)

A component may be realized by **translation/compilation** (canonically WASM) or
by **native-runtime invocation** (language-server protocol, dialed-up JIT
runtime). Both must honor this ABI and both must pass the same
[`vectors/`](../vectors/) suite. Equivalence is **proven by the vectors, never
assumed**: Turing completeness guarantees computability, not equivalence.
Translation output is a **generated artifact**, untrusted until it passes the
suite. The runtime is part of the trusted computing base: version-pinned,
signed, and recorded.
