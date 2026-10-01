# network.v1 — the pinned component network

This document freezes **`network.v1`**, the wiring layer of the CBP component
system. It is normative, versioned with `component-abi.v1`, and language- and
runtime-agnostic. It is the contract a host implements and the conformance
vectors certify; it encodes no single implementation's details.

The network is **orthogonal to the components it comprises** (SPEC-0014): a
component never knows its wiring, and at rest a component has no edges. Wiring
exists only in a network document.

## 1. Hard invariant — execution only runs a content-addressed network

A network document is **pinned** before it is executed. The host MUST refuse to
run an unpinned or mis-pinned network (fail-closed). This holds for static and
generated networks alike: a generated network is content-hashed and pinned
before it runs, so replay may reconstruct byte-identical wiring.

A **live-wired, never-pinned** network is not an admissible trust model for a
verified result and is rejected.

## 2. The document

A `network.v1` document is a canonical-JSON object (`ABI.md` §2a):

```json
{
  "schema": "cbp.network.v1",
  "abi": "component-abi.v1",
  "id": "<network id>",
  "components": [
    {"id": "<local id>", "fixture": "<component fixture id>"}
  ],
  "edges": [
    {"from": "<component id>", "from_port": "<out channel>",
     "to": "<component id>", "to_port": "<in channel>"}
  ],
  "iips": [
    {"to": "<component id>", "port": "<in channel>",
     "type": "<coarse type>", "value": <value>}
  ],
  "provenance": {"kind": "static" | "planner", "...": "..."},
  "content_hash": "<lowercase sha256 hex>"
}
```

- `components` names each node by a local id and the `component-abi.v1` fixture
  it instantiates. Local ids are unique and non-empty.
- `edges` wire a source component's declared **out** channel to a target
  component's declared **in** channel. An edge never crosses a component
  boundary implicitly: the ports named MUST be declared by the referenced
  fixtures.
- `iips` bind an Initial Information Packet to a target in channel. An in
  channel MAY carry an IIP or an incoming edge, never both (fail-closed).
- `provenance` is **optional** metadata identifying how the network was
  produced. Absent means `static` (authored and pinned by hand). A `planner`
  provenance records the deterministic generator (see §4).
- `content_hash` is the **pin** (below).

## 3. The pin (content address)

The pin is the lowercase hex sha256 of the **canonical JSON of the document with
the `content_hash` member removed**, where canonical JSON is sorted keys, tight
separators (`,` `:`), UTF-8, and integers-only numbers (`ABI.md` §2a). The pin is
independent of key insertion order and of the transport's whitespace, so two
hosts always compute the same value for the same wiring.

The pin commits to the **whole** document — components, edges, IIPs, and
provenance — so it is a complete content address of the wiring and of how it was
produced.

A host MUST reject a document whose `content_hash` is absent or empty
(`not-pinned`) or does not equal the computed pin (`pin-mismatch`), before any
component is instantiated.

## 4. Generated networks and deterministic replay

A network may be **generated** just before execution rather than authored. Two
admissible modes exist (SPEC-0014):

- **Deterministic planner** — a signed planner generates the network from
  deterministic inputs; the plan is content-addressed. **Replay re-runs the
  planner and reconstructs byte-identical wiring.**
- **Autonomy proposes, the pin disposes** — an autonomous (possibly
  model-mediated) agent proposes the network; the **pinned plan is the trust
  anchor** and replay uses the frozen plan rather than regenerating it.

A proposed plan is simply a pinned `network.v1` document (§1–§3): the pin
disposes. The stronger, self-verifying mode is the deterministic planner, which
a host records as `provenance`:

```json
"provenance": {"kind": "planner", "planner": "<planner fixture id>", "inputs": <value>}
```

For a `planner`-provenanced document the host MUST, **before executing**:

1. look up the named planner; an unknown planner is `unknown-planner`;
2. re-run the planner deterministically on `provenance.inputs` to regenerate the
   `components` / `edges` / `iips` wiring;
3. re-assemble the document from the pinned `schema` / `abi` / `id` /
   `provenance` and the regenerated wiring, canonicalize it, and require its pin
   to equal the recorded `content_hash`.

If the regenerated wiring does not reproduce the pin, the host refuses
(`plan-mismatch`). This makes the pin a proof of the planner's deterministic
output: tampering with the wiring — even with a self-consistent recomputed pin —
is caught, because replay regenerates the true wiring. A planner's output is
therefore deterministic **once its inputs are pinned**.

## 5. Typed enforcement at instantiation

Every edge is contract-checked **at instantiation**, static or dynamic, and the
network fails closed on mismatch:

- the source fixture MUST declare the named out channel, and the target fixture
  MUST declare the named in channel (`malformed-network`);
- the source out-channel type and the target in-channel type MUST be compatible:
  `any` is compatible with every type, and two concrete types are compatible only
  when equal (`type-mismatch`);
- every IIP value MUST match its target in-channel's declared type
  (`type-violation`).

Type compatibility operates on the coarse ABI vocabulary `str | int | float |
bool | dict | list | null | any`.

## 6. Execution and the trajectory

The network executes its components in a **deterministic topological order**
(ties broken by ascending component id), so identical wiring always produces the
identical trajectory. Each component activation gathers its inputs (IIPs plus the
values delivered on incoming edges), invokes its task, and validates the output
against the declared out-channel type.

A host records a single **trajectory**:

```json
{
  "network_sha256": "<the pin>",
  "encoding": "json",
  "steps": [
    {"step": 0, "component": "<id>", "task": "<task name>",
     "inputs":  [{"port": "<in>",  "type": "<coarse>", "value": <value>}],
     "outputs": [{"port": "<out>", "type": "<coarse>", "value": <value>}]}
  ]
}
```

Steps are ordered by execution; `inputs` and `outputs` are sorted by port for
determinism. For a `planner`-provenanced network the trajectory also carries a
`"provenance": {"kind": "planner", "planner": "<id>"}` record, so the recorded
trajectory states how the wiring was produced. The pin is **part of the recorded
trajectory**, so a replay can prove it ran the same wiring: replay re-runs the
same pinned document (re-verifying a planner, §4) and MUST reproduce a
byte-identical trajectory.

## 7. Errors (fail-closed)

A refusal carries an explicit, contractual `kind`. The network-level kinds are:

| kind | meaning |
| --- | --- |
| `not-pinned` | `content_hash` absent or empty |
| `pin-mismatch` | `content_hash` does not equal the computed pin |
| `unknown-planner` | a `planner` provenance names a planner the host was not configured with |
| `plan-mismatch` | re-running the planner does not reproduce the pinned wiring |
| `malformed-network` | structural defect (unknown component/port, duplicate id, cycle, bad IIP/edge pairing) |
| `unknown-fixture` | a component names a fixture the host was not configured with |
| `type-mismatch` | an edge's out/in types are incompatible |
| `type-violation` | an IIP or task output violates a declared type |
| `encoding-violation` | a value is outside the granted canonical encoding |
| `failed` | any other explicit, contained failure |

Every failure is explicit and audited; there is no silent or partial success
(Law 8).

## 8. Revisions

- **revision 2** — adds the optional `provenance` block and the deterministic
  planner replay (§4). Additive: a document with no `provenance` is unchanged.

## 9. Conformance

The executable contract is `vectors/network-suite.v1.json` against
`vectors/network-fixtures.v1.json`, pinned by `vectors/network.lock.v1.json`.
The certifier drives a host over `cbp.conformance-host.v1` and requires the
trajectory and every terminal output to match, byte-identically across
`determinism.runs` repetitions. A host is certified, never assumed.
