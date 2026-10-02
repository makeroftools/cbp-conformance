# UI ABI v1 (`ui.v1`) — target-agnostic UI components

> **Draft** (companion to
> [`SPEC-0022`](https://github.com/makeroftools/agent-centric/blob/main/specs/SPEC-0022-frontend-and-components.md)).
> This document and [`ui-v1.wit`](ui-v1.wit) are **one contract**, versioned
> `ui.v1`. The `.wit` file freezes the typed surface; this document is normative
> for the transport, the sandbox, the assembly, and the trust rules that WIT
> cannot express. Content addresses are recorded in [`ui.lock.v1.json`](ui.lock.v1.json).

## 1. One node ontology

A **UI component** is an ordinary CBP component
([`component-abi.v1`](component-abi-v1.wit)) that additionally implements the
`cbp:ui/ui` world. It is **not** a new node kind. Presentation travels with the
component, but it is a **separate, additive** artifact: changing a view never
changes a behavior component's content address or its verified semantics
([`SPEC-0013`](SPEC-0013-cross-runtime-conformance.md)).
**Core stays headless**; the UI build and targets live in pro/enterprise
([`SPEC-0016`](SPEC-0016-editions-distribution-cloud.md)).

## 2. The world

A UI component **exports**:

- `describe() -> result<ui-manifest, ui-error>` — its target-neutral manifest;
- `render(projection) -> result<json, ui-error>` — a target-neutral tree from a
  granted projection (canonical JSON);
- `handle(event) -> result<option<directive>, ui-error>` — handle one target
  event, optionally emitting a single directive.

and **imports** the host boundary (the **only** way to read state or take effect):

- `get-projection(schema) -> result<projection, ui-error>`;
- `submit-directive(directive) -> result<string, ui-error>`;
- `log(message)` — bounded, non-mutating.

A UI holds **no execution capability** and **no ambient authority** (no DOM
beyond its own boundary, no network, no filesystem, no host API).

## 3. Targets and bindings

`ui-target` is `web | cli | os | embedded`. A **target** is a renderer + sandbox
for a medium and **implements** this ABI — e.g. `web` binds to standard **web
components**, `cli` to a text/ANSI renderer, `os` to a native toolkit, `embedded`
to a minimal renderer. A target binding is **content-addressed, version-pinned,
and recorded** (it is TCB). The ABI is **target-neutral**: a target never changes
a UI component's meaning. A component may ship per-target bundles or a
target-neutral descriptor compiled to a target.

## 4. Projections — the read boundary

`render` consumes a **projection**: `{schema, content-hash, assurance, data}`,
where `data` is canonical JSON of a **pinned** document
(`cbp.diagram.v1`, `review.v1`, ledger, activity, transparency, provider
evidence, domain/artifact readouts, …). A projection is **provenance-honest**:
`assurance` is `verified | model | unverified | refused`, and a view **must**
render that status truthfully — an unverified claim never renders as verified
([`SPEC-0015`](SPEC-0015-provenance-assurance-labels.md)). A UI may request only
the schemas its manifest declares; otherwise `projection-denied`.

## 5. Directives — the effect boundary

`handle` may emit **one** content-addressed **directive** (`{name, args}`). A UI
may emit only the directives its manifest declares; otherwise `directive-denied`.
Every directive is executed by the **verified spine** (validate → canonicalize →
pin → verify → run); irreversible acts keep their operator gates. **The UI never
mutates platform state directly.**

## 6. Security (normative — security over dynamicism)

1. **Verify before execute.** A UI bundle is content-addressed and
   signature/attestation-verified **before** it loads; a failed check or an
   unknown `abi-version` → `abi-mismatch` (refuse).
2. **Mandatory, provenance-tiered sandbox.** UI code runs behind a capability
   sandbox with **zero ambient authority**. The tier follows provenance:
   **trusted** (operator-signed) may hold tightly-scoped declared capabilities;
   **appointed** (allowlist + detached signature) runs **A0** (zero capabilities,
   all I/O mediated); **discovered/generated** runs the strongest sandbox and is
   never auto-trusted.
3. **Web components are encapsulation, not isolation.** The real boundary is the
   target's host (e.g. an `iframe` with `sandbox` and no `allow-same-origin` +
   strict CSP, a worker/wasm capability runtime, or an OS sandbox).
4. **No secrets.** Secret material never enters a projection, manifest, bundle, or
   record; only **refs**. The host resolves secrets server-side and injects the
   minimum non-secret projection.
5. **Default deny + fail-closed.** Undeclared projections, directives, and
   capabilities are withheld; every refusal is explicit and audited.

## 7. Assembly and pinning

The front end serves a **content-addressed UI composition** of the UI components
applicable to the requested target, **pinned before it renders** (the
[`SPEC-0014`](SPEC-0014-network-execution-trust.md) pin rule): the same pinned
composition renders identically. Unknown or ABI-incompatible UI is **skipped, not
executed**; the surface degrades to the raw projection rather than failing whole.

## 8. Distribution

UI bundles are content-addressed, signed, cached offline, and verified on load;
they are served from the **local mirror/cache** (local-first,
[`SPEC-0007`](https://github.com/makeroftools/agent-centric/blob/main/specs/SPEC-0007-harness-shell-component-distribution.md)).
No CDN is required.

## 9. Versioning

`ui.v1` is **additive**: new targets, schemas, directives, and capability names
extend it without breaking an existing manifest. A breaking change is `ui.v2`. An
unknown version refuses.

## 10. Conformance (future)

A `ui.v1` conformance suite will pin the ABI's content address and prove, with
shared vectors, that `describe`/`render`/`handle` are deterministic and that the
deny paths (`projection-denied`, `directive-denied`, `abi-mismatch`) fail closed
on every host. The resolver is the pinned `wasm-tools`; the content address is
[`ui.lock.v1.json`](ui.lock.v1.json).
