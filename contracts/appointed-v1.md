# appointed.v1 — allowlisted appointed component sources

This document freezes **`appointed.v1`**, the trust gate for **appointed**
components (SPEC-0015). It is normative, versioned with `component-abi.v1`, and
language- and runtime-agnostic. It is the contract a host implements and the
conformance vectors certify; it encodes no single implementation's details.

An **appointed** component is admitted from a named, external origin (the
web/RAG class) rather than a static, release-signed artifact. Its bytes are
**untrusted**; they are admitted only through a host-configured **source
allowlist** and a detached signature, and they run **contained** — the A0
Assurance Label: sandboxed, **zero capabilities**.

This is the launch slice of SPEC-0015: the appointed class, its fail-closed
gate, and the recorded A0 label. The other classes (generated / discovered),
tiers A1–A4, and `review.v1` promotion remain out of scope (SPEC-0017).

## 1. Hard invariant

**Nothing executes before it is content-addressed; nothing is appointed before
it verifies against the source allowlist; every appointed component runs with
zero capabilities.** The gate is evaluated in a fixed order and fails closed: the
first violated rule refuses the component, and no component byte is executed.

## 2. Host configuration (the trust root)

The allowlist is **host configuration**, never fixture data. It is supplied to
the host at configure time (the `trust` object of the conformance protocol):

```json
"trust": {"sources": {"<source id>": "<lowercase hex ed25519 public key>"}}
```

- Each key is a 32-byte Ed25519 public key (64 lowercase hex characters).
- A source id is a non-empty string naming the appointed origin.
- An empty or absent allowlist admits nothing: every appointed component is
  `unknown-source` (fail-closed).

## 3. The appointed descriptor

An appointed component is a fixture object, canonical-JSON encoded, shaped:

```json
{
  "kind": "appointed",
  "name": "<component name>",
  "source": "<source id>",
  "license": "<SPDX identifier>",
  "artifact": {
    "file": "<path relative to the artifacts dir>",
    "sha256": "<lowercase hex sha256 of the exact bytes>",
    "signature": "<lowercase hex detached Ed25519 signature over the exact bytes>"
  },
  "channels": [ ... ],
  "tasks": [ ... ],
  "grant": {"capabilities": [], "envelope": { ... }}
}
```

- `source` names the allowlisted origin. `license` is the recorded, first-class
  license fact required for every non-static artifact (SPEC-0015).
- `artifact` content-addresses the bytes and carries the detached signature.
- `channels`, `tasks`, and the declarative `behavior` (see `ABI.md` /
  `vectors/README.md`) are the component's declared contract surface; the gate
  admits the artifact, and the declared task is then realized by the host. The
  **execution substrate** (a signed, content-addressed WASM guest) is certified
  separately by `wasm-suite.v1.json`; this suite certifies the appointment gate
  and containment.

## 4. The gate (fail-closed, ordered)

Before any byte executes, the host evaluates, in this exact order, and refuses
on the first failure:

| # | rule | refusal `kind` |
| --- | --- | --- |
| 1 | `source` and `license` are present and non-empty | `malformed-module` |
| 2 | `source` is in the host's allowlist | `unknown-source` |
| 3 | the artifact bytes match the declared `sha256` | `content-mismatch` |
| 4 | a signature is present | `unsigned-artifact` |
| 5 | the signature verifies (RFC 8032 Ed25519) over the exact bytes against the source's allowlisted key | `bad-signature` |
| 6 | the effective capabilities are empty | `capability-refused` |

Rule 6 is the A0 containment rule: an appointed component declaring any
capability is refused rather than run. The gate is deterministic and depends
only on the descriptor, the configured allowlist, and the artifact bytes.

## 5. The recorded Assurance Label

Admission records a scoped, evidence-backed **A0** label — never an absolute
"safe" claim (SPEC-0015). The recorded appointment is:

```json
{
  "property": "contained",
  "tier": "A0",
  "source": "<source id>",
  "license": "<SPDX>",
  "artifact_sha256": "<the verified content address>"
}
```

The label is a **claim plus evidence**: the tier asserts *contained,
unverified*, and the evidence is the verified content address and the
allowlisted source. It is part of the normalized observation and is reproducible.

## 6. Idempotence

The gate is pure: resolving the same descriptor against the same allowlist and
artifact bytes yields the same admission decision, the same recorded label, and
the same observation, every time. A retried admission never duplicates or
diverges from a prior one.

## 7. Errors (fail-closed)

A refusal carries an explicit, contractual `kind`:

| kind | meaning |
| --- | --- |
| `unknown-source` | the named source is not in the host allowlist |
| `content-mismatch` | the artifact bytes do not match the declared `sha256` |
| `unsigned-artifact` | no signature is present |
| `bad-signature` | the signature does not verify against the source key |
| `capability-refused` | the appointed component declares a capability (A0 requires none) |
| `malformed-module` | structural defect (missing source/license/artifact field) |
| `failed` | any other explicit, contained failure |

Every failure is explicit and audited; there is no silent or partial success
(Law 8).

## 8. Revisions

- **revision 1** — freezes the appointed class, the source allowlist, the ordered
  gate, the recorded A0 label, and idempotent admission. Additive-only from here.

## 9. Conformance

The executable contract is `vectors/appointed-suite.v1.json` against
`vectors/appointed-fixtures.v1.json`, pinned by `vectors/appointed.lock.v1.json`.
The certifier drives a host over `cbp.conformance-host.v1` and requires the
normalized observation — including the recorded appointment — to match
byte-identically across `determinism.runs` repetitions. A host is certified,
never assumed.
