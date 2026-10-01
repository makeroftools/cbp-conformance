# certifier/ — runtime certification

Runs the `vectors/` against a candidate host/runtime and emits a signed
certification record. A runtime that has not passed is not trusted to execute
(SPEC-0013). Stub at Layer 0; must record the runtime identity/version for replay.
