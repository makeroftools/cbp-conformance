# vectors/ — language-agnostic conformance vectors

Versioned contract + golden cases that any host/runtime must pass to be
certified (SPEC-0013). Coverage: pure-function semantics (typed inputs/outputs,
edge/error cases), lifecycle (`init`/`run`/`kill` ordering, pre-init handling,
deterministic teardown), transport (ZeroMQ channel/task announcement, framing),
determinism (identical vectors → identical outputs/ordering across runs and
runtimes), and capability bounds (no escape; fail closed).

Filled in at Layer 0. Fixtures must be deterministic and runtime-neutral.
