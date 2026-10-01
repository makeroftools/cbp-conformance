"""Reference conformance host — a deterministic test double for the ABI vectors.

This is **not** a production host. It implements the `component-abi.v1`
fixtures declaratively so the conformance vectors are executable offline, and it
also serves as the external host protocol endpoint (see ``PROTOCOL.md``). A real
host (Rust, WASM, native runtime) implements the same ABI and is driven by the
certifier over the same JSON-lines protocol.

Stdlib only. Deterministic: no clock, no randomness, no I/O beyond stdio.
"""

from __future__ import annotations

import json
import sys
from typing import Any

PROTOCOL = "cbp.conformance-host.v1"
ABI = "component-abi.v1"


class ConformanceError(Exception):
    """An explicit, fail-closed ABI violation, carrying a contractual ``kind``."""

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(message or kind)
        self.kind = kind
        self.message = message or kind


def coarse_type(value: Any) -> str:
    """The coarse port-type name of a value, per the ABI vocabulary."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return "any"


def matches_type(value: Any, type_name: str) -> bool:
    """True if ``value`` satisfies the coarse ``type_name`` (``any`` matches all)."""
    return type_name == "any" or coarse_type(value) == type_name


class ReferenceHost:
    """Implements the fixtures and the ABI lifecycle/transport rules."""

    def __init__(self, fixtures: dict[str, Any], abi_sha256: str = "") -> None:
        self._fixtures = fixtures["fixtures"]
        self._contract = {
            "package-name": "cbp:component",
            "version": "1.0.0",
            "contract-hash": abi_sha256,
        }

    def identity(self) -> dict[str, Any]:
        return {"name": "cbp-reference-host", "version": "1", "abi": ABI}

    def run_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Drive one case and return its normalized observation."""
        fixture = self._fixtures.get(case["fixture"])
        if fixture is None:
            return self._result(
                [], [], [],
                ConformanceError("malformed-module", f"unknown fixture {case['fixture']!r}"),
            )
        scenario = case.get("scenario", {})
        entered: list[str] = []
        announcements: list[dict[str, Any]] = []
        packets_out: list[dict[str, Any]] = []
        error: ConformanceError | None = None
        state = "new"

        for entrypoint in scenario.get("lifecycle", ["init", "run", "kill"]):
            if entrypoint == "init":
                if state != "new":
                    error = ConformanceError("malformed-module", "init out of order")
                    break
                declared = self._declared_contract(scenario)
                if declared != self._contract:
                    error = ConformanceError("malformed-module", "declared-contract mismatch")
                    break
                entered.append("init")
                state = "initialized"
            elif entrypoint == "run":
                if state != "initialized":
                    error = ConformanceError("malformed-module", "run before init")
                    break
                entered.append("run")
                state = "running"
                try:
                    announcements, packets_out = self._run(fixture, scenario)
                except ConformanceError as exc:
                    error = exc
                    break
            elif entrypoint == "kill":
                if state not in ("initialized", "running"):
                    error = ConformanceError("malformed-module", "kill out of order")
                    break
                entered.append("kill")
                state = "killed"
            else:
                error = ConformanceError("malformed-module", f"unknown entrypoint {entrypoint!r}")
                break

        return self._result(entered, announcements, packets_out, error)

    # -- internals ----------------------------------------------------------

    def _declared_contract(self, scenario: dict[str, Any]) -> dict[str, Any]:
        if scenario.get("declared_contract_mismatch"):
            return {"package-name": "cbp:component", "version": "1.0.0", "contract-hash": "0" * 64}
        return dict(self._contract)

    def _result(
        self,
        lifecycle: list[str],
        announcements: list[dict[str, Any]],
        packets_out: list[dict[str, Any]],
        error: ConformanceError | None,
    ) -> dict[str, Any]:
        return {
            "lifecycle": lifecycle,
            "announcements": announcements,
            "packets_out": packets_out,
            "error": None if error is None else {"kind": error.kind},
        }

    def _run(
        self, fixture: dict[str, Any], scenario: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        task = fixture["tasks"][0]
        behavior = task["behavior"]
        envelope = fixture["grant"]["envelope"]

        if behavior == "probe-ungranted-capability":
            granted = {cap["name"] for cap in fixture["grant"]["capabilities"]}
            if "net" not in granted:
                raise ConformanceError("capability-denied", "capability 'net' not granted")

        if behavior == "emit-before-ready":
            raise ConformanceError("announcement-violation", "packet emitted before ready")

        announcements: list[dict[str, Any]] = []
        for channel in fixture["channels"]:
            announcements.append(
                {
                    "kind": "channel",
                    "name": channel["name"],
                    "direction": channel["direction"],
                    "port_type": channel["port_type"],
                }
            )
        for task_decl in fixture["tasks"]:
            announcements.append(
                {
                    "kind": "task",
                    "name": task_decl["name"],
                    "input-ports": task_decl["input-ports"],
                    "output-ports": task_decl["output-ports"],
                }
            )
        announcements.append({"kind": "ready"})

        if behavior == "announce-after-ready":
            raise ConformanceError("announcement-violation", "announcement after ready")

        packets = scenario.get("packets", [])
        if not packets:
            return announcements, []
        if len(packets) > envelope["step-limit"]:
            raise ConformanceError("failed", f"step-limit {envelope['step-limit']} exceeded")
        values = {packet["port"]: packet["value"] for packet in packets}

        if behavior == "identity":
            out_value = values[task["input-ports"][0]]
        elif behavior == "sum-int":
            out_value = values["a"] + values["b"]
        elif behavior == "concat-str":
            out_value = values["a"] + values["b"]
        elif behavior == "fail":
            raise ConformanceError("failed", "explicit failure")
        elif behavior == "emit-wrong-type":
            out_value = "not-an-int"
        else:
            raise ConformanceError("malformed-module", f"unknown behavior {behavior!r}")

        port = task["output-ports"][0]
        declared_type = next(c["port_type"] for c in fixture["channels"] if c["name"] == port)
        if not matches_type(out_value, declared_type):
            raise ConformanceError(
                "type-violation", f"{out_value!r} does not match declared {declared_type!r}"
            )
        return announcements, [{"port": port, "type": coarse_type(out_value), "value": out_value}]


def _emit(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    """JSON-lines host endpoint used by the certifier's ``--host-cmd`` mode."""
    host: ReferenceHost | None = None
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit({"protocol": PROTOCOL, "ok": False, "error": f"invalid JSON: {exc}"})
            continue
        op = message.get("op")
        if op == "configure":
            host = ReferenceHost(message["fixtures"], message.get("abi_sha256", ""))
            _emit({"protocol": PROTOCOL, "op": op, "ok": True, "runtime": host.identity()})
        elif op == "run":
            if host is None:
                _emit({"protocol": PROTOCOL, "op": op, "ok": False, "error": "not configured"})
                continue
            _emit(
                {
                    "protocol": PROTOCOL,
                    "op": op,
                    "id": message.get("id"),
                    "result": host.run_case(message["case"]),
                }
            )
        elif op == "shutdown":
            _emit({"protocol": PROTOCOL, "op": op, "ok": True})
            return 0
        else:
            _emit({"protocol": PROTOCOL, "op": op, "ok": False, "error": "unknown op"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
