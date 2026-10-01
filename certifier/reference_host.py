"""Reference conformance host — a deterministic test double for the ABI vectors.

This is **not** a production host. It implements the `component-abi.v1`
fixtures declaratively so the conformance vectors are executable offline, and it
also serves as the external host protocol endpoint (see ``PROTOCOL.md``). A real
host (Rust, WASM, native runtime) implements the same ABI and is driven by the
certifier over the same JSON-lines protocol.

Stdlib only. Deterministic: no clock, no randomness, no I/O beyond stdio.

The data plane supports the two encodings frozen by the ABI: canonical JSON
(`json`) and the pinned canonical MessagePack profile (`msgpack`). Decoding is
**strict**: any non-canonical or non-conformant byte sequence is rejected as
`encoding-violation` (fail-closed).
"""

from __future__ import annotations

import json
import struct
import sys
from typing import Any

PROTOCOL = "cbp.conformance-host.v1"
ABI = "component-abi.v1"

_MP_MAX_DEPTH = 32
_S64_MIN = -(2**63)
_S64_MAX = 2**63 - 1


class ConformanceError(Exception):
    """An explicit, fail-closed ABI violation, carrying a contractual ``kind``."""

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(message or kind)
        self.kind = kind
        self.message = message or kind


class NotCanonical(Exception):
    """A byte sequence is not in its encoding's canonical form (fail-closed)."""


# --------------------------------------------------------------------------
# Value validation + canonical encodings
# --------------------------------------------------------------------------


def validate_value(value: Any, depth: int = 0) -> None:
    """Refuse values outside the frozen vocabulary or determinism bounds."""
    if depth > _MP_MAX_DEPTH:
        raise NotCanonical("nesting depth exceeds the bound")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not (_S64_MIN <= value <= _S64_MAX):
            raise NotCanonical("integer outside signed 64-bit range")
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise NotCanonical("non-finite float")
        return
    if isinstance(value, str):
        return
    if isinstance(value, list):
        for item in value:
            validate_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotCanonical("non-string object key")
            validate_value(item, depth + 1)
        return
    raise NotCanonical(f"unsupported value type {type(value).__name__}")


def _reject_float(value: Any) -> None:
    """Canonical JSON carries integers only; floats MUST use a binary encoding."""
    if isinstance(value, float):
        raise NotCanonical(
            "non-integer number in canonical JSON (use a binary encoding for floats)"
        )
    if isinstance(value, list):
        for item in value:
            _reject_float(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_float(item)


def canonical_json(value: Any) -> bytes:
    """Canonical JSON (see ABI.md §2a): sorted keys, tight separators, UTF-8."""
    validate_value(value)
    _reject_float(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _mp_int(n: int) -> bytes:
    if n >= 0:
        if n <= 0x7F:
            return bytes([n])
        if n <= 0xFF:
            return b"\xcc" + n.to_bytes(1, "big")
        if n <= 0xFFFF:
            return b"\xcd" + n.to_bytes(2, "big")
        if n <= 0xFFFFFFFF:
            return b"\xce" + n.to_bytes(4, "big")
        return b"\xcf" + n.to_bytes(8, "big")
    if n >= -32:
        return bytes([0xE0 | (n + 32)])
    if n >= -128:
        return b"\xd0" + n.to_bytes(1, "big", signed=True)
    if n >= -32768:
        return b"\xd1" + n.to_bytes(2, "big", signed=True)
    if n >= -2147483648:
        return b"\xd2" + n.to_bytes(4, "big", signed=True)
    return b"\xd3" + n.to_bytes(8, "big", signed=True)


def _mp_str(s: str) -> bytes:
    body = s.encode("utf-8")
    n = len(body)
    if n <= 31:
        return bytes([0xA0 | n]) + body
    if n <= 0xFF:
        return b"\xd9" + n.to_bytes(1, "big") + body
    if n <= 0xFFFF:
        return b"\xda" + n.to_bytes(2, "big") + body
    return b"\xdb" + n.to_bytes(4, "big") + body


def _mp_arr_header(n: int) -> bytes:
    if n <= 15:
        return bytes([0x90 | n])
    if n <= 0xFFFF:
        return b"\xdc" + n.to_bytes(2, "big")
    return b"\xdd" + n.to_bytes(4, "big")


def _mp_map_header(n: int) -> bytes:
    if n <= 15:
        return bytes([0x80 | n])
    if n <= 0xFFFF:
        return b"\xde" + n.to_bytes(2, "big")
    return b"\xdf" + n.to_bytes(4, "big")


def _mp_encode(value: Any) -> bytes:
    if value is None:
        return b"\xc0"
    if value is True:
        return b"\xc3"
    if value is False:
        return b"\xc2"
    if isinstance(value, int):
        return _mp_int(value)
    if isinstance(value, float):
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        return _mp_str(value)
    if isinstance(value, list):
        return _mp_arr_header(len(value)) + b"".join(_mp_encode(v) for v in value)
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-8"))
        body = b"".join(_mp_str(k) + _mp_encode(value[k]) for k in keys)
        return _mp_map_header(len(keys)) + body
    raise NotCanonical(f"unsupported value type {type(value).__name__}")


def canonical_msgpack(value: Any) -> bytes:
    """The pinned canonical MessagePack profile (see ABI.md §2b)."""
    validate_value(value)
    return _mp_encode(value)


def _take(buf: bytes, pos: int, n: int) -> bytes:
    if pos + n > len(buf):
        raise NotCanonical("truncated")
    return buf[pos : pos + n]


def _mp_parse(buf: bytes, pos: int, depth: int) -> tuple[Any, int]:
    if depth > _MP_MAX_DEPTH:
        raise NotCanonical("nesting depth exceeds the bound")
    if pos >= len(buf):
        raise NotCanonical("truncated")
    b = buf[pos]
    pos += 1
    if b <= 0x7F:
        return b, pos
    if b >= 0xE0:
        return b - 0x100, pos
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return _take(buf, pos, n).decode("utf-8"), pos + n
    if 0x90 <= b <= 0x9F:
        return _mp_parse_array(buf, pos, b & 0x0F, depth)
    if 0x80 <= b <= 0x8F:
        return _mp_parse_map(buf, pos, b & 0x0F, depth)
    if b == 0xC0:
        return None, pos
    if b == 0xC2:
        return False, pos
    if b == 0xC3:
        return True, pos
    if b == 0xCA:
        return struct.unpack(">f", _take(buf, pos, 4))[0], pos + 4
    if b == 0xCB:
        return struct.unpack(">d", _take(buf, pos, 8))[0], pos + 8
    if b == 0xCC:
        return _take(buf, pos, 1)[0], pos + 1
    if b == 0xCD:
        return int.from_bytes(_take(buf, pos, 2), "big"), pos + 2
    if b == 0xCE:
        return int.from_bytes(_take(buf, pos, 4), "big"), pos + 4
    if b == 0xCF:
        return int.from_bytes(_take(buf, pos, 8), "big"), pos + 8
    if b == 0xD0:
        return int.from_bytes(_take(buf, pos, 1), "big", signed=True), pos + 1
    if b == 0xD1:
        return int.from_bytes(_take(buf, pos, 2), "big", signed=True), pos + 2
    if b == 0xD2:
        return int.from_bytes(_take(buf, pos, 4), "big", signed=True), pos + 4
    if b == 0xD3:
        return int.from_bytes(_take(buf, pos, 8), "big", signed=True), pos + 8
    if b == 0xD9:
        n = _take(buf, pos, 1)[0]
        return _take(buf, pos + 1, n).decode("utf-8"), pos + 1 + n
    if b == 0xDA:
        n = int.from_bytes(_take(buf, pos, 2), "big")
        return _take(buf, pos + 2, n).decode("utf-8"), pos + 2 + n
    if b == 0xDB:
        n = int.from_bytes(_take(buf, pos, 4), "big")
        return _take(buf, pos + 4, n).decode("utf-8"), pos + 4 + n
    if b == 0xDC:
        return _mp_parse_array(buf, pos, int.from_bytes(_take(buf, pos, 2), "big"), depth)
    if b == 0xDD:
        return _mp_parse_array(buf, pos, int.from_bytes(_take(buf, pos, 4), "big"), depth)
    if b == 0xDE:
        return _mp_parse_map(buf, pos, int.from_bytes(_take(buf, pos, 2), "big"), depth)
    if b == 0xDF:
        return _mp_parse_map(buf, pos, int.from_bytes(_take(buf, pos, 4), "big"), depth)
    raise NotCanonical(f"byte 0x{b:02x} is outside the canonical profile")


def _mp_parse_array(buf: bytes, pos: int, n: int, depth: int) -> tuple[Any, int]:
    items = []
    for _ in range(n):
        item, pos = _mp_parse(buf, pos, depth + 1)
        items.append(item)
    return items, pos


def _mp_parse_map(buf: bytes, pos: int, n: int, depth: int) -> tuple[Any, int]:
    out: dict[str, Any] = {}
    for _ in range(n):
        key, pos = _mp_parse(buf, pos, depth + 1)
        if not isinstance(key, str):
            raise NotCanonical("map key is not a string")
        value, pos = _mp_parse(buf, pos, depth + 1)
        out[key] = value
    return out, pos


def decode_canonical_msgpack(buf: bytes) -> Any:
    """Parse and require the canonical form: re-encode must equal the input."""
    value, pos = _mp_parse(buf, 0, 0)
    if pos != len(buf):
        raise NotCanonical("trailing bytes after the value")
    if canonical_msgpack(value) != buf:
        raise NotCanonical("non-canonical MessagePack encoding")
    return value


def encode_value(value: Any, encoding: str) -> bytes:
    if encoding == "json":
        return canonical_json(value)
    if encoding == "msgpack":
        return canonical_msgpack(value)
    raise NotCanonical(f"unknown encoding {encoding!r}")


def decode_value(buf: bytes, encoding: str) -> Any:
    if encoding == "json":
        try:
            value = json.loads(buf.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NotCanonical(f"invalid JSON: {exc}") from exc
        if canonical_json(value) != buf:
            raise NotCanonical("non-canonical JSON encoding")
        return value
    if encoding == "msgpack":
        return decode_canonical_msgpack(buf)
    raise NotCanonical(f"unknown encoding {encoding!r}")


# --------------------------------------------------------------------------
# The host
# --------------------------------------------------------------------------


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
        return {"name": "cbp-reference-host", "version": "2", "abi": ABI}

    def run_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Drive one case and return its normalized observation."""
        fixture = self._fixtures.get(case["fixture"])
        if fixture is None:
            return self._result(
                [], [], [], [],
                ConformanceError("malformed-module", f"unknown fixture {case['fixture']!r}"),
            )
        scenario = case.get("scenario", {})
        entered: list[str] = []
        announcements: list[dict[str, Any]] = []
        packets_out: list[dict[str, Any]] = []
        encoded: list[dict[str, Any]] = []
        error: ConformanceError | None = None
        state = "new"

        for entrypoint in scenario.get("lifecycle", ["init", "run", "kill"]):
            if entrypoint == "init":
                if state != "new":
                    error = ConformanceError("malformed-module", "init out of order")
                    break
                if self._declared_contract(scenario) != self._contract:
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
                    announcements, packets_out, encoded = self._run(fixture, scenario)
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

        return self._result(entered, announcements, packets_out, encoded, error)

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
        encoded: list[dict[str, Any]],
        error: ConformanceError | None,
    ) -> dict[str, Any]:
        return {
            "lifecycle": lifecycle,
            "announcements": announcements,
            "packets_out": packets_out,
            "encoded": encoded,
            "error": None if error is None else {"kind": error.kind},
        }

    def _run(
        self, fixture: dict[str, Any], scenario: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        task = fixture["tasks"][0]
        behavior = task["behavior"]
        envelope = fixture["grant"]["envelope"]
        session_encoding = scenario.get("encoding", "json")

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

        values: dict[str, Any] = {}
        raw_packets = scenario.get("raw_packets", [])
        for raw in raw_packets:
            try:
                values[raw["port"]] = decode_value(bytes.fromhex(raw["hex"]), raw["encoding"])
            except NotCanonical as exc:
                raise ConformanceError("encoding-violation", str(exc)) from exc
        typed_packets = scenario.get("packets", [])
        for packet in typed_packets:
            values[packet["port"]] = packet["value"]

        count = len(raw_packets) + len(typed_packets)
        if count > envelope["step-limit"]:
            raise ConformanceError("failed", f"step-limit {envelope['step-limit']} exceeded")
        if count == 0:
            return announcements, [], []

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
        try:
            data = encode_value(out_value, session_encoding)
        except NotCanonical as exc:
            raise ConformanceError("encoding-violation", f"could not encode output: {exc}") from exc
        return (
            announcements,
            [{"port": port, "type": coarse_type(out_value), "value": out_value}],
            [{"port": port, "encoding": session_encoding, "hex": data.hex()}],
        )


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
