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

import hashlib
import json
import pathlib
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


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032) verification — the appointed trust primitive
#
# A compact, pure-stdlib **verifier** used by the reference host. It is a test
# double (not constant-time); a production host uses a hardened crypto library.
# It is validated against the RFC 8032 test vectors and the committed artifact
# signature. A detached signature is verified over the exact artifact bytes.
# --------------------------------------------------------------------------

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


_ED_D = (-121665 * _ed_inv(121666)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * _ed_inv(_ED_D * y * y + 1) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_I % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    if x == 0 and sign == 1:
        return None
    return x


def _ed_decode_point(s: bytes) -> tuple[int, int] | None:
    if len(s) != 32:
        return None
    value = int.from_bytes(s, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y)


def _ed_add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    k = _ED_D * x1 * x2 * y1 * y2 % _ED_P
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + k) % _ED_P
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - k) % _ED_P
    return (x3, y3)


def _ed_scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        e >>= 1
    return q


_ED_BY = 4 * _ed_inv(5) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
if _ED_BX is None:  # pragma: no cover - the curve base point always recovers
    raise AssertionError("Ed25519 base point failed to recover")
_ED_B = (_ED_BX, _ED_BY)


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    """True iff the detached Ed25519 ``signature`` verifies over ``message``."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _ed_decode_point(public)
    r = _ed_decode_point(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % _ED_L
    return _ed_scalarmult(_ED_B, s) == _ed_add(r, _ed_scalarmult(a, h))



class ReferenceHost:
    """Implements the fixtures and the ABI lifecycle/transport rules."""

    def __init__(
        self,
        fixtures: dict[str, Any],
        abi_sha256: str = "",
        trust: dict[str, Any] | None = None,
        artifacts_dir: str | None = None,
    ) -> None:
        self._fixtures = fixtures["fixtures"]
        self._networks = fixtures.get("networks", {})
        self._planners = fixtures.get("planners", {})
        sources = (trust or {}).get("sources", {})
        self._sources = (
            {
                name: key
                for name, key in sources.items()
                if isinstance(name, str) and isinstance(key, str)
            }
            if isinstance(sources, dict)
            else {}
        )
        self._artifacts_dir = artifacts_dir
        self._contract = {
            "package-name": "cbp:component",
            "version": "1.0.0",
            "contract-hash": abi_sha256,
        }

    def identity(self) -> dict[str, Any]:
        return {"name": "cbp-reference-host", "version": "3", "abi": ABI}

    def run_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Drive one case and return its normalized observation."""
        if case.get("category") == "network":
            return self._run_network_case(case)
        if case.get("category") == "appointed":
            return self._run_appointed_case(case)
        fixture = self._fixtures.get(case["fixture"])
        if fixture is None:
            return self._result(
                [], [], [], [],
                ConformanceError("malformed-module", f"unknown fixture {case['fixture']!r}"),
            )
        scenario = case.get("scenario", {})
        entered, announcements, packets_out, encoded, error = self._run_lifecycle(
            fixture, scenario
        )
        return self._result(entered, announcements, packets_out, encoded, error)

    def _run_lifecycle(
        self, fixture: dict[str, Any], scenario: dict[str, Any]
    ) -> tuple[
        list[str],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        ConformanceError | None,
    ]:
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

        return entered, announcements, packets_out, encoded, error

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

    # -- appointed.v1 (Layer 4: allowlisted, contained appointment) --------

    def _appointed_result(
        self,
        appointment: dict[str, Any] | None,
        lifecycle: list[str],
        announcements: list[dict[str, Any]],
        packets_out: list[dict[str, Any]],
        encoded: list[dict[str, Any]],
        error: ConformanceError | None,
    ) -> dict[str, Any]:
        result = self._result(lifecycle, announcements, packets_out, encoded, error)
        result["appointment"] = appointment
        return result

    def _admit_appointed(self, fixture: dict[str, Any]) -> dict[str, Any]:
        source = fixture.get("source")
        license_name = fixture.get("license")
        if (
            not isinstance(source, str)
            or not source
            or not isinstance(license_name, str)
            or not license_name
        ):
            raise ConformanceError(
                "malformed-module", "appointed fixture needs source and license"
            )
        if source not in self._sources:
            raise ConformanceError(
                "unknown-source", f"source {source!r} is not allowlisted"
            )
        artifact = fixture.get("artifact")
        if not isinstance(artifact, dict):
            raise ConformanceError(
                "malformed-module", "appointed fixture needs an artifact"
            )
        file_name = artifact.get("file")
        expected = artifact.get("sha256")
        signature = artifact.get("signature")
        if (
            not isinstance(file_name, str)
            or not isinstance(expected, str)
            or not isinstance(signature, str)
        ):
            raise ConformanceError(
                "malformed-module", "artifact needs file/sha256/signature"
            )
        if self._artifacts_dir is None:
            raise ConformanceError("failed", "no artifacts_dir configured")
        try:
            data = (pathlib.Path(self._artifacts_dir) / file_name).read_bytes()
        except OSError as exc:
            raise ConformanceError("failed", f"read artifact: {exc}") from exc
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ConformanceError(
                "content-mismatch", "artifact bytes do not match the declared sha256"
            )
        if not signature:
            raise ConformanceError("unsigned-artifact", "appointed artifact is unsigned")
        key = self._sources[source]
        try:
            verified = ed25519_verify(
                bytes.fromhex(key), bytes.fromhex(signature), data
            )
        except ValueError as exc:
            raise ConformanceError("bad-signature", f"malformed signature: {exc}") from exc
        if not verified:
            raise ConformanceError(
                "bad-signature", "signature does not verify against the source key"
            )
        if fixture.get("grant", {}).get("capabilities", []):
            raise ConformanceError(
                "capability-refused",
                "appointed components must declare zero capabilities (A0)",
            )
        return {
            "property": "contained",
            "tier": "A0",
            "source": source,
            "license": license_name,
            "artifact_sha256": actual,
        }

    def _run_appointed_case(self, case: dict[str, Any]) -> dict[str, Any]:
        fixture = self._fixtures.get(case.get("fixture", ""))
        if fixture is None:
            return self._appointed_result(
                None,
                [],
                [],
                [],
                [],
                ConformanceError(
                    "malformed-module", f"unknown fixture {case.get('fixture')!r}"
                ),
            )
        scenario = case.get("scenario", {})
        try:
            appointment = self._admit_appointed(fixture)
        except ConformanceError as exc:
            return self._appointed_result(None, [], [], [], [], exc)
        entered, announcements, packets_out, encoded, error = self._run_lifecycle(
            fixture, scenario
        )
        return self._appointed_result(
            appointment, entered, announcements, packets_out, encoded, error
        )

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

    # -- network.v1 (Layer 2: pinned, typed, replayable network execution) --

    def _network_error(self, kind: str, message: str = "") -> dict[str, Any]:
        return {
            "network_sha256": "",
            "lifecycle": [],
            "announcements": [],
            "packets_out": [],
            "encoded": [],
            "trajectory": None,
            "error": {"kind": kind},
        }

    def _run_network_case(self, case: dict[str, Any]) -> dict[str, Any]:
        fixture_id = case.get("fixture", "")
        doc = self._networks.get(fixture_id)
        if doc is None:
            return self._network_error(
                "malformed-network", f"unknown network {fixture_id!r}"
            )
        encoding = case.get("scenario", {}).get("encoding", "json")
        try:
            return self._run_network(doc, encoding)
        except ConformanceError as exc:
            return self._network_error(exc.kind, exc.message)

    def _run_network(self, doc: dict[str, Any], encoding: str) -> dict[str, Any]:
        def channel(fixture: dict[str, Any], name: Any, direction: str) -> Any:
            for ch in fixture["channels"]:
                if ch["name"] == name and ch["direction"] == direction:
                    return ch
            return None

        def compatible(a: str, b: str) -> bool:
            return a == "any" or b == "any" or a == b

        if not isinstance(doc, dict):
            raise ConformanceError("malformed-network", "network is not an object")
        stored = doc.get("content_hash")
        if not stored:
            raise ConformanceError("not-pinned", "network has no content_hash")
        body = {k: v for k, v in doc.items() if k != "content_hash"}
        computed = hashlib.sha256(canonical_json(body)).hexdigest()
        if computed != stored:
            raise ConformanceError(
                "pin-mismatch", "content_hash does not match the document"
            )

        provenance = doc.get("provenance")
        if isinstance(provenance, dict) and provenance.get("kind") == "planner":
            self._verify_planner(body, provenance, computed)

        components = doc.get("components")
        if not isinstance(components, list) or not components:
            raise ConformanceError(
                "malformed-network", "network must declare components"
            )
        by_id: dict[str, Any] = {}
        for entry in components:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("id"), str)
                or not entry["id"]
            ):
                raise ConformanceError(
                    "malformed-network", "each component needs a non-empty id"
                )
            cid = entry["id"]
            if cid in by_id:
                raise ConformanceError(
                    "malformed-network", f"duplicate component id {cid!r}"
                )
            fid = entry.get("fixture")
            if not isinstance(fid, str) or fid not in self._fixtures:
                raise ConformanceError(
                    "unknown-fixture", f"component {cid!r} names unknown fixture {fid!r}"
                )
            by_id[cid] = self._fixtures[fid]

        edges = doc.get("edges", [])
        iips = doc.get("iips", [])
        if not isinstance(edges, list) or not isinstance(iips, list):
            raise ConformanceError("malformed-network", "edges/iips must be lists")

        for edge in edges:
            if not isinstance(edge, dict):
                raise ConformanceError(
                    "malformed-network", "each edge must be an object"
                )
            frm, to = edge.get("from"), edge.get("to")
            if frm not in by_id or to not in by_id:
                raise ConformanceError(
                    "malformed-network", "edge references an unknown component"
                )
            src = channel(by_id[frm], edge.get("from_port"), "out")
            dst = channel(by_id[to], edge.get("to_port"), "in")
            if src is None or dst is None:
                raise ConformanceError(
                    "malformed-network", "edge references an undeclared port"
                )
            if not compatible(src["port_type"], dst["port_type"]):
                raise ConformanceError(
                    "type-mismatch",
                    f"incompatible {src['port_type']} -> {dst['port_type']}",
                )

        bound: set[tuple[str, str]] = set()
        for iip in iips:
            if not isinstance(iip, dict):
                raise ConformanceError(
                    "malformed-network", "each IIP must be an object"
                )
            to, port = iip.get("to"), iip.get("port")
            if to not in by_id:
                raise ConformanceError(
                    "malformed-network", "IIP references an unknown component"
                )
            ch = channel(by_id[to], port, "in")
            if ch is None:
                raise ConformanceError(
                    "malformed-network", "IIP references an undeclared in-port"
                )
            key = (str(to), str(port))
            if key in bound:
                raise ConformanceError(
                    "malformed-network", "in-port has more than one IIP"
                )
            bound.add(key)
            if not matches_type(iip.get("value"), ch["port_type"]):
                raise ConformanceError(
                    "type-violation", f"IIP does not match {ch['port_type']!r}"
                )
        for edge in edges:
            if (edge["to"], edge["to_port"]) in bound:
                raise ConformanceError(
                    "malformed-network", "in-port has both an IIP and an edge"
                )

        order = self._network_order(by_id, edges)

        outputs: dict[str, Any] = {}
        steps: list[dict[str, Any]] = []
        for step, cid in enumerate(order):
            fixture = by_id[cid]
            task = fixture["tasks"][0]
            values: dict[str, Any] = {}
            for iip in iips:
                if iip["to"] == cid:
                    values[iip["port"]] = iip["value"]
            for edge in edges:
                if edge["to"] == cid:
                    values[edge["to_port"]] = outputs[edge["from"]]
            try:
                out_value = self._network_behavior(task, values)
            except KeyError as exc:
                raise ConformanceError(
                    "failed", f"component {cid!r} missing input {exc}"
                ) from exc
            out_port = task["output-ports"][0]
            out_ch = channel(fixture, out_port, "out")
            declared = out_ch["port_type"] if out_ch is not None else "any"
            if not matches_type(out_value, declared):
                raise ConformanceError(
                    "type-violation",
                    f"{out_value!r} does not match declared {declared!r}",
                )
            outputs[cid] = out_value
            inputs = [
                {"port": port, "type": coarse_type(values[port]), "value": values[port]}
                for port in sorted(values)
            ]
            steps.append(
                {
                    "step": step,
                    "component": cid,
                    "task": task["name"],
                    "inputs": inputs,
                    "outputs": [
                        {
                            "port": out_port,
                            "type": coarse_type(out_value),
                            "value": out_value,
                        }
                    ],
                }
            )

        terminal: list[dict[str, Any]] = []
        for cid in order:
            fixture = by_id[cid]
            out_port = fixture["tasks"][0]["output-ports"][0]
            if any(e["from"] == cid and e["from_port"] == out_port for e in edges):
                continue
            value = outputs[cid]
            terminal.append(
                {
                    "component": cid,
                    "port": out_port,
                    "type": coarse_type(value),
                    "value": value,
                }
            )
        terminal.sort(key=lambda t: (t["component"], t["port"]))
        encoded = [
            {
                "component": t["component"],
                "port": t["port"],
                "encoding": encoding,
                "hex": encode_value(t["value"], encoding).hex(),
            }
            for t in terminal
        ]
        trajectory: dict[str, Any] = {
            "network_sha256": computed,
            "encoding": encoding,
            "steps": steps,
        }
        if isinstance(provenance, dict) and provenance.get("kind") == "planner":
            trajectory["provenance"] = {
                "kind": "planner",
                "planner": provenance.get("planner"),
            }
        return {
            "network_sha256": computed,
            "lifecycle": ["run"],
            "announcements": [],
            "packets_out": terminal,
            "encoded": encoded,
            "trajectory": trajectory,
            "error": None,
        }

    def _verify_planner(
        self, body: dict[str, Any], provenance: dict[str, Any], expected_pin: str
    ) -> None:
        planner_id = provenance.get("planner")
        planner = self._planners.get(planner_id) if isinstance(planner_id, str) else None
        if planner is None:
            raise ConformanceError(
                "unknown-planner", f"planner {planner_id!r} is not configured"
            )
        components, edges, iips = self._run_planner(planner, provenance.get("inputs", {}))
        regenerated = dict(body)
        regenerated["components"] = components
        regenerated["edges"] = edges
        regenerated["iips"] = iips
        regen_pin = hashlib.sha256(canonical_json(regenerated)).hexdigest()
        if regen_pin != expected_pin:
            raise ConformanceError(
                "plan-mismatch", "planner replay does not reproduce the pinned wiring"
            )

    def _run_planner(
        self, planner: dict[str, Any], inputs: Any
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        behavior = planner.get("behavior")
        if behavior == "linear-chain":
            if not isinstance(inputs, dict):
                raise ConformanceError(
                    "malformed-network", "planner inputs must be an object"
                )
            fixture = inputs.get("fixture")
            length = inputs.get("length")
            value = inputs.get("value")
            if (
                not isinstance(fixture, str)
                or not isinstance(length, int)
                or not (1 <= length <= 26)
            ):
                raise ConformanceError(
                    "malformed-network", "invalid linear-chain planner inputs"
                )
            components = [
                {"id": chr(97 + i), "fixture": fixture} for i in range(length)
            ]
            edges = [
                {
                    "from": chr(97 + i),
                    "from_port": "out",
                    "to": chr(97 + i + 1),
                    "to_port": "in",
                }
                for i in range(length - 1)
            ]
            iips = [{"to": "a", "port": "in", "type": "int", "value": value}]
            return components, edges, iips
        raise ConformanceError(
            "malformed-network", f"unknown planner behavior {behavior!r}"
        )

    def _network_order(
        self, by_id: dict[str, Any], edges: list[dict[str, Any]]
    ) -> list[str]:
        """A deterministic topological order (ties broken by ascending id)."""
        indegree: dict[str, int] = {cid: 0 for cid in by_id}
        adjacency: dict[str, list[str]] = {cid: [] for cid in by_id}
        for edge in edges:
            adjacency[edge["from"]].append(edge["to"])
            indegree[edge["to"]] += 1
        ready = sorted(cid for cid, deg in indegree.items() if deg == 0)
        order: list[str] = []
        while ready:
            cid = ready.pop(0)
            order.append(cid)
            for nxt in sorted(adjacency[cid]):
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    ready.append(nxt)
                    ready.sort()
        if len(order) != len(by_id):
            raise ConformanceError("malformed-network", "network contains a cycle")
        return order

    def _network_behavior(
        self, task: dict[str, Any], values: dict[str, Any]
    ) -> Any:
        behavior = task["behavior"]
        if behavior == "identity":
            return values[task["input-ports"][0]]
        if behavior == "sum-int":
            return values["a"] + values["b"]
        if behavior == "concat-str":
            return values["a"] + values["b"]
        if behavior == "fail":
            raise ConformanceError("failed", "explicit failure")
        if behavior == "emit-wrong-type":
            return "not-an-int"
        raise ConformanceError("malformed-network", f"unknown behavior {behavior!r}")


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
            host = ReferenceHost(
                message["fixtures"],
                message.get("abi_sha256", ""),
                message.get("trust"),
                message.get("artifacts_dir"),
            )
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
