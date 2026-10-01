"""Certify a host/runtime against the CBP conformance vectors (SPEC-0013).

The certifier is tooling, not a component: it may be any language. It:

1. loads the suite and fixtures and refuses unless each is in canonical form and
   matches ``vectors.lock.v1.json``, and unless ``contract_sha256`` matches
   ``contracts/ABI.lock.v1.json`` (no run against a drifted contract);
2. drives a host — the in-process **reference host**, or an external host over
   the JSON-lines protocol (``--host-cmd``) — once per case, ``determinism.runs``
   times, requiring byte-identical normalized observations across runs;
3. compares each observation to the expected one under the documented rule;
4. emits a deterministic **certification record** (no wall-clock: a record must
   be reproducible) including the host's pinned identity/version.

Exit: 0 all pass, 1 any failure, 2 a lock/canonicalization refusal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any

from reference_host import PROTOCOL, ReferenceHost

REFUSED = 2
FAILED = 1


def canonical_bytes(obj: Any) -> bytes:
    """The canonical JSON form: sorted keys, tight separators, one trailing LF."""
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _refuse(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(REFUSED)


def load_canonical(path: str) -> tuple[dict[str, Any], str]:
    """Load a JSON file, refusing unless it is byte-canonical; return (obj, sha256)."""
    raw = pathlib.Path(path).read_bytes()
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _refuse(f"{path}: not valid UTF-8 JSON: {exc}")
    if canonical_bytes(obj) != raw:
        _refuse(f"{path}: not in canonical form (refusing; see vectors/README.md)")
    return obj, hashlib.sha256(raw).hexdigest()


class InProcessHost:
    """Drives the reference host directly (the offline default)."""

    def __init__(self) -> None:
        self._host: ReferenceHost | None = None

    def configure(
        self,
        fixtures: dict[str, Any],
        abi_sha256: str,
        artifacts_dir: str,
        trust: dict[str, Any],
    ) -> dict[str, Any]:
        self._host = ReferenceHost(fixtures, abi_sha256, trust, artifacts_dir)
        return self._host.identity()

    def run(self, case: dict[str, Any]) -> dict[str, Any]:
        assert self._host is not None
        return self._host.run_case(case)

    def close(self) -> None:
        return None


class SubprocessHost:
    """Drives an external host over the JSON-lines protocol (``PROTOCOL.md``)."""

    def __init__(self, command: str) -> None:
        self._proc = subprocess.Popen(  # noqa: S602 - operator-provided host command
            command,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def _exchange(self, message: dict[str, Any]) -> dict[str, Any]:
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise SystemExit("host closed the connection without a response")
        response = json.loads(line)
        if response.get("protocol") != PROTOCOL:
            raise SystemExit(f"host protocol mismatch: {response!r}")
        return response

    def configure(
        self,
        fixtures: dict[str, Any],
        abi_sha256: str,
        artifacts_dir: str,
        trust: dict[str, Any],
    ) -> dict[str, Any]:
        response = self._exchange(
            {
                "protocol": PROTOCOL,
                "op": "configure",
                "fixtures": fixtures,
                "abi_sha256": abi_sha256,
                "artifacts_dir": artifacts_dir,
                "trust": trust,
            }
        )
        if not response.get("ok"):
            raise SystemExit(f"host configure failed: {response!r}")
        return response["runtime"]

    def run(self, case: dict[str, Any]) -> dict[str, Any]:
        response = self._exchange({"protocol": PROTOCOL, "op": "run", "id": case["id"], "case": case})
        return response["result"]

    def close(self) -> None:
        try:
            self._exchange({"protocol": PROTOCOL, "op": "shutdown"})
        finally:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
            self._proc.wait(timeout=10)


def compare(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """The documented comparison rule (see vectors/README.md)."""
    problems: list[str] = []
    expected_error = expected.get("error")
    actual_error = actual.get("error")
    if expected_error is None:
        if actual_error is not None:
            problems.append(f"expected success, got error {actual_error!r}")
        else:
            if actual.get("announcements") != expected.get("announcements"):
                problems.append(
                    f"announcements mismatch: {actual.get('announcements')!r} "
                    f"!= {expected.get('announcements')!r}"
                )
            if actual.get("packets_out") != expected.get("packets_out"):
                problems.append(
                    f"packets_out mismatch: {actual.get('packets_out')!r} "
                    f"!= {expected.get('packets_out')!r}"
                )
            if expected.get("encoded") is not None and actual.get("encoded") != expected.get("encoded"):
                problems.append(
                    f"encoded mismatch: {actual.get('encoded')!r} "
                    f"!= {expected.get('encoded')!r}"
                )
            if "appointment" in expected and actual.get("appointment") != expected.get("appointment"):
                problems.append(
                    f"appointment mismatch: {actual.get('appointment')!r} "
                    f"!= {expected.get('appointment')!r}"
                )
    elif not actual_error or actual_error.get("kind") != expected_error.get("kind"):
        problems.append(f"expected error kind {expected_error.get('kind')!r}, got {actual_error!r}")
    if "lifecycle" in expected and actual.get("lifecycle") != expected.get("lifecycle"):
        problems.append(
            f"lifecycle mismatch: {actual.get('lifecycle')!r} != {expected.get('lifecycle')!r}"
        )
    for field in ("network_sha256", "trajectory"):
        if field in expected and actual.get(field) != expected.get(field):
            problems.append(
                f"{field} mismatch: {actual.get(field)!r} != {expected.get(field)!r}"
            )
    return problems


def verify_locks(
    suite: dict[str, Any],
    suite_sha: str,
    fixtures_sha: str,
    abi_md_sha: str,
    lock_path: str,
    contract_lock_path: str,
) -> list[str]:
    lock = json.loads(pathlib.Path(lock_path).read_text())
    contract_lock = json.loads(pathlib.Path(contract_lock_path).read_text())
    contract_sha = contract_lock["source_sha256"]
    problems = []
    if lock["suite"]["sha256"] != suite_sha:
        problems.append("suite sha256 does not match vectors.lock.v1.json")
    if lock["fixtures"]["sha256"] != fixtures_sha:
        problems.append("fixtures sha256 does not match vectors.lock.v1.json")
    if lock["contract_sha256"] != contract_sha:
        problems.append("lock contract_sha256 does not match contracts/ABI.lock.v1.json")
    if suite.get("contract_sha256") != contract_sha:
        problems.append("suite contract_sha256 does not match contracts/ABI.lock.v1.json")
    if suite.get("fixtures_sha256") != fixtures_sha:
        problems.append("suite fixtures_sha256 does not match the fixtures file")
    if contract_lock.get("abi_md_sha256") != abi_md_sha:
        problems.append("ABI.md sha256 does not match contracts/ABI.lock.v1.json")
    lock_dir = pathlib.Path(lock_path).parent
    for doc in lock.get("documents", []):
        doc_path = (lock_dir / doc["path"]).resolve()
        if not doc_path.is_file():
            problems.append(f"document {doc['path']} is missing")
            continue
        actual_sha = hashlib.sha256(doc_path.read_bytes()).hexdigest()
        if actual_sha != doc.get("sha256"):
            problems.append(f"document {doc['path']} sha256 does not match the lock")
    return problems


def certify(args: argparse.Namespace) -> int:
    suite, suite_sha = load_canonical(args.suite)
    fixtures, fixtures_sha = load_canonical(args.fixtures)
    abi_md_path = pathlib.Path(args.contract_lock).parent / "ABI.md"
    abi_md_sha = (
        hashlib.sha256(abi_md_path.read_bytes()).hexdigest()
        if abi_md_path.is_file()
        else ""
    )
    problems = verify_locks(
        suite, suite_sha, fixtures_sha, abi_md_sha, args.lock, args.contract_lock
    )
    if problems:
        for problem in problems:
            print(f"refusing to run: {problem}", file=sys.stderr)
        return REFUSED

    contract_sha = json.loads(pathlib.Path(args.contract_lock).read_text())["source_sha256"]
    trust = json.loads(pathlib.Path(args.lock).read_text()).get("trust", {})
    host: InProcessHost | SubprocessHost = (
        SubprocessHost(args.host_cmd) if args.host_cmd else InProcessHost()
    )
    runtime = host.configure(fixtures, contract_sha, args.artifacts_dir, trust)

    failures: list[dict[str, Any]] = []
    total = passed = 0
    for case in suite["cases"]:
        total += 1
        runs = case.get("determinism", {}).get("runs", 1)
        try:
            observations = [host.run(case) for _ in range(runs)]
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator
            failures.append({"id": case["id"], "problems": [f"host raised: {exc}"]})
            continue
        case_problems = compare(case["expect"], observations[0])
        canonical = {json.dumps(o, sort_keys=True, separators=(",", ":")) for o in observations}
        if len(canonical) != 1:
            case_problems.append("nondeterministic: observations differ across runs")
        if case_problems:
            failures.append({"id": case["id"], "problems": case_problems})
        else:
            passed += 1
    host.close()

    record = {
        "schema": "cbp.certification.v1",
        "abi": suite["abi"],
        "suite_sha256": suite_sha,
        "fixtures_sha256": fixtures_sha,
        "contract_sha256": contract_sha,
        "host": runtime,
        "passed": not failures,
        "cases": {
            "total": total,
            "passed": passed,
            "failed": [f["id"] for f in failures],
        },
        "failures": failures,
    }
    text = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(text)
    sys.stdout.write(text)
    return 0 if not failures else FAILED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Certify a host against the CBP conformance vectors.")
    parser.add_argument("--suite", default="vectors/suite.v1.json")
    parser.add_argument("--fixtures", default="vectors/fixtures.v1.json")
    parser.add_argument("--lock", default="vectors/vectors.lock.v1.json")
    parser.add_argument("--contract-lock", default="contracts/ABI.lock.v1.json")
    parser.add_argument(
        "--host-cmd",
        default=None,
        help="External host command (JSON-lines protocol); omit for the in-process reference host.",
    )
    parser.add_argument("--out", default=None, help="Write the certification record here.")
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts",
        help="Directory of WASM fixture artifacts (for wasm-backed fixtures).",
    )
    return certify(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
