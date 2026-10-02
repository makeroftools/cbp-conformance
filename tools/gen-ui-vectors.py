"""Generate the canonical ``ui.v1`` conformance vectors (SPEC-0022 §10).

Deterministic and offline: builds the UI fixtures/cases, derives each expected
observation with the Python reference host, and writes the fixtures, suite, and
vectors lock in canonical form (so their sha256 is stable). Re-run after any
change to the UI ABI or the reference host; the certifier refuses a lock/vector
mismatch.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_CONF = _HERE.parent
sys.path.insert(0, str(_CONF / "certifier"))

from reference_host import ReferenceHost  # noqa: E402

FIXTURES = {
    "fixtures": {
        "diagram-view": {
            "id": "cbp.diagram-view",
            "abi_version": "1.0.0",
            "targets": ["web", "cli"],
            "projections": ["cbp.diagram.v1"],
            "directives": [{"name": "open-review", "requires_approval": False}],
            "capabilities": [],
            "slots": ["main"],
            "tokens": {"accent": "#38bdf8"},
            "view": "echo-keys",
        },
        "admin-view": {
            "id": "cbp.admin-view",
            "abi_version": "1.0.0",
            "targets": ["cli", "web"],
            "projections": ["review.v1", "cbp.ledger.v1"],
            "directives": [
                {"name": "open-review", "requires_approval": False},
                {"name": "provision", "requires_approval": True},
            ],
            "capabilities": [{"name": "ui.read.review", "version": "1"}],
            "slots": ["main", "sidebar"],
            "tokens": {"accent": "#a78bfa"},
            "view": "echo-keys",
        },
        "future-view": {
            "id": "cbp.future-view",
            "abi_version": "9.9.9",
            "targets": ["web"],
            "projections": ["cbp.diagram.v1"],
            "directives": [],
            "capabilities": [],
            "slots": ["main"],
            "tokens": {},
            "view": "echo-keys",
        },
    }
}

_CASES = [
    ("ui.describe", "diagram-view", {"op": "describe"}, None),
    ("ui.describe-capabilities", "admin-view", {"op": "describe"}, None),
    (
        "ui.render",
        "diagram-view",
        {
            "op": "render",
            "projection": {
                "schema": "cbp.diagram.v1",
                "data": {
                    "schema": "cbp.diagram.v1",
                    "network_sha256": "a" * 64,
                    "content_hash": "b" * 64,
                    "nodes": [{"id": "alpha", "task": "double", "rank": 0}],
                    "edges": [
                        {
                            "from": "alpha",
                            "from_port": "out",
                            "to": "beta",
                            "to_port": "in",
                            "capacity": 1,
                        }
                    ],
                },
            },
            "assurance": "verified",
        },
        3,
    ),
    (
        "ui.render-model",
        "diagram-view",
        {
            "op": "render",
            "projection": {"schema": "cbp.diagram.v1", "data": {"nodes": []}},
            "assurance": "model",
        },
        None,
    ),
    (
        "ui.handle",
        "diagram-view",
        {
            "op": "handle",
            "event": {"directive": "open-review", "args": {"id": "r1"}},
        },
        None,
    ),
    (
        "ui.handle-approval",
        "admin-view",
        {
            "op": "handle",
            "event": {"directive": "provision", "args": {"domain": "bill-extract"}},
        },
        None,
    ),
    (
        "ui.projection-denied",
        "diagram-view",
        {"op": "render", "projection": {"schema": "review.v1", "data": {}}},
        None,
    ),
    (
        "ui.directive-denied",
        "diagram-view",
        {"op": "handle", "event": {"directive": "delete-all"}},
        None,
    ),
    ("ui.abi-mismatch", "future-view", {"op": "describe"}, None),
    ("ui.malformed-op", "diagram-view", {"op": "teleport"}, None),
]


def canonical(obj: object) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    vectors = _CONF / "vectors"
    contracts = _CONF / "contracts"

    fixtures_path = vectors / "ui-fixtures.v1.json"
    fixtures_path.write_bytes(canonical(FIXTURES))
    fixtures_sha = sha256_file(fixtures_path)

    contract_sha = json.loads(
        (contracts / "ABI.lock.v1.json").read_text()
    )["source_sha256"]

    host = ReferenceHost(FIXTURES, contract_sha)
    cases: list[dict[str, object]] = []
    for case_id, fixture, scenario, runs in _CASES:
        case: dict[str, object] = {
            "id": case_id,
            "category": "ui",
            "fixture": fixture,
            "scenario": scenario,
        }
        if runs is not None:
            case["determinism"] = {"runs": runs}
        case["expect"] = host.run_case(case)
        cases.append(case)

    suite = {
        "abi": "component-abi.v1",
        "schema": "cbp.vectors.v1",
        "contract_sha256": contract_sha,
        "fixtures_sha256": fixtures_sha,
        "cases": cases,
    }
    suite_path = vectors / "ui-suite.v1.json"
    suite_path.write_bytes(canonical(suite))
    suite_sha = sha256_file(suite_path)

    ui_lock = json.loads((contracts / "ui.lock.v1.json").read_text())
    wit_sha = sha256_file(contracts / "ui-v1.wit")
    abi_md_sha = sha256_file(contracts / "UI-ABI.md")
    if wit_sha != ui_lock["source_sha256"]:
        raise SystemExit("ui-v1.wit drifted from contracts/ui.lock.v1.json")
    if abi_md_sha != ui_lock["ui_md_sha256"]:
        raise SystemExit("UI-ABI.md drifted from contracts/ui.lock.v1.json")

    lock = {
        "schema": "cbp.vectors-lock.v1",
        "abi": "component-abi.v1",
        "revision": 1,
        "contract_sha256": contract_sha,
        "note": (
            "ui.v1 suite (SPEC-0022): a target-agnostic UI component manifest is "
            "canonical and content-addressed; render is a deterministic pure "
            "function of a granted projection; a directive is a content-addressed "
            "intent; an unknown ABI version, an undeclared projection, and an "
            "undeclared directive fail closed (abi-mismatch / projection-denied / "
            "directive-denied)."
        ),
        "documents": [
            {"path": "../contracts/ui-v1.wit", "sha256": wit_sha},
            {"path": "../contracts/UI-ABI.md", "sha256": abi_md_sha},
        ],
        "suite": {"path": "ui-suite.v1.json", "sha256": suite_sha},
        "fixtures": {"path": "ui-fixtures.v1.json", "sha256": fixtures_sha},
    }
    (vectors / "ui.lock.v1.json").write_bytes(canonical(lock))
    print(f"wrote ui-fixtures.v1.json ({fixtures_sha[:12]})")
    print(f"wrote ui-suite.v1.json ({suite_sha[:12]}, {len(cases)} cases)")
    print("wrote ui.lock.v1.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
