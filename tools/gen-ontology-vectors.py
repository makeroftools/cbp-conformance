"""Generate the canonical ``ontology.v1`` (M1) conformance vectors (SPEC-0023).

Deterministic and offline: builds the semantic-graph/ontology fixtures, derives
each expected observation with the Python reference host, and writes the fixtures,
suite, and vectors lock in canonical form (so their sha256 is stable). Re-run
after any change to the ontology semantics or the reference host; the certifier
refuses a lock/vector mismatch.
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

CORE = "urn:cbp:core/"
TYPE = CORE + "type"
KIND = CORE + "kind"
HAS_CAPABILITY = CORE + "hasCapability"
IMPLEMENTS = CORE + "implements"
INPUT = CORE + "input"
OUTPUT = CORE + "output"
PORT_TYPE = CORE + "portType"
DIRECTION = CORE + "direction"
FEEDS = CORE + "feeds"
COMPONENT = CORE + "Component"
ATOMIC = CORE + "AtomicComponent"
INPUT_PORT = CORE + "InputPort"
OUTPUT_PORT = CORE + "OutputPort"
SUB_CLASS_OF = CORE + "subClassOf"
SOURCE = CORE + "SourceComponent"
SINK = CORE + "SinkComponent"
SPECIAL = CORE + "SpecialAtomic"

def _atom(s, p, o, negated=False):
    return {"s": s, "p": p, "o": o, "negated": negated}


RULES = sorted(
    [
        {
            "schema": "ontology.rules.v1",
            "id": CORE + "rule/subclass-transitive",
            "head": _atom({"var": "x"}, SUB_CLASS_OF, {"var": "z"}),
            "body": [
                _atom({"var": "x"}, SUB_CLASS_OF, {"var": "y"}),
                _atom({"var": "y"}, SUB_CLASS_OF, {"var": "z"}),
            ],
        },
        {
            "schema": "ontology.rules.v1",
            "id": CORE + "rule/type-subsumption",
            "head": _atom({"var": "x"}, TYPE, {"var": "c"}),
            "body": [
                _atom({"var": "x"}, TYPE, {"var": "d"}),
                _atom({"var": "d"}, SUB_CLASS_OF, {"var": "c"}),
            ],
        },
        {
            "schema": "ontology.rules.v1",
            "id": CORE + "rule/source",
            "head": _atom({"var": "x"}, TYPE, {"term": SOURCE}),
            "body": [
                _atom({"var": "x"}, TYPE, {"term": COMPONENT}),
                _atom({"var": "x"}, INPUT, {"var": "_"}, negated=True),
            ],
        },
        {
            "schema": "ontology.rules.v1",
            "id": CORE + "rule/sink",
            "head": _atom({"var": "x"}, TYPE, {"term": SINK}),
            "body": [
                _atom({"var": "x"}, TYPE, {"term": COMPONENT}),
                _atom({"var": "x"}, OUTPUT, {"var": "_"}, negated=True),
            ],
        },
    ],
    key=lambda rule: rule["id"],
)


ONTOLOGY = {
    "schema": "ontology.v1",
    "id": CORE + "core",
    "version": "1",
    "imports": [],
    "terms": [
        {"kind": "class", "name": COMPONENT, "sub_class_of": [], "domain": [], "range": []},
        {"kind": "class", "name": ATOMIC, "sub_class_of": [COMPONENT], "domain": [], "range": []},
        {"kind": "class", "name": CORE + "CompositeComponent", "sub_class_of": [COMPONENT], "domain": [], "range": []},
        {"kind": "class", "name": CORE + "ModelComponent", "sub_class_of": [COMPONENT], "domain": [], "range": []},
        {"kind": "class", "name": CORE + "Capability", "sub_class_of": [], "domain": [], "range": []},
        {"kind": "class", "name": CORE + "Port", "sub_class_of": [], "domain": [], "range": []},
        {"kind": "class", "name": INPUT_PORT, "sub_class_of": [CORE + "Port"], "domain": [], "range": []},
        {"kind": "class", "name": OUTPUT_PORT, "sub_class_of": [CORE + "Port"], "domain": [], "range": []},
        {"kind": "class", "name": SOURCE, "sub_class_of": [COMPONENT], "domain": [], "range": []},
        {"kind": "class", "name": SINK, "sub_class_of": [COMPONENT], "domain": [], "range": []},
        {"kind": "class", "name": SPECIAL, "sub_class_of": [ATOMIC], "domain": [], "range": []},
        {"kind": "property", "name": HAS_CAPABILITY, "sub_class_of": [], "domain": [COMPONENT], "range": []},
        {"kind": "property", "name": IMPLEMENTS, "sub_class_of": [], "domain": [COMPONENT], "range": []},
        {"kind": "property", "name": INPUT, "sub_class_of": [], "domain": [COMPONENT], "range": []},
        {"kind": "property", "name": OUTPUT, "sub_class_of": [], "domain": [COMPONENT], "range": []},
        {"kind": "property", "name": PORT_TYPE, "sub_class_of": [], "domain": [CORE + "Port"], "range": []},
        {"kind": "property", "name": DIRECTION, "sub_class_of": [], "domain": [CORE + "Port"], "range": []},
        {"kind": "property", "name": FEEDS, "sub_class_of": [], "domain": [], "range": []},
    ],
    "rules": RULES,
}

# Canonical form: terms are sorted by name (matches core Ontology.to_dict).
ONTOLOGY["terms"].sort(key=lambda term: term["name"])


def term(name: str) -> dict:
    return {"k": "t", "n": name}


def lit(datatype: str, value: str) -> dict:
    return {"k": "l", "t": datatype, "v": value}


def assertion(subject: str, predicate: str, obj: dict) -> dict:
    return {"s": subject, "p": predicate, "o": obj}


def _port(scope: str, component: str, direction: str, name: str) -> str:
    return f"urn:cbp:{scope}/port/{component}/{direction}/{name}"


def _assertions() -> list[dict]:
    scope = "demo"
    a_in = _port(scope, "alpha", "in", "x")
    a_out = _port(scope, "alpha", "out", "y")
    b_in = _port(scope, "beta", "in", "y")
    b_out = _port(scope, "beta", "out", "z")
    rows = [
        assertion("alpha", TYPE, term(ATOMIC)),
        assertion("alpha", KIND, lit("str", "atomic")),
        assertion("alpha", HAS_CAPABILITY, lit("str", "compute@1")),
        assertion("alpha", IMPLEMENTS, lit("str", "harness.v1")),
        assertion("alpha", INPUT, term(a_in)),
        assertion(a_in, TYPE, term(INPUT_PORT)),
        assertion(a_in, DIRECTION, lit("str", "in")),
        assertion(a_in, PORT_TYPE, lit("str", "int")),
        assertion("alpha", OUTPUT, term(a_out)),
        assertion(a_out, TYPE, term(OUTPUT_PORT)),
        assertion(a_out, DIRECTION, lit("str", "out")),
        assertion(a_out, PORT_TYPE, lit("str", "int")),
        assertion("beta", TYPE, term(ATOMIC)),
        assertion("beta", KIND, lit("str", "atomic")),
        assertion("beta", HAS_CAPABILITY, lit("str", "render@1")),
        assertion("beta", IMPLEMENTS, lit("str", "harness.v1")),
        assertion("beta", INPUT, term(b_in)),
        assertion(b_in, TYPE, term(INPUT_PORT)),
        assertion(b_in, DIRECTION, lit("str", "in")),
        assertion(b_in, PORT_TYPE, lit("str", "int")),
        assertion("beta", OUTPUT, term(b_out)),
        assertion(b_out, TYPE, term(OUTPUT_PORT)),
        assertion(b_out, DIRECTION, lit("str", "out")),
        assertion(b_out, PORT_TYPE, lit("str", "str")),
        assertion(a_out, FEEDS, term(b_in)),
    ]
    rows.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
    return rows


def _closure_assertions() -> list[dict]:
    scope = "closure-demo"
    s_out = _port(scope, "sensor", "out", "r")
    h_in = _port(scope, "hub", "in", "r")
    h_out = _port(scope, "hub", "out", "r")
    k_in = _port(scope, "sink", "in", "r")
    rows = [
        assertion("sensor", TYPE, term(SPECIAL)),
        assertion("sensor", OUTPUT, term(s_out)),
        assertion(s_out, TYPE, term(OUTPUT_PORT)),
        assertion(s_out, DIRECTION, lit("str", "out")),
        assertion(s_out, PORT_TYPE, lit("str", "str")),
        assertion("hub", TYPE, term(ATOMIC)),
        assertion("hub", INPUT, term(h_in)),
        assertion(h_in, TYPE, term(INPUT_PORT)),
        assertion(h_in, DIRECTION, lit("str", "in")),
        assertion(h_in, PORT_TYPE, lit("str", "str")),
        assertion("hub", OUTPUT, term(h_out)),
        assertion(h_out, TYPE, term(OUTPUT_PORT)),
        assertion(h_out, DIRECTION, lit("str", "out")),
        assertion(h_out, PORT_TYPE, lit("str", "str")),
        assertion("sink", TYPE, term(ATOMIC)),
        assertion("sink", INPUT, term(k_in)),
        assertion(k_in, TYPE, term(INPUT_PORT)),
        assertion(k_in, DIRECTION, lit("str", "in")),
        assertion(k_in, PORT_TYPE, lit("str", "str")),
        assertion("loner", TYPE, term(CORE + "CompositeComponent")),
        assertion(s_out, FEEDS, term(h_in)),
        assertion(h_out, FEEDS, term(k_in)),
    ]
    rows.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
    return rows


FIXTURES = {
    "fixtures": {},
    "ontology": ONTOLOGY,
    "graphs": {
        "demo": {
            "schema": "semantic-graph.v1",
            "scope": "demo",
            "sources": {},
            "assertions": _assertions(),
        },
        "closure-demo": {
            "schema": "semantic-graph.v1",
            "scope": "closure-demo",
            "sources": {},
            "assertions": _closure_assertions(),
        },
    },
}

_SHAPE_OK = {
    "schema": "shapes.v1",
    "id": "needs-compute",
    "target": COMPONENT,
    "closed": False,
    "requirements": [
        {"relation": HAS_CAPABILITY, "min_count": 1, "max_count": 1, "datatype": "str", "allowed": []}
    ],
}
_SHAPE_TOO_FEW = {
    "schema": "shapes.v1",
    "id": "needs-two",
    "target": COMPONENT,
    "closed": False,
    "requirements": [
        {"relation": HAS_CAPABILITY, "min_count": 2, "max_count": 2, "datatype": "str", "allowed": []}
    ],
}
_SHAPE_CLOSED = {
    "schema": "shapes.v1",
    "id": "only-capability",
    "target": COMPONENT,
    "closed": True,
    "requirements": [
        {"relation": HAS_CAPABILITY, "min_count": 0, "max_count": None, "datatype": "str", "allowed": []}
    ],
}
_SHAPE_BAD = {
    "schema": "shapes.v1",
    "id": "bad",
    "target": COMPONENT,
    "closed": False,
    "requirements": [
        {"relation": CORE + "nope", "min_count": 1, "max_count": None, "datatype": None, "allowed": []}
    ],
}

_CASES = [
    ("ontology.query-all", {"op": "query", "graph": "demo", "query": {"scope": "demo", "target_class": COMPONENT}}),
    ("ontology.query-capability", {"op": "query", "graph": "demo", "query": {"scope": "demo", "target_class": COMPONENT, "requires_capabilities": ["compute@1"]}}),
    ("ontology.query-output", {"op": "query", "graph": "demo", "query": {"scope": "demo", "target_class": COMPONENT, "output_types": ["str"]}}),
    ("ontology.query-scope-escape", {"op": "query", "graph": "demo", "query": {"scope": "other", "target_class": COMPONENT}}),
    ("ontology.query-undeclared", {"op": "query", "graph": "demo", "query": {"scope": "demo", "target_class": CORE + "Nope"}}),
    ("ontology.validate-ok", {"op": "validate", "graph": "demo", "shape": _SHAPE_OK}),
    ("ontology.validate-too-few", {"op": "validate", "graph": "demo", "shape": _SHAPE_TOO_FEW}),
    ("ontology.validate-closed", {"op": "validate", "graph": "demo", "shape": _SHAPE_CLOSED}),
    ("ontology.validate-undeclared", {"op": "validate", "graph": "demo", "shape": _SHAPE_BAD}),
    ("ontology.hash", {"op": "hash", "graph": "demo"}),
    ("ontology.closure-demo", {"op": "closure", "graph": "closure-demo"}),
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

    fixtures_path = vectors / "ontology-fixtures.v1.json"
    fixtures_path.write_bytes(canonical(FIXTURES))
    fixtures_sha = sha256_file(fixtures_path)

    contract_sha = json.loads((contracts / "ABI.lock.v1.json").read_text())[
        "source_sha256"
    ]

    host = ReferenceHost(FIXTURES, contract_sha)
    cases: list[dict[str, object]] = []
    for case_id, scenario in _CASES:
        case: dict[str, object] = {
            "id": case_id,
            "category": "ontology",
            "fixture": "demo",
            "scenario": scenario,
        }
        case["expect"] = host.run_case(case)
        cases.append(case)

    suite = {
        "abi": "component-abi.v1",
        "schema": "cbp.vectors.v1",
        "contract_sha256": contract_sha,
        "fixtures_sha256": fixtures_sha,
        "cases": cases,
    }
    suite_path = vectors / "ontology-suite.v1.json"
    suite_path.write_bytes(canonical(suite))
    suite_sha = sha256_file(suite_path)

    lock = {
        "schema": "cbp.vectors-lock.v1",
        "abi": "component-abi.v1",
        "revision": 2,
        "contract_sha256": contract_sha,
        "note": (
            "ontology.v1 suite (SPEC-0023 M1+M2): a semantic graph is canonical and "
            "content-addressed; capability discovery is exact matching over a class "
            "and its declared subclasses; a closed shape is a deterministic gate; "
            "an undeclared term and a scope escape fail closed; and the pinned "
            "entailment closure (positive Datalog + stratified negation) is bounded, "
            "canonical-sorted, and content-addressed (closure.v1)."
        ),
        "fixtures": {"path": "ontology-fixtures.v1.json", "sha256": fixtures_sha},
        "suite": {"path": "ontology-suite.v1.json", "sha256": suite_sha},
    }
    (vectors / "ontology.lock.v1.json").write_bytes(canonical(lock))
    print(f"wrote ontology vectors: fixtures {fixtures_sha[:16]} suite {suite_sha[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
