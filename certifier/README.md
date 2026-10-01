# certifier/ — runtime certification

Runs the [`vectors/`](../vectors/) against a candidate host/runtime and emits a
deterministic **certification record**. A runtime that has not passed is not
trusted to execute (SPEC-0013).

| file | what |
| --- | --- |
| [`certify.py`](certify.py) | The certifier: verifies the content-addressed suite/lock, drives a host, compares normalized observations, emits the record. Stdlib only. |
| [`reference_host.py`](reference_host.py) | A deterministic **reference host** (a test double, not a production host) that implements the ABI fixtures so the vectors run offline. Also speaks the external protocol on stdio. |
| [`PROTOCOL.md`](PROTOCOL.md) | The language-neutral `cbp.conformance-host.v1` JSON-lines protocol any host implements to be certified. |

## Run it

```sh
# offline, against the in-process reference host
python3 certifier/certify.py

# against an external host over the JSON-lines protocol
python3 certifier/certify.py --host-cmd "python3 certifier/reference_host.py"
```

Exit: `0` certified, `1` a case failed or was nondeterministic, `2` the suite/lock
or contract drifted (refused before running). The record is written to
`--out` and stdout. It is **deterministic**: no wall-clock, so a certification is
reproducible. It records the host's pinned identity/version (SPEC-0013).
