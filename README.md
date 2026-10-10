# Linux Telemetry Integrity

Linux execution-telemetry controls and a study of executable identity during concurrent pathname changes.

**Research status — 2026-10-10:** four reported V2/Falco runs recorded 400/400 matching executable identities and three candidate hybrid pathnames. An offline rule comparison found one decision difference. Two later reported live runs each recorded 100 object and 100 path alerts without reproducing a hybrid pathname. No live bypass is established; the root cause remains unverified.

## Experiments

| Experiment | Status | Documentation |
| --- | --- | --- |
| Execution attempts and completed image transitions | Control code and parser tests available; kernel integration unverified | [Methodology](docs/methodology.md) |
| V2/Falco rename–execution comparison | Four initial runs and two later live controls, each 100 trials; raw evidence retained on the research VM | [Results](docs/race-pilot.md) |
| Audit comparison | Bounded capture reported with zero audit loss; PID/object correlation pending | [Audit status](docs/methodology.md#audit-status) |

## Run the execution controls

Use an isolated x86-64 VM with Python 3.10+, a C11 compiler, and permission to trace the kernel. The intended baseline is Linux v6.6 with bpftrace 0.21.0; compatibility has not been validated. See [kernel requirements](docs/methodology.md#environment).

```bash
python3 -m unittest discover -s src/tests -v
sudo bpftrace -l 'tracepoint:syscalls:sys_*execve'
sudo bpftrace -l 'tracepoint:sched:sched_process_exec'
sudo python3 src/tests/run_lab.py
```

Output is written to `raw/exec-control-*`. All three cases must pass. CI checks Python lint and syntax, C compilation, and parser/workload tests; it does not validate kernel tracing.

## Repository

| Path | Contents |
| --- | --- |
| `src/proof_of_concept/` | C execution control and bpftrace observer |
| `src/mutation/` | Original-name and sentinel race runners |
| `src/tests/` | Control runner, validators, and unit tests |
| `docs/` | Methods, measurements, provenance, and open work |
| `.github/workflows/validation.yml` | CI validation |

The race runners depend on VM-local components not included here. See [reproduction dependencies](docs/race-pilot.md#reproduction-dependencies) before running them.

[MIT license](LICENSE).
