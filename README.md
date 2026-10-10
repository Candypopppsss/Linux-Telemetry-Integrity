# Linux Telemetry Integrity

Validation controls for Linux execution telemetry. The current experiment compares `execve()` attempts with `sched_process_exec` image transitions.

**Status:** control workload, observer, and validator implemented. Kernel tracing remains unverified for this scaffold. No vulnerability finding is claimed.

## Scope

| Control | Syscall entries | Completed transitions | Failure return |
| --- | --- | --- | --- |
| Valid executable | 1 | 1 | — |
| Invalid executable format | 1 | 0 | `-ENOEXEC` |
| Absent pathname | 1 | 0 | `-ENOENT` |

These are expected results. A failed attempt without a completion event is expected tracepoint behavior; missing records alone do not establish tampering.

## Requirements

Use an isolated x86-64 VM with upstream Linux `v6.6`, bpftrace `0.21.0`, Python `3.10+`, and a C11 compiler. This is the intended baseline, not a validated compatibility matrix.

The kernel must enable `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_PERF_EVENTS`, `CONFIG_FTRACE`, `CONFIG_FTRACE_SYSCALLS`, and `CONFIG_TRACEPOINTS`. Run in the initial PID namespace with readable tracefs at `/sys/kernel/tracing` and an executable repository filesystem. No `binfmt_misc` handler should accept the invalid-image control.

## Run

From the repository root:

```bash
# Parser tests and unprivileged workload controls
python3 -m unittest discover -s src/tests -v

# Confirm the required tracepoints
sudo bpftrace -l 'tracepoint:syscalls:sys_*execve'
sudo bpftrace -l 'tracepoint:sched:sched_process_exec'

# Kernel integration controls
sudo python3 src/tests/run_lab.py
```

The runner requires root with BPF tracing permitted by kernel policy. It uses 64 perf-buffer pages per CPU and a 30-second timeout per case. Traces, diagnostics, and a manifest containing trace hashes are written to `raw/exec-control-*`. All three cases must pass; an `INCOMPLETE` manifest is an invalid run.

CI checks C compilation, Python syntax and lint, and parser/workload tests. It does not validate BPF attachment or kernel event delivery.

## Files

| Path | Purpose |
| --- | --- |
| [docs/methodology.md](docs/methodology.md) | Event semantics, acceptance criteria, and defensive interpretation |
| `src/proof_of_concept/` | C workload and bpftrace observer |
| `src/tests/` | Integration runner, trace validator, and unit tests |
| `.github/workflows/validation.yml` | Automated validation |

## License

[MIT](LICENSE).
