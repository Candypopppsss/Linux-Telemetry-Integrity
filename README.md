# Linux Telemetry Integrity

Validation controls for Linux execution telemetry: execution attempts versus completed image transitions, and executable-object identity versus pathname representation during concurrent rename.

**Status (2026-10-10):** four user-reported V2/Falco pilots recorded 400/400 matching executable-object identities and three candidate non-snapshot pathnames. A saved-event comparison produced one object/path predicate difference in 100 sentinel trials; live detection impact remains unverified. No vulnerability finding is claimed.

See [methodology](docs/methodology.md#reported-project-results) for static and failed-execution controls and [race-pilot results](docs/race-pilot.md) for the rename experiments, provenance checks, and decision-test limits. Raw VM artifacts have not been independently imported. Kernel integration of the separate bpftrace scaffold remains unverified.

## Scope

| Control | Syscall entries | Completed transitions | Failure return |
| --- | --- | --- | --- |
| Valid executable | 1 | 1 | — |
| Invalid executable format | 1 | 0 | `-ENOEXEC` |
| Absent pathname | 1 | 0 | `-ENOENT` |

These are expected results. A failed attempt without a completion event is expected tracepoint behavior; missing records alone do not establish tampering.

## Requirements

### Execution-control scaffold

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

## Rename/exec research

The reported VM uses Debian 13.7, Linux `6.12.111+deb13-amd64`, ext4, Falco `0.45.0`, libs `0.26.0`, and the modern eBPF engine. The archived original-name and sentinel runners compare V2 successful-exec device/inode records with Falco inode and pathname fields.

These runners are not a complete reproduction package: the VM's V2 collector, target binaries, C racer, and Falco laboratory rule are not included. Preserve their recorded hashes and raw evidence before changing the experiment. The latest available audit preflight found no `auditctl` or `ausearch` command and an inactive `auditd` service; no audit comparison result is recorded.

## Files

| Path | Purpose |
| --- | --- |
| [docs/methodology.md](docs/methodology.md) | Event semantics, acceptance criteria, and defensive interpretation |
| [docs/race-pilot.md](docs/race-pilot.md) | Four race pilots, provenance review, and offline/live decision status |
| `src/proof_of_concept/` | C workload and bpftrace observer |
| `src/mutation/` | Archived V2/Falco race orchestration scripts |
| `src/tests/` | Integration runner, trace and saved-path validators, and unit tests |
| `.github/workflows/validation.yml` | Automated validation |

## License

[MIT](LICENSE).
