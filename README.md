# Linux Telemetry Integrity

Linux execution telemetry validation for defenders. The initial experiment measures the semantic gap between **execve syscall attempts** and **sched_process_exec image transitions**. A completed-execution sensor cannot independently enumerate failed execution attempts.

**Research status:** infrastructure and control workloads are implemented. Kernel tracing has not been validated in the authoring environment. No new kernel vulnerability, vendor finding, or measured bypass rate is claimed.

## Project metadata

| Field | Scope |
| --- | --- |
| Project | Linux-Telemetry-Integrity |
| Focus | Event coverage and telemetry integrity |
| Target components | `syscalls:sys_enter_execve`, `syscalls:sys_exit_execve`, `sched:sched_process_exec` |
| Source baseline | Upstream Linux tag `v6.6` |
| Objectives | Distinguish attempts from completions; validate negative controls; classify collection failures; specify defensive correlation |
| Deferred experiments | `execveat`, BPF LSM object identity, audit correlation, fanotify, journald, attachment removal, buffer pressure |

## Telemetry gap overview

In Linux `v6.6`, `fs/exec.c:exec_binprm()` returns when `search_binary_handler()` reports an error. `trace_sched_process_exec(current, old_pid, bprm)` executes only after binary-handler processing succeeds. Failure before this point does not produce that tracepoint. This is an instrumentation boundary, not evidence of kernel tampering. [S1]

The trace event receives a **task_struct**, the prior task ID, and a **linux_binprm**. Its formatted payload contains `filename`, `pid`, and `old_pid`. It does not supply an attempted syscall's error code. `bprm->filename` is a name, not an immutable `(device, inode)` identity. Interpreter chains and namespace-relative names require separate analysis. [S1, S2]

The laboratory joins entry and outcome by TID in a single-threaded workload. A failed `execve()` returns `-errno` at syscall exit; the workload independently records userspace `errno`. Missing syscall records invalidate the run rather than establishing evasion. [S3]

Tracepoint detachment, syscall policy filtering, and transport loss are separate hypotheses. They are not reproduced here. **BPF ring-buffer** reservation failure is also distinct from event non-emission. This prototype uses bpftrace's perf output transport, not a `BPF_MAP_TYPE_RINGBUF` experiment. [S4, S5]

| Operation | Required access | Impact |
| --- | --- | --- |
| Compile and execute control binary | Normal user; executable scratch filesystem | One bounded attempt per invocation |
| Attach laboratory tracer | Root in isolated VM; kernel BPF/tracing policy permits attachment | Read-only probes; no existing sensor modification |
| Delegate BPF tracing | Typically `CAP_BPF` and `CAP_PERFMON`; additional policy/resource constraints apply | Must validate on the actual kernel; container root is insufficient evidence |
| Modify audit policy | `CAP_AUDIT_CONTROL` | Not performed by this project |

## Environment & reproduction setup

Use a disposable x86-64 VM booted into a kernel built from upstream `v6.6`, with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_PERF_EVENTS=y`, `CONFIG_FTRACE=y`, `CONFIG_FTRACE_SYSCALLS=y`, and `CONFIG_TRACEPOINTS=y`. Use bpftrace `0.21.0`, Python `3.10+`, and a C11 compiler. This is the intended baseline, not a certified compatibility matrix.

Run in the VM's initial PID namespace. Require readable tracefs at `/sys/kernel/tracing`, the three named tracepoints, and an executable repository filesystem. Keep the VM idle and do not install a binfmt_misc handler that accepts the invalid-image control. Existing **auditd** and **systemd-journald** configuration is irrelevant to these three-probe controls and is not altered.

```bash
git clone https://github.com/Candypopppsss/Linux-Telemetry-Integrity.git
cd Linux-Telemetry-Integrity
python3 -m unittest discover -s src/tests -v
uname -a
bpftrace --version
sudo bpftrace --info
sudo bpftrace -l 'tracepoint:syscalls:sys_*execve'
sudo bpftrace -l 'tracepoint:sched:sched_process_exec'
sudo python3 src/tests/run_lab.py
```

The integration runner fixes `BPFTRACE_PERF_RB_PAGES=64`, imposes a 30-second timeout per case, and writes raw stdout, stderr, and a hashed manifest under `raw/exec-control-*`. Any tracer diagnostic, nonzero exit, unexpected errno, or record mismatch fails the run. Retain the VM build configuration and tracepoint `format` files alongside results before publishing.

| Control | Expected entry | Expected completion | Expected failure return |
| --- | --- | --- | --- |
| Valid self-execution | 1 | 1 | Not evaluated after completion |
| Invalid executable text, no shebang | 1 | 0 | `-ENOEXEC` (`-8`) |
| Absent pathname | 1 | 0 | `-ENOENT` (`-2`) |

These are expected values, not measured results. CI validates C compilation, Python syntax/linting, and parser/workload controls. It does not load BPF programs or establish kernel behavior.

## Repository index

| Path | Function |
| --- | --- |
| `docs/methodology.md` | Source review, state transitions, experiment acceptance criteria |
| `docs/detection_engineering.md` | Defensive correlation and collector health requirements |
| `src/proof_of_concept/attempt.c` | Single-attempt control workload |
| `src/proof_of_concept/exec_observer.bt` | Laboratory entry/completion/failure sensor |
| `src/tests/run_lab.py` | Bounded integration runner |
| `src/tests/validate.py` | Strict before/after trace validation |

## Responsible disclosure timeline

| Milestone | Date (UTC) | Evidence / status |
| --- | --- | --- |
| Vulnerability discovery | Not established | No vulnerability finding asserted |
| Maintainer notification | Not sent | No disclosure case opened |
| Maintainer acknowledgement | Not received | Not applicable to current semantic control |
| Triage / remediation | Not established | Requires a reproducible product defect |
| Research release | Not assigned | Repository scaffolding is not a validated findings release |

If a product claims failed-attempt coverage and fails the controls with healthy independent sensors, preserve its version, configuration, raw evidence, and maintainer response before assigning a finding identifier or publication date.

## Sources

- [S1: Linux v6.6 execution path](https://github.com/torvalds/linux/blob/v6.6/fs/exec.c)
- [S2: Linux v6.6 scheduler trace event definitions](https://github.com/torvalds/linux/blob/v6.6/include/trace/events/sched.h)
- [S3: execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
- [S4: bpftrace 0.21 documentation](https://bpftrace.org/docs/0.21)
- [S5: Linux 6.6 BPF ring-buffer documentation](https://docs.kernel.org/6.6/bpf/ringbuf.html)
- [S6: capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)

## License

MIT. See `LICENSE`.
