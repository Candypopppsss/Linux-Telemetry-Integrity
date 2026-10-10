# Methodology

## Event model

The execution controls compare `syscalls:sys_enter_execve`, `syscalls:sys_exit_execve`, and `sched:sched_process_exec`. In Linux v6.6, `exec_binprm()` returns on a negative binary-handler result before `trace_sched_process_exec()`. A failed attempt without a completion event is expected behavior.

| Control | Syscall entries | Completed transitions | Failure return |
| --- | ---: | ---: | --- |
| Valid executable | 1 | 1 | — |
| Invalid executable format | 1 | 0 | `-ENOEXEC` |
| Absent pathname | 1 | 0 | `-ENOENT` |

These are expected counts, not kernel integration results.

## Environment

The intended baseline is an isolated x86-64 VM with Linux v6.6, bpftrace 0.21.0, Python 3.10+, and a C11 compiler. Required kernel options are `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_PERF_EVENTS`, `CONFIG_FTRACE`, `CONFIG_FTRACE_SYSCALLS`, and `CONFIG_TRACEPOINTS`.

Run in the initial PID namespace with readable tracefs at `/sys/kernel/tracing`, an executable repository filesystem, and root access permitted by kernel tracing policy. No `binfmt_misc` handler should accept the invalid-image control.

## Collection and validation

The single-threaded C workload sets its comm to `lti-attempt` and calls `execve()` directly. The observer filters on `pid == cpid` and that comm, excluding the tracer's initial launch. This caller-controlled filter is for the laboratory only.

At entry, the observer stores pending state by TID and emits `LTI_ENTER`. Completion emits `LTI_EXEC`; a failed return emits `LTI_EXIT` with the negative errno. Either outcome clears pending state. The target or caller emits a separate `LTI_RESULT` marker in the same output stream.

Each case requires a clean tracer exit, empty stderr, one entry followed by one expected outcome, matching PID/TID, and one matching workload marker. The runner uses 64 perf-buffer pages per CPU and a 30-second timeout per case. It saves traces, diagnostics, and a manifest with trace hashes under `raw/exec-control-*`. An `INCOMPLETE` manifest is invalid.

Retain the kernel build/configuration and tracepoint `format` files with each run. To revalidate a saved invalid-image trace:

```bash
python3 src/tests/validate.py raw/exec-control-REPLACE/invalid.log --errno 8
```

## Limits

The control covers one single-threaded `execve()` attempt per case. It excludes `execveat()`, interpreter chains, nonleader-thread execution, namespace translation, TID reuse, and failures after the point of no return.

Entry and outcome share one tracer and perf-buffer transport, so they do not independently exclude collection loss. The control does not test `BPF_MAP_TYPE_RINGBUF`, buffer pressure, attachment changes, or daemon configuration changes.

## Reported project results

The following results were supplied in project conversations. Timestamps identify reports in UTC, not verified execution times. Raw VM artifacts and a complete reproducible build package are not included; these reports do not validate the separate bpftrace control above.

| Report timestamp (UTC) | Control | Reported result |
| --- | --- | --- |
| 2026-10-10 04:43:52 | Debug failed-execution control | Valid A/B images: LSM=1, EXEC=1, matching identities. Invalid ELF: `ENOEXEC` (8), LSM=1, EXEC=0. |
| 2026-10-10 05:02:33 | V2 static baseline | 100 expected, 100 correct; zero missing, mismatched, or duplicate records. |

The V2 evidence directory is `raw/v2-baseline-tjisapin`. Reported counters were seen=submitted=received=written=100, consistent accounting, and zero read, lookup, reservation, malformed-record, and write errors. A completed V2 failed-execution result is not available.

The subsequent four race runs, racer source review, and rule comparison are recorded in [race-pilot.md](race-pilot.md). The earlier racer build failure is superseded by those completed runs; source-to-binary build equivalence remains unverified.

## Audit status

The latest supplied preflight supersedes the earlier inactive-service report:

| Check | Reported value |
| --- | --- |
| `systemctl is-active auditd` | `active` |
| `sudo auditctl -s` | `enabled 1`, `failure 1`, daemon PID 15274 |
| Queue status | `rate_limit 0`, `backlog_limit 8192`, `lost 0`, `backlog 0` |
| Backlog wait | `backlog_wait_time 60000`, `backlog_wait_time_actual 0` |
| Login UID policy | `loginuid_immutable 0 unlocked` |
| `sudo auditctl -l` | `No rules` |
| Boot parameters | Kernel `6.12.111+deb13-amd64`; no explicit `audit=` parameter shown |

The unprivileged `command -v` checks printed no paths, but `sudo auditctl` executed successfully. A zero lost counter in this preflight is not a workload measurement.

A later user-reported three-observer run captured V2, Falco, and audit data:

| Report timestamp (UTC) | Evidence directory under `raw/` | Trials | Rename overlap | V2/Falco identity | Audit loss before/after |
| --- | --- | ---: | ---: | ---: | ---: |
| 2026-10-10 15:25:36 | `race-v2-falco-ozmnmdkw` | 100 | 98 | 100 / 100 correct | 0 / 0 |

The run reported zero missing, duplicate, misattributed, or representation-inconsistent V2/Falco records and passing collector accounting. Resolved paths were 64 equal and 36 with the requested filename differing from the two resolved-path fields. The bounded audit rule selected successful `execve` and `execveat` calls for the laboratory user; the saved audit log was reported as 448 KiB.

These are conversation-reported results. The raw audit log is not published, and audit serial/PID/`PATH` inode correlation has not been completed. The run therefore establishes capture with no reported audit queue loss, not agreement between audit object identity and the V2 oracle.

## Interpretation

| Observation | Interpretation |
| --- | --- |
| Entry and negative exit without completion | Failed attempt |
| Entry and completion | Completed image transition |
| Independently confirmed success without completion | Collection gap requiring investigation |
| Unmatched entry | Indeterminate; check lifecycle, identity mapping, and loss |

Collectors should distinguish attempts, failures, and completions and report attachment, transport, queue, and exporter health. A pathname is not an immutable executable identity. For an audit comparison, retain active rules, backlog settings, and before/after lost counters; success-only rules cannot establish failed-attempt coverage.

## References

- [Linux v6.6 execution path](https://github.com/torvalds/linux/blob/v6.6/fs/exec.c)
- [Linux v6.6 scheduler trace events](https://github.com/torvalds/linux/blob/v6.6/include/trace/events/sched.h)
- [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
- [bpftrace 0.21 documentation](https://bpftrace.org/docs/0.21)
