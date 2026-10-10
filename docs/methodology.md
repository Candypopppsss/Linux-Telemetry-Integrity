# Methodology

## Event model

The experiment tests whether completion-only telemetry covers failed execution attempts. It uses `syscalls:sys_enter_execve`, `syscalls:sys_exit_execve`, and `sched:sched_process_exec`.

In Linux `v6.6`, `exec_binprm()` returns on a negative binary-handler result before `trace_sched_process_exec()`. An absent pathname fails during candidate opening; unrecognized executable text ordinarily fails with `ENOEXEC`. These failures do not reach the completion tracepoint. See the [execution path](https://github.com/torvalds/linux/blob/v6.6/fs/exec.c) and [trace event definition](https://github.com/torvalds/linux/blob/v6.6/include/trace/events/sched.h).

## Controls

The single-threaded workload sets its comm to `lti-attempt` and calls `execve()` directly. The observer filters on `pid == cpid` and that comm, excluding the tracer's initial command launch. This caller-controlled filter is suitable only for the laboratory.

| Stage | Valid executable | Invalid format | Absent pathname |
| --- | --- | --- | --- |
| Syscall entry | Set pending TID; emit `LTI_ENTER` | Same | Same |
| Candidate opening | Succeeds | Succeeds | Fails |
| Binary handler | Accepts image | Returns `-ENOEXEC` | Not reached |
| Outcome | `LTI_EXEC` | `LTI_EXIT ... -8` | `LTI_EXIT ... -2` |
| Workload marker | `LTI_RESULT success` | `LTI_RESULT errno=8` | `LTI_RESULT errno=2` |

The observer deletes pending state at the outcome. It does not depend on a successful syscall-exit event after completion. The workload marker reports the result independently of probe logic, but shares the captured output stream.

## Acceptance criteria

Each case requires a clean tracer exit, empty stderr, exactly one entry followed by one expected outcome, matching PID/TID, and exactly one matching workload marker. Failure cases must return the expected negative errno. All three cases must pass before interpreting coverage.

Retain the manifest, raw traces, diagnostics, kernel build configuration, and tracepoint `format` files. Record the exact kernel revision when reviewing distribution kernels or backports.

To revalidate a saved invalid-image trace, substitute its actual path:

```bash
python3 src/tests/validate.py raw/exec-control-REPLACE/invalid.log --errno 8
```

## Limits

The observer uses bpftrace's perf-buffer transport, with 64 pages per CPU. It does not test `BPF_MAP_TYPE_RINGBUF` or deliberate buffer pressure. Entry and outcome records share one tracer; they cannot independently rule out transport loss.

Coverage is limited to one single-threaded `execve()` attempt per case. The controls do not cover `execveat()`, interpreter chains, nonleader-thread execution, namespace translation, TID reuse, or failures after the point of no return. Filenames are not immutable executable-object identities.

The experiment does not change monitoring attachments, audit rules, or daemon configuration. No measured bypass rate or product defect is established.

## Reported project results

These results come from user-posted reports in the project conversation, retrieved on 2026-10-10. Timestamps below identify the messages in UTC, not independently verified execution times. The underlying source revisions, raw artifacts, and kernel configurations were unavailable for this review. These reports do not validate the repository's bpftrace scaffold.

| Report timestamp (UTC) | Control | User-reported result | Scope |
| --- | --- | --- | --- |
| 2026-10-10 04:43:52 | Failed execution, debug transport | Valid images A and B each had LSM=1 and EXEC=1 with matching identities. Invalid ELF returned `ENOEXEC` (8), with LSM=1 and EXEC=0. Report: PASS. | Debug control only; does not validate ring-buffer delivery. |
| 2026-10-10 05:02:33 | V2 static baseline, Debian VM | Expected=100, correct=100; missing, mismatched, and duplicate records=0. Report: PASS. | One static 100-execution run; does not establish race coverage or universal loss-free collection. |

The V2 report identifies `raw/v2-baseline-tjisapin` as its local evidence directory. It reports seen=submitted=received=written=100, accounting CONSISTENT, and zero read errors, missing task/mm/exe/inode/superblock counters, reservation failures, malformed records, and write errors. The directory is an evidence locator, not an artifact included in this repository.

The V2 failed-execution control remains a proposed next step; no completed result was retrieved. A separate user-posted build failure for `src/mutation/race_exec.c` reports implicit declarations of `major()` and `minor()` under `-Werror`. That source is absent from this repository, and no confirmed build fix or completed race result was retrieved.

Before promoting these reports to reproduced results, preserve the source revision, exact kernel build/configuration, commands, raw output, and artifact hashes; rerun the corresponding controls. No bypass rate or vulnerability finding follows from these reports.

## Defensive interpretation

| Observation | Interpretation |
| --- | --- |
| Entry and negative exit without completion | Expected failed attempt |
| Entry and completion | Completed image transition |
| Independently confirmed success without completion | Collection gap requiring investigation |
| Unmatched entry | Indeterminate; inspect lifecycle, identity mapping, and loss |
| Unexpected attachment or policy change | Possible monitoring impairment; correlate actor and maintenance records |

A production collector should distinguish attempts, failures, and completions; correlate process identity across lifecycle changes; and export attachment, transport, queue, and exporter health. The laboratory comm filter must not become a production security boundary.

If audit is used as a comparator, preserve its rules, status, backlog settings, and lost-counter deltas. Success-only audit rules cannot validate failed-attempt coverage. Journal silence is not evidence that an execution attempt did not occur.

## References

- [Linux v6.6 execution path](https://github.com/torvalds/linux/blob/v6.6/fs/exec.c)
- [Linux v6.6 scheduler trace events](https://github.com/torvalds/linux/blob/v6.6/include/trace/events/sched.h)
- [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
- [bpftrace 0.21 documentation](https://bpftrace.org/docs/0.21)
