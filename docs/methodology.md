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
