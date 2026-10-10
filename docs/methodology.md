# Methodology

## Claim and threat model

The tested hypothesis is a coverage mismatch: a sensor collecting only **sched_process_exec** cannot report `execve()` attempts rejected before successful binary-handler processing. The caller requires no elevated capability to attempt execution of a permitted local file or an absent pathname. The observer requires privileged tracing access.

The experiment does not disable monitoring, modify BPF attachments, alter audit rules, or consume buffers deliberately. It evaluates the event model before considering malicious manipulation. A root adversary's ability to change the observer is outside this control's trust model.

## Static source review

Review upstream Linux tag `v6.6`, `fs/exec.c`, specifically `do_execveat_common()`, `bprm_execve()`, `search_binary_handler()`, and `exec_binprm()`. Record the resolved commit ID when repeating the review against a locally checked-out kernel. Distribution backports require a separate review.

`bprm_execve()` opens the execution candidate and assigns `bprm->file`. `search_binary_handler()` prepares the header buffer, calls `security_bprm_check()`, and evaluates registered **linux_binfmt** handlers. `exec_binprm()` propagates a negative handler result before reaching the scheduler execution tracepoint. Interpreter rewrites can invoke the handler path multiple times. [S1]

An absent pathname fails during candidate opening. An executable file containing unrecognized text without a shebang ordinarily fails binary-format recognition with `ENOEXEC`. A configured binfmt_misc handler can change that result; unexpected behavior invalidates the specified baseline. [S1, S3]

An LSM check is neither syscall entry nor proof of a completed image transition. An opening failure can precede `security_bprm_check()`. A later format failure can occur after it. This repository does not supply a BPF LSM program and makes no LSM record-count claim. [S1]

## Runtime state transition

The C workload sets its comm to `lti-attempt` and calls `execve()` directly. This prevents libc shell fallback and separates the controlled attempt from bpftrace's initial command launch. The observer additionally filters on `pid == cpid`; it is intentionally restricted to the direct child.

| Stage | Successful control | Invalid-image control | Absent-path control |
| --- | --- | --- | --- |
| Before attempt | Original task image; no pending map entry | Same | Same |
| Syscall entry | `@pending[tid]=1`; `LTI_ENTER` | Same | Same |
| Candidate open | Candidate assigned to `bprm->file` | Candidate assigned | Opening returns error |
| Binary handler | Accepts the control binary | Returns `-ENOEXEC` | Not reached |
| Scheduler completion hook | `LTI_EXEC`; pending entry deleted | Not reached | Not reached |
| Failure exit hook | Ignored after completion | `LTI_EXIT ... -8`; entry deleted | `LTI_EXIT ... -2`; entry deleted |
| Workload ground truth | New image prints success | Original image prints errno 8 | Original image prints errno 2 |

The observer deletes pending state at successful completion. It does not depend on the presence or absence of a subsequent successful syscall-exit event. Linux `execve()` does not return to the old userspace image on success. [S3]

```text
# Illustrative records only; PID/TID values are synthetic.
# Successful image transition:
LTI_ENTER 100 100
LTI_EXEC 100 100
LTI_RESULT success

# Format rejection:
LTI_ENTER 101 101
LTI_EXIT 101 101 -8
LTI_RESULT errno=8
```

## Transport and confounders

The prototype uses bpftrace `printf()` and its perf-buffer transport with 64 pages per CPU. This is not a BPF ring-buffer starvation test. Both reference and completion records share the same tracer, so they are not independent evidence against transport loss. [S4]

Treat lost-event messages, helper errors, attachment failures, timeouts, and incomplete records as invalid runs. A silent error is still possible; three bounded controls do not prove a transport cannot lose data. A production experiment requires independently collected workload truth and explicit producer/consumer health counters.

The workload is single-threaded, with one attempt per process. Production execution from a nonleader thread can change task IDs during exec. PID namespace translation, TID reuse, interpreter resolution, compat syscalls, `execveat()`, and failure after the point of no return require separate controls. [S1, S2, S3]

## Acceptance criteria and metrics

Accept a control only when the tracer exits cleanly, stderr is empty, exactly one entry and one corresponding outcome are present, PID/TID match, and the workload result agrees with the intended result. Require all three controls to pass before interpreting completion-only coverage.

| Metric | Definition | Current measured value |
| --- | --- | --- |
| Attempt coverage | Observed entries / independently confirmed attempts | Not measured under BPF |
| Failure coverage | Matched failure exits / confirmed failed attempts | Not measured under BPF |
| Completion coverage | Completion records / confirmed successful transitions | Not measured under BPF |
| Invalid runs | Runs failing health or correlation criteria | Not measured under BPF |

A missing completion accompanied by a verified negative syscall result is expected semantics. A missing completion after independently confirmed successful execution is a collection defect candidate. Do not classify either as tampering without attachment, policy, or collector evidence.

## References

Source labels S1–S6 resolve to the versioned source and primary documentation links in [README](../README.md#sources).
