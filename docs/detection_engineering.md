# Detection engineering

## Signal contract

Collect **execve** and **execveat** entry events, negative syscall results, and **sched_process_exec** completion events as separate event classes. The bundled `.bt` observer covers only one controlled `execve` process. Its comm filter is caller-controlled and must not be deployed as a security boundary.

Use a versioned event schema containing host ID, boot ID, monotonic event timestamp, kernel TID/TGID, process start identity, PID namespace identity, collector ID, event class, syscall name, and return value where applicable. Read names at entry but treat them as untrusted, truncated, namespace-relative input rather than resolved object identity.

| Condition | Classification | Action |
| --- | --- | --- |
| Entry followed by negative exit; no completion | Failed attempt, expected scheduler semantics | Preserve error and attempted target; evaluate behavior separately |
| Entry followed by completion | Completed transition | Link new process-image state to the attempt |
| Independently confirmed success without completion | Suspected collection gap | Inspect attachment, filtering, transport, and export health |
| Unmatched entry | Indeterminate | Inspect fatal exit, pending-state expiry, sensor loss, and identity mapping |
| Attachment or policy changed outside authorized maintenance | Potential monitoring impairment | Correlate change actor, approved deployment, and coverage loss |

A single failed execution is not a tampering indicator. Failed image loading, missing executables, and permission errors occur in normal operation. Frequency and target sensitivity can inform a behavioral rule but do not prove suppression.

## Usable laboratory detection

```bash
# Verify actual event schemas before loading the observer.
sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
sudo cat /sys/kernel/tracing/events/syscalls/sys_exit_execve/format
sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format

# Execute the bounded controls and validate the before/after signal contract.
sudo python3 src/tests/run_lab.py
# Revalidate a preserved invalid-image trace:
python3 src/tests/validate.py raw/exec-control-REPLACE/invalid.log --errno 8
```

Do not infer success from empty output. The validator exits nonzero when the required records or independent workload marker are absent. Review `.stderr` and `manifest.json`; an `INCOMPLETE` manifest is not a negative detection result.

## Attachment integrity

For a production BPF collector, inventory expected program tags, program types, attachment types, target tracepoints, map identities, and collector version at deployment. Program IDs and link IDs are runtime identities; a restart can legitimately change them. Compare them with an approved deployment record rather than a permanently fixed numeric ID.

Read `bpftool prog show` and `bpftool link show` where permitted. Legacy perf-event attachments may not appear as BPF links; also inventory the collector's perf-event descriptors and its attach results. An empty link list alone cannot establish detachment.

Emit an external health alert when an expected attachment is absent on repeated checks outside maintenance, or when the collector exits while the host remains reachable. Inventory from the same compromised host is not trustworthy against an adversary controlling the kernel. Forward health data to a separately administered receiver.

## Transport integrity

A production **BPF ring-buffer** sensor should increment a per-CPU failure counter when `bpf_ringbuf_reserve()` returns NULL. Export the counter through a separate health path and report interval deltas. NULL does not uniquely identify a full ring: reservation can also fail to acquire a lock in NMI context. [S5]

For perf-buffer collectors, record lost-event notifications and consumer lag. Report userspace queue drops and exporter failures separately from kernel producer failures. A healthy collector process does not establish complete delivery.

```c
/* Integration pattern, not a complete loadable program.
 * reserve_failures: BPF_MAP_TYPE_PERCPU_ARRAY, one __u64 value at key 0.
 * events: BPF_MAP_TYPE_RINGBUF. struct event must be defined by the sensor.
 */
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) {
    __u32 key = 0;
    __u64 *failures = bpf_map_lookup_elem(&reserve_failures, &key);
    if (failures)
        __sync_fetch_and_add(failures, 1);
    return 0;
}
/* Initialize every exported field before submission. */
__builtin_memset(e, 0, sizeof(*e));
bpf_ringbuf_submit(e, 0);
```

## Audit and daemon checks

If **auditd** is an independent comparator, record `auditctl -s`, `auditctl -l`, enabled architectures, failure/success filters, backlog settings, and `lost` counter deltas. Review `CONFIG_CHANGE` records and approved rule deployments. An exec rule limited to successful syscalls cannot validate failed-attempt coverage.

Use read-only `systemctl show auditd -p ActiveState -p SubState -p MainPID` and corresponding collector service checks. Missing service health must be distinguished from rule filtering and export failure. **systemd-journald** is not a default complete exec-event source; ordinary journal silence cannot refute a syscall event.

This repository does not provide a Sigma rule for invented event fields or a YARA rule purporting to detect runtime telemetry loss. Deployable fleet rules require the collector's real schema and representative positive/negative samples.

## Hardening and validation

Specify whether the sensor promises attempts, completions, object identity, or all three. Minimize collector privileges, restrict policy/attachment control to approved deployment identities, and preserve remote evidence. Audit immutable policy may be appropriate where operational requirements permit it; this laboratory does not enable it.

Gate sensor releases on the three controls plus `execveat`, interpreter, permission-denial, namespace, nonleader-thread, and bounded transport-pressure cases. Measure event coverage and invalid-run rate separately. Treat these additional cases as required future work rather than implemented coverage.

## References

Source labels S1–S6 resolve to the primary documentation links in [README](../README.md#sources).
