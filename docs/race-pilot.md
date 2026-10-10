# Rename/exec pilot: object identity and pathname representation

**Status:** User-reported pilot, 2026-10-10. The raw evidence remains on the research VM and has not been independently reviewed from this repository. The candidate anomaly is not a confirmed security defect.

## Measurement

- Environment: Debian 13.7, Linux `6.12.111+deb13-amd64`, ext4; Falco `0.45.0`, modern eBPF engine.
- Workload: 100 executions of a pathname concurrently exchanged with a second pathname by `renameat2(RENAME_EXCHANGE)`. Two distinct executable inodes represent A and B. The executable itself prints its A/B identity.
- Kernel reference: the project's V2 `sched_process_exec` collector reads the successful task's `mm->exe_file` device and inode.
- Falco comparison: PID-correlated `proc.exe_ino`, `evt.arg.exe_ino`, `proc.exepath`, `evt.arg.trusted_exepath`, and `evt.arg.filename`.
- Local evidence identifier: `raw/race-v2-falco-2_ff6nl3` (not published). The 100-trial window is not a multi-environment validation or an exhaustive event-loss assessment.

## Reported results

| Metric | Reported observation |
| --- | ---: |
| Trials | 100 |
| Executed A / B | 43 / 57 |
| Trials with recorded rename overlap | 99 |
| V2 and Falco executable-inode agreement | 100 / 100 |
| Missing, duplicate, or uncorrelatable target events | 0 |
| Falco resolved path matching requested pathname | 69 |
| Falco resolved path differing from requested pathname | 31 |
| Resolved basename `alternate` | 29 |
| Resolved basename `rlternate` | 2 |

The two named paths in the pilot were `race_exec` (requested) and `alternate` (exchange partner). The 29 `alternate` readings can occur when an already-selected file object changes pathname during the rename workload. They do **not** establish an integrity failure.

The two reported `rlternate` values are candidates for a non-snapshot pathname representation because neither path was assigned that basename. They require comparison against unmodified Falco journal output, inspection of the exact raw strings/bytes, and independent reproduction. Until then, a parser, renderer, or journal artifact remains possible. The pilot did not observe executable-object misattribution or demonstrate a detection-rule bypass.

## Implementation hypothesis

Falco 0.45.0 includes `falcosecurity/libs` 0.26.0. In its modern eBPF implementation, successful-exec telemetry stores `trusted_exepath` through `auxmap__store_task_exe_file_path`, which obtains the executable file path and invokes an approximate dentry-walking reconstruction. The implementation comments expressly note that it cannot lock pathname components and can encounter races. This is a source-supported *mechanism to investigate*, not proof that it produced the two recorded strings.

- [Falco 0.45.0 release and libs version](https://falco.org/blog/falco-0-45-0/)
- [Falco libs 0.26.0 path reconstruction](https://github.com/falcosecurity/libs/blob/0.26.0/driver/modern_bpf/helpers/store/auxmap_store_params.h)
- [Falco libs 0.26.0 successful-exec event](https://github.com/falcosecurity/libs/blob/0.26.0/driver/modern_bpf/programs/attached/events/sched_process_exec.bpf.c)

## Verification gate

1. Compare `correlation.csv` with `falco_window.log` by unique PID. Confirm each suspicious string occurs in the saved original journal line and inspect its byte encoding; preserve both the raw line and derived analysis. The original kernel event bytes are not available merely from a `journalctl -o cat` export.
2. Repeat on a controlled pair of equal-length, disjoint sentinel basenames. Treat only non-snapshot basenames as candidates; differences between the two legitimate pathnames are expected under rename.
3. For every candidate retain PID, executable self-report, V2 device/inode, Falco inode fields, path fields, exchange counters, collector health, event counts, kernel version, and exact binary hashes.
4. Investigate decision consequences only after the representation discrepancy has been independently reproduced and a concrete rule/policy consuming the affected field is identified.

**Interpretation:** The current evidence supports correct file-object attribution in a bounded trial and a testable pathname-reconstruction hypothesis. It does not support a generic Falco bypass claim.
