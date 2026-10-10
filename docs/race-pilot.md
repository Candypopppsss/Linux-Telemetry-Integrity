# Rename/exec pilot: object identity and pathname representation

**Status:** User-reported pilot and subsequent read-only text-level corroboration, 2026-10-10. The VM's raw evidence has not been independently ingested into this repository. The candidate anomaly is not a confirmed security defect.

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

The two reported `rlternate` values are candidates for a non-snapshot pathname representation because neither path was assigned that basename. A later read-only verifier was run on the saved `journalctl -o cat` text (`falco_window.log`) and `correlation.csv`; the user-reported console output showed 100 distinct target PIDs, 100 unique saved Falco records, and zero comparison failures. It reproduced `rlternate` in the **saved journal text** at trial 6/PID 10649 and trial 65/PID 10709, not only in the derived CSV. Both target programs self-reported A and both Falco inode fields matched V2 inode 1044775. The string `rlternate` could reflect a hybrid between `race_exec` and `alternate`, but the journal export is downstream of eBPF event creation; this does not establish the original ring-buffer event bytes or the exact alteration stage. Reproduction remains required. The pilot did not observe executable-object misattribution or demonstrate a detection-rule bypass.

### Independent field accounting

The verifier printed four field-level candidates, **not four independent executions**: the same two `rlternate` strings appeared once per PID in `proc_exepath` and `evt_trusted_exepath`. In `falcosecurity/libs` 0.26.0, libsinsp's successful-exec parser copies `trusted_exepath` into the thread's `exepath` state; the two Falco fields are not independent kernel observations. Compare independent file-object evidence using V2 `mm->exe_file` device/inode instead.

- [Falco libs 0.26.0 userspace exec parser](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/parsers.cpp)

## Implementation hypothesis

Falco 0.45.0 includes `falcosecurity/libs` 0.26.0. In its modern eBPF implementation, successful-exec telemetry stores `trusted_exepath` through `auxmap__store_task_exe_file_path`, which obtains the executable file path and invokes an approximate dentry-walking reconstruction. The implementation comments expressly note that it cannot lock pathname components and can encounter races. This is a source-supported *mechanism to investigate*, not proof that it produced the two recorded strings.

- [Falco 0.45.0 release and libs version](https://falco.org/blog/falco-0-45-0/)
- [Falco libs 0.26.0 path reconstruction](https://github.com/falcosecurity/libs/blob/0.26.0/driver/modern_bpf/helpers/store/auxmap_store_params.h)
- [Falco libs 0.26.0 successful-exec event](https://github.com/falcosecurity/libs/blob/0.26.0/driver/modern_bpf/programs/attached/events/sched_process_exec.bpf.c)

## Verification gate

1. **Text-level check completed in user-reported output:** compare `correlation.csv` with `falco_window.log` by PID. Both anomalous PIDs were found in the saved journal lines. Preserve the original export and exact tool output; the original kernel event bytes are not available merely from a `journalctl -o cat` export.
2. Repeat the unchanged race configuration and record the denominator for independent runs, then run a controlled pair of equal-length, disjoint sentinel basenames. Treat only non-snapshot basenames as candidates; differences between two legitimate pathnames are expected under rename.
3. For every candidate retain PID, executable self-report, V2 device/inode, Falco inode fields, path fields, exchange counters, collector health, event counts, kernel version, and exact binary hashes.
4. Investigate decision consequences only after the representation discrepancy has been independently reproduced and a concrete rule/policy consuming the affected field is identified.

**Interpretation:** The current evidence supports correct file-object attribution in a bounded trial and a testable pathname-reconstruction hypothesis. It does not support a generic Falco bypass claim.
