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

## Second independent 100-trial run

A second run was completed on 2026-10-10 using the previously committed `src/mutation/lti_race_v2_falco.py` runner. Its evidence locator is `raw/race-v2-falco-lqcpl51s` (retained on the research VM, not independently archived here).

| Metric | Run 1 | Run 2 | Both runs |
| --- | ---: | ---: | ---: |
| Target executions | 100 | 100 | 200 |
| Self-reported A / B | 43 / 57 | 42 / 58 | 85 / 115 |
| Trials with recorded exchange overlap | 99 | 98 | 197 |
| Correct V2/Falco executable-object attribution | 100 | 100 | 200 |
| Inode misattributions | 0 | 0 | 0 |
| Missing Falco records | 0 | 0 | 0 |
| Falco resolved basename `race_exec` | 69 | 59 | 128 |
| Falco resolved basename `alternate` | 29 | 41 | 70 |
| Falco resolved basename `rlternate` | 2 | 0 | 2 |

Run 2 reported Falco target events=100, V2 health/accounting=PASS, no V2 counter errors, zero missing/duplicate/uncorrelatable events, and `Pilot measurement validity: PASS`. Its path relation counts were `all_equal=59` and `proc_equals_trusted_filename_differs=41`. A subsequent read-only `verify_race_paths.py` comparison against the saved journal text found 100 unique original Falco records for 100 trials, zero comparison failures, and **zero** non-snapshot basename candidates; it counted `race_exec`=59 and `alternate`=41 for each of `proc_exepath` and `evt_trusted_exepath`.

**Interpretation:** The second run is a *negative reproduction* of the rare `rlternate` string, not an invalid experiment or evidence that the first two journal observations were CSV artifacts. Across these two bounded runs, 2 of 200 distinct executions produced a candidate non-snapshot pathname in the saved text, while every V2/Falco executable inode attribution matched. Do not present 2/200 as an established population rate, independent field-level samples, or a detection-bypass rate. The correlation and journal export are downstream artifacts; kernel ring-buffer bytes and precise race ordering were not independently inspected.

**Next verification:** Retain all evidence unchanged, run further independent same-configuration repetitions with health checks, then vary only one factor at a time (e.g., distinct equal-length sentinel basenames). Every repetition should record exact counts of object mismatches, missing records, expected path switches, and non-snapshot basename strings separately.

## Third independent 100-trial run — raw path triage complete

A third run completed on 2026-10-10 with the same existing runner. The evidence locator is `raw/race-v2-falco-hri9lt4b` (research VM only; artifact bytes not imported into this repository). The user shared its console summary and then supplied the separate raw-path triage output.

| Reported metric | Run 3 |
| --- | ---: |
| Target executions | 100 |
| Self-reported A / B | 54 / 46 |
| Unknown labels | 0 |
| Trials with recorded exchange overlap | 97 |
| Correct V2/Falco executable-object attribution | 100 |
| Inode misattributions | 0 |
| Missing V2 / Falco | 0 / 0 |
| Duplicate V2 / Falco | 0 / 0 |
| Representation-inconsistent / uncorrelatable | 0 / 0 |
| Falco target events | 100 |
| `all_equal` path relation | 75 |
| `proc_equals_trusted_filename_differs` path relation | 25 |

The runner reported V2 health/accounting **PASS**, no V2 counter errors, pilot accounting **CONSISTENT**, and measurement validity **PASS**. A subsequent user-executed, read-only `verify_race_paths.py` check compared `correlation.csv` with saved `falco_window.log` by PID: 100 trial PIDs, 100 unique original Falco records, zero comparison failures, and **zero non-snapshot basename candidates**. Both `proc_exepath` and `evt_trusted_exepath` yielded `race_exec`=75 and `alternate`=25. This is a negative reproduction of `rlternate` under the same test configuration.

### Three-run aggregate — closed pilot baseline

- 300 bounded executions; 139 A and 161 B self-reports; 294 trials with recorded exchange overlap.
- 300 correct V2/Falco file-object attributions; zero observed misattributions, missing records or duplicates under the runner's criteria.
- `all_equal` path relations: 69 + 59 + 75 = **203**.
- Resolved path differing from requested filename: 31 + 41 + 25 = **97**. These are not automatically anomalies.
- Two non-snapshot `rlternate` strings have been corroborated in **saved Falco journal text** from Run 1 (two distinct PIDs; each appears in both `proc_exepath` and `evt_trusted_exepath`). Runs 2 and 3 yielded zero non-snapshot basenames. Across 300 executions, 95 resolved basenames were the expected exchange partner `alternate`, 203 matched the requested basename `race_exec`, and two were the candidate hybrid `rlternate`. This 2/300 observed proportion is not an established anomaly rate.

**Next controlled experiment:** Keep the original three evidence directories unchanged. Repeat the workload with *only* the two pathname basenames varied to equal-length, disjoint sentinel names; preserve the original runner and add a variant. Update the raw-path verifier to obtain the two permitted basenames from the run's recorded `environment.json`, otherwise all legitimate sentinel names would be misclassified.

Preserve the original evidence. Read-only comparison against the saved journal text does not prove which internal kernel instrumentation stage generated a non-snapshot string. No rate extrapolation, file-object bypass, or policy-impact claim is supported yet.

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
