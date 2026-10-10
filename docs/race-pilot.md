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

## Disjoint-filename sentinel variation — non-snapshot path observed

**Date:** 2026-10-10. **Evidence locator:** `raw/race-v2-falco-9j2z61st` (Debian VM only; raw files not independently imported into this repository). This run used the separately saved `src/mutation/lti_race_v2_falco_sentinels.py` and the per-run metadata-aware `src/tests/verify_race_paths_sentinels.py`. The existing V2 collector, Falco rule, and original three evidence directories were not intentionally changed.

The two exchange-path basenames were **`raven0000`** (requested exec pathname) and **`tulip1111`** (alternate). Both names have length nine; their character sets are disjoint. The race runner invoked 100 successful trials, with A=42 / B=58 self-reports, 77 recorded exchange overlaps, and 100/100 matching V2/Falco executable-object identities. Missing/duplicate/uncorrelatable/representation-inconsistent records and V2 counter errors were all zero; collector health and pilot accounting passed. The runner's path relationships were `all_equal=77` and `proc_equals_trusted_filename_differs=23`.

A read-only comparison of `correlation.csv` against the saved `falco_window.log` found 100 unique Falco records for the 100 target PIDs and **zero comparison failures**. For *each* of `proc_exepath` and `evt_trusted_exepath`, the reported basenames were `raven0000`=77, `tulip1111`=22, and **`taven0000`=1**. That anomalous string appeared in both derived fields for the **same single execution**, not two independent trials:

| Field | Reported evidence |
| --- | --- |
| Trial / PID | 25 / 12548 |
| Executable self-report | B |
| V2 `mm->exe_file` inode | 1044816 |
| Falco `proc.exe_ino`, `evt.arg.exe_ino` | 1044816 / 1044816 |
| Requested `evt.arg.filename` | `.../raven0000` |
| Resolved `proc.exepath`, `evt.arg.trusted_exepath` | `.../taven0000` |
| Saved Falco journal line | 38 |
| Correlation comparison failures | 0 |

The path string **`taven0000`** has the first character of `tulip1111` and the remaining eight characters of `raven0000`. Neither configured exchange-path basename was `taven0000`. Given the expected exchange-only workload, this is a stronger cross-workload corroboration of *non-snapshot pathname representation* than the original `rlternate` candidates: it arises with newly chosen, disjoint names and the opposite executable object (B rather than A). The exact provenance of the anomalous path bytes still has not been captured at the kernel-ring-buffer boundary.

### Combined bounded evidence

Across **four** 100-trial runs (three original-name runs plus this sentinel variation): **400/400** executable-object identities matched V2 and Falco, with zero target-event misses/duplicates by the runner's PID-level checks. There are now **three candidate non-snapshot pathnames in three distinct executions**: two `rlternate` occurrences in Run 1 and one `taven0000` in the sentinel run; the two original-name repetitions produced none. Do not use 3/400 as a population-level frequency, detection-evasion probability, or independence estimate; the runs were few, not a randomized benchmark, and the resolved-path fields share a common derivation.

**Mechanism hypothesis, not a confirmed root cause:** Falco's modern eBPF `trusted_exepath` code reconstructs a path by walking and reading dentry names without locking against concurrent rename. In the code for `falcosecurity/libs` 0.26.0, this limitation is expressly documented. The hybrid name is consistent with observing a namespace name during a concurrent update, but the raw kernel event bytes and exact interleaving remain unverified. No inode confusion or real-world policy bypass has been demonstrated.

**Next gate:** Inspect the exact compiled racer source to confirm it only exchanges the two pathnames; independently repeat the sentinel variant and preserve the complete raw artifacts and code hashes. Test a concrete detection decision only after isolating the pathname's collection origin and its security-rule dependency.

### Independent field accounting

The verifier printed four field-level candidates, **not four independent executions**: the same two `rlternate` strings appeared once per PID in `proc_exepath` and `evt_trusted_exepath`. In `falcosecurity/libs` 0.26.0, libsinsp's successful-exec parser copies `trusted_exepath` into the thread's `exepath` state; the two Falco fields are not independent kernel observations. Compare independent file-object evidence using V2 `mm->exe_file` device/inode instead.

- [Falco libs 0.26.0 userspace exec parser](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/parsers.cpp)

## Mutation runner source review — user-provided C source

The researcher supplied the complete `src/mutation/race_exec.c` as two consecutive terminal excerpts (`sed -n '1,260p'` and `sed -n '261,520p'`) on 2026-10-10. This review is of those pasted source excerpts, not a separately fetched VM filesystem or a completed source-to-binary reproducible build.

Reported SHA-256 identifiers:

| Local artifact | SHA-256 |
| --- | --- |
| `src/mutation/race_exec.c` | `22ba59cd546d37d07e0d1d2ce7cb269d673974c3bc56638a418711fe2a52a95e` |
| `src/mutation/race_exec` | `91d6fede61de737779c2fb523768851dd76ba264c3f8ced7cf384a1898a0435e` |

### Scope and positive controls

- The mutation thread repeatedly invokes `syscall(SYS_renameat2, AT_FDCWD, contested, AT_FDCWD, alternate, RENAME_EXCHANGE)`. In the supplied C implementation there are **no other mutator writes, renames, unlink operations, or filename-generation routines**. Assuming only this mutator modifies those two entries, exchanges do not intentionally introduce a third pathname basename.
- The main thread uses `fork()`, redirects stdout/stderr through a pipe, and invokes `execve(contested, ...)`. It categorizes the resulting short output as A/B/UNKNOWN and records the child PID, exit status, start/end timestamps, before/after pathname inode snapshots, and exchange counters per trial.
- The mutation thread is stopped by an atomic flag and joined; the shared counters are atomic. Relaxed ordering is appropriate for standalone counters and a stop flag in this design.
- A `stat(contested)` before or after the trial observes whatever occupies that **pathname** at that instant; these values are not an independent truth source for the executable object selected by the kernel. The V2 successful-exec `mm->exe_file` observation is the designated object reference.
- Nonzero `exchanges_after - exchanges_before` indicates counter progression over a broad trial interval, **not** a proven overlap with any particular Falco path-reconstruction instruction.

### Limitations to address in a future version

1. `identity()` return values are ignored in both before/after calls; a failed `stat()` leaves initialized zero fields in the CSV without a separate error indication.
2. The mutation thread counts failed `renameat2` operations, but `main()` only prints the total; nonzero `Rename errors` is not a nonzero process exit code, and the outer Python pilot validator does not enforce a rename-error threshold.
3. If `pipe()`, `fork()`, or `waitpid()` fails, the loop breaks but `main()` eventually returns zero. The Python runner rejects an incomplete number of trials, providing a partial downstream check; the C runner should fail closed independently.
4. The pipe `read()` loop does not report non-EINTR errors separately, nor is a full buffer explicitly flagged; write/flush/close errors on the CSV are not checked. Under the trusted small A/B target output these issues are unlikely to alter the successful bounded runs, but need remediation before scaling.
5. `strstr(output, "TARGET_A")` / `strstr(output, "TARGET_B")` classifies unstructured output without exact PID or message validation. It is adequate for a controlled target contract, not adversarial content attestation.
6. `#define _GNU_SOURCE` appears after two system headers; for future builds it should precede all includes. Some headers are repeated. Do not edit or rebuild the preserved pilot binary solely to clean up style.

**Outstanding provenance check:** Compare `environment.json:racer_sha256` for all four pilot evidence directories to the current binary SHA-256 and inspect each `race_summary.txt` for the printed `Rename errors`, `Failed executions`, and `Unknown executions` totals. Hash equality would establish consistent binary bytes across recordings, but not prove the exact C source produced that binary. Preserve the existing `race_exec` and old evidence unchanged until this check is complete.

**Attribution limit:** The reviewed C source provides no intentional path construction explaining `rlalternate` or `taven0000`. The evidence therefore supports investigating a telemetry pathname-representation effect rather than a source-side manufactured hybrid. This is not yet proof of the exact kernel race, raw BPF event bytes, or security-rule impact.

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
