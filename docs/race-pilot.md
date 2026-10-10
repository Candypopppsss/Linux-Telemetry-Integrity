# Rename/exec pilot

## Scope

Compare the executable object selected during `execve()` with Falco's pathname representation while two directory entries are exchanged using `renameat2(RENAME_EXCHANGE)`.

**Evidence status:** user-supplied terminal results and source excerpts, reviewed on 2026-10-10. Raw evidence remains on the research VM. The observations do not establish a product vulnerability or live detection bypass.

## Method

Two executable inodes print distinct A/B labels. The racer exchanges their pathnames while launching 100 child executions per run. The V2 `sched_process_exec` collector reads the successful task's `mm->exe_file` device/inode. The runner correlates each child PID with Falco's `proc.exe_ino`, `evt.arg.exe_ino`, `proc.exepath`, `evt.arg.trusted_exepath`, and requested `evt.arg.filename`.

Before/after pathname `stat()` results are snapshots, not the identity of the executed object. Exchange-counter progression measures overlap with the trial interval, not with a specific path-reconstruction instruction.

## Environment

| Component | Recorded value |
| --- | --- |
| OS / kernel | Debian 13.7 / `6.12.111+deb13-amd64` |
| Filesystem | ext4 |
| Falco / libs | `0.45.0` / `0.26.0` |
| Capture engine | Modern eBPF |
| Plugin API / engine version | `3.12.0` / `0.65.0` |
| Driver API / schema | `11.0.0` / `4.3.0` |
| Default driver | `11.0.0+driver` |

## Results

Each run contains 100 executions. Evidence locators are directories under `raw/` on the VM, not published artifacts.

| Run | Evidence directory | A / B | Exchange overlap | Requested basename | Partner basename | Hybrid basename |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| 1 | `race-v2-falco-2_ff6nl3` | 43 / 57 | 99 | 69 | 29 | `rlternate`: 2 |
| 2 | `race-v2-falco-lqcpl51s` | 42 / 58 | 98 | 59 | 41 | 0 |
| 3 | `race-v2-falco-hri9lt4b` | 54 / 46 | 97 | 75 | 25 | 0 |
| 4 | `race-v2-falco-9j2z61st` | 42 / 58 | 77 | 77 | 22 | `taven0000`: 1 |

Runs 1–3 use `race_exec` and `alternate`. Run 4 changes only the configured basenames to `raven0000` and `tulip1111`: equal-length names with disjoint character sets.

All four runs reported 100/100 matching V2/Falco executable identities, zero missing, duplicate, uncorrelatable, or representation-inconsistent target records, and passing V2 health/accounting. Racer summaries reported zero rename errors, failed executions, and unknown labels.

Saved-journal comparisons found 100 unique target records per run and zero comparison failures. The pathname counts above apply to each resolved-path field. Legitimate partner-name readings are expected during rename and are not anomalies. Runs 2 and 3 did not reproduce the hybrid string.

### Hybrid observations

| Run | Trial / PID | Self-report | V2 and Falco inode | Requested basename | Resolved basename |
| --- | --- | --- | ---: | --- | --- |
| 1 | 6 / 10649 | A | 1044775 | `race_exec` | `rlternate` |
| 1 | 65 / 10709 | A | 1044775 | `race_exec` | `rlternate` |
| 4 | 25 / 12548 | B | 1044816 | `raven0000` | `taven0000` |

The strings occur in saved `falco_window.log` text and agree with `correlation.csv`; the sentinel observation is on saved journal line 38. Neither hybrid was an assigned basename. `taven0000` combines the first character of `tulip1111` with the remaining characters of `raven0000`.

There are three affected executions among 400 bounded trials. This is not an estimated population frequency or bypass rate. `proc.exepath` and `evt.arg.trusted_exepath` share a derivation: libsinsp copies the successful-exec trusted path into thread state. They are not independent observations. Journal exports also do not establish the original kernel event bytes.

## Provenance and source review

The researcher supplied the C racer as two consecutive source excerpts. The reviewed mutation thread only exchanges the two configured paths. The main thread forks, executes the requested path, reads the A/B marker, and records PID, exit status, timestamps, inode snapshots, and exchange counters.

| Artifact | Reported SHA-256 |
| --- | --- |
| `src/mutation/race_exec.c` | `22ba59cd546d37d07e0d1d2ce7cb269d673974c3bc56638a418711fe2a52a95e` |
| `src/mutation/race_exec` | `91d6fede61de737779c2fb523768851dd76ba264c3f8ced7cf384a1898a0435e` |

All four `environment.json` files recorded the same racer-binary hash, matching the current VM binary. Kernel, boot ID, service invocation, local rule hash, and V2 object/reader hashes also matched. Falco's raw version text differed because of invocation timestamps; its stable version fields matched.

These checks establish recorded consistency, not reproducible source-to-binary equivalence, immutable runtime state, or identical scheduling. The C review identified the following implementation limits:

- Before/after `stat()` failures are not checked.
- Rename errors are printed but do not cause a failure exit; the Python runner does not enforce that count.
- `pipe()`, `fork()`, or `waitpid()` failures can leave a zero exit status. The Python runner rejects incomplete trial counts.
- Pipe read errors, output truncation, and CSV write/flush/close failures are not fully checked.
- A/B labels use substring matching, suitable only for the controlled targets.
- `_GNU_SOURCE` appears after system headers; some includes are repeated.

## Decision validation — offline difference and live controls

| Check | Reported result | Interpretation |
| --- | --- | --- |
| Offline inode predicate | 100 / 100 matches | Object comparison on the sentinel dataset |
| Offline path predicate | 99 / 100 matches | Accepts `raven0000` or `tulip1111` |
| Difference | Trial 25 / PID 12548 | `taven0000` fails the path predicate |
| Rule-file validation | `tests/lti_decision_lab.yaml: Ok` | File validation only |
| Live diagnostic window | 110 baseline records; zero object and path alert markers | Invalid live comparison |

The offline result was reported at 14:14:16 UTC on 2026-10-10. The discussed rules select successful `execve`/`execveat` events requested through the race evidence directory and ending in `/raven0000`. The object predicate uses local inodes 1044775 and 1044816; the path predicate accepts either configured resolved basename. These identifiers are specific to the laboratory.

At 14:41:07 UTC, diagnostics found the temporary rule/configuration files absent and only the baseline rule recognized. Earlier service logs showed loading, but did not establish that both decision rules were active during the test. Zero alerts cannot be counted as missed detections.

Later user reports supplied two additional live runs:

| Report timestamp (UTC, 2026-10-10) | Evidence directory under `raw/` | Correct correlations | Object alerts | Path alerts | `raven0000` / `tulip1111` |
| --- | --- | ---: | ---: | ---: | ---: |
| 14:44:52 | `race-v2-falco-vxet97q5` | 100 / 100 | 100 | 100 | 67 / 33 |
| 14:50:47 | `race-v2-falco-ww7v4zpu` | 100 / 100 | 100 | 100 | 69 / 31 |

Both reports recorded zero missing, duplicate, or misattributed telemetry and passing V2 validation. The second reported rename overlap in all 100 trials. The reported pathname counts contain only the two configured basenames; neither run reproduced the hybrid pathname or an object/path alert-count difference.

These counts supersede the earlier absence of reported live decision alerts. They are user-reported conversation results, not independently revalidated VM artifacts. Underlying PID-level validation output was not recovered; aggregate alert counts alone do not establish exactly one baseline, object, and path alert per execution. The complete rule file and effective configuration for these runs remain unavailable here. No live detection bypass is established.

## Mechanism hypothesis

Falco libs 0.26.0 reconstructs `trusted_exepath` through `auxmap__store_task_exe_file_path` and a dentry walk. The implementation documents that pathname components cannot be locked against concurrent rename. The hybrid strings are consistent with this limitation; their exact collection stage and interleaving remain unverified.

## Reproduction dependencies

The archived runners expect `~/linux-telemetry-integrity`, an active `falco-modern-bpf.service`, and these VM-local components:

| Path | Component |
| --- | --- |
| `src/reference/ringbuf_v2/oracle_reader_v2` | V2 reader |
| `src/reference/ringbuf_v2/oracle_v2.bpf.o` | V2 BPF object |
| `src/mutation/race_exec` | C racer |
| `src/targets/target_a`, `src/targets/target_b` | A/B targets |
| `/etc/falco/falco_rules.local.yaml` | Laboratory telemetry rule |

The V2 source, C racer, targets, and Falco rule are not included. The original-name and sentinel scripts are retained as separate experiment variants.

For saved evidence, use `src/tests/verify_race_paths.py` on original-name runs and `src/tests/verify_race_paths_sentinels.py` on sentinel runs. The latter requires `environment.json:sentinel_basenames`.

## Outstanding work

1. Archive the complete source/build package and raw evidence with hashes; preserve the four original runs.
2. Repeat the sentinel run and capture evidence closer to the kernel event boundary.
3. Archive the live-control rule/configuration files and PID-level alert join; verify active rules and `rule_matching: all` for each repeat, with one baseline, object, and path alert per ordinary control PID.
4. Configure and validate the audit comparator described in [methodology](methodology.md#audit-status).

## References

- [Falco 0.45.0 release](https://falco.org/blog/falco-0-45-0/)
- [Libs 0.26.0 path reconstruction](https://github.com/falcosecurity/libs/blob/0.26.0/driver/modern_bpf/helpers/store/auxmap_store_params.h)
- [Libs 0.26.0 successful-exec event](https://github.com/falcosecurity/libs/blob/0.26.0/driver/modern_bpf/programs/attached/events/sched_process_exec.bpf.c)
- [Libs 0.26.0 userspace parser](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/parsers.cpp)
