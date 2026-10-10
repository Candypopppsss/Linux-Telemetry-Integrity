#!/usr/bin/env python3
import csv
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

PROJECT = Path.home() / "linux-telemetry-integrity"
V2 = PROJECT / "src" / "reference" / "ringbuf_v2"
READER = V2 / "oracle_reader_v2"
OBJ = V2 / "oracle_v2.bpf.o"
RACER = PROJECT / "src" / "mutation" / "race_exec"
TARGET_A = PROJECT / "src" / "targets" / "target_a"
TARGET_B = PROJECT / "src" / "targets" / "target_b"
RULE = Path("/etc/falco/falco_rules.local.yaml")
RAW = PROJECT / "raw"
TRIALS = 100
CAPTURE_SECONDS = 20
ERROR_COUNTERS = (
    "read_errors", "no_task", "no_mm", "no_exe", "no_inode",
    "no_superblock", "reserve_failures", "malformed", "write_errors",
)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def identity(path):
    st = os.stat(path)
    return {
        "path": str(path),
        "dev_major": os.major(st.st_dev),
        "dev_minor": os.minor(st.st_dev),
        "inode": st.st_ino,
        "size": st.st_size,
        "sha256": sha256(path),
    }

def save_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

def need(path):
    if not path.exists():
        raise RuntimeError(f"Required path missing: {path}")

def run_text(argv, *, sudo=False, check=True):
    cmd = list(argv)
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(cmd)}\n{p.stdout}")
    return p.stdout

def parse_falco_line(line):
    fields = {}
    for m in re.finditer(r"([A-Za-z0-9_]+)=([^\s]*)", line):
        fields[m.group(1)] = m.group(2)
    return fields

def main():
    os.chdir(PROJECT)
    RAW.mkdir(exist_ok=True)
    for path in (READER, OBJ, RACER, TARGET_A, TARGET_B):
        need(path)
    if not os.access(READER, os.X_OK):
        raise RuntimeError(f"Reader is not executable: {READER}")
    if not os.access(RACER, os.X_OK):
        raise RuntimeError(f"Racer is not executable: {RACER}")

    subprocess.run(["sudo", "-v"], check=True)
    if subprocess.run(["systemctl", "is-active", "--quiet", "falco-modern-bpf.service"]).returncode != 0:
        raise RuntimeError("falco-modern-bpf.service is not active")

    falco_version = run_text(["falco", "--version"], check=False).strip()
    service_exec = run_text(["systemctl", "show", "falco-modern-bpf.service", "-p", "ExecStart"], check=False).strip()

    run = Path(tempfile.mkdtemp(prefix="race-v2-falco-", dir=RAW))
    contested = run / "race_exec"
    alternate = run / "alternate"
    os.link(TARGET_A, contested)
    os.link(TARGET_B, alternate)

    target_ids = {"A": identity(TARGET_A), "B": identity(TARGET_B)}
    initial_race_ids = {"contested": identity(contested), "alternate": identity(alternate)}
    if target_ids["A"]["inode"] == target_ids["B"]["inode"]:
        raise RuntimeError("Target A and B unexpectedly share an inode")
    if initial_race_ids["contested"]["inode"] != target_ids["A"]["inode"]:
        raise RuntimeError("Initial contested path is not hard-linked to target A")
    if initial_race_ids["alternate"]["inode"] != target_ids["B"]["inode"]:
        raise RuntimeError("Initial alternate path is not hard-linked to target B")

    env = {
        "start_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "kernel": list(os.uname()),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uid": os.getuid(),
        "falco_version": falco_version,
        "falco_service_exec": service_exec,
        "v2_object_sha256": sha256(OBJ),
        "v2_reader_sha256": sha256(READER),
        "racer_sha256": sha256(RACER),
        "targets": target_ids,
        "initial_race_paths": initial_race_ids,
        "trials_requested": TRIALS,
        "collector_duration_seconds": CAPTURE_SECONDS,
        "note": "100-trial pilot. PID correlation is valid only within this short controlled run; path fields are diagnostic and not object truth.",
    }
    if RULE.exists():
        try:
            env["falco_local_rule_sha256"] = sha256(RULE)
        except PermissionError:
            env["falco_local_rule_sha256"] = None
    save_json(run / "environment.json", env)

    collector = None
    collector_status = None
    try:
        with (run / "collector.log").open("x") as clog:
            collector = subprocess.Popen([
                "sudo", "-n", str(READER), str(OBJ),
                str(run / "events.csv"), str(run / "counters.json"),
                str(run / "ready"), str(CAPTURE_SECONDS),
            ], stdout=clog, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while not (run / "ready").exists():
                if collector.poll() is not None:
                    raise RuntimeError("V2 collector stopped before readiness; inspect collector.log")
                if time.monotonic() > deadline:
                    raise RuntimeError("V2 collector did not signal readiness within 30 seconds")
                time.sleep(0.05)

            journal_start = (dt.datetime.now() - dt.timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S")
            (run / "journal_start.txt").write_text(journal_start + "\n")
            print(f"Evidence directory: {run}")
            print("V2 attached. Running 100 rename/exec trials...", flush=True)

            with (run / "race_summary.txt").open("x") as summary:
                race = subprocess.Popen([
                    str(RACER), str(contested), str(alternate), str(TRIALS), str(run / "trials.csv")
                ], stdout=summary, stderr=subprocess.STDOUT)
                while race.poll() is None:
                    if collector.poll() is not None:
                        race.terminate()
                        try:
                            race.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            race.kill()
                            race.wait()
                        raise RuntimeError("V2 collector ended before race workload completed")
                    time.sleep(0.05)
                if race.returncode != 0:
                    raise RuntimeError(f"race_exec returned {race.returncode}; inspect race_summary.txt")

            time.sleep(2)
            journal_end = (dt.datetime.now() + dt.timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S")
            (run / "journal_end.txt").write_text(journal_end + "\n")
            print(f"Race finished. Waiting for V2's {CAPTURE_SECONDS}-second capture to detach and drain...", flush=True)
            collector_status = collector.wait(timeout=45)
    finally:
        if collector is not None and collector.poll() is None:
            collector.terminate()
            try:
                collector.wait(timeout=20)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait()

    need(run / "trials.csv")
    need(run / "events.csv")
    need(run / "counters.json")

    journal_start = (run / "journal_start.txt").read_text().strip()
    journal_end = (run / "journal_end.txt").read_text().strip()
    falco_raw = run_text([
        "journalctl", "-u", "falco-modern-bpf.service",
        "--since", journal_start, "--until", journal_end,
        "--no-pager", "-o", "cat",
    ], sudo=True)
    (run / "falco_window.log").write_text(falco_raw)
    falco_lti_lines = [line for line in falco_raw.splitlines() if "LTI_FALCO" in line]
    (run / "falco_all.log").write_text("\n".join(falco_lti_lines) + ("\n" if falco_lti_lines else ""))

    with (run / "trials.csv").open(newline="") as f:
        trials = list(csv.DictReader(f))
    if len(trials) != TRIALS:
        raise RuntimeError(f"Expected {TRIALS} trial rows, found {len(trials)}")
    pids = [int(r["pid"]) for r in trials]
    if len(set(pids)) != len(pids):
        raise RuntimeError("PID reuse/duplication occurred inside the pilot run")
    trial_by_pid = {int(r["pid"]): r for r in trials}

    v2_by_pid = defaultdict(list)
    with (run / "events.csv").open(newline="") as f:
        for row in csv.DictReader(f):
            pid = int(row["pid"])
            if pid in trial_by_pid:
                v2_by_pid[pid].append({
                    "timestamp_ns": int(row["timestamp_ns"]), "pid": pid,
                    "tid": int(row["tid"]), "dev_major": int(row["dev_major"]),
                    "dev_minor": int(row["dev_minor"]), "inode": int(row["inode"]),
                })

    falco_by_pid = defaultdict(list)
    falco_target_lines = []
    for line in falco_lti_lines:
        fields = parse_falco_line(line)
        try:
            pid = int(fields.get("pid", ""))
        except ValueError:
            continue
        if pid in trial_by_pid:
            fields["_raw"] = line
            falco_by_pid[pid].append(fields)
            falco_target_lines.append(line)
    (run / "falco_targets.log").write_text("\n".join(falco_target_lines) + ("\n" if falco_target_lines else ""))

    counters = json.loads((run / "counters.json").read_text())
    classes = Counter()
    labels = Counter()
    path_relations = Counter()
    correlation_rows = []

    for row in trials:
        pid = int(row["pid"])
        label = row["label"]
        labels[label] += 1
        vrs = v2_by_pid.get(pid, [])
        frs = falco_by_pid.get(pid, [])
        klass = None
        reason = ""
        v2_inode = ""
        v2_dev = ""
        proc_inode = ""
        evt_inode = ""

        if row["exit_code"] != "0" or row["signal"] != "0" or label not in ("A", "B"):
            klass = "UNCORRELATABLE"
            reason = f"trial outcome label={label} exit={row['exit_code']} signal={row['signal']}"
        elif not vrs:
            klass = "MISSING_V2"
            reason = "no V2 record for successful trial PID"
        elif len(vrs) != 1:
            klass = "DUPLICATE_V2"
            reason = f"{len(vrs)} V2 records for trial PID"
        elif not frs:
            klass = "MISSING_FALCO"
            reason = "no Falco record for successful trial PID"
        elif len(frs) != 1:
            klass = "DUPLICATE_FALCO"
            reason = f"{len(frs)} Falco records for trial PID"
        else:
            vr = vrs[0]
            fr = frs[0]
            v2_inode = vr["inode"]
            v2_dev = f"{vr['dev_major']}:{vr['dev_minor']}"
            try:
                proc_inode = int(fr["proc_exe_ino"])
                evt_inode = int(fr["evt_exe_ino"])
            except (KeyError, TypeError, ValueError):
                klass = "REPRESENTATION_INCONSISTENT"
                reason = f"non-numeric/missing Falco inode fields: proc={fr.get('proc_exe_ino')} evt={fr.get('evt_exe_ino')}"
            else:
                expected_inode = target_ids[label]["inode"]
                if v2_inode != expected_inode:
                    klass = "UNCORRELATABLE"
                    reason = f"target self-report {label} conflicts with V2 inode {v2_inode}; expected {expected_inode}"
                elif proc_inode != evt_inode:
                    klass = "REPRESENTATION_INCONSISTENT"
                    reason = f"Falco proc.exe_ino={proc_inode} differs from evt.exe_ino={evt_inode}"
                elif proc_inode != v2_inode:
                    klass = "MISATTRIBUTED"
                    reason = f"V2 inode={v2_inode}; Falco inode={proc_inode}"
                else:
                    klass = "CORRECT"
                    reason = "V2, proc.exe_ino, and evt.exe_ino agree"

                p1 = fr.get("proc_exepath", "")
                p2 = fr.get("evt_trusted_exepath", "")
                p3 = fr.get("evt_filename", "")
                if p1 == p2 == p3 and p1:
                    path_relations["all_equal"] += 1
                elif p1 == p2 and p1:
                    path_relations["proc_equals_trusted_filename_differs"] += 1
                else:
                    path_relations["other"] += 1

        classes[klass] += 1
        fr = frs[0] if len(frs) == 1 else {}
        correlation_rows.append({
            "trial": row["trial"], "pid": pid, "self_report": label,
            "classification": klass, "reason": reason,
            "v2_dev": v2_dev, "v2_inode": v2_inode,
            "falco_proc_exe_ino": proc_inode, "falco_evt_exe_ino": evt_inode,
            "proc_name": fr.get("proc_name", ""), "proc_exe": fr.get("proc_exe", ""),
            "proc_exepath": fr.get("proc_exepath", ""), "evt_exe": fr.get("evt_exe", ""),
            "evt_trusted_exepath": fr.get("evt_trusted_exepath", ""),
            "evt_filename": fr.get("evt_filename", ""),
            "before_inode": row["before_inode"], "after_inode": row["after_inode"],
            "exchanges_before": row["exchanges_before"], "exchanges_after": row["exchanges_after"],
            "overlap_exchange": int(row["exchanges_after"]) > int(row["exchanges_before"]),
        })

    overlap = sum(1 for r in correlation_rows if r["overlap_exchange"])
    corr_fields = [
        "trial", "pid", "self_report", "classification", "reason",
        "v2_dev", "v2_inode", "falco_proc_exe_ino", "falco_evt_exe_ino",
        "proc_name", "proc_exe", "proc_exepath", "evt_exe",
        "evt_trusted_exepath", "evt_filename", "before_inode", "after_inode",
        "exchanges_before", "exchanges_after", "overlap_exchange",
    ]
    with (run / "correlation.csv").open("x", newline="") as f:
        w = csv.DictWriter(f, fieldnames=corr_fields)
        w.writeheader()
        w.writerows(correlation_rows)

    counter_errors = {k: counters.get(k) for k in ERROR_COUNTERS if counters.get(k, 0) != 0}
    health_ok = (
        collector_status == 0 and counters.get("capture_ok") is True
        and counters.get("accounting_ok") is True
        and counters.get("attached") is True and counters.get("detached") is True
        and counters.get("drained") is True and counters.get("stats_read") is True
        and not counter_errors
    )
    correlatable = classes["CORRECT"] + classes["MISATTRIBUTED"] + classes["REPRESENTATION_INCONSISTENT"]
    misattrib_rate = classes["MISATTRIBUTED"] / correlatable if correlatable else None

    result = {
        "trials": len(trials), "labels": dict(labels), "overlap_trials": overlap,
        "classes": dict(classes), "path_relations": dict(path_relations),
        "v2_health_ok": health_ok, "v2_counter_errors": counter_errors,
        "collector_status": collector_status, "v2_system_counters": counters,
        "falco_lti_events_in_window": len(falco_lti_lines),
        "falco_target_events": len(falco_target_lines), "correlatable": correlatable,
        "misattribution_rate": misattrib_rate,
        "scope": "100-trial renameat2(RENAME_EXCHANGE)/exec pilot on one Debian VM. PID-correlated. Not yet a scale result or cross-environment claim.",
    }
    save_json(run / "result.json", result)

    lines = [
        "=== LTI V2 <-> FALCO RENAME/EXEC PILOT ===",
        f"Trials:                          {len(trials)}",
        f"Self-report A:                   {labels.get('A', 0)}",
        f"Self-report B:                   {labels.get('B', 0)}",
        f"Unknown labels:                  {labels.get('UNKNOWN', 0)}",
        f"Trials with exchange overlap:    {overlap}", "",
        f"CORRECT:                         {classes.get('CORRECT', 0)}",
        f"MISATTRIBUTED:                   {classes.get('MISATTRIBUTED', 0)}",
        f"MISSING_V2:                      {classes.get('MISSING_V2', 0)}",
        f"MISSING_FALCO:                   {classes.get('MISSING_FALCO', 0)}",
        f"DUPLICATE_V2:                    {classes.get('DUPLICATE_V2', 0)}",
        f"DUPLICATE_FALCO:                 {classes.get('DUPLICATE_FALCO', 0)}",
        f"REPRESENTATION_INCONSISTENT:     {classes.get('REPRESENTATION_INCONSISTENT', 0)}",
        f"UNCORRELATABLE:                  {classes.get('UNCORRELATABLE', 0)}", "",
        f"Falco target events:             {len(falco_target_lines)}",
        f"V2 health/accounting:            {'PASS' if health_ok else 'FAIL'}",
        f"V2 counter errors:               {counter_errors if counter_errors else 'none'}",
        f"Path relation counts:            {dict(path_relations)}",
    ]
    if misattrib_rate is None:
        lines.append("Misattribution rate:             N/A (no correlatable trials)")
    else:
        lines.append(f"Misattribution rate:             {classes['MISATTRIBUTED']}/{correlatable} ({misattrib_rate * 100:.4f}%)")
    lines.append("Pilot accounting:                " + ("CONSISTENT" if health_ok and sum(classes.values()) == TRIALS else "INVESTIGATE"))
    valid = (
        health_ok and classes.get("MISSING_V2", 0) == 0
        and classes.get("MISSING_FALCO", 0) == 0
        and classes.get("DUPLICATE_V2", 0) == 0
        and classes.get("DUPLICATE_FALCO", 0) == 0
        and classes.get("UNCORRELATABLE", 0) == 0
    )
    lines.append("Pilot measurement validity:      " + ("PASS" if valid else "INVESTIGATE"))
    lines += ["", "Scope: 100-trial controlled rename/exec pilot only.",
              "Path fields are diagnostic and are not treated as file-object truth.",
              f"Evidence: {run}"]
    report = "\n".join(lines) + "\n"
    (run / "report.txt").write_text(report)
    print()
    print(report)

    abnormal = [r for r in correlation_rows if r["classification"] != "CORRECT"]
    if abnormal:
        print("=== ABNORMAL TRIALS (first 20) ===")
        for r in abnormal[:20]:
            print(f"trial={r['trial']} pid={r['pid']} class={r['classification']} reason={r['reason']}")
        print()
    print(f"Full correlation CSV: {run / 'correlation.csv'}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)