"""Bounded VM-only integration controls; existing monitoring is not modified."""
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile

from validate import validate

ROOT = Path(__file__).resolve().parents[2]


def main():
    if not shutil.which("bpftrace"):
        raise SystemExit("bpftrace is required; integration validation was not performed")
    if os.geteuid() != 0:
        raise SystemExit("run in a disposable VM as root")
    output = ROOT / "raw"
    output.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="exec-control-", dir=output))
    binary = run / "attempt"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(ROOT / "src/proof_of_concept/attempt.c"), "-o", str(binary)], check=True)
    invalid = run / "invalid-image"
    invalid.write_bytes(b"LTI invalid executable image\n")
    invalid.chmod(0o700)
    manifest = {"kernel": platform.release(), "architecture": platform.machine(),
                "bpftrace": subprocess.check_output(["bpftrace", "--version"], text=True).strip(),
                "pid_namespace": os.readlink("/proc/self/ns/pid"),
                "cases": {}, "status": "INCOMPLETE"}
    try:
        for name, target, error in [("success", binary, 0), ("invalid", invalid, errno.ENOEXEC),
                                    ("missing", run / "absent", errno.ENOENT)]:
            command = shlex.join([str(binary), str(target), str(error)])
            result = subprocess.run(["bpftrace", "-q", "-c", command,
                                     str(ROOT / "src/proof_of_concept/exec_observer.bt")],
                                    capture_output=True, text=True, timeout=30,
                                    env={**os.environ, "BPFTRACE_PERF_RB_PAGES": "64"})
            trace = run / f"{name}.log"
            trace.write_text(result.stdout)
            (run / f"{name}.stderr").write_text(result.stderr)
            if result.returncode or result.stderr.strip():
                raise RuntimeError(f"{name}: tracer failure or diagnostic; inspect {run}")
            manifest["cases"][name] = {**validate(result.stdout, error),
                "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest()}
        manifest["status"] = "PASS"
    finally:
        (run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(run)


if __name__ == "__main__":
    main()
