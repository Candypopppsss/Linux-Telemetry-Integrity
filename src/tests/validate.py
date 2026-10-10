"""Strict control-trace validation. Missing data is an error, never a pass."""
import argparse
import json
from pathlib import Path


def validate(text, expected_errno):
    events = []
    for line in text.splitlines():
        if line.startswith(("LTI_ENTER ", "LTI_EXEC ", "LTI_EXIT ")):
            fields = line.split()
            kind = fields[0]
            size = 4 if kind == "LTI_EXIT" else 3
            if len(fields) != size:
                raise ValueError("malformed telemetry record")
            events.append((kind, *map(int, fields[1:])))
    expected = ["LTI_ENTER", "LTI_EXIT" if expected_errno else "LTI_EXEC"]
    if [e[0] for e in events] != expected:
        raise ValueError(f"expected {expected}, observed {[e[0] for e in events]}")
    if events[0][1:3] != events[1][1:3]:
        raise ValueError("PID/TID correlation mismatch")
    if expected_errno and events[1][3] != -expected_errno:
        raise ValueError("unexpected syscall return value")
    marker = f"LTI_RESULT errno={expected_errno}" if expected_errno else "LTI_RESULT success"
    if text.splitlines().count(marker) != 1:
        raise ValueError("missing or duplicate independent workload result")
    return {"status": "PASS", "attempts": 1, "completed_execs": int(not expected_errno),
            "failed_attempts": int(bool(expected_errno)), "pid": events[0][1]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--errno", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.trace.read_text(), args.errno), indent=2))
