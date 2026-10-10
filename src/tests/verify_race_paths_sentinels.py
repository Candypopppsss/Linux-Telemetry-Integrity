#!/usr/bin/env python3
"""Read-only triage of saved LTI rename/exec pilot pathname candidates."""
import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

FIELD = re.compile(r'(?<!\S)([A-Za-z][A-Za-z0-9_]*)=([^\s]*)')
REQUIRED = {'pid', 'proc_exepath', 'evt_trusted_exepath', 'evt_filename', 'proc_exe_ino', 'evt_exe_ino'}

def fields(line):
    return dict(FIELD.findall(line))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path, help='Existing raw/race-v2-falco-* run')
    args = p.parse_args()
    run = args.directory
    source = run / 'falco_window.log'
    corr = run / 'correlation.csv'
    trials = run / 'trials.csv'
    for f in (source, corr, trials):
        if not f.is_file():
            p.error(f'Missing required evidence: {f}')
    with trials.open(newline='') as fh:
        trows = list(csv.DictReader(fh))
    with corr.open(newline='') as fh:
        crows = list(csv.DictReader(fh))
    pids = [r['pid'] for r in trows]
    if len(pids) != len(set(pids)) or len(crows) != len(pids):
        p.error('Unexpected PID duplication or correlation row count; investigate before interpreting')
    target = set(pids)
    by_pid = defaultdict(list)
    for number, line in enumerate(source.read_text(errors='surrogateescape').splitlines(), 1):
        if 'LTI_FALCO' not in line:
            continue
        f = fields(line)
        if f.get('pid') in target:
            by_pid[f['pid']].append((number, line, f))
    env_path = run / 'environment.json'
    if not env_path.is_file():
        p.error(f'Missing required evidence: {env_path}')
    env = json.loads(env_path.read_text())
    sentinels = env.get('sentinel_basenames')
    if not isinstance(sentinels, dict) or set(sentinels) != {'contested', 'alternate'}:
        p.error('Expected variant-specific sentinel_basenames in environment.json')
    known = set(sentinels.values())
    if any(not isinstance(name, str) or not name or '/' in name for name in known) or len(known) != 2:
        p.error('Invalid or duplicate sentinel basenames in metadata')
    print('Permitted basenames:', sorted(known))
    anomalies = []
    mismatches = []
    count = Counter()
    for row in crows:
        pid = row['pid']
        records = by_pid[pid]
        if len(records) != 1:
            mismatches.append((pid, f'expected exactly one original Falco record, found {len(records)}'))
            continue
        lineno, original, raw = records[0]
        if not REQUIRED.issubset(raw):
            mismatches.append((pid, 'Falco record missing required fields'))
            continue
        for col in REQUIRED:
            if col in row and row[col] != raw[col]:
                mismatches.append((pid, f'{col} differs between original Falco record and correlation.csv'))
        for col in ('proc_exepath', 'evt_trusted_exepath'):
            path = raw[col]
            basename = path.rsplit('/', 1)[-1]
            count[(col, basename)] += 1
            if basename not in known:
                anomalies.append({
                    'pid': pid, 'trial': row.get('trial'), 'field': col,
                    'basename': basename, 'path': path, 'path_utf8_hex': path.encode('utf-8', 'surrogateescape').hex(),
                    'source_line': lineno, 'raw_line': original,
                    'self_report': row.get('self_report'), 'v2_inode': row.get('v2_inode'),
                    'falco_inode': raw['proc_exe_ino'],
                })
    print('=== LTI RACE PATH EVIDENCE TRIAGE ===')
    print('Run:', run)
    print('Trial PIDs:', len(pids))
    print('Unique original Falco records:', sum(len(by_pid[pid]) == 1 for pid in target))
    print('Comparison failures:', len(mismatches))
    print('Non-snapshot basename candidates:', len(anomalies))
    print('Basenames by resolved field:')
    for (field, name), n in sorted(count.items()):
        print(f'  {field}: {name!r} = {n}')
    for pid, reason in mismatches[:20]:
        print('CHECK pid=', pid, reason)
    for a in anomalies[:20]:
        print('CANDIDATE', json.dumps(a, ensure_ascii=True))
    print('Notes: This compares saved journal text, not original kernel event bytes.')
    print('A non-snapshot pathname alone is not evidence of object misattribution or rule bypass.')
    if mismatches:
        raise SystemExit(2)

if __name__ == '__main__':
    main()
