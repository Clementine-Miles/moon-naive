#!/usr/bin/env python3
"""Summarize offline OpenGFW output without turning missing verdicts into negatives."""
import argparse
from collections import Counter
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('input', type=Path)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
flows = {}
errors = []
complete = None
for line in args.input.read_text().splitlines():
    row = json.loads(line)
    if row['event'] == 'complete':
        complete = row
    if row['event'] in ('rule_error', 'analyzer_error', 'modify_error'):
        errors.append(row)
    if 'props' not in row:
        continue
    # Aggregate tuple, preserving classifications when the reassembler creates
    # an empty stream object for a final pure ACK. No claim of session counting.
    endpoints = sorted((row['src'], row['dst']))
    key = (row['protocol'], *endpoints)
    flow = flows.setdefault(key, {
        'protocol': row['protocol'], 'first_src': row['src'], 'first_dst': row['dst'],
        'props': {}, 'rules': set(), 'engine_ids': set(),
    })
    flow['engine_ids'].add(row['id'])
    if row['props']:
        flow['props'].update(row['props'])
    if row['event'] == 'rule':
        flow['rules'].add(row['rule'])

counts = Counter()
result = []
for key in sorted(flows):
    flow = flows[key]
    props = flow.pop('props')
    protocol = flow['protocol']
    counts[protocol + '_tuples'] += 1
    for analyzer in ('fet', 'trojan'):
        verdict = props.get(analyzer, {}).get('yes')
        label = 'yes' if verdict is True else 'no' if verdict is False else 'no_result' if protocol == 'tcp' else 'not_applicable'
        counts[analyzer + '_' + label] += 1
        flow[analyzer] = props.get(analyzer)
    for analyzer in ('tls', 'quic'):
        request = props.get(analyzer, {}).get('req')
        if request is not None:
            counts[analyzer + '_client_hello'] += 1
            flow[analyzer] = {key: request.get(key) for key in ('sni', 'alpn', 'version', 'supported_versions', 'ech')}
    if 'http' in props:
        counts['http_visible'] += 1
        flow['http'] = props['http']
    flow['rules'] = sorted(flow['rules'])
    flow['engine_ids'] = sorted(flow['engine_ids'])
    result.append(flow)

output = {
    'input': str(args.input), 'complete': complete, 'errors': errors,
    'counts': dict(counts), 'tuples': result,
    'scope': 'Fixed OpenGFW v0.4.3 observation rules; no network blocking or TLS decryption. no_result is not a negative classifier result.',
}
encoded = json.dumps(output, indent=2) + '\n'
if args.output:
    args.output.write_text(encoded)
else:
    print(encoded, end='')
if complete is None or errors:
    raise SystemExit(1)
