#!/usr/bin/env python3
"""Assert independent positive/negative fixture expectations after engine replay."""
import json
from pathlib import Path

base = Path(__file__).resolve().parent
rows = [json.loads(x) for x in (base / 'controls.jsonl').read_text().splitlines()]
flows = {}
for row in rows:
    if row['event'] in ('rule_error', 'analyzer_error', 'modify_error'):
        raise AssertionError(row)
    if 'props' in row:
        port = row['src'].rsplit(':', 1)[1]
        flow = flows.setdefault(port, {'props': {}, 'rules': set()})
        # The unmodified reassembler may create an empty stream object for the
        # final ACK after both FINs. It must not erase a classified tuple.
        if row['props']:
            flow['props'] = row['props']
        if row['event'] == 'rule':
            flow['rules'].add(row['rule'])
expected = json.loads((base / 'controls.expected.json').read_text())
for port, checks in expected.items():
    flow = flows[port]
    for key, value in checks.items():
        if key == 'rule':
            assert value in flow['rules'], (port, key, value, flow)
        elif key == 'absent_rule':
            assert value not in flow['rules'], (port, key, value, flow)
        else:
            actual = flow['props']
            for part in key.split('.'):
                actual = actual[part]
            assert actual == value, (port, key, actual, value)
    print(port, 'passed', sorted(flow['rules']))
assert rows[-1]['event'] == 'complete'
(base / 'controls.result.json').write_text(json.dumps({
    'passed': len(expected), 'failed': 0, 'complete': rows[-1],
    'fixtures': 'Synthetic protocol classifier tests, not captured successful TLS sessions; QUIC payloads from upstream Chrome153 fixture.'
}, indent=2) + '\n')
