#!/usr/bin/env python3
"""Exercise the upstream Trojan first-payload validation behavior offline.

Generates a non-TLS payload followed by a synthetic CCS/length sequence and
runs the unmodified OpenGFW adapter. No network access or production keys.
"""
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile

here = Path(__file__).resolve().parent
os.environ.setdefault('OPENGFW_SOURCE', str(here.parents[2] / 'target/packet-lab/OpenGFW'))
with tempfile.TemporaryDirectory(prefix='moon-nontls-control-') as temp:
    temp = Path(temp)
    shutil.copy(here/'make-controls.py', temp/'make-controls.py')
    namespace = runpy.run_path(str(temp/'make-controls.py'))
    namespace['packets'].clear()
    ccs = bytes.fromhex('140303000101')
    namespace['tcp_flow'](51008, [
        (False, b'NOT_TLS_START'), (False, ccs + bytes(294)),
        (True, bytes(100)), (False, bytes(300)),
        (True, bytes(100)), (False, b'\x00'),
    ])
    capture = temp/'nontls-control.pcap'
    with capture.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, packet in enumerate(namespace['packets']):
            f.write(struct.pack('<IIII', 1793145600, i * 1000, len(packet), len(packet)))
            f.write(packet)
    result = subprocess.check_output([
        here/'opengfw-pcap', '-pcap', capture, '-rules', here/'rules.yaml'
    ], timeout=10)
    rows = [json.loads(line) for line in result.splitlines()]
    assert rows[-1]['event'] == 'complete'
    assert not any(row['event'] in ('rule_error', 'analyzer_error', 'modify_error') for row in rows)
    positives = [row for row in rows if row.get('event') == 'rule' and row.get('rule') == 'trojan-positive']
    assert positives and positives[-1]['props']['trojan'] == {'seq': [300, 100, 300, 100], 'yes': True}
    assert not positives[-1]['props'].get('tls')
    shutil.copy(capture, here/'nontls-control.pcap')
    (here/'nontls-control.jsonl').write_bytes(result)
    print('PASS: non-TLS initial data, no TLS property, Trojan yes=true, seq=[300,100,300,100]')
