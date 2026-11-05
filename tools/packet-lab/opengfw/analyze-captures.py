#!/usr/bin/env python3
"""Replay completed local PCAP workloads through the fixed OpenGFW lab rules.

Usage: python3 analyze-captures.py baseline [optimized ...]
Only PCAPs with a completed workload.json are accepted. This does not inspect
TLS key logs, change an analyzer, simulate blocking, or send any packets.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

here = Path(__file__).resolve().parent
lab = here.parents[2] / 'reports/packet-lab'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('phases', nargs='+', help='Capture directories below reports/packet-lab')
args = parser.parse_args()
for phase_name in args.phases:
    phase = (lab / phase_name).resolve()
    if phase.parent != lab or not phase.is_dir():
        parser.error(f'unknown capture phase: {phase_name}')
    if (phase / 'INVALID.txt').exists():
        parser.error(f'capture phase marked incomplete: {phase_name}')
    results = []
    totals = Counter()
    for directory in sorted(phase.iterdir()):
        if (directory / 'INVALID.txt').exists():
            raise ValueError(f'capture marked incomplete: {directory}')
        capture = directory / 'trace.pcap'
        workload_file = directory / 'workload.json'
        if not capture.is_file() or not workload_file.is_file():
            continue
        workload = json.loads(workload_file.read_text())
        port = int(workload['tcp_udp_port'])
        if not (1 <= port <= 65535):
            raise ValueError(f'invalid lab port in {workload_file}')
        raw = directory / 'opengfw.jsonl'
        summary_path = directory / 'opengfw.summary.json'
        with raw.open('wb') as output:
            subprocess.run([str(here/'opengfw-pcap'), '-pcap', str(capture), '-rules',
                            str(here/'rules.yaml'), '-port', str(port)], stdout=output,
                           check=True, timeout=45)
        subprocess.run([sys.executable, str(here/'summarize.py'), str(raw), '--output',
                        str(summary_path)], check=True, timeout=15)
        summary = json.loads(summary_path.read_text())
        if summary['errors'] or summary['complete']['packets'] < 1:
            raise ValueError(f'empty or failed replay: {directory}')
        flows = []
        for flow in summary['tuples']:
            item = {'transport': flow['protocol'], 'rules': flow['rules']}
            for classifier in ('fet', 'trojan'):
                result = flow[classifier]
                if flow['protocol'] != 'tcp':
                    verdict = 'not_applicable'
                elif result is None or not isinstance(result.get('yes'), bool):
                    verdict = 'no_result'
                else:
                    verdict = 'yes' if result['yes'] else 'no'
                item[classifier] = verdict
                totals[classifier + '_' + verdict] += 1
                if classifier == 'trojan' and result is not None:
                    item['trojan_sequence'] = result.get('seq')
                if classifier == 'fet' and result is not None:
                    item['fet_tls_http_exemption'] = result.get('ex5')
            item['hello'] = flow.get('tls', flow.get('quic'))
            totals[flow['protocol']+'_tuples'] += 1
            flows.append(item)
        results.append({
            'scenario': workload['scenario'], 'sample': directory.name,
            'capture_sha256': hashlib.sha256(capture.read_bytes()).hexdigest(),
            'capture_packets': summary['complete']['packets'],
            'capture_skipped': summary['complete']['skipped_packets'],
            'connections_expected': workload['transport_connections'],
            'target_dials': workload['target_dials'], 'client': workload['client'],
            'flows': flows,
        })
    if not results:
        raise SystemExit(f'no completed capture workloads in {phase}')
    combined = {
        'phase': phase_name, 'samples': len(results), 'counts': dict(totals),
        'upstream': json.loads((here/'upstream.json').read_text()),
        'rules_sha256': hashlib.sha256((here/'rules.yaml').read_bytes()).hexdigest(),
        'constraints': [
            'Local synthetic loopback workloads, not Chromium browsing or a live censorship network.',
            'OpenGFW fixed observation rules only; no live block/drop and no TLS key logs.',
            'FET and Trojan are TCP analyzers; their absence on UDP is not a negative result.',
            'no_result is not a negative result. Trojan no is a local heuristic result, not a guarantee.',
            'Packet timing, offload/segmentation and MTU on loopback differ from real networks.',
        ],
        'results': results,
    }
    output = phase/'opengfw-matrix.json'
    output.write_text(json.dumps(combined, indent=2) + '\n')
    print(f'{phase_name}: {len(results)} samples; {dict(totals)}; {output}')
