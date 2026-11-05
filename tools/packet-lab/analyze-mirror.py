#!/usr/bin/env python3
"""Describe encrypted record/frame lengths and reuse; no classifier training."""
import collections, json, os, pathlib, statistics, subprocess, sys
ROOT = pathlib.Path(__file__).resolve().parents[2] / 'reports/packet-lab'
ENV = os.environ.copy()
for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
    ENV.pop(name, None)
DOCKER = ['docker', '-H', 'unix:///var/run/docker.sock', 'exec', os.environ.get('MOON_NAIVE_LAB_CONTAINER', 'moon-naive-musl-builder'), 'tshark']
FIELDS = ['frame.time_epoch', 'tcp.srcport', 'tcp.stream', 'tcp.len', 'tls.record.content_type', 'tls.record.length', 'http2.type', 'http2.length', 'http2.streamid']
def numbers(value):
    return [int(part, 0) for part in value.split(';') if part]
def describe(values):
    return {'count': len(values), 'min': min(values), 'median': statistics.median(values), 'max': max(values)} if values else {'count': 0}
def analyze(directory):
    work = json.loads((directory / 'workload.json').read_text())
    args = DOCKER + ['-r', str(directory / 'trace.pcapng'), '-d', 'tcp.port==18443,tls', '-o', 'tls.keylog_file:' + str(directory / 'tls.keys'), '-T', 'fields', '-E', 'separator=|', '-E', 'occurrence=a', '-E', 'aggregator=;']
    for field in FIELDS:
        args += ['-e', field]
    lines = subprocess.run(args, env=ENV, check=True, text=True, capture_output=True).stdout.splitlines()
    streams = set(); heads = {}; timestamps = []; payload_packets = []
    for line in lines:
        row = dict(zip(FIELDS, line.split('|')))
        if row['tcp.stream']:
            streams.add(row['tcp.stream'])
        ts = float(row['frame.time_epoch'])
        if row['tcp.len'] and int(row['tcp.len']) > 0:
            payload_packets.append(ts)
        if row['tcp.srcport'] != str(work['tcp_udp_port']):
            continue
        types = numbers(row['http2.type']); sizes = numbers(row['http2.length']); ids = numbers(row['http2.streamid'])
        assert len(types) == len(sizes) == len(ids), (directory, 'ambiguous HTTP2 fields')
        for typ, length, sid in zip(types, sizes, ids):
            if typ == 1 and sid:
                heads.setdefault(str(sid), []).append(length)
        if 23 in numbers(row['tls.record.content_type']):
            timestamps.append(ts)
    assert len(streams) == work['transport_connections'], (directory, streams)
    events = work.get('events', []) + [event for stream in work['streams'] for event in stream.get('events', [])]
    idle = []
    for event in events:
        if event.get('event') != 'idle':
            continue
        # Exclude 50 ms on each edge for delayed delivery/control updates.
        start = event['start_unix_us'] / 1e6 + .05
        end = event['end_unix_us'] / 1e6 - .05
        count = sum(start < t < end for t in payload_packets)
        assert count == 0, (directory, 'TCP payload in idle interval', count)
        idle.append({'measured_middle_seconds': end - start, 'tcp_payload_packets': count})
    durations = [(e['end_unix_us'] - e['start_unix_us']) / 1000 for e in events if e.get('event') == 'response']
    durations += [(s['end_unix_us'] - s['start_unix_us']) / 1000 for s in work['streams'] if 'start_unix_us' in s]
    header_sizes = [size for sizes in heads.values() for size in sizes]
    result = {'scenario': work['scenario'], 'observed_tcp_connections': len(streams), 'h2_headers_payload_lengths_by_stream': heads, 'h2_headers_length_histogram': dict(sorted(collections.Counter(header_sizes).items())), 'idle_checks': idle, 'response_elapsed_ms': describe(durations), 'server_tls_bearing_packet_gaps_ms': describe([(b-a)*1000 for a,b in zip(timestamps, timestamps[1:])]), 'target_dials': work['target_dials'], 'mirror_upstream_connections': work.get('mirror_upstream_connections'), 'note': 'HEADERS lengths exclude the 9-byte HTTP2 header; TLS-bearing packet gaps are loopback capture timings, not per-record send timings or real browsing statistics.'}
    (directory / 'mirror.summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
for phase in sys.argv[1:]:
    summaries = {}
    for directory in sorted((ROOT / phase).iterdir()):
        if directory.is_dir() and (directory / 'workload.json').exists():
            work = json.loads((directory / 'workload.json').read_text())
            if work['scenario'].startswith(('h1', 'h2')):
                summaries[directory.name] = analyze(directory)
    (ROOT / phase / 'mirror-matrix.json').write_text(json.dumps(summaries, indent=2) + '\n')
    for name, row in summaries.items():
        print(phase, name, 'TCP',row['observed_tcp_connections'], 'origin',row['mirror_upstream_connections'], 'HEADERS', row['h2_headers_length_histogram'], 'idle', row['idle_checks'])
