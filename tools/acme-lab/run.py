#!/usr/bin/env python3
"""Execute every selected group, retaining its real exit code, even after failure."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
NAMESPACE = ['unshare', '--user', '--map-root-user', '--net', '--', 'sh', '-c',
             'ip link set lo up; exec "$@"', 'lab']

def command(run, name, args, env, timeout=600, namespace=True):
    actual = (NAMESPACE if namespace else []) + args
    start = time.time()
    record = {'name': name, 'command': actual, 'start_epoch': start}
    with (run / (name + '.stdout.log')).open('wb') as out, (run / (name + '.stderr.log')).open('wb') as err:
        process = subprocess.Popen(actual, cwd=REPO, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
            record['timeout_seconds'] = timeout
    record.update(exit_code=code, elapsed_seconds=time.time() - start)
    (run / (name + '.result.json')).write_text(json.dumps(record, indent=2))
    print(name, code, flush=True)
    return record

def baseline(run, env):
    values = {}
    for name, args in [('HEAD', ['git', 'rev-parse', 'HEAD']),
                       ('worktree', ['git', 'status', '--porcelain=v1']),
                       ('rustc', ['rustc', '-Vv']), ('cargo', ['cargo', '-V']),
                       ('kernel', ['uname', '-a']), ('cpu', ['lscpu']),
                       ('production_features', ['cargo', 'tree', '--locked', '-p', 'moon-naive', '-e', 'features,no-dev'])]:
        result = subprocess.run(args, cwd=REPO, env=env, capture_output=True, text=True)
        values[name] = {'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    values['lockfiles_sha256'] = {str(p): hashlib.sha256((REPO / p).read_bytes()).hexdigest()
                                 for p in [Path('Cargo.lock'), Path('vendor/instant-acme/Cargo.lock')]}
    values['source_sha256'] = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted((REPO / 'src').rglob('*.rs'))}
    values['tools'] = {}
    for name in ['PEBBLE_BIN', 'CHALLTESTSRV_BIN', 'ACME_LAB_TCPDUMP', 'ACME_LAB_TSHARK']:
        path = Path(env.get(name, '/nonexistent'))
        if path.is_file():
            values['tools'][name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            version_args = ([str(path), '--version'] if 'TCPDUMP' in name else
                            [str(path), '-v'] if 'TSHARK' in name else
                            [str(Path(env.get('ACME_LAB_HOME', '/workspace/.moon-naive-acme-lab')) / 'tools/go/bin/go'), 'version', '-m', str(path)])
            version = subprocess.run(version_args, env=env, capture_output=True, text=True)
            values['tools'][name]['version'] = {'exit_code': version.returncode, 'stdout': version.stdout, 'stderr': version.stderr}
    (run / 'baseline.json').write_text(json.dumps(values, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path)
    parser.add_argument('--only', choices=['all', 'unit', 'pebble', 'vendor', 'live', 'legacy', 'resolver'], default='all')
    args = parser.parse_args()
    run = (args.run or Path('/workspace/acme-lab-artifacts') / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')).resolve()
    run.mkdir(parents=True, exist_ok=False)
    run.chmod(0o700)
    env = dict(os.environ, ACME_LAB_ARTIFACTS=str(run), RUST_BACKTRACE='1', RUST_TEST_THREADS='1')
    baseline(run, env)
    records = []
    if args.only in ('all', 'unit'):
        records.append(command(run, 'unit-acme', ['cargo', 'test', '--locked', '-p', 'moon-naive', '--lib', 'acme::'], env))
    if args.only in ('all', 'resolver'):
        try:
            nameserver = next(line.split()[1] for line in Path('/etc/resolv.conf').read_text().splitlines() if line.startswith('nameserver '))
            address = ipaddress.IPv4Address(nameserver)
        except (StopIteration, ipaddress.AddressValueError) as error:
            record = {'name': 'system-resolver', 'exit_code': 2, 'error': f'IPv4 nameserver required: {error}'}
            (run / 'system-resolver.result.json').write_text(json.dumps(record, indent=2))
            records.append(record)
        else:
            resolver = ['sh', '-c', 'ip addr add "$1/32" dev lo; shift; exec "$@"', 'resolver', str(address),
                        'cargo', 'test', '--locked', '-p', 'moon-naive', '--lib', 'actual_system_dns_cancellation', '--', '--ignored', '--nocapture']
            records.append(command(run, 'system-resolver', resolver, dict(env, RES_OPTIONS='timeout:4 attempts:1', ACME_LAB_DNS_LISTEN=f'{address}:53')))
    if args.only in ('all', 'pebble'):
        build = command(run, 'build-integration', ['cargo', 'test', '--locked', '--test', 'acme_pebble', '--no-run'], env, namespace=False)
        records.append(build)
        if not build['exit_code']:
            records.append(command(run, 'pebble', ['cargo', 'test', '--locked', '--test', 'acme_pebble', '--', '--ignored', '--test-threads=1', '--nocapture'], dict(env, ACME_LAB_FORCE_DNS_TCP='1')))
    if args.only in ('all', 'vendor'):
        vendor_env = dict(env, CARGO_TARGET_DIR=str(Path(env.get('ACME_LAB_HOME', '/workspace/.moon-naive-acme-lab')) / 'vendor-target'))
        records.append(command(run, 'vendor-locked', ['cargo', 'test', '--manifest-path', 'vendor/instant-acme/Cargo.toml', '--locked', '--no-default-features', '--features', 'time,x509-parser', '--lib'], vendor_env, namespace=False))
    if args.only in ('all', 'live'):
        records.append(command(run, 'live-renewal', ['cargo', 'test', '--locked', '-p', 'moon-naive', '--lib', 'acme_live', '--', '--nocapture'], env))
    if args.only in ('all', 'legacy'):
        records.append(command(run, 'legacy', ['cargo', 'test', '--locked', '--workspace', '--lib', '--', '--skip', 'acme::lab', '--skip', 'acme_live'], env))
    (run / 'commands.json').write_text(json.dumps(records, indent=2))
    print('ARTIFACT_ROOT=' + str(run))
    return int(any(r['exit_code'] for r in records))
if __name__ == '__main__':
    sys.exit(main())
