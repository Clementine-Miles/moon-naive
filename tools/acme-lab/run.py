#!/usr/bin/env python3
"""Private orchestrator for cargo xtask lab. result.json is authoritative."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import analyze

REPO = Path(__file__).resolve().parents[2]
NAMESPACE = ['unshare', '--user', '--map-root-user', '--net', '--', 'sh', '-c',
             'ip link set lo up; exec "$@"', 'lab']
# Named contracts, not a generated list that silently shrinks when a case is removed.
ACME = ['ari_remote_retry_after_is_not_clipped_by_local_recheck_policy',
        'ari_rate_limit_wait_is_not_capped_by_local_recheck_policy','nonce_endpoint_404_preserves_existing_order','order_endpoint_404_is_attributed_to_order',
        'finalize_processing_honors_initial_retry_after_120','retry_after_maximum_does_not_panic',
        'outer_retry_after_overflow_does_not_persist_saturated_date','deferred_order_wait_survives_restart',
        'recovered_processing_preserves_first_retry_after','cancellation_during_order_wait_preserves_restart_deadline','retry_after_beyond_operation_deadline_defers_without_early_poll',
        'completed_future_not_before_recovers_same_order','external_cancellation_closes_socket_and_owned_driver']
for provider in ['cloudflare','porkbun']:
    ACME += [f'{provider}_{suffix}' for suffix in ['discovery_failure_recovers','list_failure_recovers',
             'confirmed_create_rejection_recovers','intent_cancel_before_post_recovers',
             'durable_send_gap_retains_uncertainty','late_create_empty_cleanup_and_restart']]
ACME += [f'certificate_{kind}_{size}' for kind in ['invalid','pem']
         for size in ['1m','1m_plus_one','2m','3m','4m','4m_plus_one']]
LIVE = ['acme_invalid_renewal_material_keeps_valid_network','acme_live_two_renewals_h2_h3_and_old_connections','acme_live_outer_expiry_then_inner_renewal_and_recovery',
        'acme_control_panic_degrades_renewal_and_keeps_valid_network',
        'acme_tls_loaded_diagnostic_failure_does_not_block_activation']
LOCAL_CASES = ['coalesced_output_wake_keeps_bounded_website_drain_running','acme_tls_status_create_failure_before_load','acme_tls_status_rename_failure_before_load',
             'acme_tls_status_fsync_failure_before_load','acme_tls_status_failures_after_load_observe_partial_activation']
PEBBLE = ['issue_restart_renew_and_keep_certificate_during_dns_outage',
          'eab_issue_restart_renew_and_recover_account_without_eab_file',
          'challenge_timeout_before_ca_dns_preserves_validation','challenge_sigterm_before_ca_dns_preserves_validation',
          'challenge_crash_restart_before_ca_dns_preserves_validation','continuous_nonce_rejection_fails_boundedly',
          'authorization_reuse_does_not_require_second_dns_create']
CODEC = 'negotiated_windows_share_h2_h3_connections_without_content_changes'
WEBSITE = 'website_pingora_streaming_proxy_reuses_pool_across_h2_h3_and_sanitizes_headers'
MIXED = 'mixed_h1_h2_h3_websocket_admission_holds_through_half_close'
# One laboratory suite definition; workspace runs unit/network/CLI once.
SUITES = {
    'ari': (['cargo','test','--locked','-p','moon-naive','--lib','ari_'],
            ['ari_remote_retry_after_is_not_clipped_by_local_recheck_policy',
             'ari_rate_limit_wait_is_not_capped_by_local_recheck_policy'], True),
    'workspace': (['cargo','test','--locked','--workspace'], ACME + LIVE + LOCAL_CASES + [MIXED, WEBSITE, CODEC], True),
    'acme': (['cargo','test','--locked','-p','moon-naive','--lib','acme::'], ACME, True),
    'network': (['cargo','test','--locked','-p','moon-naive','--lib','net::'], LIVE + LOCAL_CASES + [MIXED, WEBSITE, CODEC], True),
    'pebble': (['cargo','test','--locked','-p','moon-naive','--lib','acme::pebble::','--','--ignored','--test-threads=1','--nocapture'], PEBBLE, True),
    'resolver': ([], ['actual_system_dns_cancellation_keeps_running_job_until_reply'], True),
    'vendor': (['cargo','test','--manifest-path','vendor/instant-acme/Cargo.toml','--locked',
                '--no-default-features','--features','time,x509-parser','--lib'],
               ['retry_wait_checks_deadline_before_sleep','retry_wait_does_not_discard_last_permitted_attempt'], False),
    'oracles': ([sys.executable,'-c','import run; raise SystemExit(not run.self_test())'], [], False),
}
DEFAULT = ['oracles','workspace','pebble','vendor','resolver']

def command(run, name, args, env, namespace, tests=True):
    actual = (NAMESPACE if namespace else []) + args
    start = time.time()
    with (run/(name+'.stdout.log')).open('wb') as out, (run/(name+'.stderr.log')).open('wb') as err:
        process = subprocess.Popen(actual,cwd=REPO,env=env,stdout=out,stderr=err,start_new_session=True)
        try:
            code = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait();code=124
    output=(run/(name+'.stdout.log')).read_text(errors='replace')
    counts=re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed',output)
    names=re.findall(r'^test ([\w:]+) \.\.\. (?!ignored)',output,re.M)
    errors=[]
    if name=='oracles' and not re.search(r'Ran [1-9][0-9]* tests', (run/(name+'.stderr.log')).read_text(errors='replace')):errors.append('zero verification oracle tests')
    if tests and not sum(int(a)+int(b) for a,b in counts):errors.append('zero relevant Rust tests')
    record=dict(name=name,command=actual,exit_code=code,elapsed_seconds=time.time()-start,tests=names,errors=errors)
    print(name,code,flush=True)
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
                               for p in sorted([*(REPO / 'src').rglob('*.rs'), *(REPO / 'core').rglob('*.rs'), *(REPO / 'tools/acme-lab').glob('*.py')])}
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
    for required in ['HEAD', 'worktree', 'rustc', 'cargo', 'production_features']:
        if values[required]['exit_code']:
            raise RuntimeError('required baseline command failed: '+required)

def matches(name, suffix):
    return name==suffix or name.endswith('::'+suffix)

def needs_jose(name):
    # These contracts exercise only provider reads or raw HTTPS cancellation.
    # They must have captures, but contain no ACME JWS to verify.
    non_jws = ['external_cancellation_closes_socket_and_owned_driver',
               'cloudflare_durable_send_gap_retains_uncertainty',
               'porkbun_durable_send_gap_retains_uncertainty']
    return any(matches(name,n) for n in ACME) and not any(matches(name,n) for n in non_jws)

def evidence(run, records):
    errors=[];summaries=[]
    manifests=[(p.parent,json.loads(p.read_text())) for p in run.rglob('manifest.json')]
    for record in records:
        expected=SUITES[record['name']][1] if record['name'] in SUITES else []
        for test in expected:
            if not any(matches(name,test) for name in record['tests']):errors.append('expected test did not run: '+test)
            if not SUITES[record['name']][2]:continue  # Library-only cases have no packet fixture.
            cases=[p for p,m in manifests if matches(m.get('test_name') or '',test)]
            if not cases:errors.append('expected case manifest missing: '+test)
            for case in cases:
                if test in LOCAL_CASES:continue  # Named local IO/queue cases need no packet evidence.
                if not (case/'wire.pcap').exists():errors.append('expected capture missing: '+case.name)
    for case,manifest in manifests:
        if not (case/'wire.pcap').exists():continue  # Pure IO/lock tests have no network.
        try:summary=analyze.analyze(case,os.environ['ACME_LAB_TSHARK'])
        except Exception as error:
            errors.append(case.name+': analysis failed: '+str(error));continue
        summaries.append(summary)
        errors += [case.name+': '+e for e in summary.get('errors',[])]
        name=manifest.get('test_name') or ''
        if needs_jose(name) and not summary.get('valid_jose',0):errors.append('JOSE not observed: '+case.name)
        if 'eab_issue_' in name and not summary.get('eab_valid',0):errors.append('EAB not verified: '+case.name)
        events=[json.loads(line) for line in (case/'events.jsonl').read_text().splitlines()]
        if any(e['data'].get('outage_was_not_exercised') for e in events):errors.append('target outage was skipped: '+case.name)
        if case.name.startswith('live-renew'):
            probes=[e for e in events if e['kind']=='active_generation']
            if len(probes)<3 or any(e['data']['h2_sha256']!=e['data']['h3_sha256'] for e in probes):errors.append('missing or inconsistent real activation probes: '+case.name)
    if any(SUITES[r['name']][2] for r in records if r['name'] in SUITES) and not summaries:
        errors.append('zero relevant captures analyzed')
    return summaries,errors

def successful(records,errors,selected):
    return bool(selected) and not errors and all(r['exit_code']==0 and not r['errors'] for r in records) and all(any(r['name']==n for r in records) for n in selected)

def self_test():
    assert not successful([dict(name='test',exit_code=101,errors=[])],[],['test'])
    assert not successful([dict(name='test',exit_code=0,errors=['zero relevant Rust tests'])],[],['test'])
    assert not successful([],[],['missing'])
    assert not successful([],[],[])
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        summaries, errors = evidence(Path(directory), [dict(name='acme', tests=ACME)])
        assert not summaries and errors, 'empty artifact directory must fail'
    assert needs_jose('acme::lab::nonce_endpoint_404_preserves_existing_order')
    assert not needs_jose('acme::lab::external_cancellation_closes_socket_and_owned_driver')
    assert not needs_jose('acme::lab::cloudflare_durable_send_gap_retains_uncertainty')
    return analyze.self_test()

def main():
    parser=argparse.ArgumentParser(description='Use cargo xtask lab; all captures are required in this explicit mode.')
    parser.add_argument('--only',choices=SUITES)
    parser.add_argument('--run',type=Path)
    parser.add_argument('--home',type=Path,default=Path(os.environ.get('ACME_LAB_HOME','/workspace/.moon-naive-acme-lab')))
    for name in ['pebble','challtestsrv','tcpdump','tshark','pebble-source']:parser.add_argument('--'+name,type=Path)
    args=parser.parse_args();home=args.home.resolve()
    run=(args.run or Path('/workspace/acme-lab-artifacts')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')).resolve()
    if run==REPO or REPO in run.parents:parser.error('artifacts must be outside the source checkout')
    run.mkdir(parents=True,exist_ok=False);run.chmod(0o700)
    env=dict(os.environ,ACME_LAB_HOME=str(home),ACME_LAB_ARTIFACTS=str(run),ACME_LAB_CAPTURE='required',RUST_TEST_THREADS='1',RUST_BACKTRACE='1')
    for var,path in [('PEBBLE_SOURCE',args.pebble_source or home/'tools/pebble-src'),('PEBBLE_BIN',args.pebble or home/'tools/bin/pebble'),
                     ('CHALLTESTSRV_BIN',args.challtestsrv or home/'tools/bin/pebble-challtestsrv'),
                     ('ACME_LAB_TCPDUMP',args.tcpdump or home/'apt/prefix/usr/bin/tcpdump'),('ACME_LAB_TSHARK',args.tshark or home/'apt/prefix/usr/bin/tshark')]:
        env[var]=str(path) if getattr(args,{'PEBBLE_SOURCE':'pebble_source','PEBBLE_BIN':'pebble','CHALLTESTSRV_BIN':'challtestsrv','ACME_LAB_TCPDUMP':'tcpdump','ACME_LAB_TSHARK':'tshark'}[var]) else env.get(var,str(path))
    env['LD_LIBRARY_PATH']=str(home/'apt/prefix/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
    env.setdefault('WIRESHARK_DATA_DIR',str(home/'apt/prefix/usr/share/wireshark'))
    env['PYTHONPATH']=str(Path(__file__).parent)
    os.environ.update({key:env[key] for key in ['ACME_LAB_TSHARK','LD_LIBRARY_PATH','WIRESHARK_DATA_DIR']})
    selected=[args.only] if args.only else DEFAULT
    result=dict(schema=1,success=False,selected=selected,commands=[],evidence=[],errors=[],bundle=str(run)+'.tar.gz')
    try:
        if any(SUITES[name][2] for name in selected):
            import cryptography  # Fail before tests if required crypto verification is unavailable.
            result['crypto_verifier'] = dict(python=sys.executable, version=cryptography.__version__)
        baseline(run,env)
        for name in selected:
            argv,expected,namespace=SUITES[name];local=env.copy()
            if namespace:
                for key in ['ACME_LAB_TCPDUMP','ACME_LAB_TSHARK']:
                    if not (Path(local[key]).is_file() or shutil.which(local[key])):raise RuntimeError('required tool unavailable: '+key)
            if name=='pebble':
                for key in ['PEBBLE_SOURCE','PEBBLE_BIN','CHALLTESTSRV_BIN']:
                    if not Path(local[key]).exists():raise RuntimeError('required Pebble prerequisite missing: '+key)
                local['ACME_LAB_FORCE_DNS_TCP']='1'
            if name=='vendor':local['CARGO_TARGET_DIR']=str(home/'vendor-target')
            if name=='resolver':
                ns=ipaddress.IPv4Address(next(line.split()[1] for line in Path('/etc/resolv.conf').read_text().splitlines() if line.startswith('nameserver ')))
                local.update(RES_OPTIONS='timeout:4 attempts:1',ACME_LAB_DNS_LISTEN=f'{ns}:53')
                argv=['sh','-c','ip addr add "$1/32" dev lo; shift; exec "$@"','resolver',str(ns),
                      'cargo','test','--locked','-p','moon-naive','--lib','actual_system_dns_cancellation','--','--ignored','--nocapture']
            result['commands'].append(command(run,name,argv,local,namespace,tests=name!='oracles'))
        result['evidence'],result['errors']=evidence(run,result['commands'])
    except Exception as error:
        result['errors'].append(type(error).__name__+': '+str(error))
    result['success']=successful(result['commands'],result['errors'],selected)
    (run/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    with tarfile.open(result['bundle'],'w:gz') as archive:archive.add(run,arcname=run.name)
    Path(result['bundle']).chmod(0o600)
    print('RESULT='+str(run/'result.json'),flush=True)
    return 0 if result['success'] else 1
if __name__=='__main__':sys.exit(main())
