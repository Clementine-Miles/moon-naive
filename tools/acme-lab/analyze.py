#!/usr/bin/env python3
"""Decode laboratory pcaps. Raw keys and full journals never enter the Git index."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess

FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport",
          "http.request.method", "http.request.uri", "http.host", "http.response.code",
          "http.response.line", "http.request_in", "http.file_data", "dns.qry.name",
          "dns.qry.type", "dns.flags.response", "dns.flags.truncated", "dns.flags.authoritative",
          "dns.id", "dns.txt", "dns.count.answers", "dns.flags.rcode"]

def un64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

def analyze(case, exe):
    if not (case/'wire.pcap').exists() or (case/'wire.pcap').stat().st_size<=24:
        return {'case':case.name,'errors':['empty or missing capture'],'tshark_exit':None}
    events = [json.loads(line) for line in (case / 'events.jsonl').read_text().splitlines()]
    tls_ports, dns_ports, quic_ports = set(), set(), set()
    ports=json.loads((case / "ports.json").read_text())["ports"]
    if case.name.startswith(("live-renew", "control-panic", "renewal-invalid")):
        tls_ports.add(ports[1]);quic_ports.add(ports[2])
    elif case.name.startswith(("tls-loaded-failure", "website-streaming", "codec-windows")):
        tls_ports.add(ports[0]);quic_ports.add(ports[1])
    for event in events:
        data = event['data']
        if event['kind'] == 'server':
            tls_ports.add(data['port'])
        if event['kind'] == 'processes':
            tls_ports.update(data['ports'][:2])
            dns_ports.add(data['ports'][2])
            dns_ports.add(int(data['authority'].rsplit(':', 1)[1]))
    keys = case / 'analysis.keys'
    keys.write_bytes(b''.join(p.read_bytes() for p in [case / 'tls.keys', case / 'h3.keys'] if p.exists()))
    keys.chmod(0o600)
    args = [exe, '-r', str(case / 'wire.pcap'), '-o', f'tls.keylog_file:{keys}']
    for port in sorted(tls_ports):
        args += ['-d', f'tcp.port=={port},tls']
    for port in sorted(dns_ports):
        args += ['-d', f'tcp.port=={port},dns', '-d', f'udp.port=={port},dns']
    args += ['-Y', 'http or dns or http2 or quic or tls', '-T', 'json']
    for field in FIELDS:
        args += ['-e', field]
    with (case / 'tshark.stderr.log').open('wb') as error:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=error, check=False)
    (case / 'tshark.result.json').write_text(json.dumps({'command': args, 'exit_code': result.returncode}, indent=2))
    if result.returncode:
        return {'case': case.name, 'tshark_exit': result.returncode, 'errors': ['decoder failed']}
    packets = json.loads(result.stdout)
    if not packets:
        return {'case': case.name, 'tshark_exit': 0, 'errors': ['zero decoded protocol packets']}
    errors=[]
    if not any(e['kind']=='capture_stopped' and e['data'].get('exit_code')==0 for e in events):
        errors.append('capture did not finish successfully')
    timeline = []
    # Derive only a public verifier from the synthetic persisted account key.
    verifier = None
    try:
        from cryptography.hazmat.primitives import serialization
        for journal in sorted(case.glob('journal-*.json')):
            value = json.loads(journal.read_text())
            if value.get('account_key'):
                verifier = serialization.load_der_private_key(bytes(value['account_key']), None).public_key()
                break
    except (ImportError, ValueError):
        pass
    for packet in packets:
        fields = packet['_source']['layers']
        def first(key):
            return fields.get(key, [None])[0]
        item = {'source': 'pcap', 'frame': int(first('frame.number')), 'epoch': float(first('frame.time_epoch')),
                'tcp_stream': first('tcp.stream')}
        method = first('http.request.method')
        item.update(method=method, endpoint=first('http.request.uri'), status=first('http.response.code'),
                    request_frame=first('http.request_in'))
        headers = fields.get('http.response.line', [])
        for name in ('Replay-Nonce', 'Retry-After', 'Location'):
            for line in headers:
                if line.lower().startswith(name.lower() + ':'):
                    item[name] = line.split(':', 1)[1].strip()
        data = b''.join(bytes.fromhex(v.replace(':', '')) for v in fields.get('http.file_data', []))
        if data:
            try:
                body = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                item['body_length'] = len(data)
                item['body_sha256'] = hashlib.sha256(data).hexdigest()
            else:
                if isinstance(body, dict):
                    item['problem_type'] = body.get('type')
                    item['acme_status'] = body.get('status')
                    item['body_keys'] = sorted(body)
                    if isinstance(body.get('records'), list):
                        item['record_count'] = len(body['records'])
                    elif isinstance(body.get('result'), list):
                        item['record_count'] = len(body['result'])
                    if isinstance(body.get('challenges'), list):
                        item['challenge_statuses'] = [{'type': c.get('type'), 'status': c.get('status')} for c in body['challenges']]
                    if 'protected' in body:
                        protected = json.loads(un64(body['protected']))
                        payload_bytes = un64(body['payload'])
                        payload = json.loads(payload_bytes) if payload_bytes else None
                        item['protected'] = protected
                        item['payload_empty'] = not payload_bytes
                        item['payload_keys'] = sorted(payload) if isinstance(payload, dict) else None
                        actual = f"https://{first('http.host')}{item['endpoint']}"
                        item['protected_url_matches'] = protected.get('url') == actual
                        item['signature_length'] = len(un64(body['signature']))
                        item['signature_sha256'] = hashlib.sha256(un64(body['signature'])).hexdigest()
                        item['payload_sha256'] = hashlib.sha256(payload_bytes).hexdigest()
                        try:
                            from cryptography.hazmat.primitives.asymmetric import ec, utils
                            from cryptography.hazmat.primitives import hashes
                            jwk = protected.get('jwk')
                            if jwk:
                                verifier = ec.EllipticCurvePublicNumbers(int.from_bytes(un64(jwk['x']), 'big'), int.from_bytes(un64(jwk['y']), 'big'), ec.SECP256R1()).public_key()
                                thumb = {k: jwk[k] for k in ('crv', 'kty', 'x', 'y')}
                                item['jwk_thumbprint'] = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(thumb, separators=(',', ':'), sort_keys=True).encode()).digest()).decode().rstrip('=')
                            if verifier:
                                sig = un64(body['signature'])
                                assert len(sig) == 64
                                verifier.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), f"{body['protected']}.{body['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
                                item['jose_signature_valid'] = True
                        except ImportError:
                            item['jose_verification'] = 'cryptography_unavailable'
                        except Exception as error:
                            item['jose_signature_valid'] = False
                            item['jose_error'] = type(error).__name__
                        if isinstance(payload, dict) and 'externalAccountBinding' in payload:
                            eab = payload['externalAccountBinding']
                            item['eab_protected'] = json.loads(un64(eab['protected']))
                            item['eab_bound'] = json.loads(un64(eab['payload'])) == protected.get('jwk') and item['eab_protected'].get('url') == protected.get('url') and item['eab_protected'].get('alg') == 'HS256'
                            item['eab_hs256_valid'] = hmac.compare_digest(hmac.digest(b'B' * 32, f"{eab['protected']}.{eab['payload']}".encode(), 'sha256'), un64(eab['signature']))
                        if isinstance(payload, dict) and 'csr' in payload:
                            try:
                                from cryptography import x509
                                csr = x509.load_der_x509_csr(un64(payload['csr']))
                                item['csr_signature_valid'] = csr.is_signature_valid
                                item['csr_san'] = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                            except ImportError:
                                item['csr_verification'] = 'cryptography_unavailable'
        if first('dns.qry.name'):
            item['dns'] = {k.removeprefix('dns.'): v for k, v in fields.items() if k.startswith('dns.')}
        timeline.append(item)
    for event in events:
        timeline.append({'source': 'test_log', 'epoch': event['utc_epoch_us'] / 1e6, 'kind': event['kind'], 'data': event['data']})
    timeline.sort(key=lambda row: row['epoch'])
    (case / 'timeline.json').write_text(json.dumps(timeline, indent=2))
    errors += protocol_errors(timeline)
    summary = {'case': case.name, 'errors':errors, 'tshark_exit': 0, 'pcap_rows': len(packets),
               'http_requests': sum(bool(p.get('method')) for p in timeline),
               'dns_frames': sum('dns' in p for p in timeline),
               'valid_jose': sum(p.get('jose_signature_valid') is True for p in timeline),
               'invalid_jose': sum(p.get('jose_signature_valid') is False for p in timeline),
               'eab_valid': sum(p.get('eab_hs256_valid') is True for p in timeline),
               'url_mismatch': sum(p.get('protected_url_matches') is False for p in timeline)}
    if quic_ports:
        handshake_args = args[:args.index('-Y')]
        for port in quic_ports:
            handshake_args += ['-d', f'udp.port=={port},quic']
        handshake_args += ['-Y', 'tls.handshake.type == 11', '-T', 'json']
        for field in ['frame.number', 'frame.time_epoch', 'tcp.stream', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'tls.handshake.certificate']:
            handshake_args += ['-e', field]
        with (case / 'handshake-tshark.stderr.log').open('wb') as error:
            decoded = subprocess.run(handshake_args, stdout=subprocess.PIPE, stderr=error, check=False)
        certificates=[]
        if not decoded.returncode:
            for packet in json.loads(decoded.stdout):
                fields=packet['_source']['layers']
                for certificate in fields.get('tls.handshake.certificate', []):
                    der=bytes.fromhex(certificate.replace(':',''))
                    entry={'frame':int(fields['frame.number'][0]),'epoch':float(fields['frame.time_epoch'][0]),'sha256':hashlib.sha256(der).hexdigest(),'transport':'quic' if fields.get('udp.srcport') else 'tcp','ports':fields.get('udp.srcport',fields.get('tcp.srcport',[]))+fields.get('udp.dstport',fields.get('tcp.dstport',[]))}
                    try:
                        from cryptography import x509
                        entry['serial_hex']=format(x509.load_der_x509_certificate(der).serial_number,'x')
                    except ImportError:
                        pass
                    certificates.append(entry)
        (case/'handshake-analysis.json').write_text(json.dumps({'command':handshake_args,'exit_code':decoded.returncode,'certificates':certificates},indent=2))
        summary['wire_certificates']=len(certificates)
        if decoded.returncode:summary['errors'].append('handshake decoder failed')
    (case / 'analysis.json').write_text(json.dumps(summary, indent=2))
    return summary

def protocol_errors(rows):
    errors=[]
    for row in rows:
        if row.get('signature_length') is not None:
            if row.get('signature_length')!=64 or row.get('jose_signature_valid') is not True:
                errors.append(f"frame {row.get('frame')}: JOSE verification failed or was not executed")
            if row.get('protected_url_matches') is not True:
                errors.append(f"frame {row.get('frame')}: protected.url mismatch")
        keys=row.get('payload_keys') or []
        if 'csr' in keys and (row.get('csr_signature_valid') is not True or not row.get('csr_san')):
            errors.append('CSR verification failed or was not executed')
        if 'externalAccountBinding' in keys and (row.get('eab_hs256_valid') is not True or row.get('eab_bound') is not True):
            errors.append('EAB verification failed or was not executed')
    return errors

def self_test():
    """Counterexamples for the evidence gate, including a real failed decoder."""
    import tempfile
    import unittest
    class Evidence(unittest.TestCase):
        def test_empty_capture(self):
            with tempfile.TemporaryDirectory() as temp:
                case=Path(temp);(case/'wire.pcap').write_bytes(bytes(24))
                self.assertIn('empty or missing capture',analyze(case,'/bin/false')['errors'])
        def test_decoder_failure(self):
            with tempfile.TemporaryDirectory() as temp:
                case=Path(temp);(case/'wire.pcap').write_bytes(bytes(25))
                (case/'events.jsonl').write_text('');(case/'ports.json').write_text('{"ports":[]}')
                result=analyze(case,'/bin/false')
                self.assertEqual(result['tshark_exit'],1);self.assertTrue(result['errors'])
        def test_zero_decoded_packets(self):
            from unittest.mock import patch
            with tempfile.TemporaryDirectory() as temp:
                case=Path(temp);(case/'wire.pcap').write_bytes(bytes(25))
                (case/'events.jsonl').write_text('');(case/'ports.json').write_text('{"ports":[]}')
                with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'[]')):
                    result=analyze(case, 'fixture-decoder')
                self.assertIn('zero decoded protocol packets', result['errors'])
        def test_failed_or_unexecuted_protocol_verification(self):
            good={'signature_length':64,'jose_signature_valid':True,'protected_url_matches':True}
            self.assertFalse(protocol_errors([good]))
            for field,value in [('jose_signature_valid',False),('jose_signature_valid',None),('protected_url_matches',False)]:
                self.assertTrue(protocol_errors([dict(good,**{field:value})]))
            self.assertTrue(protocol_errors([{'payload_keys':['csr']}]))
            self.assertTrue(protocol_errors([{'payload_keys':['externalAccountBinding'],'eab_hs256_valid':True,'eab_bound':False}]))
    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Evidence)).wasSuccessful()
