#!/usr/bin/env python3
"""Independent mona v4 oracle: Python stdlib only; never invokes Rust."""
import base64
import hashlib
import hmac
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
def digest(b):
    return hashlib.sha256(b).digest()
def proof(domain, stream, offer, selected, fields):
    transcript = domain + bytes([7]) * 32 + stream.to_bytes(8, 'big') + bytes([offer, selected])
    for field in fields:
        transcript += (2**64-1).to_bytes(8, 'big') if field is None else len(field.encode()).to_bytes(8, 'big') + field.encode()
    key = digest(b'moon-naive/v4/key\0user:a-long-test-secret-123')
    return base64.b64encode(hmac.digest(key, digest(transcript), 'sha256')).decode()

auth = ['# stream\toffer\tselected\tmethod\tauthority\tscheme\tpath\tprotocol\trequest\tresponse; - = absent']
for stream, fields in [(1, ['CONNECT','example.org:443',None,None,None]), (0, ['CONNECT','example.org:443',None,None,None]), (4,['GET','example.org:443','https','/a%2Fb?q=1',None]), (8,['CONNECT','example.org:443','https','','websocket'])]:
    for offer, selected in [(2,2),(7,5),(7,6),(1,1)]:
        req = 'moon-naive %02x.' % offer + proof(b'moon-naive/v4/request\0',stream,offer,0,fields)
        resp = 'moon-naive %02x.' % selected + proof(b'moon-naive/v4/response/200\0',stream,offer,selected,fields)
        auth.append('\t'.join(map(str,[stream,offer,selected,*['-' if x is None else x for x in fields],req,resp])))
framing=['# name\tmode\twire hex\tpayload hex\tvalid EOF']
def frame(name, mode, wire, payload, ok=True):
    framing.append('\t'.join([name,str(mode),wire.hex(),payload.hex(),str(int(ok))]))
for mode, count in [(1,8),(2,16),(5,8),(6,16)]:
    # Nonzero padding was always accepted in v4. Zero is an encoder convention.
    wire=b''.join(b'\0\x08\x01abcdefgh'+bytes([i+1]) for i in range(count))
    payload=b'abcdefgh'*count
    if mode < 4:
        wire += b'\0\0\xffRAW';payload += b'\0\0\xffRAW'
    else:
        wire += b'\0\x80\x01'+b'x'*128+b'\xfe';payload += b'x'*128
    frame('transition-'+str(mode),mode,wire,payload)
frame('coalesced',2,b'\0\x01\0a\0\x02\0bc',b'abc')
frame('empty-stream',2,b'',b'')
for name,wire in [('empty-record',b'\0\0\0'),('oversize',b'\xff\xff\0'),('padding-budget',b'\0\x08\x02abcdefgh\0\0'),('truncated-header',b'\0'),('truncated-payload',b'\0\x02\0a'),('truncated-padding',b'\0\x08\x01abcdefgh')]:
    frame(name,2,wire,b'',False)
for name, lines in [('auth.tsv',auth),('framing.tsv',framing)]:
    path=ROOT/'core/tests/vectors'/name
    result='\n'.join(lines)+'\n'
    if '--check' in sys.argv:
        assert path.read_text()==result, f'{path}: regenerate vectors'
    else:
        path.write_text(result)
