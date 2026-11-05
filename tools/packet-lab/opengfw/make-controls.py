#!/usr/bin/env python3
"""Deterministic analyzer fixtures, not recordings of a TLS session.

Writes valid Ethernet/IPv4/TCP/UDP envelopes and checksums. TLS ClientHello fields
are syntactically valid; synthetic CCS/flight payloads exercise the original
Trojan length-tree positive and negative branches, not a cryptographic handshake.
QUIC Initial payloads are the pinned upstream's real Chromium 153 test fixtures.
"""
import os
import hashlib
import json
from pathlib import Path
import struct

BASE = Path(__file__).resolve().parent
UPSTREAM = Path(os.environ['OPENGFW_SOURCE']) if 'OPENGFW_SOURCE' in os.environ else BASE.parents[2] / 'target/packet-lab/OpenGFW'
packets = []


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def emit(protocol, transport, rev=False):
    src, dst = (b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02')
    if rev:
        src, dst = dst, src
    pseudo = src + dst + struct.pack('!BBH', 0, protocol, len(transport))
    at = 16 if protocol == 6 else 6
    transport = transport[:at] + struct.pack('!H', checksum(pseudo + transport)) + transport[at + 2:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), len(packets), 0x4000, 64, protocol, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    packets.append(bytes.fromhex('0200000000020200000000010800') + ip + transport)


def tcp_flow(port, chunks):
    seq = [1000, 9000]

    def send(rev, flags, payload=b''):
        direction = int(rev)
        src, dst = (443, port) if rev else (port, 443)
        ack = seq[1 - direction] if flags & 0x10 else 0
        tcp = struct.pack('!HHIIBBHHH', src, dst, seq[direction], ack, 0x50, flags, 65535, 0, 0) + payload
        emit(6, tcp, rev)
        seq[direction] += len(payload) + bool(flags & 2) + bool(flags & 1)

    send(False, 2)
    send(True, 0x12)
    send(False, 0x10)
    for rev, data in chunks:
        send(rev, 0x18, data)
    send(False, 0x11)
    send(True, 0x11)
    send(False, 0x10)


def client_hello(host):
    name = host.encode()
    server_name = struct.pack('!H', len(name) + 3) + b'\0' + struct.pack('!H', len(name)) + name
    alpn = b'\0\x03\x02h2'
    extensions = struct.pack('!HH', 0, len(server_name)) + server_name + struct.pack('!HH', 16, len(alpn)) + alpn
    body = b'\x03\x03' + bytes(range(32)) + b'\0\0\x02\xc0\x2f\x01\0' + struct.pack('!H', len(extensions)) + extensions
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + struct.pack('!H', len(handshake)) + handshake


tcp_flow(51000, [(False, client_hello('blocked.test'))])
tcp_flow(51001, [(False, client_hello('allowed.test'))])
tcp_flow(51002, [(False, b'GET / HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n')])
tcp_flow(51003, [(False, b'GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n')])
random_bytes = b''.join(hashlib.sha256(b'fet-fixture' + bytes([i])).digest() for i in range(32))
tcp_flow(51004, [(False, random_bytes)])
for port, seq in [(51005, [300, 100, 300, 100]), (51006, [100, 100, 100, 100])]:
    chunks = [(False, client_hello('allowed.test'))]
    chunks += [(False, b'\x14\x03\x03\0\x01\x01' + bytes(seq[0] - 6))]
    chunks += [(True, bytes(seq[1])), (False, bytes(seq[2])), (True, bytes(seq[3])), (False, b'\0')]
    tcp_flow(port, chunks)
for i in range(3):
    data = (UPSTREAM / f'analyzer/udp/testdata/quic-chrome153-{i}.bin').read_bytes()
    emit(17, struct.pack('!HHHH', 51007, 443, 8 + len(data), 0) + data)

with (BASE / 'controls.pcap').open('wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, packet in enumerate(packets):
        f.write(struct.pack('<IIII', 1793145600 + i // 1000, (i % 1000) * 1000, len(packet), len(packet)))
        f.write(packet)
(BASE / 'controls.expected.json').write_text(json.dumps({
    '51000': {'tls.req.sni': 'blocked.test', 'fet.yes': False, 'rule': 'tls-sni-positive-control'},
    '51001': {'tls.req.sni': 'allowed.test', 'fet.yes': False, 'absent_rule': 'tls-sni-positive-control'},
    '51002': {'http.req.headers.host': 'blocked.test', 'fet.yes': False, 'rule': 'http-host-positive-control'},
    '51003': {'http.req.headers.host': 'allowed.test', 'fet.yes': False, 'absent_rule': 'http-host-positive-control'},
    '51004': {'fet.yes': True, 'rule': 'fully-encrypted-positive'},
    '51005': {'trojan.yes': True, 'trojan.seq': [300, 100, 300, 100], 'rule': 'trojan-positive'},
    '51006': {'trojan.yes': False, 'trojan.seq': [100, 100, 100, 100], 'absent_rule': 'trojan-positive'},
    '51007': {'quic.req.sni': 'chrome.sniff.test', 'rule': 'quic-visible'},
}, indent=2) + '\n')
print('wrote', len(packets), 'packets', BASE / 'controls.pcap')
