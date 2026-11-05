import pathlib,subprocess,os,json,xml.etree.ElementTree as X,sys,hashlib
R=pathlib.Path(__file__).resolve().parents[2]/'reports/packet-lab'
E=os.environ.copy()
for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):E.pop(k,None)
D=['docker','-H','unix:///var/run/docker.sock','exec',os.environ.get('MOON_NAIVE_LAB_CONTAINER', 'moon-naive-musl-builder'),'tshark']
def run(a):return subprocess.run(D+a,env=E,check=True,capture_output=True).stdout
def varint(b,i):
 n=1<<(b[i]>>6);assert i+n<=len(b);return int.from_bytes(b[i:i+n],'big')&((1<<(8*n-2))-1),i+n
for phase in sys.argv[1:]:
 results={}
 for p in sorted((R/phase).glob('h3*')):
  w=json.loads((p/'workload.json').read_text());raw=p/'trace.pcapng';view=p/'analysis-after-retry.pcapng'
  retry=run(['-r',str(raw),'-d','udp.port==18443,quic','-Y','quic.long.packet_type==3','-T','fields','-e','frame.number'])
  last=max([int(x) for x in retry.splitlines()] or [0])
  # Only the analysis view excludes Retry; original remains the DPI/length input.
  run(['-r',str(raw),'-Y',f'frame.number > {last}','-w',str(view)])
  tree=X.fromstring(run(['-r',str(view),'-d','udp.port==18443,quic','-o','tls.keylog_file:'+str(p/'tls.keys'),'-Y','udp.srcport==18443','-T','pdml']))
  wanted={s['id']:s for s in w['streams']};chunks={i:{} for i in wanted};fins={}
  for f in tree.iter('field'):
   if f.get('name')!='quic.frame':continue
   fs={v.get('name'):v for v in f.iter('field')}
   if 'quic.stream.stream_id' not in fs:continue
   sid=int(fs['quic.stream.stream_id'].get('show'));offset=int(fs['quic.stream.offset'].get('show')) if 'quic.stream.offset' in fs else 0
   if sid not in wanted:continue
   data=bytes.fromhex(fs['quic.stream_data'].get('value')) if 'quic.stream_data' in fs else b''
   for at,v in enumerate(data,offset):
    assert at not in chunks[sid] or chunks[sid][at]==v
    chunks[sid][at]=v
   if 'quic.stream.fin' in fs and fs['quic.stream.fin'].get('value')=='1':fins[sid]=offset+len(data)
  result={}
  for sid,s in wanted.items():
   assert sid in fins,(p,sid,'no FIN')
   end=fins[sid];assert len(chunks[sid])==end,(p,sid,'gap')
   wire=bytes(chunks[sid][i] for i in range(end));at=0;payload=bytearray()
   while at<len(wire):
    typ,at=varint(wire,at);n,at=varint(wire,at);assert at+n<=len(wire)
    if typ==0:payload.extend(wire[at:at+n])
    at+=n
   expected=s['server']['wire_bytes'] if 'server' in s else s['payload_bytes']
   assert len(payload)==expected,(p,sid,len(payload),expected)
   if (p/f'stream-{sid}.bin').exists():assert payload==(p/f'stream-{sid}.bin').read_bytes()
   result[str(sid)]={'fin':True,'gap_free':True,'http3_data_bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
  summary={'analysis_only_excluded_frames':last,'original_pcap_unchanged':True,'streams':result,'integrity':'passed'}
  (p/'h3-integrity.json').write_text(json.dumps(summary,indent=2)+'\n');results[p.name]=summary;print(phase,p.name,'passed',flush=True)
 (R/phase/'h3-integrity-matrix.json').write_text(json.dumps(results,indent=2)+'\n')
