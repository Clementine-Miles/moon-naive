#!/usr/bin/env python3
"""Analyze complete synthetic captures; never print test TLS key material."""
import collections, json, os, pathlib, statistics, subprocess, sys
import xml.etree.ElementTree as ET
R=pathlib.Path(__file__).resolve().parents[2]/'reports/packet-lab'
E=os.environ.copy()
for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):E.pop(k,None)
D=['docker','-H','unix:///var/run/docker.sock','exec',os.environ.get('MOON_NAIVE_LAB_CONTAINER', 'moon-naive-musl-builder'),'tshark']
FIELDS=['frame.number','tcp.srcport','tcp.dstport','tcp.len','udp.srcport','udp.dstport','udp.length','tls.record.content_type','tls.record.length','http2.length','http2.type','http2.streamid','tls.handshake.extensions_server_name','tls.handshake.ja3','tls.handshake.ja3s']
def nums(s):return [int(v,0) for v in s.split(';') if v]
OBSERVE_FIELDS = [
 'frame.time_epoch', 'tcp.srcport', 'tcp.dstport', 'tcp.len',
 'udp.srcport', 'udp.dstport', 'udp.length', 'tls.handshake.type',
 'tls.record.content_type','tls.record.length','tls.handshake.certificate_length', 'tls.handshake.extensions_server_name',
 'tls.handshake.ja3', 'tls.handshake.ja3s', 'tls.handshake.ja4',
 'tls.handshake.ciphersuite', 'tls.handshake.sig_hash_alg',
 'tls.handshake.extensions_alpn_str', 'tcp.analysis.retransmission',
 'tcp.analysis.zero_window', 'tcp.analysis.window_full', 'tcp.analysis.ack_rtt',
 'http.response.code', 'http2.headers.status', 'http2.type', 'http2.length',
 'http2.settings.initial_window_size', 'http2.settings.max_concurrent_streams',
 'http2.window_update.window_size_increment',
]
def passive_tls_record_lengths(trace):
 # TLS 1.3 without a keylog uses opaque_type, not content_type. Read each
 # record's tree independently: flattened fields lose alignment when a frame
 # contains ServerHello, CCS and encrypted records together.
 args=D+['-r',str(trace.resolve()),'-d','tcp.port==18443,tls',
         '-Y','tcp.srcport == 18443 && (tls.record.content_type == 23 || tls.record.opaque_type == 23)',
         '-T','pdml','-j','tls tls.record tls.record.content_type tls.record.opaque_type tls.record.length']
 tree=ET.fromstring(subprocess.run(args,env=E,check=True,capture_output=True,text=True).stdout)
 lengths=[]
 for record in tree.iter('field'):
  if record.get('name')!='tls.record':continue
  fields={field.get('name'):field.get('show') for field in record.findall('field')}
  if fields.get('tls.record.opaque_type',fields.get('tls.record.content_type'))=='23':
   lengths.append(int(fields['tls.record.length']))
 if tree.findall('packet') and not lengths:
  raise ValueError('TLS type23 packets present but record trees could not be decoded')
 return lengths
def observe(directory, keyed=False):
 trace=directory/'trace.pcapng'
 if keyed and (directory/'analysis-after-retry.pcapng').exists():
  trace=directory/'analysis-after-retry.pcapng'
 args=D+['-r',str(trace),'-d','tcp.port==18443,tls','-d','udp.port==18443,quic']
 if keyed: args+=['-o','tls.keylog_file:'+str(directory/'tls.keys')]
 args+=['-T','fields','-E','separator=|','-E','occurrence=a','-E','aggregator=;']
 for field in OBSERVE_FIELDS: args+=['-e',field]
 output=subprocess.run(args,env=E,check=True,capture_output=True,text=True)
 values=collections.defaultdict(set);sizes=collections.defaultdict(collections.Counter)
 times=collections.defaultdict(list);counts=collections.Counter();headers=collections.Counter();acks=[]
 record_lengths=[]
 for line in output.stdout.splitlines():
  row=dict(zip(OBSERVE_FIELDS,line.split('|')))
  direction='server' if '18443' in (row['tcp.srcport'],row['udp.srcport']) else 'client'
  protocol='tcp' if row['tcp.srcport'] else 'udp'
  length=int(row['tcp.len'] or 0) if protocol=='tcp' else max(0,int(row['udp.length'] or 8)-8)
  sizes[direction+'_'+protocol][length]+=1
  if length: times[direction].append(float(row['frame.time_epoch']))
  if direction=='server':
   for typ,size in zip(nums(row['tls.record.content_type']),nums(row['tls.record.length'])):
    if typ==23:record_lengths.append(size)
  for field in ('tls.handshake.extensions_server_name','tls.handshake.ja3','tls.handshake.ja3s','tls.handshake.ja4',
                'tls.handshake.extensions_alpn_str','http.response.code','http2.headers.status',
                'http2.settings.initial_window_size','http2.settings.max_concurrent_streams'):
   if row[field]: values[direction+'_'+field].update(row[field].split(';'))
  if row['tls.handshake.certificate_length']:
   values[direction+'_certificate_lengths'].add(tuple(nums(row['tls.handshake.certificate_length'])))
  if direction=='server' and 2 in nums(row['tls.handshake.type']):
   values['server_selected_cipher'].update(row['tls.handshake.ciphersuite'].split(';'))
  for field in ('tcp.analysis.retransmission','tcp.analysis.zero_window','tcp.analysis.window_full'):
   if row[field]: counts[direction+'_'+field]+=1
  if row['tcp.analysis.ack_rtt']: acks.extend(float(v) for v in row['tcp.analysis.ack_rtt'].split(';'))
  types=nums(row['http2.type']);lengths=nums(row['http2.length'])
  if direction=='server' and len(types)==len(lengths):
   for typ,length in zip(types,lengths):
    if typ==1: headers[length]+=1
  counts[direction+'_h2_window_updates']+=len(nums(row['http2.window_update.window_size_increment']))
 def quantiles(numbers):
  numbers=sorted(numbers)
  return {'count':len(numbers),'median':statistics.median(numbers),'p95':numbers[min(len(numbers)-1,int(.95*len(numbers)))],'max':numbers[-1]} if numbers else {'count':0}
 if not keyed:record_lengths=passive_tls_record_lengths(trace)
 gaps={side:quantiles([(b-a)*1e6 for a,b in zip(ticks,ticks[1:])]) for side,ticks in times.items()}
 return {'keylog_used':keyed,'capture_view':trace.name,'values':{k:sorted(v) for k,v in values.items()},
         'packet_payload_lengths':{k:dict(sorted(v.items())) for k,v in sizes.items()},
         'server_first_type23_record_length':record_lengths[0] if record_lengths else None,
         'server_type23_record_lengths':dict(sorted(collections.Counter(record_lengths).items())),
         'payload_interarrival_us':gaps,'tcp_ack_rtt_ms':quantiles([v*1000 for v in acks]),
         'tcp_and_flow_control_events':dict(counts),'server_h2_headers_lengths':dict(sorted(headers.items()))}
def run(d):
 assert not (d/'INVALID.txt').exists(), str(d)
 trace=d/'trace.pcapng'; key=d/'tls.keys'; work=json.loads((d/'workload.json').read_text())
 args=D+['-r',str(trace),'-d','tcp.port==18443,tls','-d','udp.port==18443,quic','-o','tls.keylog_file:'+str(key),'-T','fields','-E','separator=|','-E','occurrence=a','-E','aggregator=;']
 for f in FIELDS:args+=['-e',f]
 out=subprocess.run(args,env=E,check=True,capture_output=True,text=True)
 records=collections.Counter(); h2data=collections.Counter();pck={'tcp':0,'udp':0,'tcp_server_bytes':0,'tcp_client_bytes':0,'udp_server_bytes':0,'udp_client_bytes':0};ja3=set();ja3s=set();sni=set();warnings=[]
 for line in out.stdout.splitlines():
  cols=line.split('|');cols+=['']*(len(FIELDS)-len(cols));r=dict(zip(FIELDS,cols))
  ts=r['tcp.srcport'];td=r['tcp.dstport'];us=r['udp.srcport'];ud=r['udp.dstport']
  direction='server' if ts=='18443' else 'client' if td=='18443' else None
  if ts or td:
   pck['tcp']+=1
   if direction:pck['tcp_'+direction+'_bytes']+=int(r['tcp.len'] or 0)
  if us or ud:
   pck['udp']+=1
   direction='server' if us=='18443' else 'client' if ud=='18443' else None
   if direction:pck['udp_'+direction+'_bytes']+=max(0,int(r['udp.length'] or 8)-8)
  types=nums(r['tls.record.content_type']);lens=nums(r['tls.record.length'])
  if len(types)!=len(lens):warnings.append('mismatched tls record field counts at frame '+r['frame.number'])
  for typ,ln in zip(types,lens):
   if direction=='server' and typ==23:records[ln]+=1
  ls=nums(r['http2.length']);ys=nums(r['http2.type']);ids=nums(r['http2.streamid'])
  if ls or ys or ids:
   if len(ls)!=len(ys) or len(ys)!=len(ids):warnings.append('mismatched h2 frame field counts at frame '+r['frame.number'])
   else:
    for size,typ,sid in zip(ls,ys,ids):
     if direction=='server' and typ==0 and sid:h2data[str(sid)]+=size
  if r['tls.handshake.extensions_server_name']:sni.update(r['tls.handshake.extensions_server_name'].split(';'))
  if r['tls.handshake.ja3']:ja3.update(r['tls.handshake.ja3'].split(';'))
  if r['tls.handshake.ja3s']:ja3s.update(r['tls.handshake.ja3s'].split(';'))
 expected={}
 if work['scenario'].startswith('h2'):
  for stream in work['streams']:
   if 'server' in stream:expected[str(stream['id'])]=stream['server']['wire_bytes']
   elif 'payload_bytes' in stream:expected[str(stream['id'])]=stream['payload_bytes']
 mismatches={s:{'expected':size,'decoded':h2data.get(s,0)} for s,size in expected.items() if h2data.get(s,0)!=size}
 capturelog=(d/'capture.log').read_text()
 lst=list(records.elements());count=len(lst)
 result={'scenario':work['scenario'],'record_server_ciphertext_length_count':{str(k):v for k,v in sorted(records.items())},'server_tls_records':count,'records_273_count':records[273], 'records_273_fraction':records[273]/count if count else None,'median_server_tls_record_length':statistics.median(lst) if count else None,'decrypted_h2_data_bytes_by_stream':dict(h2data),'expected_h2_data_bytes_by_stream':expected,'h2_data_mismatches':mismatches,'counts':pck,'sni':sorted(sni),'ja3_client':sorted(ja3),'ja3s_server':sorted(ja3s),'tshark_warnings':warnings,'capture_log':capturelog.strip().replace('\r','')}
 result['passive']=observe(d)
 result['decrypted_protocol']=observe(d,True)
 result['certificate']=work.get('certificate')
 (d/'tshark.summary.json').write_text(json.dumps(result,indent=2)+'\n')
 return result
if __name__=='__main__':
 phase=R/sys.argv[1]; summary={}
 for p in sorted(phase.iterdir()):
  if p.is_dir() and (p/'workload.json').exists() and (p/'trace.pcapng').exists():
   s=run(p);summary[p.name]=s
   print(p.name,'tls273',s['records_273_count'],'/',s['server_tls_records'],'h2_mismatch',s['h2_data_mismatches'],flush=True)
 (phase/'tshark-matrix.json').write_text(json.dumps(summary,indent=2)+'\n')
 assert all(not s['h2_data_mismatches'] and not s['tshark_warnings'] for s in summary.values()), 'Incomplete or ambiguous capture; see matrix'
