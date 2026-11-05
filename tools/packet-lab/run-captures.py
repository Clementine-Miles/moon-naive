#!/usr/bin/env python3
"""Loopback-only lab driver. Requires the prepared local builder and lib test binary."""
import argparse, heapq, json, os, pathlib, random, re, select, shlex, signal, socket, subprocess, sys, time, threading
ROOT=pathlib.Path(__file__).resolve().parents[2]
LAB=ROOT/'reports/packet-lab'
ENV=os.environ.copy()
for name in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
 ENV.pop(name,None)
DOCKER=['docker','-H','unix:///var/run/docker.sock','exec']
CONTAINER=os.environ.get('MOON_NAIVE_LAB_CONTAINER', 'moon-naive-musl-builder')
DUMPCAP=os.environ.get('MOON_NAIVE_LAB_DUMPCAP', 'dumpcap')
def cmd(args,**kw):
 return subprocess.run(DOCKER+[CONTAINER]+list(args),env=ENV,check=True,**kw)
def relay_worker(directory, mode, loss_percent=.2, seed=42, outage_ms=0, outage_after_ms=1000):
 # Loopback-only, one client, fixed upstream; never a general UDP proxy.
 directory=pathlib.Path(directory);rng=random.Random(seed);running=True
 front=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);front.bind(('127.0.0.1',18444))
 upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(('127.0.0.1',0))
 for sock in (front,upstream):sock.setblocking(False)
 client=None;pending=[];queued=0;sequence=0;next_send=[0.,0.];started=None
 stats={'mode':mode,'delay_ms_each_direction':20,'rate_bits_per_sec_each_direction':100_000_000,
        'random_loss_probability':loss_percent/100 if mode=='loss' else 0,'seed':seed,
        'outage_after_ms':outage_after_ms,'outage_duration_ms':outage_ms,'outage_drops':[0,0],
        'received':[0,0],'forwarded':[0,0],'emulated_drops':[0,0],'queue_drops':0,'send_errors':0}
 def stop(*_):
  nonlocal running
  running=False
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 (directory/'relay.pid').write_text(str(os.getpid()))
 (directory/'relay.ready').write_text('127.0.0.1:18444\n')
 try:
  while running:
   now=time.monotonic()
   while pending and pending[0][0]<=now:
    _,_,data,sock,destination,direction=heapq.heappop(pending);queued-=len(data)
    try:
     sock.sendto(data,destination);stats['forwarded'][direction]+=1
    except OSError:stats['send_errors']+=1
   timeout=max(0,pending[0][0]-time.monotonic()) if pending else .1
   readable,_,_=select.select([front,upstream],[],[],timeout)
   for sock in readable:
    for _ in range(64):
     try:data,source=sock.recvfrom(65535)
     except BlockingIOError:break
     direction=0 if sock is front else 1
     if direction==0:
      if client is None:client=source
      if source!=client:continue
      output=upstream;destination=('127.0.0.1',18443)
     else:
      if source!=('127.0.0.1',18443) or client is None:continue
      output=front;destination=client
     stats['received'][direction]+=1
     if started is None:
      started=time.monotonic()
      stats['first_received_unix_us']=time.time_ns()//1000
      stats['outage_start_unix_us']=stats['first_received_unix_us']+outage_after_ms*1000
     elapsed=time.monotonic()-started
     if outage_after_ms/1000<=elapsed<(outage_after_ms+outage_ms)/1000:
      stats['outage_drops'][direction]+=1;continue
     if rng.random()<stats['random_loss_probability']:
      stats['emulated_drops'][direction]+=1;continue
     if queued+len(data)>4*1024*1024:
      stats['queue_drops']+=1;continue
     at=max(time.monotonic()+.020,next_send[direction])
     next_send[direction]=at+(len(data)+28)*8/100_000_000
     sequence+=1;queued+=len(data)
     heapq.heappush(pending,(at,sequence,data,output,destination,direction))
 finally:
  stats['pending_at_shutdown']=len(pending)
  (directory/'relay-stats.json').write_text(json.dumps(stats,indent=2)+'\n')
  front.close();upstream.close()

def stop_worker(directory, filename):
 pid=directory/filename
 if pid.exists():
  subprocess.run(DOCKER+[CONTAINER,'sh','-c','kill -TERM "$1"','sh',pid.read_text().strip()],env=ENV,check=False,capture_output=True)

def main():
 p=argparse.ArgumentParser()
 p.add_argument('phase');p.add_argument('binary');p.add_argument('scenarios',nargs='+');p.add_argument('--repeat',type=int,default=1)
 p.add_argument('--certificate', choices=['p256-leaf-only','p256-ca','rsa2048-ca','p384-chain'], default='p256-ca')
 p.add_argument('--tls-version', choices=['1.2','1.3'], default='1.3')
 p.add_argument('--tcp-congestion', choices=['system','bbr'], default='bbr')
 p.add_argument('--quic-congestion', choices=['cubic','bbr2'], default='bbr2')
 p.add_argument('--socket-stats', action='store_true')
 p.add_argument('--quic-relay', choices=['none','delay','loss'], default='none')
 p.add_argument('--loss-percent',type=float,default=.2)
 p.add_argument('--seed',type=int,default=42)
 p.add_argument('--outage-ms',type=int,default=0)
 p.add_argument('--outage-after-ms',type=int,default=1000)
 p.add_argument('--timeout-secs',type=int,default=30)
 p.add_argument('--soak-secs',type=int,default=120)
 a=p.parse_args()
 if not (0<=a.loss_percent<=30 and 0<=a.outage_ms<=15000 and 0<=a.outage_after_ms<=60000 and 30<=a.timeout_secs<=600 and 1<=a.soak_secs<=300):
  p.error('loss 0..30%, outage 0..15000ms after 0..60000ms, timeout 30..600s, soak 1..300s required')
 if a.quic_relay!='none' and any(not scenario.startswith('h3-') for scenario in a.scenarios):
  p.error('datagram impairment applies only to H3 scenarios')
 if a.tls_version == '1.2' and any(not scenario.startswith('h1-') for scenario in a.scenarios):
  p.error('TLS 1.2 experiments are restricted to H1 website scenarios')
 for scenario in a.scenarios:
  for i in range(1,a.repeat+1):
   directory=LAB/a.phase/f'{scenario}-{i:02}'
   directory.mkdir(parents=True,exist_ok=False)
   pid=directory/'dumpcap.pid';capture=directory/'trace.pcapng'
   log=(directory/'capture.log').open('w')
   # The shell's pid is retained by exec; no unrelated interface traffic is recorded.
   start=f'echo $$ > {shlex.quote(str(pid))}; exec {shlex.quote(DUMPCAP)} -i lo -p -q -B 64 -f "tcp port 18443 or udp port 18443" -a duration:{a.timeout_secs+10} -w -'
   # Capture stdout is opened by the host user; dumpcap drops filesystem
   # capabilities, so it cannot open this 0700 workspace itself.
   capture_out=capture.open('wb')
   proc=subprocess.Popen(DOCKER+[CONTAINER,'sh','-c',start],env=ENV,stdout=capture_out,stderr=log)
   relay=None;relay_log=None
   try:
    if a.quic_relay!='none':
     relay_log=(directory/'relay.log').open('w')
     relay=subprocess.Popen(DOCKER+[CONTAINER,'python3',str(pathlib.Path(__file__).resolve()),'--relay-worker',str(directory),a.quic_relay,str(a.loss_percent),str(a.seed),str(a.outage_ms),str(a.outage_after_ms)],env=ENV,stdout=relay_log,stderr=subprocess.STDOUT)
     ready_until=time.monotonic()+5
     while not (directory/'relay.ready').exists():
      if relay.poll() is not None or time.monotonic()>ready_until:raise RuntimeError('relay startup failed')
      time.sleep(.01)
    deadline=time.monotonic()+5
    while capture.stat().st_size == 0:
     if proc.poll() is not None:raise RuntimeError('capture failed to start: '+str(directory))
     if time.monotonic()>deadline:raise RuntimeError('capture startup timeout')
     time.sleep(.025)
    with (directory/'test.log').open('w') as out:
     extra=['-e','MOON_NAIVE_CAPTURE_QUIC_RELAY=127.0.0.1:18444'] if relay else []
     extra+=['-e',f'MOON_NAIVE_CAPTURE_TIMEOUT_SECS={min(a.timeout_secs,60)}','-e',f'MOON_NAIVE_CAPTURE_SOAK_SECS={a.soak_secs}']
     test=DOCKER+extra+['-e',f'MOON_NAIVE_CAPTURE_DIR={directory}','-e',f'MOON_NAIVE_CAPTURE_SCENARIO={scenario}','-e',f'MOON_NAIVE_CAPTURE_CERT={a.certificate}','-e',f'MOON_NAIVE_CAPTURE_TLS_VERSION={a.tls_version}','-e',f'MOON_NAIVE_TEST_QUIC_CONGESTION={a.quic_congestion}','-e',f'MOON_NAIVE_TEST_TCP_CONGESTION={a.tcp_congestion}',CONTAINER,a.binary,'--ignored','--exact','net::tests::capture::packet_capture_lab','--nocapture']
     samples=[];stop=threading.Event()
     def monitor():
      while not stop.is_set():
       snapshot=cmd(['ss','-tin','state','established','( sport = :18443 or dport = :18443 )'],capture_output=True,text=True,timeout=3)
       samples.append({'unix_ns':time.time_ns(),'ss':snapshot.stdout})
       stop.wait(.1)
     watcher=threading.Thread(target=monitor,daemon=True) if a.socket_stats else None
     if watcher:watcher.start()
     try:
      result=subprocess.run(test,env=ENV,stdout=out,stderr=subprocess.STDOUT,timeout=a.timeout_secs)
     finally:
      stop.set()
      if watcher:
       watcher.join(timeout=4)
       (directory/'socket-stats.json').write_text(json.dumps(samples,indent=2)+'\n')
   except BaseException:
    (directory/'INVALID.txt').write_text('Capture/workload/relay failed; sample excluded.\n')
    raise
   finally:
    # libpcap TPACKET_V3 buffers short loopback traffic; allow a block
    # retirement interval before interrupting dumpcap so the tail is saved.
    time.sleep(0.7)
    if relay:
     stop_worker(directory,'relay.pid');relay.wait(timeout=5);relay_log.close()
    if pid.exists() and proc.poll() is None:
     subprocess.run(DOCKER+[CONTAINER,'sh','-c','kill -INT "$1"','sh',pid.read_text().strip()],env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    proc.wait(timeout=5);capture_out.close();log.close()
    cmd(['chown','-R',f'{os.getuid()}:{os.getgid()}',str(directory)])
   if result.returncode:
    (directory/'INVALID.txt').write_text('Workload failed; this capture is excluded.\n')
    raise RuntimeError('workload failed: '+str(directory))
   if relay:
    stats=json.loads((directory/'relay-stats.json').read_text())
    if stats['queue_drops'] or stats['send_errors'] or stats['pending_at_shutdown']:
     (directory/'INVALID.txt').write_text('Unexpected relay drops or unfinished queue.\n')
     raise RuntimeError('invalid relay run: '+str(directory))
   drops=re.findall(r"received/dropped.*?:\s*\d+/(\d+)", (directory/'capture.log').read_text())
   if not drops or any(int(n) for n in drops):
    (directory/'INVALID.txt').write_text('Missing drop count or capture packet loss; rerun in a new phase.\n')
    raise RuntimeError('incomplete capture: '+str(directory))
   cmd(['editcap','-F','pcap',str(capture),str(directory/'trace.pcap')],stdout=subprocess.DEVNULL)
   cmd(['chown',f'{os.getuid()}:{os.getgid()}',str(directory/'trace.pcap')])
   print(f'{a.phase} {scenario} {i}: passed ({capture.stat().st_size} bytes)',flush=True)
if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]=='--relay-worker':relay_worker(sys.argv[2],sys.argv[3],float(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6]),int(sys.argv[7]))
 else:main()
