# Local packet and offline DPI lab

This optional test harness is excluded from production execution. The Rust
workload lives in `src/net/tests/capture.rs`; Python orchestrates capture and
analysis. The Go adapter in `opengfw/` calls the pinned, unmodified OpenGFW engine
on saved packets. The source package contains no captures, TLS secrets, analyzer
binaries or build outputs.

The runner uses `MOON_NAIVE_LAB_CONTAINER` (default
`moon-naive-musl-builder`), the repository mounted at the **same absolute path**,
and TShark/editcap/dumpcap inside that container, with permission to capture
loopback. `MOON_NAIVE_LAB_DUMPCAP` can select a private dumpcap executable.
Configure Docker and mount paths for your own environment.
Use a standalone local lab rather than capturing a live server interface.
Historical results used Wireshark 4.4.7; the 0.6.0 BBR/certificate matrix uses
TShark 4.4.19. If a packaged dumpcap
has unavailable file capabilities, the lab administrator can install a private
copy without file capabilities; do not change production capture permissions.

Compile the ignored test with the normal project toolchain:

```sh
cargo test -p moon-naive --lib --locked --no-run --message-format=json > test-build.jsonl
```

Use the `compiler-artifact` executable for target `moon_naive`, with
`profile.test=true`, as the absolute `BINARY` argument below. The container must
be able to run that target's ABI. The `--ignored --exact` flag restricts execution
to the capture workload. Never run two drivers concurrently: both bind 18443.

```sh
python3 tools/packet-lab/run-captures.py sample "$BINARY" \
  h1-site h1-connect h2-site-burst h2-tunnel-burst \
  h2-site-h2origin-burst h2-site-h2origin-idle h2-site-long h2-tunnel-long \
  h2-bulk8 h2-bulk16 h2-inner-tls h3-site h3-probe h3-tunnel16
python3 tools/packet-lab/analyze-tshark.py sample
python3 tools/packet-lab/analyze-mirror.py sample
python3 tools/packet-lab/verify-h3.py sample
# Build the optional adapter following opengfw/README.md first:
python3 tools/packet-lab/opengfw/analyze-captures.py sample
```

Outputs are under ignored `reports/packet-lab/sample`; choose a new phase name
for every run. `--repeat 3` repeats each scenario. The runner waits for capture
startup and buffer drain; a completed `workload.json` is mandatory. Workloads use
a local self-signed CA and CA-signed leaf with certificate/hostname verification.
They generate short-lived test-only keylogs mode 0600, never production keys.
Treat the captures and keylogs as sensitive; keep them out of published archives.

## Certificate and BBR experiments (0.6.0)

The capture fixture supports `--certificate p256-leaf-only`, `p256-ca`,
`rsa2048-ca`, and `p384-chain`. All use a fresh, locally self-signed CA and
verified leaf identity. The first sends only the leaf (the client explicitly
trusts its root); the others send two, two, and three certificates. P-384 includes
an intermediate CA. No verification bypass is used. Certificate metadata and
DER hashes are recorded in `workload.json`; temporary private keys are removed
with the fixture. The inner HTTPS origin also sends its complete chain.

```sh
export MOON_NAIVE_LAB_CONTAINER=moon-naive-packet-lab
python3 tools/packet-lab/run-captures.py cert-p384 "$BINARY" \
  h1-site h1-head h1-connect h1-unknown-host h1-ambiguous \
  h2-site h2-probe h2-tunnel8 h2-tunnel16 h2-sparse16 h2-inner-tls \
  h3-site h3-probe h3-tunnel8 h3-tunnel16 h3-sparse16 \
  --certificate p384-chain --tcp-congestion bbr --quic-congestion bbr2
python3 tools/packet-lab/run-captures.py cert-rsa-tls12 "$BINARY" \
  h1-site --certificate rsa2048-ca --tls-version 1.2
python3 tools/packet-lab/verify-h3.py cert-p384
python3 tools/packet-lab/analyze-tshark.py cert-p384
```

TLS 1.2 capture is restricted to H1 website scenarios; authenticated proxy
requests still require TLS 1.3. H1 ambiguity means CL+TE. H2/H3 probes send one
request without credentials and another with a correctly shaped invalid proof;
neither may dial a proxy target. Bulk scenarios include `h2-bulk16` and
`h3-bulk16`; each verifies two streams with paced initial pieces followed by
1 MiB per stream. Transfer timing starts after the outer handshake and ends
before shutdown. TCP lab clients and redirected test targets use TCP_NODELAY,
matching the production data path instead of adding a Nagle/delayed-ACK artifact.

`analyze-tshark.py` produces separate passive and keylog-assisted views. The
passive view never loads TLS secrets and measures SNI, JA3/JA3S, client JA4,
packet payload sizes, timing and TCP events. The assisted view checks certificate
chains, HTTP status, H2 SETTINGS, WINDOW_UPDATE and HEADERS lengths. A client JA4
is not a server fingerprint; decoded H2 fields are not plaintext DPI signals.
Run `verify-h3.py` first so the assisted H3 view can use its Retry analysis copy.
Original packets remain the size/timing input. Capture loss or workload failure
invalidates a sample. `--socket-stats` saves filtered `ss -tin` samples; reserve
it for diagnostic runs, not the paired timing runs.

The recorded container has NET_RAW/NET_ADMIN, MTU 1500 on its private loopback,
GRO/GSO/TSO disabled, and fq. These are **lab namespace changes**, never host/VPS
changes. Example setup inside that disposable container:

```sh
ip link set lo mtu 1500
ethtool -K lo gro off gso off tso off
tc qdisc replace dev lo root fq
```

This kernel does not provide prio/netem qdiscs, so the recorded impairment
experiment uses `--quic-relay delay` or `--quic-relay loss` for H3 only. It needs
Python 3 in the container. The relay binds loopback port 18444, forwards to the
fixed server port 18443, and never terminates TLS/QUIC. Each direction has 20 ms
delay and 100 Mbit/s serialization (including 28 bytes of IPv4/UDP overhead).
The loss mode independently drops datagrams with probability 0.002 by default,
seed 42. `--loss-percent` and `--seed` select a different reproducible random
sequence; packet scheduling still varies, so this is not identical packet loss
across two implementations.
A bounded 4 MiB queue, unexpected send/queue drops and unfinished shutdown are
checked separately from intentional loss. Original captures observe the
server-facing leg; `relay-stats.json` records the impairment, and `workload.json`
records the client's measured QUIC RTT. The TCP origin remains on loopback.

```sh
python3 tools/packet-lab/run-captures.py quic-delay "$BINARY" \
  h3-bulk16 --quic-relay delay --repeat 3
python3 tools/packet-lab/run-captures.py quic-loss "$BINARY" \
  h3-bulk16 --quic-relay loss --repeat 3
```

This is a userspace datagram-path experiment, not a physical WAN. It does not
measure kernel TCP BBR under RTT/loss; that requires a suitable netem host or
real test endpoints. Do not substitute TCP application-level sleeps and call
them TCP network congestion.

## Long channels and high loss (2026-11-04)

`h2-soak` and `h3-soak` hold one authenticated duplex CONNECT open, verify each
1 KiB echo, wait 250 ms between exchanges, and verify clean FIN and quota release.
`--soak-secs` accepts 1–300 seconds (default 120). The fixture's idle timeout is
10 seconds; production defaults to 600 seconds. `workload.json` records exchange
latency, whole-process RSS/FD samples and test-only H3 driver iteration counts.
These memory samples include both client and server, fixture buffers and saved
results; they are not a standalone server memory benchmark.

```sh
python3 tools/packet-lab/run-captures.py loss10-seed42 "$BINARY" \
  h3-bulk16 --quic-relay loss --loss-percent 10 --seed 42 --timeout-secs 90
python3 tools/packet-lab/run-captures.py long-outage "$BINARY" \
  h3-soak --quic-relay loss --loss-percent 10 --seed 42 \
  --outage-ms 2000 --outage-after-ms 10000 --soak-secs 120 --timeout-secs 180
python3 tools/packet-lab/run-captures.py long-h2 "$BINARY" \
  h2-soak --soak-secs 120 --timeout-secs 180
python3 tools/packet-lab/verify-h3.py loss10-seed42 long-outage
python3 tools/packet-lab/analyze-tshark.py long-outage
```

Loss accepts 0–30 percent. An optional 0–15000 ms blackout starts
`--outage-after-ms` (default 1000, range 0–60000) after the relay's first packet,
drops datagrams in both directions,
and is counted separately from random loss. Already queued datagrams may still
arrive. `--timeout-secs` bounds the whole test (30–600 seconds); individual
test-client I/O deadlines use that value capped at 60 seconds. These options
never change production timeouts, inject keepalive traffic or disable pacing.
For established-channel recovery, verify that relay `outage_start_unix_us`
falls after the workload's `transfer_start_unix_us` and before its end. An early
blackout may affect only the handshake; do not report it as tunnel recovery.
Use a fresh phase per attempt; preserve and disclose failed/invalid attempts.
Use paired control/final runs, alternate execution order, and vary random seeds.
Two-minute tests and virtual-clock deadline tests are not a 24-hour soak.

Compare an unchanged-workload control binary with the old QUIC send loop against
the current driver, alternating their order, after compilation has stopped.
Keep raw evidence under reports and publish only the summary. BBR, flow-control
windows, application pacing and source delays are distinct limits; a faster
QUIC timer does not establish the VPS bandwidth or a DPI recognition rate.

Scenarios compare deterministic 512 B–64 KiB objects, 32 concurrent H2 streams,
a warmed HTTPS/H2 origin, and 16 sequential requests with four two-second idle
gaps against a three-second idle timeout. Bulk scenarios send 24 paced segments
followed by 1 MiB on each of two CONNECT streams. They verify byte-for-byte
payload integrity and authenticated response selection. Idle analysis checks
TCP payload absence in the middle of each idle interval, excluding 50 ms at both
edges for control delivery. A long scenario exercises activity-based expiry,
not hours of operation. One outer connection and many target connections are
separate counts; a server cannot combine arbitrary target TCP byte streams.

`verify-h3.py` works around Wireshark 4.4.7 Retry reassembly by making a separate
analysis view after the final Retry, then verifies QUIC offsets, FIN and H3 DATA.
Original captures, including Retry, remain the DPI and packet-size inputs.

These BoringSSL/h2/quiche test clients are **not Chromium**. Loopback timings,
MTU/segmentation and synthetic objects are not a statistical model of mirror-site
visits. HEADERS payload length is not TLS record or IP packet length. OpenGFW's
`no_result` is inconclusive, and its TCP Trojan/FET analyzers do not cover QUIC.
Do not infer real censorship evasion or a reduction in recognition rate from
these local tests. See `docs/FINGERPRINTS.md` for measured results and limitations.
