# Client

`moon-naive-client` is the first-party client for a Moon-naive server. It
exposes a local SOCKS5 and HTTP CONNECT proxy on one port and carries every
local connection over its own authenticated mona (Rupin) CONNECT stream on
HTTP/2 or HTTP/3. It is not compatible with upstream NaiveProxy servers.

The client is two parts. The Rust application (`client/`) handles
configuration, the local listener, the mona proofs and confirmations, and the
record codec. Every proxy connection is made by the **Chromium native engine**
(`libmoon_engine.so`, built from Chromium's network stack; see
[development](development.md#chromium-native-engine)): DNS, TCP/UDP sockets,
TLS 1.3 with BoringSSL, HTTP/2, QUIC/HTTP/3, the socket pools and certificate
verification. The client has no HTTP/2, QUIC or TLS implementation of its own
and no fallback to one: without the engine it refuses to start tunnels.

```sh
cargo build --release --locked -p moon-naive-client
cargo xtask engine fetch /work/chromium && cargo xtask engine toolchain /work/chromium
cargo xtask engine build /work/chromium         # -> /work/chromium/src/out/engine/libmoon_engine.so
install -Dm755 /work/chromium/src/out/engine/libmoon_engine.so ~/.local/lib/moon-naive/libmoon_engine.so
install -Dm600 client.example.toml ~/.config/moon-naive/client.toml   # then edit
moon-naive-client check ~/.config/moon-naive/client.toml               # offline validation
moon-naive-client run ~/.config/moon-naive/client.toml
curl --proxy socks5h://127.0.0.1:1080 https://example.org/
```

The configuration contains the password, so `run` and `check` refuse files
that are group- or world-accessible. A systemd user unit is in
[`deploy/moon-naive-client.service`](../deploy/moon-naive-client.service).

## Configuration

See [`client.example.toml`](../client.example.toml); unknown keys are
rejected.

| Key | Default | Meaning |
| --- | --- | --- |
| `server` | required | `host:port` (DNS name, IPv4, or `[IPv6]:port`); H2 uses TCP and H3 uses UDP on this port |
| `server_name` | host of `server` | TLS name for SNI (or the ECH inner name) and certificate verification; required if `server` is an IP |
| `listen` | `127.0.0.1:1080` | Local SOCKS5 + HTTP CONNECT listener. It has no authentication, so only loopback addresses (`127.0.0.0/8`, `[::1]`) are accepted |
| `username`, `password` | required | A user configured on the server; password at least 16 bytes |
| `transport` | `h2` | `h2`, `h3`, or `h3-then-h2` |
| `ca_file` | Chrome Root Store | Additional PEM trust anchors (for a private CA); verification cannot be disabled |
| `ech_config_list` | none | Base64 ECHConfigList from `moon-naive ech dns`; when set, ECH is mandatory |
| `connect_timeout_secs` | 15 | Connection establishment and tunnel setup deadline |
| `local_handshake_timeout_secs` | 10 | Deadline for the local SOCKS5/HTTP request |
| `max_tunnels` | 256 | Concurrent local connections; excess connections are closed |
| `quic_idle_timeout_secs` | 30 | QUIC idle timeout; the connection is re-established on demand |
| `engine_library` | see below | Path to `libmoon_engine.so` |
| `log_level` | `info` | `error`, `info` or `debug`. Credentials and proofs are never logged; targets only at `debug` |

The engine is looked up in this order: `engine_library`, the
`MOON_NAIVE_ENGINE` environment variable, next to the executable, then
`../lib/moon-naive/` relative to the executable (the layout of the client
release archive). The engine's ABI version is checked when it is loaded.

## Behavior

- **Local protocols.** SOCKS5 `CONNECT` with "no authentication" (IPv4,
  IPv6 and domain targets; domains are sent to the server for resolution, as
  with `socks5h`). `BIND` and `UDP ASSOCIATE` are answered with "command not
  supported". HTTP `CONNECT host:port`; other methods get 405. Plain HTTP
  proxying (absolute-form `GET`) is not supported.
- **Authentication.** Each tunnel is a separate CONNECT stream with a proof
  bound to the TLS exporter and the stream ID that Chromium actually
  allocated (the patched engine calls back into the client after the ID is
  assigned and before HEADERS are encoded). Payload flows only after status
  200 and exactly one valid server confirmation; anything else closes the
  stream without sending a byte. `proxy-authorization` is never indexed by
  HPACK/QPACK.
- **TLS.** TLS 1.3 with Chromium's BoringSSL and certificate verifier
  (Chrome Root Store plus `ca_file`), hostname verification always on.
  With `ech_config_list`, ECH is mandatory: a server that does not accept ECH
  is refused and no proof is ever signed on a non-ECH connection. On HTTP/2,
  Chromium applies server-provided retry configurations once (ECH stays
  accepted); on HTTP/3 Chromium does not retry, so a stale list fails closed
  until the configured list is updated.
- **Transports.** Chromium's HTTP/2 and QUIC session pools share one
  connection per transport among all tunnels and reopen it on demand.
  `h3-then-h2` uses HTTP/2 only when a QUIC connection cannot be established
  (connection error or timeout), then avoids QUIC for 5 minutes. A server's
  answer (403, 502, …) is final on any transport, and tunnel bytes are never
  replayed. Half-close is carried in both directions (FIN / `END_STREAM`).
- **Errors to local applications.** Server 403 → SOCKS5 "not allowed" / HTTP
  403; 502 → "host unreachable" / 502; 504 or timeout → "TTL expired" / 504;
  authentication rejection, invalid confirmation and other failures →
  "general failure" / 502.
- **Resource bounds.** At most `max_tunnels` local connections. Each tunnel
  has one outstanding read (at most 64 KiB) and one outstanding write between
  the client and the engine, so flow control is Chromium's own.
- **TCP Fast Open** is never requested, and NaiveProxy's "fast open"
  (sending payload before the CONNECT reply) is refused for these tunnels.

## Platforms and limitations

Linux x86_64 with glibc is the supported and tested platform: the engine is
a glibc shared library, so the client must be a dynamically linked (gnu)
executable, not a static musl one. Other platforms are not built or tested.
DNS-based ECH discovery (HTTPS records) is not used; the ECHConfigList is
configured explicitly.

The engine makes the client's connections with Chromium's real network
stack, but this is not a claim that its traffic cannot be told apart from a
Chrome browser: the engine is a build of Chromium's `net/` without the
browser, its request pattern (one CONNECT per local connection, the mona
headers, record padding) is its own, and no fingerprint comparison has been
done.
