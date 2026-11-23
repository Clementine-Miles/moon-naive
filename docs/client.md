# Client

`moon-naive-client` is the first-party client for a Moon-naive server. It
exposes a local SOCKS5 and HTTP CONNECT proxy on one port and carries every
local connection over its own authenticated mona (Rupin) CONNECT stream on
HTTP/2 or HTTP/3. It is not compatible with upstream NaiveProxy servers.

```sh
cargo build --release --locked -p moon-naive-client
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
| `listen` | `127.0.0.1:1080` | Local SOCKS5 + HTTP CONNECT listener; it has no authentication, so keep it on loopback (a warning is logged otherwise) |
| `username`, `password` | required | A user configured on the server; password at least 16 bytes |
| `transport` | `h2` | `h2`, `h3`, or `h3-then-h2` |
| `ca_file` | system store | PEM trust anchors; verification cannot be disabled |
| `ech_config_list` | none | Base64 ECHConfigList from `moon-naive ech dns`; when set, ECH is mandatory |
| `connect_timeout_secs` | 15 | Connection establishment and tunnel setup deadline |
| `local_handshake_timeout_secs` | 10 | Deadline for the local SOCKS5/HTTP request |
| `max_tunnels` | 256 | Concurrent local connections; excess connections are closed |
| `quic_idle_timeout_secs` | 30 | QUIC idle timeout; the connection is re-established on demand |
| `log_level` | `info` | `error`, `info` or `debug`. Credentials and proofs are never logged; targets only at `debug` |

## Behavior

- **Local protocols.** SOCKS5 `CONNECT` with "no authentication" (IPv4,
  IPv6 and domain targets; domains are sent to the server for resolution, as
  with `socks5h`). `BIND` and `UDP ASSOCIATE` are answered with "command not
  supported". HTTP `CONNECT host:port`; other methods get 405. Plain HTTP
  proxying (absolute-form `GET`) is not supported.
- **Authentication.** Each tunnel is a separate CONNECT stream with a proof
  bound to the TLS exporter and the actual stream ID. Payload flows only after
  status 200 and a valid server confirmation.
- **TLS.** TLS 1.3 only, certificate and hostname verification always on.
  With `ech_config_list`, a server that does not accept ECH is refused; there
  is no fallback to a cleartext server name. Retry configurations from the
  server are not applied automatically; update the configured list instead.
- **Transports.** One pooled connection per transport is shared by all
  tunnels and reopened after it closes. `h3-then-h2` uses HTTP/2 only when a
  QUIC connection cannot be established (handshake failure or timeout), then
  avoids QUIC for 5 minutes. A server's answer (403, 502, …) is final on any
  transport, and tunnel bytes are never replayed.
- **Errors to local applications.** Server 403 → SOCKS5 "not allowed" / HTTP
  403; 502 → "host unreachable" / 502; 504 or timeout → "TTL expired" / 504;
  authentication rejection, invalid confirmation and other failures →
  "general failure" / 502.
- **Resource bounds.** At most `max_tunnels` local connections. Per H3
  stream, at most 8 records (about 128 KiB) are buffered in each direction
  between the QUIC driver and the local socket; H2 relies on HTTP/2 flow
  control, releasing credit only after bytes reach the local peer.
- **TCP Fast Open** is never requested.

## Platforms and limitations

Linux is the supported and tested platform. The code is portable Rust apart
from Unix signal handling and the permission check, but other platforms are
untested. Android is not supported by the Rust client (the previous
experimental Chromium-based Android client was removed). DNS-based ECH
discovery (HTTPS records) is not implemented; the ECHConfigList is
configured explicitly.
