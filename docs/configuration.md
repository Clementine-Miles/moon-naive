# Server configuration

The authoritative field list and defaults are the commented examples
[`config.example.toml`](../config.example.toml) (one endpoint) and
[`config.dual.example.toml`](../config.dual.example.toml) (two endpoints),
plus configuration validation in `core/src/config.rs`. Both examples are
parsed by tests. The client is configured separately; see [client.md](client.md).

```sh
moon-naive config init /etc/moon-naive/config.toml   # private 0600, never overwrites
moon-naive check-config /etc/moon-naive/config.toml  # structure only
moon-naive check /etc/moon-naive/config.toml         # full offline preflight
moon-naive check-transport /etc/moon-naive/config.toml
moon-naive serve /etc/moon-naive/config.toml
```

`check-config` validates structure. `check` also loads external files (users,
ACL, ECH, certificates) without contacting the CA or DNS provider and without
opening listeners. Create the parent directory, owned by the service user,
before `config init`.

## Essentials

- `domain`: the public host name. A/AAAA must point at a reachable address;
  do not publish AAAA for unreachable IPv6. The website origin must not point
  back at this name.
- `state_dir` (default `/var/lib/moon-naive`, mode 0700) holds the ACME
  account, renewal journal and certificate generations. It must persist.
- Users: `[[proxy.users]]` inline, or a private `credentials_file`. Passwords
  need at least 16 bytes; use 32+ random characters. SHA-256 is not a password
  hardening KDF, so low-entropy passwords are unsafe.
- `accept_terms = true` is required before any live ACME request.

## Endpoints and resource limits

Schema 1/2 `[listener]` and `[limits]` remain valid (TCP/UDP 443 by default).
`[[listeners]]` (up to 16) replaces `[listener]` entirely; never configure
both. Each endpoint has a unique ASCII `name` and its own `tcp`, `udp`, `h1`,
`h2`, `h3` switches. Disabling a protocol skips binding its transport. HTTP/1.1
serves the website only. IPv6 sockets are v6-only (`"[::]:443"`); add a
separately named endpoint per address family. Duplicate or overlapping binds
fail startup, and all sockets bind before any is used.

| Setting | Meaning |
| --- | --- |
| top-level `[limits]` | Process-wide ceilings: connections, H2/H3 streams, pending requests, tunnels per user, byte budgets |
| `[listeners.limits]` | Endpoint budgets and connect/idle/graceful timeouts; still bounded by the global limits |
| `listeners.handshake_timeout_secs` | Inbound handshake deadline (default 10 s) |
| `[listeners.flow]` | `h2_stream_window`, `h2_connection_window`, `h3_stream_window`, `h3_connection_window` in bytes |
| `listeners.public_addresses` | Public/NAT addresses of this endpoint; all of them join the mandatory self-connection deny set |
| `listeners.bandwidth_bytes_per_sec` | Optional per-endpoint byte rate (one bucket per direction, 16 KiB burst; 1024..10^12). Not a flow-control window |

An omitted endpoint `limits` table inherits the top-level values. A present
table uses the standard defaults for unspecified fields (no per-field merge).
Window defaults derive from the endpoint limits. The H2 connection window is at
least 65535. For H3, `stream window × max streams + control reserve` must fit
the connection window. Larger windows reserve receive credit that cannot be
returned early; they are not a speed switch. HTTP/1.1 has no multiplexing:
each connection carries one website request at a time, bounded by
`max_connections`.

`Alt-Svc` advertises only the endpoint's own enabled UDP/H3 port. The server
cannot verify public firewall, NAT or carrier UDP reachability; open TCP and
UDP for every enabled public port. Changes to listeners, ACL or limits need a
restart; certificates and ECH keys hot-reload.

### QUIC network changes

Active (client-initiated) connection migration is disabled because the server
issues a single connection ID. Passive NAT rebinding keeps that ID and is
validated by quiche (path validation and anti-amplification). Each H3
connection survives at least 7 rebindings (bounded by
`active_connection_id_limit = 8`); after that it idles out and clients
reconnect. See [security.md](security.md#quic-paths-and-connection-ids).

## Website, forward proxy and next hop

- `[website].origin` is the single-site shorthand, such as
  `http://127.0.0.1:8080`: scheme, host and port only. HTTPS origins use
  correct SNI and chain verification. Redirects and cookies are not rewritten.
- Several origins use `[[website.upstreams]]` and `[[website.routes]]`
  (mutually exclusive with `origin`). Routes match the longest `path_prefix`
  and may set the Host header, TLS server name, a private CA, and H1 or H2
  upstreams. Configured origins may be private addresses; visitors can never
  choose an origin.
- Websites keep WebSocket, streaming responses, trailers, Range, SSE/gRPC and
  `no-transform` semantics. HTTP/1.1 framing, Host and Connection fields are
  checked strictly, and forged forwarding and proxy metadata is removed.
- Website defaults: 64 MiB upload, connect 5 s, read/write 30 s, upstream idle
  and DNS TTL 60 s. These are data and connection deadlines; bodies stream.
- `[proxy.forward]` (authenticated ordinary HTTP(S) forwarding) is
  independent of the website: 1 GiB upload, connect 10 s, read/write 120 s,
  idle pool 30 s, 32 concurrent requests per user. Established CONNECT tunnels
  and non-idempotent requests with uncertain state are never retried
  transparently.
- Egress dials only checked, concrete resolved candidates: ASCII DNS names,
  explicit ports, bracketed IPv6. Private, special-purpose, mapped-private and
  self addresses are denied. Configured website origins use their own trust
  policy.
- `[proxy.upstream]` HTTP/HTTPS/SOCKS5 next hops keep their own authentication
  and TLS checks, never fall back to direct egress, and never receive a
  hostname to re-resolve remotely around local checks.

## Destination ACL

Add `acl_file = "/etc/moon-naive/acl.toml"` to the existing `[proxy]` table.
The file must be a private (0600) regular file readable by the service user,
at an absolute path without `..`. Symbolic-link final components, FIFOs,
non-private modes, oversized files (over 256 KiB, 4096 rules, or 128 port
ranges per rule) and invalid content prevent startup; there is no
fail-open. `check-config` does not read the ACL; `check` does.

[`acl.example.toml`](../acl.example.toml) is a complete example: `default =
"allow" | "deny"` (deny when omitted) and ordered `[[rules]]`, each with
`action` and at most one selector:

| Selector | Matches |
| --- | --- |
| `domain = "example.org"` | That exact ASCII DNS name, case-insensitive |
| `suffix = "example.org"` | The name and subdomains on label boundaries (not `notexample.org`) |
| `ip = "1.1.1.1"` | One IPv4/IPv6 address |
| `cidr = "2606:4700::/32"` | A canonical network (host bits rejected) |
| none | Any destination, optionally limited by ports |

`ports = ["443", "8000-8080"]` is an optional union of closed ranges. Unicode
names, wildcards and trailing dots are rejected (convert IDNs to punycode).
IPv4-mapped IPv6 normalizes to IPv4; mapped CIDR prefixes must be at least
/96.

The first rule matching the original target name, port and the current
concrete IP candidate wins; otherwise `default` applies. Decisions that are
known before DNS run early; rules that depend on IP wait for the resolved
candidates, and every candidate is checked. The ACL applies identically to
CONNECT and ordinary forwarding on all endpoints. Mandatory private, special,
local-interface and self-address denials run before any `allow`; the ACL
cannot create private-network exceptions. A next hop is an administrative
trust boundary: the server can only verify the concrete address it hands over.

## Website routing example

Replace the existing `[website]` table with this block (and drop the `origin`
shorthand). Core tests parse this exact block.

```toml
[website]
compression_level = 5
[[website.upstreams]]
name = "app"
origins = ["http://127.0.0.1:3000"]
http2 = true
[[website.routes]]
path_prefix = "/api/"
upstream = "app"
strip_prefix = true
```

`/api/users?limit=10` becomes `/users?limit=10`; unmatched paths return 404.

## Credentials, EAB and migration

Users, DNS credentials and EAB may be inline or in private TOML files. Never
commit a filled-in configuration. `config migrate OLD NEW` writes a migrated
copy and keeps the original; legacy `fast_open` and `zero_rtt` keys are
rejected and dropped, never honored.

Google Trust Services needs External Account Binding (EAB) **only to register
the ACME account the first time**:

```sh
gcloud services enable publicca.googleapis.com
gcloud publicca external-account-keys create --format=json
moon-naive acme import-eab /private/export.json /private/eab.toml
```

`keyId`/`b64MacKey` map to `key_id`/`b64_mac_key` (keep the base64url text).
Use matching staging/production endpoints and EAB. Once the account is stored
in `state_dir`, the EAB may be removed: restarts and renewals recover the
persisted account. If the journal holds only a key (registration outcome
unknown), recovery looks the account up by key; EAB is then needed only if
the account truly does not exist. CAA must allow the chosen CA. Porkbun needs
API access enabled for the zone; Cloudflare needs a token with TXT edit rights
for the zone.

## ECH

```sh
moon-naive ech init CONFIG    # generate keys
moon-naive ech check CONFIG   # validate keys, public name and outer certificate
moon-naive ech dns CONFIG     # print the ECHConfigList for DNS HTTPS records and clients
```

ECH uses BoringSSL with an outer `public_name`, keys and a separate outer
certificate (the outer certificate's renewal is external). An expired outer
certificate pauses new TLS/QUIC handshakes; existing connections continue.
Validation can never be disabled to restore ECH. Publish a new ECHConfigList
in DNS only after `ech check` passes and the server has reloaded it, and keep
old keys configured until cached DNS records expire (at least the record TTL).
