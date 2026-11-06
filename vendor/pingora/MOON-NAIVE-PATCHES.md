# moon-naive Pingora patch set

Baseline: https://github.com/cloudflare/pingora/tree/4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19

Local changes provide HTTP/2 informational responses; request trailers on H1/H2;
H1 chunked response trailers; and extraction of upgraded H1 streams together with
bytes already read after the handshake. The proxy bridges these to H3 in native/.
Trailer fields that change framing, routing or proxy authentication are discarded.
Parsing and serialization are bounded. H2 request bodies forwarded to H1 use
chunked framing to permit trailing HEADERS even when DATA length is known.

The BoringSSL/OpenSSL connector also verifies literal IP authorities against
iPAddress SANs using `set_ip`, rather than feeding them to DNS-name matching.
DNS authorities retain the upstream hostname/alternative-name behavior. Native
forward-proxy regression tests check matching IP identity, mismatching IP identity,
untrusted CA rejection and trust-cache isolation. Only BoringSSL is built here.

An opt-in `HttpServerOptions::h1_header_timeout` bounds the complete HTTP/1
header read, including keepalive idle time. It is independent of body/response
timeouts and does not affect upgraded IO. moon-naive sets it to ten seconds.
Native ingress additionally rejects ambiguous raw H1 framing before origin
selection. H1/H2 trailer sanitizers share a deny list that also removes Proxy
(httpoxy) and CGI underscore aliases of routing/framing/credential metadata.
Wire tests exercise slow header drips, smuggling, trailers and TLS pool isolation.

`SHA256SUMS` covers every vendored file except itself. `xtask audit-native` checks
the baseline, inventory, contents and resolved package paths. Release BUILD-INFO
records the manifest hash. Source archives include fixtures ignored by Git.
Retain upstream licensing. Only the BoringSSL backend is enabled in Cargo's graph;
other backend source in this complete upstream snapshot is not linked.

When changing this patch set, review the diff against UPSTREAM_REVISION, run the
wire-level regression tests, and regenerate SHA256SUMS before release auditing.

Two upstream test-key directory symlinks are materialized as regular files for
portable, complete source archives. These are upstream test fixtures only.


## Rust codec profile (RC4)

moon-naive selects `flate2/rust_backend` (miniz_oxide) instead of zlib-ng.
Brotli and Zstandard response encoders are optional `compression-brotli` /
`compression-zstd` features on pingora-core; upstream defaults enable them,
but moon-naive's existing default-features=false profile does not. Algorithm
recognition and origin Content-Encoding pass-through remain available.

pingora-header-serde's original dictionary/Zstandard implementation is behind
its default `zstd` feature. pingora-cache forwards this with its default
`header-compression` feature. The proxy uses neither default feature set and
never enables the object cache. Serialization without the feature returns an
explicit error, rather than writing a different cache format or panicking.
No public request is decompressed solely because these codecs were removed.

Generic local error responses no longer add `Server: Pingora`. This does not
rewrite an origin's Server header or make malformed traffic indistinguishable
from every other web server. Native H1 malformed-request regressions cover this.

Response compression now skips unavailable local encoders when negotiating an
unencoded body, while preserving origin Content-Encoding passthrough. The
existing Rust SFV parser supplies q weights; zero/invalid qualities do not enable
compression, explicit identity preference is respected. Malformed field contents
are no longer echoed into logs. Native H3 tests cover gzip-only, browser-style
multiple offers, unavailable algorithms and quality exclusions.

## Moon/2 channel binding

The H2 server session exposes the already parsed request stream ID as a read-only
`u64`. The Moon/2 adapter combines this with BoringSSL TLS 1.3 exporter material
for per-request HMAC authentication. No synthetic stream counter, HTTP header
or connection-wide login is accepted as a substitute.

## Candidate TCP/TLS retry before HTTP transmission

`connectors::L4Connect` adds opt-in `connection_attempts` and `attempt_timeout`
(default one attempt, no additional timeout). The connector retries the complete
TCP/TLS establishment only inside the original total connection deadline, before
an HTTP session is handed to the proxy. moon-naive advances validated concrete
candidates while retaining logical SNI, certificate verification and pool grouping.
This does not retry an HTTP request or change `error_while_proxy`/POST policy.
A real TLS regression stalls the first connected address and verifies the second.
The proxy also applies the peer's remaining total connection timeout around pool
acquisition and HTTP-session initialization, before handing any request to it.

Upgrade half-close correction (correctness consolidation): proxy_h1 no longer marks
both directions complete when one upgraded direction reaches EOF, and does not
idle-probe a completed upgraded upload. H1 client/server finish paths half-close
the write stream without resetting the opposite body reader. The proxy-task API
has the same rule. Full completion, errors and resets still terminate the session;
upgraded connections are not reusable. The first-party mixed H1/H2/H3 admission
regression holds the shared tunnel lease until the duplex operation finishes,
including a delayed download after upload EOF. Ordinary framed HTTP behavior is
unchanged. Only the three related Rust files were edited; no vendor reformat.
