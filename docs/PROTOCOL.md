# moon-naive (mona), wire revision 4

This document is authoritative for the server protocol. The executable, service
and config directory remain `moon-naive`. `mona` is a short human-readable name,
not a new authentication scheme, ALPN, exporter label or cryptographic domain.
Revision 4 is identified by the exact exporter and proof domains below. There is
no legacy negotiation, Basic fallback or upstream NaiveProxy compatibility.
Older experimental wire revisions are unsupported. Production client development
is deferred; repository loopback clients are test infrastructure.

## Transport, requests and routing

Authenticated proxy requests require a completed TLS 1.3 handshake and standard
`h2` or `h3` ALPN. Never use early exporters or 0-RTT. Website traffic also accepts
HTTP/1.1 (including no-ALPN fallback) and TLS 1.2 H2. TLS-terminating intermediaries
break channel-bound proofs unless they are themselves the authenticating client;
caller-supplied exporter or stream-ID fields have no authority.

Ordinary CONNECT has exactly one `:method=CONNECT` and `:authority=host:port`,
and no `:scheme`, `:path`, or `:protocol`. IPv6 uses `[address]:port`. H2 client
request IDs are odd, starting at 1; H3 client bidirectional request IDs are
0,4,8,... . **Stream 0 is valid**. Obtain the ID from the actual transport stream,
not a count of CONNECTs. Duplicate, out-of-order or unknown pseudo-fields fail.
An ordinary forward request has a method, HTTP(S) scheme, authority, and absolute
path with query (`*` is allowed for OPTIONS); its HTTP body is unframed.
An optional Host must agree with authority. Hop-by-hop fields are forbidden on
H2/H3; TE is permitted only with value `trailers`.

Website names route to configured fixed origins. Other ordinary HTTP(S) targets
require authentication on each stream. CONNECT never authenticates a connection
for subsequent streams. Authentication failures (missing, duplicate, malformed,
incorrect or replayed proof) follow the same ordinary website routing, with all
proxy metadata removed, no 407 or proxy-specific banner and no target DNS/dial.
Malformed HTTP syntax can fail earlier. Unknown website hosts need not return
the same status as the configured site. Website extended CONNECT supports only
`websocket`, https scheme and a configured path/host. It is not an authenticated
arbitrary tunnel. CONNECT-UDP, MASQUE and WebTransport are unsupported.

## Authentication, octet-exact construction

Each proxy request has exactly one `proxy-authorization` field:

```
moon-naive hh.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
```

The value is exactly 58 ASCII bytes. The scheme is ASCII case-insensitive; one
space follows it. `hh` is exactly two **lowercase** hexadecimal capability digits,
then `.`, then canonical standard RFC 4648 Base64 encoding of 32 MAC bytes (44
characters, including `=`). No whitespace, comma lists, URL-safe alphabet,
trailing bytes or noncanonical Base64 trailing bits. Header-name matching follows
HTTP case-insensitivity; underscore aliases never authenticate. CGI-style alias
matching is used only to strip metadata from requests and trailers.

All integer encodings below are unsigned big-endian. `||` means concatenation.
Strings are their exact UTF-8 bytes as present in the validated request: do not
normalize case, percent escapes, port spelling or authority before signing.

```
exporter = TLS-Exporter("EXPORTER-moon-naive-v4", context="", length=32)
key = SHA256("moon-naive/v4/key\0" || user || ":" || password)
field(s) = u64be(byte_length(s)) || s       # present, including empty
field(absent) = ff ff ff ff ff ff ff ff
fields = field(method) || field(authority) || field(scheme)
         || field(path-and-query) || field(protocol)
request = "moon-naive/v4/request\0" || exporter || u64be(stream_id)
          || u8(offer) || 00 || fields
proof = HMAC-SHA256(key, SHA256(request))
```

`\0` denotes one zero byte, not a literal backslash. Obtain exporter bytes from
BoringSSL on the accepted connection, with an explicitly present empty context,
after handshake completion. H2 takes the ID from Pingora's session; H3 takes it
from quiche's event. Usernames are nonempty, contain no colon/control characters;
passwords contain no controls and have at least 16 bytes; combined length at most
2048. Use high-entropy independent secrets: SHA256 is not a password-hardening
KDF. All configured keys are checked with constant-time proof comparisons.
Proofs are not bearer credentials but must still be never-indexed in HPACK/QPACK.

## Negotiation and confirmation

Offer bits: `01` initial 8 records, `02` initial 16 records, `04` sparse tail.
At least one initial bit is mandatory. Unknown bits fail authentication. A
selection contains exactly one initial bit and optionally sparse: 01,02,05,06.
It must be a subset of the offer. Server preference selects 8 or 16 when offered;
sparse is selected only when offered and enabled. No separate unauthenticated
padding header can override the offer. Both directions use the selection with
independent counters and credit.

A successful tunnel sends 200 only after policy/admission and target connection
succeed. It has no normal HTTP response body framing or Content-Length and has
exactly one `proxy-authentication-info`, in the same syntax, with selected bits:

```
response = "moon-naive/v4/response/200\0" || exporter || u64be(stream_id)
           || u8(original_offer) || u8(selection) || fields
confirmation = HMAC-SHA256(key, SHA256(response))
```

The client must verify status 200, unique confirmation, accepted selection and
MAC before treating the tunnel as established or sending target payload. Changing
offer or selection invalidates confirmation; request proofs cannot be reflected
as confirmations. Ordinary HTTP forwarding uses request authentication only;
its response is the origin's ordinary HTTP response, with no tunnel codec.

## Record codec

```
u16be payload_length | u8 padding_length | payload | padding
```

Payload length is 1..16309; header is 3 bytes; padding at most 63; total maximum
16375. Empty/control/cover records are invalid. **Padding octets are ignored and
may have any value in revision 4.** This preserves existing decoder semantics and
nonzero historical vectors. The server encoder emits zeroes; older prose saying
all received padding must be zero was inaccurate, not a different wire revision.
The record counter starts at zero in each direction and increments only after
all payload and padding of a record have been consumed.

For initial count K=8 or 16 and completed count i<K:
`P <= min(floor(N/8), 63 - i*(64/K))`.
For finite modes, immediately after record K (including its padding), all remaining
bytes are raw, even within the same DATA fragment. No terminator is sent.
For sparse modes, retain record headers forever. Maintain credit C in payload-byte
units, initially 0, capped at 16384. Each record earns N, saturating at 16384.
Initial padding does not spend credit. After K records,
`P <= min(31, floor(N/32), floor(min(C+N,16384)/128))` for N<8192;
otherwise P=0. Subtract 128*P after crediting the record. Counter saturates at K.
Header overhead does not spend credit. The server randomly samples permitted
initial padding on small chunks, and attempts sparse padding on 1/16 small reads;
this sampling policy is not a peer interoperability requirement.

Records may be fragmented/coalesced at any byte boundary. Partial reads retain
header/payload/padding state. Partial writes retain unsent bytes and apply flow
control. Clean EOF is valid between complete records, including before K, or at
any point in raw mode. EOF inside a record is truncation and resets the stream;
a decoder failure is terminal. Application bytes already streamed before detecting
terminal truncation cannot be retracted. No whole-tunnel buffering is required.

## Lifecycle, early data and errors

Early application data is bounded by transport credit and configured application
buffers. Accepted streams may queue bytes while admission/dialing is pending;
no target payload is written before successful admission. Pending EOF is retained.
Normal EOF closes only that direction, flushes queued data and sends FIN/write
shutdown; the other direction may continue. Reset, abnormal error, deadline or
shutdown cancellation drops queues/tasks/sockets and owned permits. Resolver jobs
that continue in blocking threads retain their own permits until actually done.
Advertised receive-credit reservations belong to connections, not completed
requests; application buffer accounting is independent.

The duplex idle deadline is refreshed by actual nonempty application progress in
either direction. Empty DATA, padding-only consumption and QUIC keepalives do not
count. Established tunnel bytes are never transparently retried. Websites support
streaming, informational responses and sanitized trailers; tunnel trailers are
unsupported. Framing, routing, credential and hop-by-hop metadata must not cross
trailer boundaries. WebSocket handshakes preserve read-ahead bytes.

Authenticated target errors: invalid request/authority 400; denied/self address
403; DNS failure/no usable answer or failed connect 502; overall dial timeout 504;
admission exhaustion 503 (transport rejection may instead use H3 REQUEST_REJECTED
0x10b). H3 malformed request fields use MESSAGE_ERROR 0x10e; cancellation uses
REQUEST_CANCELLED 0x10c. Protocol-level malformed framing can reset a stream or
close the connection before an HTTP response is possible. No success confirmation
is sent on a failed CONNECT. Policy evaluates concrete resolved candidates and
dials only approved addresses; configured next-hop failure never falls back direct.

## Executable contract

`python3 tools/vectors/generate.py --check` independently reconstructs checked-in
TSV authentication and framing vectors using Python hashlib/hmac, without loading
Rust code. `cargo test -p moon-naive-core --locked` checks those fixed expectations,
all fragmentation sizes, coalescing, finite/raw and sparse transitions, nonzero
padding, malformed sizes, truncation, context binding and response domains.
The loopback server suite additionally exercises actual TLS exporters and IDs.
This specification is not evidence that every runtime acceptance case has passed;
see [implementation record](IMPLEMENTATION.md) for current results and gaps.

### Experimental finite-sixteen client profile

The imported C++ test/experimental client offers only `0x02`. Every supported
server preference (`initial_records` 8 or 16, sparse enabled or disabled) selects
`0x02` for this offer: preferences cannot select an unoffered capability. Thus
its fixed confirmation/codec profile is consistent; no global server restriction
or wire change is necessary. This is covered by the core negotiation regression,
not a claim of production client readiness.
