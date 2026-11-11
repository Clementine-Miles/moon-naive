Source: https://github.com/djc/instant-acme at UPSTREAM_REVISION.

- AccountBuilder::create_with_key is retained: durable PKCS#8 account registration and optional EAB delegate to upstream create_inner. No second nonce/JWS/EAB implementation.
- Error::Response identifies the actual method, URL and HTTP status at order POST-as-GET and ARI response boundaries, preserving the underlying Problem/decoding error. Nonce acquisition failures are never mistaken for an order response. Client::post badNonce retry/re-signing is unchanged.
- parse_retry_after / RetryAfter distinguish absent, malformed, absolute and unrepresentable inputs. Time arithmetic is checked. The same parser is used by the BoringSSL HTTP adapter; overflow is never saturated into a durable timestamp.
- new-order, finalize, recovery, refresh and Processing-certificate responses capture Retry-After without losing a known order on a malformed/unrepresentable header. Order::retry_after exposes the hint so an application can persist it before every wait. The first poll retains that wait; cached Valid orders download without redundant refresh. Poll/retry deadline and exponential-backoff arithmetic are checked. The deadline is tested before sleeping, and a final permitted attempt is not discarded because its following backoff would be too long. ARI recheck bounds remain application policy, not a library/order cap.

Pinned features and cryptographic interfaces remain unchanged. This adds an Error enum variant / parsing API and changes polling timing; exhaustive downstream Error matches must be updated.

## Regression validation

This remains a trimmed upstream source distribution. The two local RetryState
regressions now run with `CARGO_TARGET_DIR=/tmp/mona-acme-target cargo test --manifest-path vendor/instant-acme/Cargo.toml
--locked --no-default-features --features time,x509-parser --lib`. The test-only
Tokio runtime feature changes no production TLS or signing backend. Application
ACME fixtures cover endpoint attribution, restore/finalize waits and persistence.
