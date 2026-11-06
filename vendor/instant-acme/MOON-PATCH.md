Source: https://github.com/djc/instant-acme at UPSTREAM_REVISION.

- AccountBuilder::create_with_key is retained: durable PKCS#8 account registration and optional EAB delegate to upstream create_inner. No second nonce/JWS/EAB implementation.
- Error::Response identifies the actual method, URL and HTTP status at order POST-as-GET and ARI response boundaries, preserving the underlying Problem/decoding error. Nonce acquisition failures are never mistaken for an order response. Client::post badNonce retry/re-signing is unchanged.
- parse_retry_after / RetryAfter distinguish absent, malformed, absolute and unrepresentable inputs. Time arithmetic is checked. The same parser is used by the BoringSSL HTTP adapter; overflow is never saturated into a durable timestamp.
- new-order, finalize, recovery, refresh and Processing-certificate responses capture Retry-After without losing a known order on a malformed/unrepresentable header. Order::retry_after exposes the hint so an application can persist it before every wait. The first poll retains that wait; cached Valid orders download without redundant refresh. Poll/retry deadline and exponential-backoff arithmetic are checked. The deadline is tested before sleeping, and a final permitted attempt is not discarded because its following backoff would be too long. ARI recheck bounds remain application policy, not a library/order cap.

Pinned features and cryptographic interfaces remain unchanged. This adds an Error enum variant / parsing API and changes polling timing; exhaustive downstream Error matches must be updated.

## Runtime-only source distribution

The pinned library and its explicit production feature selection are retained.
Tests (including inline unit tests), benchmarks, examples, fixtures, test CI and
development dependencies have been removed from this checkout at the repository
owner's request; Cargo test/doctest/bench harnesses are disabled. This is a trimmed
source distribution, not the complete upstream tree. Historical regression
coverage is available in moon-naive commit bcf418ea1f99900da64ed2abbee292d2484dbbc7;
it is not evidence of execution against this trimmed checkout.
