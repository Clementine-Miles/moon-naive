Source: https://github.com/djc/instant-acme at UPSTREAM_REVISION.

Local additive API: AccountBuilder::create_with_key accepts NewAccount, a durable PKCS#8 key and optional ExternalAccountKey, delegating to upstream create_inner. This preserves crash recovery with single-use EAB without a second JWS/nonce implementation. No protocol or cryptographic implementation changed.
