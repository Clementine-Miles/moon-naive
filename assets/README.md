# ACME staging certificate roots

`le-staging-roots.crt` contains public CA certificates, not private keys.
Retrieved over verified HTTPS on 2026-10-21:

| Source | SHA-256 certificate fingerprint |
| --- | --- |
| https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem | E70570A989F8565AABDF7CAE27ABD1621872D6A3F811E3FEF27E3DBA02912198 |
| https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem | 9B2A339FE6A3E85585C4CD75536CB8C1CF7CD603B9A64BEC2521858AE48DA85D |

These additional roots are used **only** to validate issued certificates when
the configured directory is the built-in Let's Encrypt staging directory.
They are not added to the CA API HTTPS client, the Cloudflare API client, or the
production certificate validator. Staging certificates are not browser trusted.

`gts-test-roots.crt` contains the two public Google test roots, retrieved over
verified HTTPS from https://pki.goog/test_roots.pem on 2026-10-21.
Bundle SHA-256: `70548cf799245900c44e46a19513f59eb67badc9a5170ce9c9f04ffe1c7238b1`.

| Subject CN | SHA-256 certificate fingerprint |
| --- | --- |
| Test GTS Root ECC | 036649D176EF17B766CF4F44F4A9B6B86C95513E748355EFF1193332194D87BF |
| Test GTS Root | 77321BF854FD9C18C04C7EEACF4F5BDB2B946620BFC57BD70518BDECA05C90C7 |

Google test roots apply only to the built-in Google staging directory with
`issuer = "google"`. They are not added to production, custom directories,
the CA API HTTPS client or any DNS-provider HTTPS client. A unit test checks
issuer/environment/directory isolation. These are not production trust roots.
