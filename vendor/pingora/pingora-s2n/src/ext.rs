// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Extended functionalities for s2n-tls

use s2n_tls::connection::Connection;
use s2n_tls::error::Error;

/// Export keying material from a TLS connection
///
/// Derives keying material for application use in accordance with RFC 5705.
///
/// Note: Currently only available with TLS 1.3 connections.
///
/// See [tls_exporter](https://docs.rs/s2n-tls/latest/s2n_tls/connection/struct.Connection.html#method.tls_exporter).
pub fn ssl_export_keying_material(
    conn: &Connection,
    out: &mut [u8],
    label: &str,
    context: Option<&[u8]>,
) -> Result<(), Error> {
    let context_bytes = context.unwrap_or(&[]);
    conn.tls_exporter(label.as_bytes(), context_bytes, out)
}
