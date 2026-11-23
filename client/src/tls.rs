//! One TLS policy for both transports: TLS 1.3 only, verified certificates,
//! hostname checks, and mandatory ECH whenever an ECHConfigList is configured.
use crate::config::Settings;
use boring::ssl::{SslContextBuilder, SslMethod, SslRef, SslVersion};

pub fn configure(
    settings: &Settings,
    builder: &mut SslContextBuilder,
    alpn: &[u8],
) -> Result<(), String> {
    // mona authentication requires a TLS 1.3 exporter; never negotiate lower.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| format!("TLS setup: {e}"))?;
    match &settings.ca_file {
        Some(path) => builder
            .set_ca_file(path)
            .map_err(|_| format!("cannot load ca_file {}", path.display()))?,
        None => builder
            .set_default_verify_paths()
            .map_err(|e| format!("cannot load system trust store: {e}"))?,
    }
    builder.set_verify(boring::ssl::SslVerifyMode::PEER);
    builder
        .set_alpn_protos(alpn)
        .map_err(|e| format!("TLS setup: {e}"))
}
/// Context for quiche, which performs SNI and hostname verification itself.
pub fn quic_context(settings: &Settings) -> Result<SslContextBuilder, String> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|e| format!("TLS setup: {e}"))?;
    configure(settings, &mut builder, b"\x02h3")?;
    Ok(builder)
}

/// Install the configured ECHConfigList on a connection before its handshake.
pub fn apply_ech(settings: &Settings, ssl: &mut SslRef) -> Result<(), String> {
    if let Some(list) = &settings.ech_config_list {
        ssl.set_ech_config_list(list)
            .map_err(|_| "ECHConfigList rejected by BoringSSL".to_string())?;
    }
    Ok(())
}

/// After a completed handshake: enforce ECH policy and derive the exporter.
/// Certificate verification already succeeded independently of ECH.
pub fn exporter(settings: &Settings, ssl: &SslRef) -> Result<[u8; 32], String> {
    if settings.ech_config_list.is_some() && !ssl.ech_accepted() {
        return Err("server did not accept ECH; refusing to continue without it".into());
    }
    if ssl.version2() != Some(SslVersion::TLS1_3) {
        return Err("server did not negotiate TLS 1.3".into());
    }
    let mut output = [0; 32];
    ssl.export_keying_material(
        &mut output,
        moon_naive_core::auth::EXPORTER_LABEL,
        Some(b""),
    )
    .map_err(|e| format!("TLS exporter: {e}"))?;
    Ok(output)
}
