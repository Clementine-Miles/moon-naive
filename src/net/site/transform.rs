//! Shared byte-preserving routing and trusted metadata for fixed websites.
use pingora_http::RequestHeader;

pub(super) fn target(uri: &http::Uri, prefix: &str, strip: bool) -> String {
    let mut target = if strip {
        let suffix = &uri.path()[prefix.len()..];
        if prefix.ends_with('/') || !suffix.starts_with('/') {
            format!("/{suffix}")
        } else {
            suffix.to_owned()
        }
    } else {
        uri.path().to_owned()
    };
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

pub(super) fn metadata(
    request: &mut RequestHeader,
    authority: &str,
    ip: Option<std::net::IpAddr>,
) -> pingora_core::Result<()> {
    let remove = request
        .headers
        .keys()
        .filter(|n| {
            super::is_forwarded_header(n.as_str()) || super::normalized_header_eq(n.as_str(), "via")
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in remove {
        request.remove_header(&name);
    }
    request.insert_header("x-forwarded-host", authority)?;
    request.insert_header("x-forwarded-proto", "https")?;
    if let Some(ip) = ip {
        request.insert_header("x-forwarded-for", ip.to_string())?;
    }
    Ok(())
}

pub(super) fn protocols(head: &super::Head) -> Result<Vec<String>, u16> {
    let mut tokens = Vec::new();
    for (_, value) in head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-protocol"))
    {
        for token in std::str::from_utf8(value).map_err(|_| 400u16)?.split(',') {
            let token = token.trim_matches([' ', '\t']);
            if !valid_token(token) || tokens.iter().any(|t| t == token) {
                return Err(400);
            }
            tokens.push(token.to_owned());
        }
    }
    Ok(tokens)
}
pub(super) fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routing_preserves_slashes_escapes_and_query() {
        for (path, prefix, want) in [
            ("/ws//x%2Fy?q=%2f", "/ws", "//x%2Fy?q=%2f"),
            ("/ws//x", "/ws/", "//x"),
            ("/ws", "/ws", "/"),
        ] {
            assert_eq!(target(&path.parse().unwrap(), prefix, true), want);
        }
        assert!(valid_token("chat.v2"));
        for bad in ["", "a b", "a/b", "a,b", "é"] {
            assert!(!valid_token(bad));
        }
    }
}
