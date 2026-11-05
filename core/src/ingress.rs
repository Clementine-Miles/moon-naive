//! One dispatch boundary for both adapters. No resolver, dialer or certificate IO.
//! Adapters validate HTTP syntax/pseudo-header cardinality and apply header limits
//! before constructing this view. Header names below are ordinary fields only.
use crate::{
    auth::{Binding, Context, Credentials},
    policy::Authority,
};

pub struct RequestHead<'a> {
    pub binding: Option<&'a Binding>,
    pub method: &'a str,
    pub authority: &'a str,
    pub scheme: Option<&'a str>,
    pub path: Option<&'a str>,
    pub protocol: Option<&'a str>,
    pub headers: &'a [(&'a str, &'a [u8])],
}

/// Only this variant reaches the egress service. There is no connection-level
/// authenticated flag: dispatch must run again for every H2/H3 stream.
pub enum Dispatch<'a> {
    Site(SiteRequest<'a>),
    Tunnel(TunnelRequest),
}

/// A local site receives the original method/target, with proxy metadata removed.
/// It must never interpret CONNECT authority as a reverse-proxy backend address.
pub struct SiteRequest<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub scheme: Option<&'a str>,
    pub path: Option<&'a str>,
    pub headers: Vec<(&'a str, &'a [u8])>,
}

pub struct TunnelRequest {
    target: Authority,
    principal: usize,
    offer: crate::codec::Offer,
}

impl TunnelRequest {
    pub fn offer(&self) -> crate::codec::Offer {
        self.offer
    }
    pub fn principal(&self) -> usize {
        self.principal
    }
    pub fn target(&self) -> &Authority {
        &self.target
    }
}

/// Proxy credentials and Naïve negotiation never reach a website or origin.
pub const PROXY_HEADERS: &[&str] = &[
    // CGI maps this to HTTP_PROXY (httpoxy). It is not a website identity.
    "proxy",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-connection",
    "padding",
    "fastopen",
    "padding-type-request",
    "padding-type-reply",
];
pub fn is_proxy_header(name: &str) -> bool {
    PROXY_HEADERS
        .iter()
        .any(|field| normalized_header_eq(name, field))
}
/// Match names as a CGI-style environment would. Use only when stripping
/// untrusted metadata, never to accept aliases as authentication credentials.
pub fn normalized_header_eq(name: &str, field: &str) -> bool {
    name.len() == field.len()
        && name
            .bytes()
            .zip(field.bytes())
            .all(|(a, b)| a.to_ascii_lowercase() == b || (a == b'_' && b == b'-'))
}

impl RequestHead<'_> {
    pub fn principal(&self, credentials: &Credentials) -> Option<usize> {
        self.authenticate(credentials).map(|(user, _)| user)
    }
    fn authenticate(&self, credentials: &Credentials) -> Option<(usize, crate::codec::Offer)> {
        let binding = self.binding?;
        let mut headers = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("proxy-authorization"));
        let (_, value) = headers.next()?;
        if headers.next().is_some() {
            return None;
        }
        // Authentication accepts exactly one UTF-8 field. Scan lazily without
        // allocating a Vec, and stop immediately at the second occurrence.
        let value = std::str::from_utf8(value).ok()?;
        credentials.authenticate(
            &[value],
            &Context {
                binding,
                method: self.method,
                authority: self.authority,
                scheme: self.scheme,
                path: self.path,
                protocol: self.protocol,
            },
        )
    }
}
pub fn dispatch<'a>(
    head: RequestHead<'a>,
    credentials: &Credentials,
) -> Result<Dispatch<'a>, &'static str> {
    if head.method == "CONNECT"
        && let Some((principal, offer)) = head.authenticate(credentials)
    {
        if head.scheme.is_some() || head.path.is_some() || head.protocol.is_some() {
            return Err("ordinary CONNECT must omit scheme, path and protocol");
        }
        return Ok(Dispatch::Tunnel(TunnelRequest {
            target: Authority::parse(head.authority)?,
            principal,
            offer,
        }));
    }
    Ok(Dispatch::Site(SiteRequest {
        method: head.method,
        authority: head.authority,
        scheme: head.scheme,
        path: head.path,
        headers: head
            .headers
            .iter()
            .copied()
            .filter(|(n, _)| !is_proxy_header(n))
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    static BINDING: Binding = Binding {
        exporter: [7; 32],
        stream_id: 1,
    };

    fn credentials() -> Credentials {
        Credentials::new(&[("user", "a-long-test-secret-123")]).unwrap()
    }
    fn head<'a>(headers: &'a [(&'a str, &'a [u8])]) -> RequestHead<'a> {
        RequestHead {
            binding: Some(&BINDING),
            method: "CONNECT",
            authority: "example.org:443",
            scheme: None,
            path: None,
            protocol: None,
            headers,
        }
    }
    fn authorization() -> String {
        credentials()
            .authorization(
                0,
                &Context {
                    binding: &BINDING,
                    method: "CONNECT",
                    authority: "example.org:443",
                    scheme: None,
                    path: None,
                    protocol: None,
                },
            )
            .unwrap()
    }

    #[test]
    fn cgi_metadata_aliases_are_stripped_but_never_authenticate() {
        let auth = authorization();
        for alias in [
            "Proxy",
            "Proxy_Authorization",
            "proxy-authorization",
            "Padding_Type_Request",
            "FastOpen",
        ] {
            assert!(is_proxy_header(alias));
        }
        let headers = [
            ("Proxy_Authorization", auth.as_bytes()),
            ("Proxy", b"http://attacker".as_slice()),
            ("FastOpen", b"1".as_slice()),
            ("X_App_Value", b"keep".as_slice()),
        ];
        let Dispatch::Site(site) = dispatch(head(&headers), &credentials()).unwrap() else {
            panic!()
        };
        assert_eq!(site.headers, [("X_App_Value", b"keep".as_slice())]);
    }

    #[test]
    fn all_failed_authentication_uses_the_same_sanitized_site_request() {
        let auth = authorization();
        for headers in [
            vec![],
            vec![("Proxy-Authorization", b"Basic invalid".as_slice())],
            vec![("proxy-authorization", b"\xff".as_slice())],
            vec![
                ("proxy-authorization", auth.as_bytes()),
                ("padding", b"ignored separator".as_slice()),
                ("Proxy-Authorization", auth.as_bytes()),
            ],
            vec![
                ("proxy-authorization", b"\xff".as_slice()),
                ("Proxy-Authorization", auth.as_bytes()),
            ],
        ] {
            let mut headers = headers;
            headers.extend([
                ("Padding", b"secret".as_slice()),
                ("padding-type-request", b"1, 0".as_slice()),
                ("Accept", b"text/html".as_slice()),
            ]);
            let mut request = head(&headers);
            request.authority = "malformed/target";
            request.protocol = Some("unsupported");
            let Dispatch::Site(site) = dispatch(request, &credentials()).unwrap() else {
                panic!()
            };
            assert_eq!(site.headers, [("Accept", b"text/html".as_slice())]);
            assert_eq!(site.method, "CONNECT");
            assert_eq!(site.authority, "malformed/target");
        }
    }

    #[test]
    fn preamble_and_next_stream_do_not_inherit_tunnel_authentication() {
        let auth = authorization();
        let headers = [
            ("proxy-authorization", auth.as_bytes()),
            ("padding", b"~".as_slice()),
        ];
        let credentials = credentials();
        let Dispatch::Tunnel(tunnel) = dispatch(head(&headers), &credentials).unwrap() else {
            panic!()
        };
        assert_eq!(tunnel.target().host, "example.org");
        assert!(matches!(
            dispatch(head(&[]), &credentials).unwrap(),
            Dispatch::Site(_)
        ));
        let mut get = head(&headers);
        get.method = "GET";
        get.path = Some("/");
        get.scheme = Some("https");
        let Dispatch::Site(site) = dispatch(get, &credentials).unwrap() else {
            panic!()
        };
        assert!(site.headers.is_empty());
        assert_eq!(site.path, Some("/"));
    }

    #[test]
    fn legacy_padding_headers_cannot_downgrade_framing() {
        let auth = authorization();
        let headers = [
            ("proxy-authorization", auth.as_bytes()),
            ("padding-type-request", b"1, 0".as_slice()),
            ("padding", b"".as_slice()),
            ("Padding", b"second".as_slice()),
        ];
        let Dispatch::Tunnel(tunnel) = dispatch(head(&headers), &credentials()).unwrap() else {
            panic!()
        };
        assert_eq!(tunnel.target().host, "example.org");
        for field in 0..3 {
            let mut request = head(&headers);
            match field {
                0 => request.scheme = Some("https"),
                1 => request.path = Some("/"),
                _ => request.protocol = Some("connect-udp"),
            }
            assert!(matches!(
                dispatch(request, &credentials()).unwrap(),
                Dispatch::Site(_)
            ));
        }
    }

    #[test]
    fn opaque_site_values_preserved_and_non_ascii_credentials_fail_closed() {
        let headers = [
            ("proxy-authorization", b"Basic \xff".as_slice()),
            ("x-opaque", b"\x80\xff".as_slice()),
        ];
        let Dispatch::Site(site) = dispatch(head(&headers), &credentials()).unwrap() else {
            panic!()
        };
        assert_eq!(site.headers, [("x-opaque", b"\x80\xff".as_slice())]);
    }
}
