use moon_naive_core::config::{Config, TransportProfile};

const SAMPLE: &str = include_str!("../../config.example.toml");

fn parse(extra: &str) -> Result<Config, &'static str> {
    Config::parse(&format!("{SAMPLE}\n{extra}"))
}

#[test]
fn legacy_defaults_and_protocol_subsets_remain_explicit() {
    let legacy = parse("").unwrap();
    let endpoints = legacy.effective_listeners();
    assert_eq!(endpoints[0].listener.tcp.port(), 443);
    assert_eq!(endpoints[0].listener.udp.port(), 443);
    for flags in [
        "h1=true\nh2=false\nh3=false",
        "h1=false\nh2=true\nh3=false",
        "h1=false\nh2=false\nh3=true",
    ] {
        assert!(parse(&format!("[[listeners]]\nname='only'\n{flags}")).is_ok());
    }
    assert!(parse("[[listeners]]\nname='none'\nh1=false\nh2=false\nh3=false").is_err());
}

#[test]
fn names_and_socket_overlap_fail_before_binding() {
    for name in ["", "has space", "../unsafe", "端口", &"x".repeat(65)] {
        assert!(parse(&format!("[[listeners]]\nname='{name}'")).is_err());
    }
    for second in [
        "name='first'\ntcp='127.0.0.1:8443'\nudp='127.0.0.1:8443'",
        "name='second'\ntcp='0.0.0.0:443'\nudp='127.0.0.1:8443'",
        "name='second'\ntcp='127.0.0.1:8443'\nudp='127.0.0.1:443'",
    ] {
        assert!(
            parse(&format!(
                "[[listeners]]\nname='first'\n[[listeners]]\n{second}"
            ))
            .is_err()
        );
    }
    // Production creates v6-only sockets, so these distinct families coexist.
    assert!(
        parse("[[listeners]]\nname='v4'\n[[listeners]]\nname='v6'\ntcp='[::]:443'\nudp='[::]:443'")
            .is_ok()
    );
    let many: String = (0..17)
        .map(|n| {
            format!(
                "[[listeners]]\nname='port{n}'\ntcp='127.0.0.1:{}'\nudp='127.0.0.1:{}'\n",
                10000 + n,
                10000 + n
            )
        })
        .collect();
    assert!(parse(&many).is_err());
}

#[test]
fn per_endpoint_limits_inherit_only_when_the_table_is_absent() {
    let config = parse("[limits]\nmax_connections=10\n[[listeners]]\nname='inherited'\n[[listeners]]\nname='explicit'\ntcp='127.0.0.1:8443'\nudp='127.0.0.1:8443'\n[listeners.limits]\nmax_streams=2").unwrap();
    let endpoints = config.effective_listeners();
    assert_eq!(endpoints[0].limits.as_ref().unwrap().max_connections, 10);
    assert_eq!(endpoints[1].limits.as_ref().unwrap().max_connections, 128);
    assert_eq!(endpoints[1].limits.as_ref().unwrap().max_streams, 2);
    assert_eq!(config.limits.max_connections, 10);
}

#[test]
fn windows_and_rate_limits_have_independent_validation() {
    let valid = "[[listeners]]\nname='main'\nbandwidth_bytes_per_sec=1024\n[listeners.flow]\nh2_stream_window=32768\nh2_connection_window=65535\nh3_stream_window=1024\nh3_connection_window=262144";
    let config = parse(valid).unwrap();
    let endpoint = config.effective_listeners().remove(0);
    let profile = TransportProfile::for_endpoint(&config, &endpoint).unwrap();
    assert_eq!(profile.stream_window(), 32768);
    assert_eq!(profile.connection_window(), 65535);
    assert_eq!(profile.h3_stream_window(), 1024);
    assert_eq!(profile.h3_connection_window(), 262144);
    for invalid in [
        "bandwidth_bytes_per_sec=0",
        "bandwidth_bytes_per_sec=1023",
        "handshake_timeout_secs=0",
        "handshake_timeout_secs=301",
        "[listeners.flow]\nh2_connection_window=65534",
        "[listeners.flow]\nh2_stream_window=0",
        "[listeners.flow]\nh3_stream_window=262144\nh3_connection_window=65535",
        "[listeners.limits]\nmax_total_buffer_bytes=0",
        "[listeners.flow]\nunknown_window=1",
    ] {
        assert!(
            parse(&format!("[[listeners]]\nname='main'\n{invalid}")).is_err(),
            "{invalid}"
        );
    }
}
