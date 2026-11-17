use moon_naive_core::config::Config;

#[test]
fn shipped_acl_example_parses_without_io() {
    moon_naive_core::acl::Policy::parse(include_str!("../../acl.example.toml")).unwrap();
}

#[test]
fn shipped_single_and_dual_port_examples_validate() {
    let single = Config::parse(include_str!("../../config.example.toml")).unwrap();
    assert_eq!(single.effective_listeners().len(), 1);
    let dual = Config::parse(include_str!("../../config.dual.example.toml")).unwrap();
    let listeners = dual.effective_listeners();
    assert_eq!(listeners.len(), 2);
    assert_eq!(dual.limits.max_connections, 128);
    assert_eq!(listeners[0].name, "main");
    assert_eq!(listeners[1].name, "secondary");
    assert_ne!(
        listeners[0].flow.h2_stream_window,
        listeners[1].flow.h2_stream_window
    );
    assert_ne!(
        listeners[0].flow.h3_connection_window,
        listeners[1].flow.h3_connection_window
    );
}
