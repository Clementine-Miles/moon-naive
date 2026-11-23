//! `moon-naive-client` command-line entry point.
use moon_naive_client::Config;
use std::{process::ExitCode, sync::Arc};

const HELP: &str = "Moon-naive client (mona protocol, Rupin profile)

moon-naive-client run <client.toml>     serve local SOCKS5 and HTTP CONNECT
moon-naive-client check <client.toml>   validate the configuration offline
moon-naive-client --version

The configuration holds the proxy password and must be private (mode 0600).
See docs/client.md.";

fn load(path: &str) -> Result<moon_naive_client::Settings, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{path} contains credentials and must not be group/world accessible (chmod 600)"
            ));
        }
    }
    let mut text = String::new();
    file.take(256 * 1024)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {path}: {e}"))?;
    Config::parse(&text)?.settings()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["--version" | "-V"] => {
            println!(
                "Moon-naive client {} ({} protocol, {} profile; boringssl/quiche)",
                env!("CARGO_PKG_VERSION"),
                moon_naive_core::auth::PROTOCOL,
                moon_naive_core::auth::PROFILE
            );
            Ok(())
        }
        ["--help" | "-h"] | [] => {
            println!("{HELP}");
            Ok(())
        }
        ["check", path] => load(path).map(|s| {
            println!(
                "configuration=valid\nserver={}:{}\nserver_name={}\nlisten={}\ntransport={:?}\nech={}\nnetwork_requests=false",
                s.host, s.port, s.server_name, s.listen, s.transport, s.ech_config_list.is_some()
            );
        }),
        ["run", path] => load(path).and_then(run),
        _ => Err("usage: moon-naive-client --help".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("event=client_error reason={error:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(settings: moon_naive_client::Settings) -> Result<(), String> {
    // A small, fixed runtime: few devices and tunnels per client.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let (Ok(mut term), Ok(mut int)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) else {
                return;
            };
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            let _ = stop.send(true);
        });
        moon_naive_client::run(Arc::new(settings), shutdown).await
    })
}
