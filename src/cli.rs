//! The single supported operator interface for the daemon and ACME maintenance.
use crate::acme::persist::DiskStore;
use crate::{
    Result,
    acme::{self, certificate::Validator, http::Http},
    net::{self, Prepared},
    runtime::{self, Control, Mode},
};
use moon_naive_core::config::Config;
use std::{fs, io::Read, path::Path, sync::Arc, time::Duration};
use tokio::sync::watch;

const HELP: &str = "moon-naive serve <config.toml>\nmoon-naive check <config.toml>\nmoon-naive check-config <config.toml>\nmoon-naive check-transport <config.toml>\nmoon-naive status [config.toml]\nmoon-naive acme <once|run|status|cleanup|check-ca> <config.toml>\nmoon-naive acme import-eab <gcloud-export.json> <eab.toml>\nmoon-naive config init <config.toml>\nmoon-naive config migrate <old.toml> <new.toml>\nmoon-naive ech <init|dns|check> <config.toml>\nmoon-naive --version\n\nserve obtains the first DNS-01 certificate, starts HTTPS websites and H2/H3 proxy, and renews automatically.\ncheck validates local setup without CA/DNS requests or listeners.\nconfig and secret files use TOML; see README.md and docs/CONFIGURATION.md.";

fn config(path: &str) -> Result<Arc<Config>> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err("configuration exceeds 1 MiB".into());
    }
    let config = Config::parse(&text).inspect_err(|reason| {
        eprintln!("event=config_error reason={reason}");
    })?;
    if config.schema_version == 2
        || !config.proxy.users.is_empty()
        || config.acme.dns_credentials.is_some()
        || config.acme.eab.is_some()
    {
        // Reload through the private-file reader; parse exactly the checked bytes.
        let bytes = crate::acme::persist::read_private(Path::new(path), 1024 * 1024)?;
        return Ok(Arc::new(Config::parse(
            std::str::from_utf8(&bytes).map_err(|_| "config must be UTF-8")?,
        )?));
    }
    Ok(Arc::new(config))
}
pub async fn run(args: &[String]) -> Result<()> {
    match args {
        [cmd, action, path] if cmd == "config" && action == "init" => {
            acme::persist::write_private_new(
                Path::new(path),
                include_bytes!("../config.example.toml"),
            )?;
            println!(
                "configuration_created=true\nmode=0600\nnext=edit_then_check\nnetwork_requests=false"
            );
            Ok(())
        }
        [cmd, action, path] if cmd == "ech" => net::tls::ech_command(action, &*config(path)?),
        [cmd, action, old, new] if cmd == "config" && action == "migrate" => migrate(old, new),
        [cmd] if cmd == "--help" || cmd == "-h" => {
            println!("{HELP}");
            Ok(())
        }
        [cmd] if cmd == "--version" || cmd == "-V" => {
            println!(
                "moon-naive {} (boringssl/quiche; {}-linux-{})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::ARCH,
                if cfg!(target_env = "musl") {
                    "musl"
                } else {
                    "gnu"
                }
            );
            Ok(())
        }
        [cmd] if cmd == "status" => {
            println!(
                "version={}\nprotocols=h1-website,h2,h3\ntls=boringssl\nquic=quiche\nautomatic_acme=integrated\nconfiguration=not_loaded\nlisteners=not_checked",
                env!("CARGO_PKG_VERSION")
            );
            println!("{}", net::acceleration_report());
            println!("{}", net::kernel_security_report());
            Ok(())
        }
        [cmd, path] if cmd == "check-config" => {
            let config = config(path)?;
            println!(
                "configuration valid (structure/policy only)\nprotocols={}\nacme_directory={}\nterms_accepted={}\nexternal_secret_files=not read\nlisteners=not opened",
                if config.listener.h1 {
                    "h1-website,h2,h3"
                } else {
                    "h2,h3"
                },
                config.acme.directory(),
                config.acme.accept_terms
            );
            Ok(())
        }
        [cmd, path] if cmd == "check-transport" => {
            let config = config(path)?;
            transport(&config)?;
            println!("transport_check=passed\nlisteners_opened=false");
            Ok(())
        }
        [cmd, path] if cmd == "check" => {
            let config = config(path)?;
            transport(&config)?;
            let _prepared = Prepared::load(config.clone()).await?;
            let (_stop, receive) = watch::channel(false);
            let mut control = Control::start(config, receive, Mode::Check)?;
            control.wait().await?;
            println!(
                "local_setup=valid\ncertificate_ready={}\ninitial_issuance=automatic_if_needed\nca_dns_requests=false\nlisteners_opened=false",
                *control.ready.borrow()
            );
            Ok(())
        }
        [cmd, path] if cmd == "status" => certificate_status(config(path)?.as_ref()),
        [cmd, path] if cmd == "serve" => {
            let config = config(path)?;
            transport(&config)?;
            with_shutdown(move |shutdown| runtime::serve(config, shutdown)).await
        }
        [cmd, rest @ ..] if cmd == "acme" => acme_command(rest).await,
        _ => Err("usage: moon-naive --help".into()),
    }
}
fn transport(config: &Config) -> Result<()> {
    if let Err(error) = net::check_transport(config) {
        eprintln!("event=transport_error reason={error}");
        return Err("transport unavailable".into());
    }
    println!(
        "backend=boring-quiche\nquic_congestion={}\ntcp_congestion={}",
        config.transport.quic_congestion.as_str(),
        config.transport.tcp_congestion.as_str()
    );
    println!("{}", net::acceleration_report());
    println!("{}", net::flow_control_report(config)?);
    println!("{}", net::kernel_security_report());
    Ok(())
}
fn certificate_status(config: &Config) -> Result<()> {
    let observation = config.state_dir.join("certificates/TLS-LOADED");
    if observation.exists() {
        let text = acme::persist::read_private(&observation, 4096)?;
        println!(
            "runtime_observation_may_be_stale=true\n{}",
            std::str::from_utf8(&text)?
        );
    }
    let store = DiskStore::open(&config.state_dir.join("certificates"))?;
    if let Some(stored) = store.read_current()? {
        let ready = Validator::for_config(config)?
            .verify(stored.candidate, acme::now())
            .is_ok();
        println!(
            "certificate_ready={ready}\ngeneration={}\nnot_after={}\nlisteners=not_checked",
            stored.generation, stored.lifetime.not_after
        );
    } else {
        println!("certificate_ready=false\ncertificate=missing\nlisteners=not_checked");
    }
    Ok(())
}
async fn acme_command(args: &[String]) -> Result<()> {
    if let [cmd, input, output] = args
        && cmd == "import-eab"
    {
        acme::account::import_gcloud(Path::new(input), Path::new(output))?;
        println!("eab_imported=true\nformat=toml\nnetwork_requests=false");
        return Ok(());
    }
    let [cmd, path] = args else {
        return Err("usage: moon-naive acme <command> <config.toml>".into());
    };
    let config = config(path)?;
    match cmd.as_str() {
        "status" => certificate_status(&config),
        "retry-certificate" => {
            let timeout = Duration::from_secs(config.acme.request_timeout_secs);
            let http = Http::new(config.acme.directory_ca_file.as_deref(), timeout)?;
            let provider = acme::dns::provider_from_config(&config, Http::new(None, timeout)?)?;
            let mut manager = acme::manager::Manager::open(&config, provider, http)?;
            manager.retry_certificate()?;
            println!("certificate_validation_retry_scheduled=true; existing order retained");
            Ok(())
        }
        "check-ca" => {
            let http = Http::new(
                config.acme.directory_ca_file.as_deref(),
                Duration::from_secs(config.acme.request_timeout_secs),
            )?;
            let data = http
                .json("GET", config.acme.directory(), None, None)
                .await?;
            if ["newNonce", "newAccount", "newOrder"]
                .iter()
                .any(|key| data[*key].as_str().is_none())
            {
                return Err("incomplete ACME directory".into());
            }
            println!(
                "ca_directory=reachable\ntls_verification=enabled\naccount_created=false\ndns_modified=false"
            );
            Ok(())
        }
        "run" | "once" | "cleanup" => {
            let mode = match cmd.as_str() {
                "once" => Mode::Once,
                "cleanup" => Mode::Cleanup,
                _ => Mode::Run,
            };
            with_shutdown(move |shutdown| async move {
                Control::start(config, shutdown, mode)?.wait().await
            })
            .await
        }
        _ => Err("unknown ACME command".into()),
    }
}
async fn with_shutdown<F, Fut>(run: F) -> Result<()>
where
    F: FnOnce(watch::Receiver<bool>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let (stop, receive) = watch::channel(false);
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let signals = tokio::spawn(async move {
        tokio::select! {_=interrupt.recv()=>{},_=terminate.recv()=>{}}
        let _ = stop.send(true);
    });
    let result = run(receive).await;
    signals.abort();
    result
}

fn migrate(old: &str, new: &str) -> Result<()> {
    let mut original = Vec::new();
    fs::File::open(old)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut original)?;
    if original.len() > 1024 * 1024 {
        return Err("configuration exceeds 1 MiB".into());
    }
    let mut doc: toml::Value = crate::acme::persist::parse_toml(&original)?;
    if let Some(listener) = doc.get_mut("listener").and_then(toml::Value::as_table_mut) {
        for field in ["fast_open", "zero_rtt"] {
            if let Some(value) = listener.remove(field)
                && value.as_bool() != Some(false)
            {
                return Err("retired Fast Open/0-RTT fields must have been false".into());
            }
        }
    }
    let normalized = toml::to_string(&doc).map_err(|_| "cannot encode configuration")?;
    let source = Config::parse(&normalized)?;
    if source.schema_version == 2
        || !source.proxy.users.is_empty()
        || source.acme.dns_credentials.is_some()
        || source.acme.eab.is_some()
    {
        let checked = crate::acme::persist::read_private(Path::new(old), 1024 * 1024)?;
        if checked != original {
            return Err("configuration changed during migration".into());
        }
    }

    let table = doc.as_table_mut().ok_or("invalid configuration")?;
    table.insert("schema_version".into(), toml::Value::Integer(2));
    if !source.credentials_file.as_os_str().is_empty() {
        let users: toml::Value =
            crate::acme::persist::load_toml(&source.credentials_file, 512 * 1024)?;
        table
            .entry("proxy")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .ok_or("invalid proxy table")?
            .insert(
                "users".into(),
                users.get("users").ok_or("users missing")?.clone(),
            );
        table.remove("credentials_file");
    }
    let acme = table
        .get_mut("acme")
        .and_then(toml::Value::as_table_mut)
        .ok_or("acme missing")?;
    if !source.acme.dns_token_file.as_os_str().is_empty() {
        acme.insert(
            "dns_credentials".into(),
            crate::acme::persist::load_toml(&source.acme.dns_token_file, 16384)?,
        );
        acme.remove("dns_token_file");
    }
    if let Some(path) = &source.acme.eab_credentials_file {
        acme.insert("eab".into(), crate::acme::persist::load_toml(path, 32768)?);
        acme.remove("eab_credentials_file");
    }
    let text = toml::to_string_pretty(&doc).map_err(|_| "cannot encode configuration")?;
    Config::parse(&text)?;
    acme::persist::write_private_new(Path::new(new), text.as_bytes())?;
    println!("configuration migrated; source and ACME state unchanged");
    Ok(())
}
