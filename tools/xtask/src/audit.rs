use super::{Result, capture, check, root};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};
pub const SOURCES: [(&str, &str, &str); 3] = [
    (
        "pingora-core",
        "https://github.com/cloudflare/pingora.git",
        "f86ffda5d3ae5c3baf5125682138b33b26c01b08",
    ),
    (
        "quiche",
        "https://github.com/cloudflare/quiche.git",
        "7ccccc7b7f4bd4ec6bc70219fdbe491024f5cb0b",
    ),
    (
        "instant-acme",
        "https://github.com/djc/instant-acme.git",
        "1909bed8eee54d7289d64b3e9ff573ac5b272676",
    ),
];
pub fn metadata(target: Option<&str>) -> Result<serde_json::Value> {
    let mut args = vec!["metadata", "--locked", "--format-version", "1"];
    if let Some(target) = target {
        args.extend(["--filter-platform", target]);
    }
    Ok(serde_json::from_str(&capture(&root(), "cargo", &args)?)?)
}
pub fn sources() -> Result<()> {
    no_go_sources()?;
    let metadata = metadata(None)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo packages missing")?;
    for (name, url, rev) in SOURCES {
        if name == "pingora-core" {
            for package in packages.iter().filter(|p| {
                p["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("pingora-"))
            }) {
                let manifest = Path::new(
                    package["manifest_path"]
                        .as_str()
                        .ok_or("manifest path missing")?,
                )
                .canonicalize()?;
                check(
                    package["source"].is_null()
                        && manifest.starts_with(root().join("vendor/pingora").canonicalize()?),
                    "Pingora must use the audited local source",
                )?;
            }
            check(
                fs::read_to_string(root().join("vendor/pingora/UPSTREAM_REVISION"))?.trim() == rev,
                "Pingora baseline revision mismatch",
            )?;
            vendor_digest()?;
            continue;
        }
        if name == "instant-acme" {
            let matching = packages
                .iter()
                .filter(|p| p["name"] == name)
                .collect::<Vec<_>>();
            let directory = root().join("vendor/instant-acme").canonicalize()?;
            check(
                matching.len() == 1,
                "instant-acme package missing or duplicated",
            )?;
            let package = matching[0];
            check(
                package["source"].is_null()
                    && Path::new(
                        package["manifest_path"]
                            .as_str()
                            .ok_or("manifest missing")?,
                    )
                    .canonicalize()?
                    .starts_with(&directory),
                "instant-acme must use audited local source",
            )?;
            check(
                fs::read_to_string(directory.join("UPSTREAM_REVISION"))?.trim() == rev,
                "instant-acme baseline revision mismatch",
            )?;
            digest_directory(&directory)?;
            continue;
        }
        let expected = format!("git+{url}?rev={rev}#{rev}");
        let matching = packages
            .iter()
            .filter(|p| p["name"].as_str() == Some(name))
            .collect::<Vec<_>>();
        check(
            matching.len() == 1 && matching[0]["source"].as_str() == Some(&expected),
            "native Git revision differs from the release pin",
        )?;
    }
    Ok(())
}

/// Server sources must not grow a Go sidecar or a second Go network stack.
/// External tooling checkouts are not runtime build inputs.
fn no_go_sources() -> Result<()> {
    fn visit(path: &Path) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(&entry.path())?;
            } else if kind.is_file() {
                let path = entry.path();
                check(
                    path.extension().is_none_or(|extension| extension != "go")
                        && path
                            .file_name()
                            .is_none_or(|name| name != "go.mod" && name != "go.sum"),
                    "Go source/module found in server build inputs",
                )?;
            }
        }
        Ok(())
    }
    for directory in [
        "core",
        "src",
        "tools/xtask/src",
        "tools/xtask/build-support",
        "deploy",
        "vendor",
    ] {
        visit(&root().join(directory))?;
    }
    Ok(())
}

/// Validate every retained vendored file, including additions ignored by Git.
pub fn vendor_digest() -> Result<String> {
    digest_directory(&root().join("vendor/instant-acme"))?;
    digest_directory(&root().join("vendor/pingora"))
}
fn digest_directory(directory: &Path) -> Result<String> {
    fn walk(dir: &Path, files: &mut BTreeSet<std::path::PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(&entry.path(), files)?;
            } else {
                check(
                    kind.is_file(),
                    "vendored source must contain regular files only",
                )?;
                files.insert(entry.path());
            }
        }
        Ok(())
    }
    let manifest = fs::read(directory.join("SHA256SUMS"))?;
    let mut expected = BTreeSet::new();
    for line in std::str::from_utf8(&manifest)?.lines() {
        let (hash, name) = line.split_once("  ").ok_or("invalid vendor manifest")?;
        check(
            !Path::new(name).is_absolute()
                && Path::new(name)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "invalid vendor manifest path",
        )?;
        let path = directory.join(name);
        check(
            expected.insert(path.clone()),
            "duplicate vendor manifest path",
        )?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("cannot read vendored source {}: {error}", path.display()))?;
        check(
            super::hex(Sha256::digest(bytes)) == hash,
            &format!("vendored source checksum mismatch: {}", path.display()),
        )?;
    }
    let mut actual = BTreeSet::new();
    walk(directory, &mut actual)?;
    actual.remove(&directory.join("SHA256SUMS"));
    check(expected == actual, "vendored file inventory mismatch")?;
    Ok(super::hex(Sha256::digest(manifest)))
}

/// Independent v4 reference serializer: never calls application/core auth or codec.
/// Existing checked-in Python-generated known answers must remain byte-identical.
pub fn vectors(verify: bool) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hmac::{Hmac, KeyInit, Mac};
    fn proof(
        domain: &[u8],
        stream: u64,
        offer: u8,
        selected: u8,
        fields: &[Option<&str>],
    ) -> Result<String> {
        let mut transcript = domain.to_vec();
        transcript.extend([7; 32]);
        transcript.extend(stream.to_be_bytes());
        transcript.extend([offer, selected]);
        for field in fields {
            match field {
                Some(text) => {
                    transcript.extend((text.len() as u64).to_be_bytes());
                    transcript.extend(text.as_bytes());
                }
                None => transcript.extend(u64::MAX.to_be_bytes()),
            }
        }
        let key = Sha256::digest(b"moon-naive/v4/key\0user:a-long-test-secret-123");
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
        mac.update(&Sha256::digest(transcript));
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }
    let mut auth=vec!["# stream\toffer\tselected\tmethod\tauthority\tscheme\tpath\tprotocol\trequest\tresponse; - = absent".to_owned()];
    for (stream, fields) in [
        (
            1,
            [Some("CONNECT"), Some("example.org:443"), None, None, None],
        ),
        (
            0,
            [Some("CONNECT"), Some("example.org:443"), None, None, None],
        ),
        (
            4,
            [
                Some("GET"),
                Some("example.org:443"),
                Some("https"),
                Some("/a%2Fb?q=1"),
                None,
            ],
        ),
        (
            8,
            [
                Some("CONNECT"),
                Some("example.org:443"),
                Some("https"),
                Some(""),
                Some("websocket"),
            ],
        ),
    ] {
        for (offer, selected) in [(2, 2), (7, 5), (7, 6), (1, 1)] {
            let request = format!(
                "moon-naive {offer:02x}.{}",
                proof(b"moon-naive/v4/request\0", stream, offer, 0, &fields)?
            );
            let response = format!(
                "moon-naive {selected:02x}.{}",
                proof(
                    b"moon-naive/v4/response/200\0",
                    stream,
                    offer,
                    selected,
                    &fields
                )?
            );
            auth.push(format!(
                "{stream}\t{offer}\t{selected}\t{}\t{request}\t{response}",
                fields.map(|f| f.unwrap_or("-")).join("\t")
            ));
        }
    }
    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
    let mut framing = vec!["# name\tmode\twire hex\tpayload hex\tvalid EOF".into()];
    let mut frame = |name: &str, mode: u8, wire: &[u8], payload: &[u8], ok: bool| {
        framing.push(format!(
            "{name}\t{mode}\t{}\t{}\t{}",
            hex(wire),
            hex(payload),
            u8::from(ok)
        ))
    };
    for (mode, count) in [(1, 8), (2, 16), (5, 8), (6, 16)] {
        let mut wire = Vec::new();
        let mut payload = b"abcdefgh".repeat(count);
        for i in 0..count {
            wire.extend(b"\0\x08\x01abcdefgh");
            wire.push(i as u8 + 1);
        }
        if mode < 4 {
            wire.extend(b"\0\0\xffRAW");
            payload.extend(b"\0\0\xffRAW");
        } else {
            wire.extend(b"\0\x80\x01");
            wire.extend([b'x'; 128]);
            wire.push(254);
            payload.extend([b'x'; 128]);
        }
        frame(&format!("transition-{mode}"), mode, &wire, &payload, true);
    }
    frame("coalesced", 2, b"\0\x01\0a\0\x02\0bc", b"abc", true);
    frame("empty-stream", 2, b"", b"", true);
    for (name, wire) in [
        ("empty-record", &b"\0\0\0"[..]),
        ("oversize", &b"\xff\xff\0"[..]),
        ("padding-budget", &b"\0\x08\x02abcdefgh\0\0"[..]),
        ("truncated-header", &b"\0"[..]),
        ("truncated-payload", &b"\0\x02\0a"[..]),
        ("truncated-padding", &b"\0\x08\x01abcdefgh"[..]),
    ] {
        frame(name, 2, wire, b"", false);
    }
    for (name, lines) in [("auth.tsv", auth), ("framing.tsv", framing)] {
        let path = root().join("core/tests/vectors").join(name);
        let data = lines.join("\n") + "\n";
        if verify {
            check(
                fs::read(&path)? == data.as_bytes(),
                &format!("{}: regenerate vectors", path.display()),
            )?;
        } else {
            fs::write(path, data)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_sources_survive_a_clean_checkout() -> Result<()> {
        let checkout = tempfile::tempdir()?;
        let repository = root();
        // A warm workspace may contain ignored files named by SHA256SUMS.
        // Copy only tracked paths to reproduce what CI and source archives get.
        // Already-exported sources have no Git metadata: audit them directly.
        if repository.join(".git").exists() {
            let files = capture(
                &repository,
                "git",
                &[
                    "ls-files",
                    "-z",
                    "--",
                    "vendor/instant-acme",
                    "vendor/pingora",
                ],
            )?;
            check(!files.is_empty(), "tracked vendor sources missing")?;
            for name in files.split('\0').filter(|name| !name.is_empty()) {
                let destination = checkout.path().join(name);
                fs::create_dir_all(destination.parent().ok_or("vendor path missing parent")?)?;
                fs::copy(repository.join(name), destination)?;
            }
        }
        let sources = if repository.join(".git").exists() {
            checkout.path()
        } else {
            &repository
        };
        for directory in ["vendor/instant-acme", "vendor/pingora"] {
            digest_directory(&sources.join(directory))?;
        }
        Ok(())
    }
}

/// Socket-level TCP Fast Open is prohibited in project-owned code, deployment
/// material and documentation. Tokens are assembled at runtime so this file
/// does not match itself. Reading the option back (`getsockopt`) to prove it
/// is disabled is the only permitted use. Vendored Pingora still contains its
/// opt-in TFO helpers; this audit proves that no project-owned code reaches
/// them, because enabling them requires one of the tokens below.
fn tfo_tokens() -> Vec<String> {
    let fastopen = ["fast", "open"].concat();
    vec![
        format!("tcp_{fastopen}"),
        format!("msg_{fastopen}"),
        format!("tcp_{}_open", "fast"),
        format!("tcp{fastopen}"),
        format!("ipv4.tcp_{fastopen}"),
    ]
}
pub fn tfo_violations(path: &str, text: &str) -> Vec<String> {
    let tokens = tfo_tokens();
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let lower = line.to_ascii_lowercase();
            tokens.iter().any(|token| lower.contains(token.as_str()))
                && !lower.contains("getsockopt(")
        })
        .map(|(number, line)| format!("{path}:{}: {}", number + 1, line.trim()))
        .collect()
}
pub fn no_tfo() -> Result<()> {
    let files = capture(&root(), "git", &["ls-files", "-z"])?;
    let mut violations = Vec::new();
    for path in files.split('\0').filter(|p| !p.is_empty()) {
        if path.starts_with("vendor/")
            || path.starts_with("licenses/")
            || matches!(path, "Cargo.lock" | "SHA256SUMS")
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(root().join(path)) else {
            continue; // Binary assets or files removed from the work tree.
        };
        violations.extend(tfo_violations(path, &text));
    }
    check(
        violations.is_empty(),
        &format!("TCP Fast Open is prohibited:\n{}", violations.join("\n")),
    )?;
    println!("tcp-fast-open audit: no project-owned use");
    Ok(())
}
#[cfg(test)]
mod tfo_tests {
    use super::*;
    #[test]
    fn tfo_audit_flags_enabling_and_allows_readback() {
        let open = ["FAST", "OPEN"].concat();
        let flagged = [
            format!("setsockopt(fd, IPPROTO_TCP, TCP_{open}, 5)"),
            format!("send(fd, b, MSG_{open})"),
            format!("options.tcp_{}_open = true;", "fast"),
            format!("sysctl -w net.ipv4.tcp_{}=3", open.to_lowercase()),
            format!("sockopt::Tcp{}Connect", "FastOpen"),
        ];
        for line in &flagged {
            assert_eq!(tfo_violations("x", line).len(), 1, "{line}");
        }
        let allowed = format!("getsockopt(&s, sockopt::Tcp{}Connect)", "FastOpen");
        assert!(tfo_violations("x", &allowed).is_empty());
        // Rejecting the legacy config key or stripping a header is not TFO.
        assert!(tfo_violations("x", "for field in [\"fast_open\", \"fastopen\"]").is_empty());
    }
    #[test]
    fn repository_has_no_tfo_use() {
        no_tfo().unwrap();
    }
}
