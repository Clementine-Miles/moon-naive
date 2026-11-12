use super::{Result, capture, check, root};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};
pub const SOURCES: [(&str, &str, &str); 3] = [
    (
        "pingora-core",
        "https://github.com/cloudflare/pingora.git",
        "4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19",
    ),
    (
        "quiche",
        "https://github.com/cloudflare/quiche.git",
        "925b225825e2188f8e58e359114150500557bf61",
    ),
    (
        "instant-acme",
        "https://github.com/djc/instant-acme.git",
        "4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52",
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
        check(
            format!("{:x}", Sha256::digest(fs::read(path)?)) == hash,
            "vendored source checksum mismatch",
        )?;
    }
    let mut actual = BTreeSet::new();
    walk(directory, &mut actual)?;
    actual.remove(&directory.join("SHA256SUMS"));
    check(expected == actual, "vendored file inventory mismatch")?;
    Ok(format!("{:x}", Sha256::digest(manifest)))
}

/// Independent v4 reference serializer: never calls application/core auth or codec.
/// Existing checked-in Python-generated known answers must remain byte-identical.
pub fn vectors(verify: bool) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac};
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
