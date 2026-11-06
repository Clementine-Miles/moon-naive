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
