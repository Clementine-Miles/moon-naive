//! Release archives are built from explicit inputs; no credentials or build caches.
use super::{Result, audit, audit_native, capture, check, root};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
const TARGET: &str = "x86_64-unknown-linux-musl";
fn checksum(path: &Path) -> Result<String> {
    let mut input = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let len = input.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        digest.update(&buffer[..len]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn copy(source: &Path, target: &Path, executable: bool) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    check(!target.exists(), "release file already exists")?;
    fs::copy(source, target)?;
    fs::set_permissions(
        target,
        fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )?;
    Ok(())
}
fn paths(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            paths(&entry.path(), output)?;
        } else if kind.is_file() {
            output.push(entry.path());
        } else {
            return Err("release inputs must be regular files/directories".into());
        }
    }
    Ok(())
}
fn archive(stage: &Path, output: &Path) -> Result<()> {
    let mut files = Vec::new();
    paths(stage, &mut files)?;
    // A source checkout can already carry a manifest. Never hash the old
    // manifest into itself or archive a duplicate after regenerating it.
    files.retain(|path| path != &stage.join("SHA256SUMS"));
    files.sort();
    let mut sums = String::new();
    for path in &files {
        sums.push_str(&format!(
            "{}  {}\n",
            checksum(path)?,
            path.strip_prefix(stage)?.display()
        ));
    }
    fs::write(stage.join("SHA256SUMS"), sums)?;
    let name = stage
        .file_name()
        .ok_or("release stage name")?
        .to_string_lossy();
    let artifact = output.join(format!("{name}.tar.gz"));
    check(!artifact.exists(), "release archive already exists")?;
    // Deterministic archive generation in Rust: no tar/gzip subprocesses.
    let gzip = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(fs::File::create(&artifact)?, flate2::Compression::default());
    let mut tar = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    // Explicit parent entries make extracted permissions independent of umask.
    let mut directories = BTreeSet::from([PathBuf::from(name.as_ref())]);
    for path in &files {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == stage {
                break;
            }
            directories.insert(Path::new(name.as_ref()).join(directory.strip_prefix(stage)?));
            parent = directory.parent();
        }
    }
    for directory in directories {
        tar.append_data(&mut header, directory, std::io::empty())?;
    }
    files.push(stage.join("SHA256SUMS"));
    files.sort();
    for path in files {
        let metadata = fs::metadata(&path)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(if metadata.permissions().mode() & 0o111 != 0 {
            0o755
        } else {
            0o644
        });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(
            &mut header,
            Path::new(name.as_ref()).join(path.strip_prefix(stage)?),
            fs::File::open(path)?,
        )?;
    }
    tar.into_inner()?.finish()?.sync_all()?;
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644))?;
    let sidecar = output.join(format!("{name}.tar.gz.sha256"));
    fs::write(
        &sidecar,
        format!("{}  {name}.tar.gz\n", checksum(&artifact)?),
    )?;
    fs::set_permissions(sidecar, fs::Permissions::from_mode(0o644))?;
    println!("artifact={}", artifact.display());
    Ok(())
}
fn output(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        root().join(path)
    };
    fs::create_dir_all(&path)?;
    Ok(path)
}
fn require_static_elf(bytes: &[u8]) -> Result<()> {
    let elf = goblin::elf::Elf::parse(bytes)?;
    check(
        elf.is_64
            && elf.little_endian
            && elf.header.e_machine == goblin::elf::header::EM_X86_64
            && matches!(
                elf.header.e_type,
                goblin::elf::header::ET_EXEC | goblin::elf::header::ET_DYN
            ),
        "release must be a Linux x86_64 executable ELF",
    )?;
    check(
        elf.interpreter.is_none() && elf.libraries.is_empty(),
        "musl release must have no interpreter or shared-library dependencies",
    )?;
    check(
        elf.section_headers.iter().all(|section| {
            !matches!(
                elf.shdr_strtab.get_at(section.sh_name),
                Some(".go.buildinfo" | ".gopclntab" | ".note.go.buildid")
            )
        }),
        "Go runtime/build metadata found in server release",
    )
}

/// Validate the actual artifact using Rust ELF parsing, without file/readelf.
pub fn check_elf(binary: &Path) -> Result<()> {
    require_static_elf(&fs::read(binary)?)?;
    println!(
        "{}: static Linux x86_64 ELF; sha256={}",
        binary.display(),
        checksum(binary)?
    );
    Ok(())
}

pub fn dist(binary: &Path, directory: &Path) -> Result<()> {
    audit_native()?;
    let binary = fs::canonicalize(binary)?;
    let version = capture(
        &root(),
        binary.to_str().ok_or("binary UTF-8")?,
        &["--version"],
    )?;
    check(
        version.contains(env!("CARGO_PKG_VERSION")) && version.contains("x86_64-linux-musl"),
        "binary version/target differs from release",
    )?;
    require_static_elf(&fs::read(&binary)?)?;
    let output = output(directory)?;
    let stage = output.join(format!("moon-naive-{}-{TARGET}", env!("CARGO_PKG_VERSION")));
    fs::create_dir(&stage)?;
    copy(&binary, &stage.join("moon-naive"), true)?;
    for (source, destination, executable) in [
        ("README.md", "README.md", false),
        ("LICENSE", "LICENSE", false),
        (
            "deploy/moon-naive.service",
            "deploy/moon-naive.service",
            false,
        ),
        ("deploy/moon-naive.openrc", "deploy/moon-naive.openrc", true),
        ("docs/VPS-GUIDE.md", "docs/VPS-GUIDE.md", false),
        ("config.example.toml", "config.example.toml", false),
        ("deploy/Dockerfile.musl", "deploy/Dockerfile.musl", false),
        ("docs/VERIFICATION.md", "docs/VERIFICATION.md", false),
        ("docs/CONFIGURATION.md", "docs/CONFIGURATION.md", false),
        ("docs/PROTOCOL.md", "docs/PROTOCOL.md", false),
    ] {
        copy(&root().join(source), &stage.join(destination), executable)?;
    }
    for directory in ["licenses"] {
        let mut files = Vec::new();
        paths(&root().join(directory), &mut files)?;
        for path in files {
            copy(
                &path,
                &stage
                    .join(directory)
                    .join(path.strip_prefix(root().join(directory))?),
                false,
            )?;
        }
    }
    notices(&stage)?;
    let sources = audit::SOURCES
        .iter()
        .map(|(name, url, revision)| serde_json::json!({"name":name,"url":url,"revision":revision}))
        .collect::<Vec<_>>();
    fs::write(
        stage.join("BUILD-INFO.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version":env!("CARGO_PKG_VERSION"),"target":TARGET,"static":true,
            "binary_sha256":checksum(&binary)?,"cargo_lock_sha256":checksum(&root().join("Cargo.lock"))?,
            "boring":"5.2.0","tokio-boring":"5.0.0","sources":sources,
            "pingora_vendor_manifest_sha256":audit::vendor_digest()?,
            "public_network_acceptance":"pending","fingerprint_improvement":"not_measured",
        }))?,
    )?;
    archive(&stage, &output)
}
fn license_paths(directory: &Path, depth: usize, output: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if kind.is_file()
            && ["LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT"]
                .iter()
                .any(|prefix| name.to_ascii_uppercase().starts_with(prefix))
            && entry.metadata()?.len() <= 2 * 1024 * 1024
        {
            output.insert(entry.path());
        } else if kind.is_dir()
            && depth > 0
            && ![".git", "target", "tests", "examples"].contains(&name.as_ref())
        {
            license_paths(&entry.path(), depth - 1, output)?;
        }
    }
    Ok(())
}
fn notices(stage: &Path) -> Result<()> {
    let graph = capture(
        &root(),
        "cargo",
        &[
            "tree",
            "-p",
            "moon-naive",
            "--locked",
            "--target",
            TARGET,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
    )?;
    let selected = graph
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            Some((
                words.next()?.to_owned(),
                words.next()?.trim_start_matches('v').to_owned(),
            ))
        })
        .collect::<HashSet<_>>();
    let metadata = audit::metadata(Some(TARGET))?;
    let mut inventory = Vec::new();
    let mut text = String::from(
        "moon-naive third-party software inventory\nThe selected normal/build dependency graph and available upstream license files follow.\nRust, musl and GCC runtime license texts are also provided in licenses/.\n\n",
    );
    for package in metadata["packages"].as_array().ok_or("cargo packages")? {
        let name = package["name"].as_str().ok_or("package name")?;
        let version = package["version"].as_str().ok_or("package version")?;
        if !selected.contains(&(name.to_owned(), version.to_owned())) {
            continue;
        }
        inventory.push(serde_json::json!({"name":name,"version":version,"license":package["license"],"source":package["source"]}));
        text.push_str(&format!(
            "{name} {version}: {}\n",
            package["license"]
                .as_str()
                .unwrap_or("see upstream license")
        ));
        let directory = Path::new(package["manifest_path"].as_str().ok_or("manifest path")?)
            .parent()
            .ok_or("manifest directory")?;
        let mut files = BTreeSet::new();
        license_paths(directory, 3, &mut files)?;
        if let Some(file) = package["license_file"].as_str() {
            let file = PathBuf::from(file);
            files.insert(if file.is_absolute() {
                file
            } else {
                directory.join(file)
            });
        }
        if files.is_empty() {
            for ancestor in directory.ancestors().take(4) {
                let path = ancestor.join("LICENSE");
                if path.is_file() {
                    files.insert(path);
                    break;
                }
            }
        }
        for (index, path) in files.iter().enumerate() {
            let relative = format!(
                "third-party-licenses/{name}-{version}/{index:03}-{}",
                path.file_name().ok_or("license name")?.to_string_lossy()
            );
            copy(path, &stage.join(&relative), false)?;
        }
    }
    fs::write(stage.join("THIRD-PARTY-NOTICES.txt"), text)?;
    fs::write(
        stage.join("dependency-inventory.json"),
        serde_json::to_vec_pretty(&inventory)?,
    )?;
    Ok(())
}
pub fn source(directory: &Path) -> Result<()> {
    audit::sources()?;
    let output = output(directory)?;
    let stage = output.join(format!("moon-naive-{}-source", env!("CARGO_PKG_VERSION")));
    fs::create_dir(&stage)?;
    let files = capture(
        &root(),
        "git",
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    for name in files.split('\0').filter(|name| !name.is_empty()) {
        let path = root().join(name);
        if name.starts_with("vendor/") || !path.is_file() {
            continue;
        }
        check(
            !Path::new(name).is_absolute()
                && !Path::new(name)
                    .components()
                    .any(|part| part == std::path::Component::ParentDir),
            "invalid source path",
        )?;
        copy(&path, &stage.join(name), name.ends_with(".openrc"))?;
    }
    let mut vendor_files = Vec::new();
    paths(&root().join("vendor"), &mut vendor_files)?;
    for path in vendor_files {
        copy(&path, &stage.join(path.strip_prefix(root())?), false)?;
    }
    archive(&stage, &output)
}
fn docker(args: &[String]) -> Result<String> {
    let output = Command::new("docker")
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .arg("--host=unix:///var/run/docker.sock")
        .args(args)
        .output()?;
    check(
        output.status.success(),
        &format!(
            "platform container failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok(String::from_utf8(output.stdout)?)
}
pub fn platform_smoke(binary: &Path, ca_bundle: Option<&Path>) -> Result<()> {
    let binary = fs::canonicalize(binary)?;
    let example = super::private_example(&binary, None)?;
    let config = fs::canonicalize(&example.0)?;
    let mut report = String::new();
    for (name, image) in [
        (
            "alpine-3.22",
            "alpine@sha256:d406446bc05b82480756ce8f1287964d28768c23955fa9480d2a74a2eae7a654",
        ),
        (
            "debian-12",
            "debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8",
        ),
        (
            "archlinux-base",
            "archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0",
        ),
    ] {
        report.push_str(&format!("platform={name}\nimage={image}\n"));
        let base = vec![
            "run".into(),
            "--rm".into(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--user".into(),
            format!(
                "{}:{}",
                fs::metadata(&config)?.uid(),
                fs::metadata(&config)?.gid()
            ),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/moon-naive,readonly",
                binary.display()
            ),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/config.toml,readonly",
                config.display()
            ),
        ];
        for args in [
            vec!["--version"],
            vec!["check-config", "/config.toml"],
            vec!["check-transport", "/config.toml"],
        ] {
            println!("platform={name} check={}", args[0]);
            let mut command = base.clone();
            command.extend(["--network=none".into(), image.into(), "/moon-naive".into()]);
            command.extend(args.into_iter().map(str::to_owned));
            report.push_str(&docker(&command)?);
        }
        if let Some(ca_bundle) = ca_bundle {
            println!("platform={name} check=read-only-ca-directory");
            let mut command = base.clone();
            command.extend([
                "--mount".into(),
                format!(
                    "type=bind,src={},dst=/etc/ssl/certs/ca-certificates.crt,readonly",
                    ca_bundle.display()
                ),
                image.into(),
                "/moon-naive".into(),
                "acme".into(),
                "check-ca".into(),
                "/config.toml".into(),
            ]);
            report.push_str(&docker(&command)?);
        }
        println!("platform={name} result=passed");
    }
    super::save_report("platform-smoke", &report)
}
