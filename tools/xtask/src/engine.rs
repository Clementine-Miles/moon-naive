//! Reproducible build of the Chromium native engine (`libmoon_engine.so`).
//!
//! The engine is Chromium's network stack from the pinned upstream
//! NaiveProxy source tree (`engine/UPSTREAM_REVISION`, Chromium
//! `engine/CHROMIUM_VERSION`), plus `engine/chromium.patch` (edits to existing
//! Chromium files) and the `engine/src/` overlay (new files). Build flags are
//! `engine/args.gn`. Nothing is modified inside an existing work directory
//! except by `fetch` into a new or empty one.
//!
//! cargo xtask engine fetch <work-dir>
//! cargo xtask engine toolchain <work-dir> [--gn-source <git-url>]
//! cargo xtask engine build <work-dir> [--gn <path>] [--out <name>]
//! cargo xtask engine check <work-dir>
//! cargo xtask engine export <work-dir>
//!
//! `export` is the maintainer path: it regenerates `engine/chromium.patch` from
//! the work tree and verifies the overlay is identical to `engine/src/`.
use super::{Result, check, root};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const UPSTREAM: &str = "https://github.com/klzgrad/naiveproxy.git";
const GN_SOURCE: &str = "https://gn.googlesource.com/gn";
pub const LIBRARY: &str = "libmoon_engine.so";

fn engine_dir() -> PathBuf {
    root().join("engine")
}

fn pin() -> Result<String> {
    let revision = fs::read_to_string(engine_dir().join("UPSTREAM_REVISION"))?
        .trim()
        .to_owned();
    check(
        revision.len() == 40
            && revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "engine/UPSTREAM_REVISION must be a 40-digit lowercase commit",
    )?;
    Ok(revision)
}

/// Run without the generic 480-second limit: Chromium builds take a while.
fn exec(dir: &Path, program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Result<()> {
    let program = program.as_ref();
    println!("RUN {} {}", program.to_string_lossy(), args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .status()?;
    check(
        status.success(),
        &format!("{} {args:?}: {status}", program.to_string_lossy()),
    )
}

fn output(dir: &Path, program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program).args(args).current_dir(dir).output()?;
    check(
        out.status.success(),
        &format!(
            "{program} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    Ok(String::from_utf8(out.stdout)?)
}

fn overlay_files() -> Result<Vec<PathBuf>> {
    let base = engine_dir().join("src");
    let mut stack = vec![base.clone()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path.strip_prefix(&base)?.to_path_buf());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn check_head(work: &Path) -> Result<()> {
    let head = output(work, "git", &["rev-parse", "HEAD"])?;
    check(
        head.trim() == pin()?,
        &format!("{} is not at the pinned upstream revision", work.display()),
    )
}

fn fetch(work: &Path) -> Result<()> {
    let repository = root();
    let work = std::path::absolute(work)?;
    check(
        !work.starts_with(&repository),
        "use a work directory outside the repository",
    )?;
    if work.exists() {
        check(
            fs::read_dir(&work)?.next().is_none(),
            "work directory must be new or empty; existing work is preserved",
        )?;
    }
    fs::create_dir_all(&work)?;
    let revision = pin()?;
    exec(&work, "git", &["init", "-q"])?;
    exec(&work, "git", &["remote", "add", "origin", UPSTREAM])?;
    exec(&work, "git", &["fetch", "--depth=1", "origin", &revision])?;
    exec(&work, "git", &["checkout", "-q", "--detach", "FETCH_HEAD"])?;
    check_head(&work)?;
    let patch = engine_dir().join("chromium.patch");
    let patch = patch.to_str().ok_or("non-UTF-8 repository path")?;
    exec(&work, "git", &["apply", "--check", patch])?;
    exec(&work, "git", &["apply", patch])?;
    for file in overlay_files()? {
        let destination = work.join("src").join(&file);
        check(
            !destination.exists(),
            &format!("overlay file {} already exists upstream", file.display()),
        )?;
        fs::create_dir_all(destination.parent().ok_or("bad overlay path")?)?;
        fs::copy(engine_dir().join("src").join(&file), destination)?;
    }
    println!(
        "prepared {} at {revision} with chromium.patch and overlay",
        work.display()
    );
    Ok(())
}

fn src(work: &Path) -> PathBuf {
    work.join("src")
}

fn clang(work: &Path) -> PathBuf {
    src(work).join("third_party/llvm-build/Release+Asserts/bin/clang++")
}

/// Download the pinned Chromium Clang and build the pinned GN from source.
fn toolchain(work: &Path, gn_source: &str) -> Result<()> {
    check_head(work)?;
    let src = src(work);
    if !clang(work).is_file() {
        // Chromium's own pin (tools/clang/scripts/update.py).
        let revision = output(
            &src.join("tools/clang/scripts"),
            "python3",
            &["-c", "import update; print(update.PACKAGE_VERSION)"],
        )?;
        let revision = revision.trim();
        check(
            !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_graphic()),
            "unexpected Clang package version",
        )?;
        let dir = src.join("third_party/llvm-build/Release+Asserts");
        fs::create_dir_all(&dir)?;
        let url = format!(
            "https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/clang-{revision}.tar.xz"
        );
        let archive = dir.join("clang.tar.xz");
        let archive_str = archive.to_str().ok_or("non-UTF-8 path")?;
        exec(
            &dir,
            "curl",
            &["-fsSL", "--retry", "3", "-o", archive_str, &url],
        )?;
        exec(&dir, "tar", &["xJf", archive_str])?;
        fs::remove_file(&archive)?;
        fs::write(dir.join("cr_build_revision"), format!("{revision}\n"))?;
    }
    let gn = src.join("gn/out/gn");
    if !gn.is_file() {
        // DEPS pins GN as 'gn_version': 'git_revision:<sha>'.
        let deps = fs::read_to_string(src.join("DEPS"))?;
        let revision = deps
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("'gn_version': 'git_revision:")
                    .and_then(|rest| rest.strip_suffix("',"))
            })
            .ok_or("gn_version not found in DEPS")?
            .to_owned();
        let dir = src.join("gn");
        check(
            !dir.exists(),
            "src/gn exists without a built gn; remove it first",
        )?;
        fs::create_dir_all(&dir)?;
        exec(&dir, "git", &["init", "-q"])?;
        exec(&dir, "git", &["remote", "add", "origin", gn_source])?;
        exec(&dir, "git", &["fetch", "origin", &revision])?;
        exec(&dir, "git", &["checkout", "-q", "--detach", "FETCH_HEAD"])?;
        let head = output(&dir, "git", &["rev-parse", "HEAD"])?;
        check(head.trim() == revision, "GN source is not at the DEPS pin")?;
        // GN's own bootstrap, compiled with the pinned Chromium Clang.
        let bin = clang(work);
        let cxx = bin.to_str().ok_or("non-UTF-8 path")?;
        let cc = cxx.trim_end_matches("++");
        let status = Command::new("python3")
            .args(["build/gen.py", "--no-last-commit-position"])
            .current_dir(&dir)
            .env("CXX", cxx)
            .env("CC", cc)
            .env("AR", bin.with_file_name("llvm-ar"))
            .status()?;
        check(status.success(), "gn build/gen.py failed")?;
        fs::write(
            dir.join("out/last_commit_position.h"),
            format!(
                "#ifndef OUT_LAST_COMMIT_POSITION_H_\n#define OUT_LAST_COMMIT_POSITION_H_\n#define LAST_COMMIT_POSITION_NUM 0\n#define LAST_COMMIT_POSITION \"0 ({})\"\n#endif\n",
                &revision[..12]
            ),
        )?;
        exec(&dir, "ninja", &["-C", "out", "gn"])?;
    }
    println!(
        "toolchain ready: {} and {}",
        clang(work).display(),
        gn.display()
    );
    Ok(())
}

fn build(work: &Path, gn: Option<&Path>, out: &str) -> Result<PathBuf> {
    check_head(work)?;
    let src = src(work);
    check(
        clang(work).is_file(),
        "pinned Clang missing; run `cargo xtask engine toolchain`",
    )?;
    let gn = match gn {
        Some(path) => path.to_path_buf(),
        None => src.join("gn/out/gn"),
    };
    check(
        gn.is_file(),
        "GN missing; run `cargo xtask engine toolchain` or pass --gn",
    )?;
    check(
        !out.contains('/') && !out.contains("..") && !out.is_empty(),
        "--out is a directory name under src/out",
    )?;
    let flags = fs::read_to_string(engine_dir().join("args.gn"))?;
    let output_dir = src.join("out").join(out);
    fs::create_dir_all(&output_dir)?;
    fs::write(
        output_dir.join("args.gn"),
        format!("{flags}target_os = \"linux\"\ntarget_cpu = \"x64\"\n"),
    )?;
    let out_rel = format!("out/{out}");
    exec(&src, &gn, &["gen", &out_rel])?;
    exec(&src, "ninja", &["-C", &out_rel, "moon_engine"])?;
    let library = output_dir.join(LIBRARY);
    check(
        library.is_file(),
        "ninja finished without libmoon_engine.so",
    )?;
    super::release::check_engine(&library)?;
    println!("built {}", library.display());
    Ok(library)
}

/// Patch and overlay consistency of a prepared work tree.
fn verify(work: &Path) -> Result<()> {
    check_head(work)?;
    let patch = engine_dir().join("chromium.patch");
    let expected = fs::read_to_string(&patch)?;
    let actual = output(work, "git", &["diff", "--full-index", "--no-color", "--no-ext-diff"])?;
    check(
        actual == expected,
        "work tree differs from engine/chromium.patch (run `cargo xtask engine export` if intended)",
    )?;
    for file in overlay_files()? {
        let ours = fs::read(engine_dir().join("src").join(&file))?;
        let theirs = fs::read(src(work).join(&file))
            .map_err(|e| format!("overlay {}: {e}", file.display()))?;
        check(
            ours == theirs,
            &format!("overlay {} differs", file.display()),
        )?;
    }
    println!("work tree matches the pin, chromium.patch and the overlay");
    Ok(())
}

fn export(work: &Path) -> Result<()> {
    check_head(work)?;
    let diff = output(work, "git", &["diff", "--full-index", "--no-color", "--no-ext-diff"])?;
    check(!diff.is_empty(), "no changes to export")?;
    fs::write(engine_dir().join("chromium.patch"), &diff)?;
    let untracked = output(
        work,
        "git",
        &["ls-files", "--others", "--exclude-standard", "src/net"],
    )?;
    for path in untracked.lines() {
        let relative = Path::new(path).strip_prefix("src")?;
        let ours = engine_dir().join("src").join(relative);
        if !ours.exists() {
            println!("NOTE untracked file not in the overlay: {path}");
            continue;
        }
        let theirs = fs::read(work.join(path))?;
        if fs::read(&ours)? != theirs {
            fs::write(&ours, theirs)?;
            println!("updated overlay {}", relative.display());
        }
    }
    println!("exported engine/chromium.patch ({} bytes)", diff.len());
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["fetch", work] => fetch(Path::new(work)),
        ["toolchain", work] => toolchain(Path::new(work), GN_SOURCE),
        ["toolchain", work, "--gn-source", url] => toolchain(Path::new(work), url),
        ["build", work, rest @ ..] => {
            let mut gn = None;
            let mut out = "engine";
            let mut rest = rest.iter();
            while let Some(flag) = rest.next() {
                match (*flag, rest.next()) {
                    ("--gn", Some(path)) => gn = Some(PathBuf::from(path)),
                    ("--out", Some(name)) => out = name,
                    _ => {
                        return Err(
                            "usage: engine build <work> [--gn <path>] [--out <name>]".into()
                        );
                    }
                }
            }
            build(Path::new(work), gn.as_deref(), out).map(|_| ())
        }
        ["check", work] => verify(Path::new(work)),
        ["export", work] => export(Path::new(work)),
        _ => Err("usage: cargo xtask engine fetch|toolchain|build|check|export <work-dir>".into()),
    }
}

/// `cargo xtask interop [--engine <lib>] [--release] [--bench]`: the ignored
/// client↔server interop tests against a real engine library.
pub fn interop(args: &[String]) -> Result<()> {
    let mut library = std::env::var_os(moon_engine_env()).map(PathBuf::from);
    let mut release = false;
    let mut bench = false;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--engine" => library = rest.next().map(PathBuf::from),
            "--release" => release = true,
            "--bench" => bench = true,
            _ => {
                return Err(
                    "usage: cargo xtask interop [--engine <lib>] [--release] [--bench]".into(),
                );
            }
        }
    }
    let library = library.ok_or(
        "no engine library: pass --engine <path to libmoon_engine.so> or set MOON_NAIVE_ENGINE",
    )?;
    let library = std::path::absolute(&library)?;
    check(
        library.is_file(),
        &format!("{} not found", library.display()),
    )?;
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(root())
        .env(moon_engine_env(), &library)
        .args(["test", "--locked", "-p", "moon-naive", "--lib"]);
    if release {
        command.arg("--release");
    }
    command.args([
        "net::tests::client_e2e",
        "--",
        "--ignored",
        "--test-threads=1",
    ]);
    if bench {
        command.args([
            "--exact",
            "net::tests::client_e2e::client_throughput_benchmark",
            "--nocapture",
        ]);
    } else {
        command.args(["--skip", "client_throughput_benchmark"]);
    }
    println!("RUN interop with {}", library.display());
    let status = command.status()?;
    check(status.success(), "interop tests failed")
}

fn moon_engine_env() -> &'static str {
    "MOON_NAIVE_ENGINE"
}
