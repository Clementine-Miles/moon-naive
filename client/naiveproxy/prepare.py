#!/usr/bin/env python3
# Copyright 2026 moon-naive contributors. SPDX-License-Identifier: Apache-2.0
"""Prepare the pinned Chromium dependency checkout; never modify an existing one."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
UPSTREAM = "https://github.com/klzgrad/naiveproxy.git"


def run(*args, cwd):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, check=True)


def check_source(source, revision):
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, text=True
    ).strip()
    if actual != revision:
        raise ValueError(f"expected {revision}, found {actual}")
    run("git", "apply", "--check", ROOT / "chromium.patch", cwd=source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    location = parser.add_mutually_exclusive_group(required=True)
    location.add_argument("--work-dir", type=Path)
    location.add_argument("--check-source", type=Path)
    parser.add_argument("--target-os", choices=["linux", "android"], default="linux")
    parser.add_argument("--target-cpu", choices=["x64", "x86", "arm64", "arm"], default="x64")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--gn", type=Path)
    parser.add_argument("--ninja", type=Path)
    args = parser.parse_args()
    revision = (ROOT / "UPSTREAM_REVISION").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("invalid source pin")
    if args.check_source:
        if args.build:
            raise ValueError("--check-source checks patch applicability only")
        check_source(args.check_source.resolve(), revision)
        print("pinned patch applicability: passed; compilation: not performed")
        return

    work = args.work_dir.resolve()
    if work == REPOSITORY or work.is_relative_to(REPOSITORY):
        raise ValueError("use a build directory outside the maintained repository")
    if work.exists() and any(work.iterdir()):
        raise ValueError("work directory must be new or empty; existing work is preserved")
    work.mkdir(parents=True, exist_ok=True)
    run("git", "init", cwd=work)
    run("git", "remote", "add", "origin", UPSTREAM, cwd=work)
    run("git", "fetch", "--depth=1", "--filter=blob:none", "origin", revision, cwd=work)
    run("git", "checkout", "--detach", "FETCH_HEAD", cwd=work)
    check_source(work, revision)
    run("git", "apply", ROOT / "chromium.patch", cwd=work)
    for source in (ROOT / "src").rglob("*"):
        if source.is_file():
            destination = work / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    print(f"prepared source: {work}; upstream={revision}")
    if not args.build:
        print("compilation: not performed (use --build with the pinned toolchain installed)")
        return
    gn = args.gn.resolve() if args.gn else work / "src/gn/out/gn"
    ninja = args.ninja.resolve() if args.ninja else shutil.which("ninja")
    clang = work / "src/third_party/llvm-build/Release+Asserts/bin/clang++"
    if not gn.is_file() or not ninja or not clang.is_file():
        raise ValueError(
            "source was prepared, but GN/Ninja/pinned Chromium Clang is missing; "
            "install the pinned upstream toolchain before building (see docs/PROJECT.md)"
        )
    flags = (ROOT / "args.gn").read_text()
    flags += f'\ntarget_os="{args.target_os}"\ntarget_cpu="{args.target_cpu}"\n'
    if args.target_os == "android":
        flags += "is_desktop_android=true\ndefault_min_sdk_version=24\nis_high_end_android=true\n"
    output = f"out/moon-{args.target_os}-{args.target_cpu}"
    run(gn, "gen", output, "--args=" + flags, cwd=work / "src")
    run(ninja, "-C", output, "naive", cwd=work / "src")
    print(f"compiled client: {work / 'src' / output / 'naive'}")
    print("runtime/Android installation/network interoperability: not verified by compilation")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"client preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
