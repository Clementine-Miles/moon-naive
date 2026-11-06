#!/usr/bin/env bash
# No system package writes, disabled checksums, or lockfile changes.
set -euo pipefail
lab_root=${ACME_LAB_HOME:-/workspace/.moon-naive-acme-lab}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$lab_root/tools/bin"
if [ ! -x "$lab_root/tools/go/bin/go" ]; then
 curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o "$lab_root/tools/go.tar.gz"
 printf '%s  %s\n' 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 "$lab_root/tools/go.tar.gz" | sha256sum -c -
 tar -xzf "$lab_root/tools/go.tar.gz" -C "$lab_root/tools"
fi
if [ ! -d "$lab_root/tools/pebble-src/.git" ]; then
 git clone --no-checkout https://github.com/letsencrypt/pebble.git "$lab_root/tools/pebble-src"
 git -C "$lab_root/tools/pebble-src" checkout --detach d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b
fi
test "$(git -C "$lab_root/tools/pebble-src" rev-parse HEAD)" = d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b
if git -C "$lab_root/tools/pebble-src" diff --quiet; then
 git -C "$lab_root/tools/pebble-src" apply "$repo_root/tools/acme-lab/pebble-lab.patch"
else
 git -C "$lab_root/tools/pebble-src" diff | cmp - "$repo_root/tools/acme-lab/pebble-lab.patch"
fi
export PATH="$lab_root/tools/go/bin:$PATH" GOTOOLCHAIN=local
export GOPATH="$lab_root/go-path" GOCACHE="$lab_root/go-cache"
(cd "$lab_root/tools/pebble-src"; go build -mod=readonly -ldflags '-X main.version=v2.8.0-acme-lab-d52948c' -o ../bin/pebble ./cmd/pebble; go build -mod=readonly -o ../bin/pebble-challtestsrv ./cmd/pebble-challtestsrv)
apt_root=$lab_root/apt
mkdir -p "$apt_root"/{etc/conf.d,etc/sourceparts,state/lists/partial,cache/archives/partial,prefix}
cat > "$apt_root/apt.conf" <<CONF
Dir "$apt_root";
Dir::State "state";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache "cache";
Dir::Etc "etc";
Dir::Etc::parts "conf.d";
Dir::Etc::main "apt.conf";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "sourceparts";
APT::Architecture "amd64";
APT::Sandbox::User "";
CONF
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main' > "$apt_root/etc/sources.list"
APT_CONFIG="$apt_root/apt.conf" /usr/bin/apt-get update > "$apt_root/update.log" 2>&1
APT_CONFIG="$apt_root/apt.conf" /usr/bin/apt-get -o Debug::NoLocking=1 --download-only --no-install-recommends -y install tcpdump tshark > "$apt_root/download.log" 2>&1
for package in "$apt_root"/cache/archives/*.deb; do dpkg-deb -x "$package" "$apt_root/prefix"; done
sha256sum "$apt_root"/cache/archives/*.deb > "$apt_root/packages.sha256"
for package in "$apt_root"/cache/archives/*.deb; do dpkg-deb -f "$package" Package Version; done > "$apt_root/packages.versions"
printf 'Ready: source %s/tools/acme-lab/env.sh\n' "$repo_root"
