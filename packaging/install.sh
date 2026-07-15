#!/usr/bin/env sh
set -eu

repository="${CFCTL_REPOSITORY:-rogu3bear/cfctl}"
version="${CFCTL_VERSION:?set CFCTL_VERSION to an existing release tag}"
install_dir="${CFCTL_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) target="x86_64-unknown-linux-musl" ;;
  Linux:aarch64|Linux:arm64) target="aarch64-unknown-linux-musl" ;;
  *) echo "cfctl installer supports Linux x86_64 and arm64" >&2; exit 1 ;;
esac

base="https://github.com/${repository}/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 "$base/cfctl-$target" -o "$tmp/cfctl-$target"
curl --fail --location --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
(cd "$tmp" && grep "  cfctl-$target\$" SHA256SUMS | sha256sum -c -)
mkdir -p "$install_dir"
install -m 0755 "$tmp/cfctl-$target" "$install_dir/cfctl"
"$install_dir/cfctl" --version
