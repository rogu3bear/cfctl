#!/usr/bin/env sh
set -eu

sigstore_identity='@SIGSTORE_IDENTITY@'
sigstore_oidc_issuer='@SIGSTORE_OIDC_ISSUER@'

if [ "$sigstore_identity" = "UNSIGNED_ASSEMBLY" ] || [ "$sigstore_oidc_issuer" = "UNSIGNED_ASSEMBLY" ]; then
  echo "cfctl: this installer came from an unsigned assembly; run the identity-bearing release lane" >&2
  exit 1
fi

repository="${CFCTL_REPOSITORY:-rogu3bear/cfctl}"
version="${CFCTL_VERSION:?set CFCTL_VERSION to an existing release tag}"
install_dir="${CFCTL_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    target="x86_64-unknown-linux-musl"
    expected_hash="@X86_64_LINUX_SHA256@"
    ;;
  Linux:aarch64|Linux:arm64)
    target="aarch64-unknown-linux-musl"
    expected_hash="@AARCH64_LINUX_SHA256@"
    ;;
  *)
    echo "cfctl installer supports Linux x86_64 and arm64" >&2
    exit 1
    ;;
esac

command -v cosign >/dev/null 2>&1 || {
  echo "cfctl: cosign is required to verify the release identity" >&2
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "cfctl: sha256sum is required to verify the release content" >&2
  exit 1
}

base="https://github.com/${repository}/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 "$base/cfctl-$target" -o "$tmp/cfctl-$target"
curl --fail --location --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
curl --fail --location --proto '=https' --tlsv1.2 \
  "$base/SHA256SUMS.sigstore.json" -o "$tmp/SHA256SUMS.sigstore.json"

cosign verify-blob \
  --bundle "$tmp/SHA256SUMS.sigstore.json" \
  --certificate-identity "$sigstore_identity" \
  --certificate-oidc-issuer "$sigstore_oidc_issuer" \
  "$tmp/SHA256SUMS" >/dev/null

manifest_matches="$(grep -c "  cfctl-$target\$" "$tmp/SHA256SUMS" || true)"
if [ "$manifest_matches" -ne 1 ]; then
  echo "cfctl: signed checksum manifest has no unique entry for $target" >&2
  exit 1
fi
(cd "$tmp" && grep "  cfctl-$target\$" SHA256SUMS | sha256sum -c -)
actual_hash="$(sha256sum "$tmp/cfctl-$target" | awk '{print $1}')"
if [ "$actual_hash" != "$expected_hash" ]; then
  echo "cfctl: binary hash differs from the identity-bound installer" >&2
  exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "$tmp/cfctl-$target" "$install_dir/cfctl"
"$install_dir/cfctl" --version
