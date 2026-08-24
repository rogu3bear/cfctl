#!/usr/bin/env sh
set -eu

source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/cfctl-bootstrap-cleanliness.XXXXXX")
fixture_root=$(CDPATH= cd -- "$fixture_root" && pwd -P)
trap 'rm -rf "$fixture_root"' EXIT HUP INT TERM

repository="$fixture_root/repository"
fake_bin="$fixture_root/bin"
cargo_log="$fixture_root/cargo.log"
mkdir -p "$repository" "$fake_bin"
cp "$source_root/bootstrap.sh" "$repository/bootstrap.sh"

git -C "$repository" init --quiet
git -C "$repository" add bootstrap.sh
git -C "$repository" \
  -c user.name='cfctl bootstrap test' \
  -c user.email='cfctl-bootstrap@example.invalid' \
  commit --quiet -m 'bootstrap fixture'

cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$*" >>"$CFCTL_BOOTSTRAP_TEST_CARGO_LOG"
exit 99
EOF
cat >"$fake_bin/rustc" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
chmod 0755 "$fake_bin/cargo" "$fake_bin/rustc"

touch "$repository/untracked-compiler-input"
if (
  cd "$repository"
  PATH="$fake_bin:$PATH" \
    CFCTL_BOOTSTRAP_TEST_CARGO_LOG="$cargo_log" \
    sh ./bootstrap.sh --check-only
) >"$fixture_root/stdout" 2>"$fixture_root/stderr"; then
  echo "bootstrap unexpectedly admitted an untracked file" >&2
  exit 1
fi

if [ -e "$cargo_log" ]; then
  echo "bootstrap invoked cargo before rejecting the untracked file" >&2
  exit 1
fi
if ! grep -q "tracked-and-untracked clean checkout" "$fixture_root/stderr"; then
  sed -n '1,20p' "$fixture_root/stderr" >&2
  echo "bootstrap did not report its tracked-and-untracked cleanliness blocker" >&2
  exit 1
fi
