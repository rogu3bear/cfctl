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
printf '/target/\n' >"$repository/.gitignore"

git -C "$repository" init --quiet
git -C "$repository" add bootstrap.sh .gitignore
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

# A completed offline install may have no evidence authority yet. Existing
# authorities must be inspectable; a successful status read is not a repair.
rm "$repository/untracked-compiler-input"
install_root="$fixture_root/install"
mkdir -p "$install_root/bin"
cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$*" >>"$CFCTL_BOOTSTRAP_TEST_CARGO_LOG"
case "$1" in
  build)
    [ "$#" -eq 8 ]
    [ "$1 $2 $3 $4 $5 $6 $7" = 'build --locked -p xtask --target fixture-native --target-dir' ]
    [ "${CFCTL_BOOTSTRAP_TEST_FAIL:-}" != build ] || exit 88
    mkdir -p "$8/$6/debug"
    cat >"$8/$6/debug/xtask" <<'VERIFIER'
#!/usr/bin/env sh
set -eu
[ "$*" = verify ]
printf 'verify\n' >>"$CFCTL_BOOTSTRAP_TEST_PROOF_LOG"
[ "${CFCTL_BOOTSTRAP_TEST_FAIL:-}" != verify ] || exit 89
VERIFIER
    chmod 0755 "$8/$6/debug/xtask" ;;
  install) [ -s "$CFCTL_BOOTSTRAP_TEST_PROOF_LOG" ] ;;
  *) echo "unexpected Cargo command: $*" >&2; exit 98 ;;
esac
EOF
cat >"$fake_bin/rustc" <<'EOF'
#!/usr/bin/env sh
[ "${CFCTL_BOOTSTRAP_TEST_FAIL:-}" != host ] || exit 87
if [ "${CFCTL_BOOTSTRAP_TEST_FAIL:-}" = invalid_host ]; then
  printf 'host: ../wrong\n'
  exit 0
fi
printf 'host: fixture-native\n'
EOF
cat >"$install_root/bin/cfctl" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$*" >>"$CFCTL_BOOTSTRAP_TEST_BINARY_LOG"
case "$*" in
  'version --json')
    printf '{"git_commit":"%s"}\n' "$CFCTL_BOOTSTRAP_TEST_HEAD" ;;
  'agents doctor'|'doctor') ;;
  'auth evidence-key status --json')
    case "$CFCTL_BOOTSTRAP_TEST_EVIDENCE_STATE" in
      empty) printf '{"ok":true,"result":{"status":{"initialized":false}}}\n' ;;
      initialized) printf '{"ok":true,"result":{"status":{"initialized":true}}}\n' ;;
      *) echo "fixture evidence status failure: $CFCTL_BOOTSTRAP_TEST_EVIDENCE_STATE" >&2; exit 1 ;;
    esac ;;
  *) echo "unexpected bootstrap command: $*" >&2; exit 98 ;;
esac
EOF
chmod 0755 "$install_root/bin/cfctl"
proof_log="$fixture_root/proof.log"
run_bootstrap() {
  (
    cd "$repository"
    PATH="$fake_bin:$PATH" \
      CARGO_INSTALL_ROOT="$install_root" \
      CFCTL_BOOTSTRAP_TEST_CARGO_LOG="$cargo_log" \
      CFCTL_BOOTSTRAP_TEST_PROOF_LOG="$proof_log" \
      CFCTL_BOOTSTRAP_TEST_BINARY_LOG="$binary_log" \
      CFCTL_BOOTSTRAP_TEST_HEAD="$(git rev-parse HEAD)" \
      CFCTL_BOOTSTRAP_TEST_EVIDENCE_STATE="$evidence_state" \
      CFCTL_BOOTSTRAP_TEST_FAIL="${failure:-}" \
      sh ./bootstrap.sh "$@"
  ) >"$fixture_root/stdout" 2>"$fixture_root/stderr"
}
for evidence_state in empty initialized inaccessible split malformed; do
  binary_log="$fixture_root/$evidence_state-binary.log"
  : >"$proof_log"
  result=0
  run_bootstrap --skip-agent-sync || result=$?
  case "$evidence_state" in
    empty|initialized)
      if [ "$result" -ne 0 ]; then
        cat "$fixture_root/stderr" >&2
        echo "bootstrap rejected coherent $evidence_state evidence state" >&2
        exit 1
      fi ;;
    *)
      if [ "$result" -ne 0 ] || ! grep -q "fixture evidence status failure: $evidence_state" "$fixture_root/stderr"; then
        echo "bootstrap hid $evidence_state failure or invalidated a completed install" >&2
        exit 1
      fi
      grep -q 'cfctl is installed' "$fixture_root/stderr" ;;
  esac
  [ "$(grep -c '^auth evidence-key status --json$' "$binary_log")" -eq 1 ]
  [ "$(grep -c '^doctor$' "$binary_log")" -eq 1 ]
done

# A prior successful verifier must not be reused after host/build failure.
for failure in host invalid_host build verify; do
  : >"$cargo_log"
  : >"$proof_log"
  binary_log="$fixture_root/$failure-binary.log"
  if run_bootstrap --skip-agent-sync; then
    echo "bootstrap admitted a $failure failure" >&2
    exit 1
  fi
  [ ! -e "$binary_log" ]
  if grep -q '^install ' "$cargo_log"; then
    echo "bootstrap installed after a $failure failure" >&2
    exit 1
  fi
  case "$failure" in host|invalid_host|build) [ ! -s "$proof_log" ] ;; esac
done
failure=

# Check-only proves the native host even with a configured cross target and
# an output directory containing spaces; it must never invoke installation.
export CARGO_BUILD_TARGET=fixture-cross
export CARGO_TARGET_DIR="$fixture_root/output with spaces"
: >"$cargo_log"
: >"$proof_log"
binary_log="$fixture_root/check-only-binary.log"
run_bootstrap --check-only
[ -s "$proof_log" ]
[ ! -e "$binary_log" ]
if grep -q '^install ' "$cargo_log"; then
  echo "check-only invoked installation" >&2
  exit 1
fi
