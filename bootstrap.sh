#!/usr/bin/env bash
#
# bootstrap.sh — first-run setup for cfctl.
#
# What this does (in order):
#   1. Detects platform (macOS / Linux).
#   2. Checks required tools: bash, jq, curl, python3.
#   3. Checks optional tools: wrangler, cloudflared.
#   4. Symlinks cfctl into ~/bin (or $CFCTL_BIN_DIR) if not already there.
#   5. Scaffolds an env file at $CFCTL_ENV_FILE (default ~/.config/cfctl/.env) from
#      .env.example with mode 600, but never overwrites an existing file.
#   6. Runs `cfctl doctor` as a smoke test.
#
# What this does NOT do:
#   - Install anything. Tool installation is up to you (homebrew, apt, etc.).
#   - Touch any Cloudflare account. Doctor is read-only.
#   - Overwrite an existing env file or a symlink that points elsewhere.
#
# Flags:
#   --check-only   Only run checks; do not create symlink or env file.
#   -h, --help     Show this help.
#
# Environment overrides:
#   CFCTL_BIN_DIR    Where to symlink cfctl. Default: ~/bin
#   CFCTL_ENV_FILE   Where to scaffold the env file. Default: ~/.config/cfctl/.env
#
# Re-running this script is safe: every step is idempotent.

set -euo pipefail

# Resolve the script through any chain of symlinks (so ROOT_DIR points at the
# checkout, not at $CFCTL_BIN_DIR if someone symlinks bootstrap.sh too).
# python3 is required anyway, so use it to dodge macOS readlink not having -f
# on older versions.
_resolve_script() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}"
  elif readlink -f -- "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    readlink -f -- "${BASH_SOURCE[0]}"
  else
    # Fallback: best-effort resolve (won't follow symlinks, but better than nothing)
    cd -P "$(dirname "${BASH_SOURCE[0]}")" && printf '%s/%s\n' "$(pwd)" "$(basename "${BASH_SOURCE[0]}")"
  fi
}
SCRIPT_PATH="$(_resolve_script)"
ROOT_DIR="$(cd -P "$(dirname "${SCRIPT_PATH}")" && pwd)"
CFCTL_BIN_DIR="${CFCTL_BIN_DIR:-${HOME}/bin}"
CFCTL_CONFIG_HOME="${CFCTL_CONFIG_HOME:-${XDG_CONFIG_HOME:-${HOME}/.config}/cfctl}"
CFCTL_ENV_FILE="${CFCTL_ENV_FILE:-${CFCTL_CONFIG_HOME}/.env}"
CHECK_ONLY=0

# ---------- output helpers (diagnostics go to stderr; stdout reserved for data) ----------

if [[ -t 2 ]]; then
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RESET=$'\033[0m'
else
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_DIM=""; C_RESET=""
fi

step()  { printf '%s==>%s %s\n' "${C_BLUE}${C_BOLD}" "${C_RESET}" "$*" >&2; }
ok()    { printf '%s ok %s   %s\n' "${C_GREEN}" "${C_RESET}" "$*" >&2; }
warn()  { printf '%swarn%s   %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
fail()  { printf '%sfail%s   %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }
info()  { printf '%s     %s%s\n'  "${C_DIM}" "$*" "${C_RESET}" >&2; }

usage() {
  cat <<'EOF'
bootstrap.sh — first-run setup for cfctl.

Usage:
  ./bootstrap.sh [--check-only] [-h|--help]

What it does (in order):
  1. Detects platform (macOS / Linux).
  2. Checks required tools: bash, jq, curl, python3.
  3. Checks optional tools: wrangler, cloudflared.
  4. Symlinks cfctl into ~/bin (or $CFCTL_BIN_DIR) if not already there.
  5. Scaffolds an env file at $CFCTL_ENV_FILE (default ~/.config/cfctl/.env) from
     .env.example with mode 600, but never overwrites an existing file.
  6. Runs `cfctl doctor` as a smoke test.

Flags:
  --check-only  Only run the tool checks; do not modify the filesystem.
  -h, --help    Show this help and exit.

Environment overrides:
  CFCTL_BIN_DIR    Where to symlink cfctl. Default: ~/bin
  CFCTL_ENV_FILE   Where to scaffold the env file. Default: ~/.config/cfctl/.env

Re-running this script is safe: every step is idempotent.
EOF
  exit 0
}

# ---------- arg parsing ----------

for arg in "$@"; do
  case "${arg}" in
    --check-only) CHECK_ONLY=1 ;;
    -h|--help) usage ;;
    *)
      fail "unknown flag: ${arg}"
      info "run: ${0} --help"
      exit 2
      ;;
  esac
done

# ---------- platform detection ----------

step "Detecting platform"
case "$(uname -s)" in
  Darwin) PLATFORM=macos; PKG_HINT="brew install <tool>" ;;
  Linux)  PLATFORM=linux; PKG_HINT="apt install <tool>  # or your distro's equivalent" ;;
  *)      PLATFORM="$(uname -s)"; PKG_HINT="install <tool> via your platform's package manager" ;;
esac
ok "platform: ${PLATFORM}"

# ---------- required tool checks ----------

ERRORS=0
WARNINGS=0

check_required() {
  local tool="$1"
  local why="$2"
  if command -v "${tool}" >/dev/null 2>&1; then
    ok "${tool} found at $(command -v "${tool}")"
  else
    fail "${tool} missing — ${why}"
    info "install hint: ${PKG_HINT/<tool>/${tool}}"
    ERRORS=$((ERRORS + 1))
  fi
}

check_optional() {
  local tool="$1"
  local why="$2"
  local install_hint="$3"
  if command -v "${tool}" >/dev/null 2>&1; then
    ok "${tool} found at $(command -v "${tool}")"
  else
    warn "${tool} missing — ${why} (optional)"
    info "install hint: ${install_hint}"
    WARNINGS=$((WARNINGS + 1))
  fi
}

step "Checking required tools"
check_required bash    "runtime"
check_required jq      "every API response and catalog file is parsed with jq"
check_required curl    "direct Cloudflare API calls"
check_required python3 "cfctl standards audit uses a Python script"

step "Checking optional tools"
check_optional wrangler   "needed for cfctl wrangler ..."   "https://developers.cloudflare.com/workers/wrangler/install-and-update/"
check_optional cloudflared "needed for cfctl cloudflared ... and tunnel surfaces" "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"

if (( ERRORS > 0 )); then
  fail "${ERRORS} required tool(s) missing — install them and re-run."
  exit 1
fi

if (( CHECK_ONLY == 1 )); then
  step "Check-only mode: stopping before any setup actions"
  ok "checks passed (${WARNINGS} optional warning(s))"
  exit 0
fi

# ---------- symlink cfctl into PATH ----------

step "Setting up cfctl on PATH"
mkdir -p "${CFCTL_BIN_DIR}"
LINK_TARGET="${CFCTL_BIN_DIR}/cfctl"
SOURCE_BIN="${ROOT_DIR}/cfctl"

if [[ ! -x "${SOURCE_BIN}" ]]; then
  fail "expected an executable at ${SOURCE_BIN} — re-clone the repo or chmod +x cfctl"
  exit 1
fi

if [[ -L "${LINK_TARGET}" ]]; then
  CURRENT_TARGET="$(readlink "${LINK_TARGET}")"
  if [[ "${CURRENT_TARGET}" == "${SOURCE_BIN}" ]]; then
    ok "${LINK_TARGET} already points to ${SOURCE_BIN}"
  else
    warn "${LINK_TARGET} points to ${CURRENT_TARGET}, not this checkout"
    info "leaving the existing symlink alone — repoint manually if you want this checkout primary:"
    info "  ln -snf '${SOURCE_BIN}' '${LINK_TARGET}'"
  fi
elif [[ -e "${LINK_TARGET}" ]]; then
  warn "${LINK_TARGET} already exists and is not a symlink — leaving it alone"
  info "remove or rename it manually before re-running, if you want cfctl on PATH there"
else
  ln -s "${SOURCE_BIN}" "${LINK_TARGET}"
  ok "symlinked ${LINK_TARGET} -> ${SOURCE_BIN}"
fi

case ":${PATH}:" in
  *":${CFCTL_BIN_DIR}:"*) ok "${CFCTL_BIN_DIR} is on \$PATH" ;;
  *)
    warn "${CFCTL_BIN_DIR} is NOT on \$PATH"
    info "add this to your shell rc (e.g. ~/.zshrc or ~/.bashrc):"
    info "  export PATH=\"${CFCTL_BIN_DIR}:\$PATH\""
    ;;
esac

# ---------- scaffold env file ----------

step "Setting up env file"
ENV_TEMPLATE="${ROOT_DIR}/.env.example"
if [[ ! -f "${ENV_TEMPLATE}" ]]; then
  fail "expected env template at ${ENV_TEMPLATE} — re-clone the repo"
  exit 1
fi

if [[ -f "${CFCTL_ENV_FILE}" ]]; then
  ok "${CFCTL_ENV_FILE} already exists — leaving it alone"
else
  ENV_DIR="$(dirname "${CFCTL_ENV_FILE}")"
  mkdir -p "${ENV_DIR}"
  # Create the file mode-tight from the start. The subshell-umask pattern
  # ensures the file is never observable at 0644 between cp and chmod.
  ( umask 077 && cp "${ENV_TEMPLATE}" "${CFCTL_ENV_FILE}" )
  chmod 600 "${CFCTL_ENV_FILE}"
  ok "scaffolded ${CFCTL_ENV_FILE} from .env.example (mode 600)"
  warn "${CFCTL_ENV_FILE} is empty — fill in CF_DEV_TOKEN and CLOUDFLARE_ACCOUNT_ID before continuing"
  info "open with your editor of choice, e.g.: \$EDITOR ${CFCTL_ENV_FILE}"
fi

# ---------- doctor ----------

step "Running cfctl doctor"
DOCTOR_BIN="${ROOT_DIR}/cfctl"
DOCTOR_OUT="$(mktemp -t cfctl-bootstrap-doctor.XXXXXX)"
trap 'rm -f "${DOCTOR_OUT}"' EXIT
if "${DOCTOR_BIN}" doctor >"${DOCTOR_OUT}" 2>&1; then
  ok "cfctl doctor reports green"
else
  warn "cfctl doctor reports issues — output below:"
  info "(run \`${DOCTOR_BIN} doctor\` to reproduce)"
  printf '%s\n' "----- doctor output -----" >&2
  cat "${DOCTOR_OUT}" >&2
  printf '%s\n' "-------------------------" >&2
  info "common causes: env file empty, CF_DEV_TOKEN wrong scope, CLOUDFLARE_ACCOUNT_ID missing"
  WARNINGS=$((WARNINGS + 1))
fi

# ---------- summary ----------

step "Done"
ok "bootstrap complete"
if (( WARNINGS > 0 )); then
  warn "${WARNINGS} non-fatal warning(s) above — review before relying on cfctl"
fi

cat >&2 <<NEXT

${C_BOLD}Next steps:${C_RESET}
  1. ${C_DIM}# if your env file was just scaffolded:${C_RESET}
     \$EDITOR ${CFCTL_ENV_FILE}
  2. cfctl doctor
  3. cfctl surfaces
  4. cfctl docs

See QUICKSTART.md for a full walkthrough.
NEXT
