#!/bin/bash
# Source admission for the canonical pre-push proof. Invoked by the gate.
# The exact residue declaration is source policy, never an environment waiver.

snapshot_push_source() (
  set -euo pipefail
  local snapshot="$1" status="${1}.status" inventory="${1}.paths"
  local declaration=.githooks/pre-push-residue.tsv
  local record path metadata digest size mode extra source_digest declared_source
  local expected="${1}.expected" actual="${1}.actual" observed="${1}.observed"

  refuse() { echo "pre-push REFUSED: $*" >&2; exit 1; }
  if ! git status --porcelain=v1 -z --untracked-files=all > "$status"; then
    refuse "could not observe checked-out source cleanliness"
  fi
  while IFS= read -r -d '' record; do
    case "$record" in
      '?? experiments/ai-search/'*) ;;
      *) refuse "tracked and untracked source must be clean outside declared residue" ;;
    esac
  done < "$status"
  [ -z "$record" ] || refuse "incomplete checked-out source observation"

  if [ ! -e experiments ] && [ ! -L experiments ]; then
    printf '%s\n' 'tracked-clean; residue-absent' > "$snapshot"
    exit 0
  fi
  [ -d experiments ] && [ ! -L experiments ] || refuse "residue root must be a real directory"
  [ -f "$declaration" ] && [ ! -L "$declaration" ] || refuse "missing regular residue declaration"
  git ls-files -z -- experiments/ > "${1}.tracked" || refuse "could not observe tracked residue paths"
  [ ! -s "${1}.tracked" ] || refuse "declared residue must remain untracked"

  # A new tracked input invalidates this reviewed non-consumption classification.
  # Excluding only the declaration avoids a self-referential digest. Its own bytes
  # remain bound by tracked cleanliness and the exact pushed HEAD/ref checks.
  git ls-tree --full-tree -r -z HEAD > "${1}.tree" || refuse "could not enumerate the reviewed proof input tree"
  [ -s "${1}.tree" ] || refuse "empty proof input tree observation"
  : > "${1}.bound"
  while IFS= read -r -d '' record; do
    metadata="${record%%$'\t'*}"
    path="${record#*$'\t'}"
    [[ "$metadata" =~ ^(100644|100755|120000|160000)\ (blob|commit)\ [0-9a-f]{40}$ ]] &&
      [ "$path" != "$record" ] && [ -n "$path" ] || refuse "invalid proof input tree observation"
    if [ "$path" != "$declaration" ]; then
      printf '%s\0' "$record" >> "${1}.bound"
    fi
  done < "${1}.tree"
  [ -z "$record" ] && [ -s "${1}.bound" ] || refuse "incomplete proof input tree observation"
  source_digest="$(shasum -a 256 "${1}.bound")" || refuse "could not hash the reviewed proof input tree"
  source_digest="${source_digest%% *}"
  exec 3< "$declaration"
  IFS=' ' read -r record declared_source extra <&3 || refuse "invalid residue declaration header"
  [ "$record" = source-tree-sha256 ] && [[ "$declared_source" =~ ^[0-9a-f]{64}$ ]] &&
    [ -z "$extra" ] || refuse "invalid residue declaration header"
  [ "$source_digest" = "$declared_source" ] || refuse "reviewed residue proof input tree changed"

  : > "$expected"
  : > "$observed"
  while IFS=' ' read -r digest size mode path extra; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] && [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] &&
      [ "$mode" = 644 ] && [ -z "$extra" ] || refuse "invalid residue declaration entry"
    [[ "$path" =~ ^experiments/ai-search/[a-zA-Z0-9_.-]+$ ]] &&
      [ "${path##*/}" != . ] && [ "${path##*/}" != .. ] &&
      [ "${path##*/}" != .git ] || refuse "invalid residue declaration path"
    printf '%s\n' "$path" >> "$expected"
    printf '%s %s %s %s\n' "$digest" "$size" "$mode" "$path" >> "$observed"
  done <&3
  [ -z "$digest$size$mode$path$extra" ] || refuse "incomplete residue declaration entry"
  exec 3<&-
  [ -s "$expected" ] || refuse "empty residue declaration"
  LC_ALL=C sort "$expected" > "${1}.sorted"
  cmp -s "$expected" "${1}.sorted" || refuse "residue declaration must be sorted"
  [ "$(uniq "$expected" | wc -l | tr -d ' ')" = "$(wc -l < "$expected" | tr -d ' ')" ] ||
    refuse "duplicate residue declaration path"

  find experiments -print0 > "$inventory" || refuse "could not inventory preserved residue"
  : > "$actual"
  : > "${1}.hashes"
  while IFS= read -r -d '' path; do
    [ ! -L "$path" ] || refuse "residue symlink is not admitted"
    case "$path" in
      experiments|experiments/ai-search)
        [ -d "$path" ] || refuse "residue parent is not a directory"
        ;;
      *)
        [ -f "$path" ] || refuse "extra directory or special residue file"
        [[ "$path" =~ ^experiments/ai-search/[a-zA-Z0-9_.-]+$ ]] || refuse "undeclared residue path"
        case "$(uname -s)" in
          Darwin) record="$(stat -f '%z %Lp' "$path")" ;;
          Linux) record="$(stat -c '%s %a' "$path")" ;;
          *) refuse "unsupported residue metadata observation platform" ;;
        esac
        digest="$(shasum -a 256 -- "$path")" || refuse "could not hash preserved residue"
        printf '%s\n' "$path" >> "$actual"
        printf '%s %s %s\n' "${digest%% *}" "$record" "$path" >> "${1}.hashes"
        ;;
    esac
  done < "$inventory"
  LC_ALL=C sort "$actual" > "${1}.sorted"
  cmp -s "$expected" "${1}.sorted" || refuse "residue inventory differs from declaration"
  LC_ALL=C sort -k4,4 "${1}.hashes" > "${1}.sorted"
  cmp -s "$observed" "${1}.sorted" || refuse "residue bytes, size or mode differ from declaration"
  # Include directory modes so preservation checks also detect parent-mode drift.
  case "$(uname -s)" in
    Darwin) stat -f '%Lp %N' experiments experiments/ai-search > "$snapshot" ;;
    Linux) stat -c '%a %n' experiments experiments/ai-search > "$snapshot" ;;
  esac
  cat "$declaration" >> "$snapshot"
)

snapshot_push_source "$1"
