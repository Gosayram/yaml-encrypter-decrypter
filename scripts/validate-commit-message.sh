#!/usr/bin/env bash
set -euo pipefail

MSG_FILE="${1:-}"
if [[ -z "${MSG_FILE}" || ! -f "${MSG_FILE}" ]]; then
  echo "commit-msg validator: message file is required"
  exit 1
fi

msg="$(head -n 1 "${MSG_FILE}" | tr -d '\r')"

allowed_types='ADD|UPD|FIX|BUGFIX|FEATURE|REFACTOR|STYLE|LINT|RULE|INIT|DOCS|TEST|CI'
base_pattern="^\\[(${allowed_types})\\] - .+;$"

if [[ "${msg}" =~ [[:space:]]$ ]]; then
  echo "Invalid commit message: trailing spaces are not allowed."
  exit 1
fi

if (( ${#msg} > 72 )); then
  echo "Invalid commit message: max length is 72 characters."
  exit 1
fi

if ! [[ "${msg}" =~ ${base_pattern} ]]; then
  echo "Invalid commit message format."
  echo "Expected: [TYPE] - description;"
  echo "Allowed types: [ADD] [UPD] [FIX] [BUGFIX] [FEATURE] [REFACTOR] [STYLE] [LINT] [RULE] [INIT] [DOCS] [TEST] [CI]"
  exit 1
fi

staged_files="$(git diff --cached --name-only --diff-filter=ACMR || true)"

has_changelog=0
has_readme=0
has_gitignore=0

while IFS= read -r f; do
  [[ -z "${f}" ]] && continue
  case "${f}" in
    CHANGELOG.md) has_changelog=1 ;;
    README.md) has_readme=1 ;;
    .gitignore) has_gitignore=1 ;;
  esac
done <<< "${staged_files}"

# Special file rules are strict and override everything else.
if (( has_changelog + has_readme + has_gitignore > 1 )); then
  echo "Invalid commit scope: split special files into separate commits."
  echo "Special rules conflict for CHANGELOG.md / README.md / .gitignore."
  exit 1
fi

if (( has_changelog == 1 )); then
  if [[ "${msg}" != "[UPD] - bump CHANGELOG;" ]]; then
    echo "For CHANGELOG.md commit message must be exactly:"
    echo "[UPD] - bump CHANGELOG;"
    exit 1
  fi
fi

if (( has_gitignore == 1 )); then
  if [[ "${msg}" != "[UPD] - bump gitignore;" ]]; then
    echo "For .gitignore commit message must be exactly:"
    echo "[UPD] - bump gitignore;"
    exit 1
  fi
fi

if (( has_readme == 1 )); then
  if ! [[ "${msg}" =~ ^\[DOCS\]\ -\ .+\;$ ]]; then
    echo "For README.md commit message type must be [DOCS]."
    exit 1
  fi
fi

exit 0
