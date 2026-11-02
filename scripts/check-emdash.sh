#!/usr/bin/env bash
# PyCentric constitutional typography check.
#
# Scans Rust sources and governance documentation for forbidden unicode
# em-dash (U+2014) and en-dash (U+2013) characters. The constitutional rule
# requires hyphens (-), colons (:), and parentheses exclusively.
#
# Replaces the previous machine-absolute validator invocation in
# `task validate-docs` with a self-contained, repo-local check.
set -euo pipefail

cd "$(dirname "$0")/.."

EMDASH="$(printf '\u2014')"
ENDASH="$(printf '\u2013')"

TARGETS=(
  src
  tests
  README.md
  SECURITY.md
  CHANGELOG.md
  AUDIENCE_MANIFEST.md
  FEASIBILITY_AND_STRATEGY.md
  docs/PRD.md
  docs/QUICKSTART.md
  docs/OPERATIONS_AND_WORKLOAD_GUIDE.md
  docs/adr/ADR-L0-SEC-02.md
  docs/newsletter/post-your-ai-agent-runs-as-you.php
)

violations=0
for target in "${TARGETS[@]}"; do
  if [ ! -e "${target}" ]; then
    continue
  fi
  if hits="$(grep -rn -e "${EMDASH}" -e "${ENDASH}" "${target}" 2>/dev/null)"; then
    echo "FORBIDDEN unicode dash detected in ${target}:"
    echo "${hits}"
    violations=$((violations + 1))
  fi
done

if [ "${violations}" -gt 0 ]; then
  echo "check-emdash: FAILED (${violations} target(s) contain forbidden unicode dashes)" >&2
  exit 1
fi

echo "check-emdash: OK (no em-dash or en-dash characters in Rust sources or governance docs)"
