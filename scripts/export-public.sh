#!/usr/bin/env bash
# export-public.sh: sanitized, squashed public export of the Cordon AGPL open core.
#
# Produces a fresh Git repository containing one squashed orphan-style commit
# holding only the AGPL-3.0-only covered works (NOTICE.md section 1). Excluded
# works (NOTICE.md section 2), branded distribution artifacts (NOTICE.md
# section 3), build caches, and machine-local scratch never enter the export.
#
# Usage:
#   scripts/export-public.sh [--dry-run] [--check-only] [OUTPUT_DIR]
#
#   --dry-run     Stage, sanitize, and verify the export (runs gitleaks when
#                 available) but do not create the export commit.
#   --check-only  Hygiene checks only (stray tracked artifacts, secret scan).
#                 No staging, no clean-tree gate, no output directory. Used by
#                 `task release:sanitize`.
#   --write-gitleaks-config
#                 Print the shared gitleaks allowlist config (synthetic secret
#                 fixture values) to stdout and exit. Used by CI so the secret
#                 scan and the export share one allowlist source of truth.
#   OUTPUT_DIR    Export destination (default: ../cordon-public).
#
# The script refuses to export from a dirty working tree: the public export
# must correspond exactly to a committed, reviewable tree.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DRY_RUN=0
CHECK_ONLY=0
WRITE_GITLEAKS_CONFIG=0
OUTPUT_DIR="${ROOT_DIR}/../cordon-public"

log() { echo "export-public: $*"; }
die() { echo "export-public: FAIL: $*" >&2; exit 1; }

usage() {
  sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=1 ;;
    --check-only) CHECK_ONLY=1 ;;
    --write-gitleaks-config)
      WRITE_GITLEAKS_CONFIG=1
      ;;
    -h|--help) usage; exit 0 ;;
    "") ;; # tolerate an empty {{.OUTPUT_DIR}} expansion from Taskfile
    *) OUTPUT_DIR="${arg}" ;;
  esac
done

# Excluded works (NOTICE.md section 2) and branded distribution staging
# (section 3): exact repository-relative paths that must never be exported.
EXCLUDED_PATHS=(
  "docs/governance"
  "docs/legal"
  "docs/adr"
  "docs/newsletter"
  "docs/PRD.md"
  "docs/FLUTTER_UI_UX_SIGNOFF.md"
  "AUDIENCE_MANIFEST.md"
  "FEASIBILITY_AND_STRATEGY.md"
  "pc.toml"
  ".opencode"
  "dist"
)

# Machine-local scratch and caches that must never be exported or tracked.
STRAY_NAME_PATTERN='(^|/)(__pycache__|\.pytest_cache|\.ruff_cache|\.mypy_cache|\.venv|target|\.cordon-build-tmp|\.opencode)(/|$)|(^|/)tea\.db|\.py[co]$|\.pcap(ng)?$'

# Synthetic fixture values that gitleaks flags by design: the L7 secret corpus
# and its unit tests must contain fake credential shapes (GitHub PAT, OpenAI
# key, JWT, rule-id markers) to pin the 6 secret signature families. Suppressed
# by EXACT value only: any other secret in the same files still fails the scan.
write_gitleaks_config() {
  local out="$1"
  local config
  config="$(cat <<'EOF'
[extend]
useDefault = true

[allowlist]
description = "Synthetic secret-scanner fixture values (exact match only)"
regexes = [
  '''ghp_1234567890abcdefghijklmnopqrstuvwx''',
  '''sk-1234567890abcdefghijklmnop''',
  '''eyJhbGciOiJIUzI1NiJ9\.eyJzdWIiOiIxMjM0NTY3ODkwIn0\.abcdefghij0123456789klmnop''',
  '''UC-02_SECRET_EXFILTRATION_DETECTED''',
]
EOF
)"
  if [ "${out}" = "-" ]; then
    printf '%s\n' "${config}"
  else
    printf '%s\n' "${config}" > "${out}"
  fi
}

run_gitleaks() {
  local scan_dir="$1"
  if ! command -v gitleaks >/dev/null 2>&1; then
    log "gitleaks not found on PATH; secret scan skipped (install gitleaks before release)"
    return 0
  fi
  local config git_mode
  config="$(mktemp "${TMPDIR:-/tmp}/cordon-gitleaks.XXXXXX.toml")"
  write_gitleaks_config "${config}"
  # Plain directories (export staging) must be scanned file-wise (--no-git);
  # scanning them in git mode would silently inspect 0 bytes.
  git_mode="--no-git"
  if [ -d "${scan_dir}/.git" ]; then
    git_mode=""
  fi
  log "running gitleaks on ${scan_dir}"
  if ! gitleaks detect --no-banner --redact --config "${config}" ${git_mode} --source "${scan_dir}"; then
    rm -f "${config}"
    die "gitleaks reported findings in ${scan_dir}"
  fi
  rm -f "${config}"
}

check_stray_tracked() {
  local strays
  strays="$(git ls-files | grep -E "${STRAY_NAME_PATTERN}" || true)"
  if [ -n "${strays}" ]; then
    echo "${strays}" >&2
    die "machine-local scratch or caches are tracked by git (list above)"
  fi
  log "no stray artifacts tracked"
}

if [ "${WRITE_GITLEAKS_CONFIG}" -eq 1 ]; then
  write_gitleaks_config -
  exit 0
fi

if [ "${CHECK_ONLY}" -eq 1 ]; then
  check_stray_tracked
  run_gitleaks "${ROOT_DIR}"
  log "PASS: hygiene checks clean"
  exit 0
fi

# Refuse to export anything but a fully committed tree.
if [ -n "$(git status --porcelain)" ]; then
  git status --short >&2
  die "working tree is dirty; commit or stash before exporting"
fi

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cordon-export-staging.XXXXXX")"
cleanup() { rm -rf "${STAGING_DIR}"; }
trap cleanup EXIT

log "staging AGPL open core from HEAD"
git archive --format=tar HEAD | tar -x -C "${STAGING_DIR}"

for excluded in "${EXCLUDED_PATHS[@]}"; do
  rm -rf "${STAGING_DIR:?}/${excluded}"
done

verify_no_excluded() {
  local excluded found
  for excluded in "${EXCLUDED_PATHS[@]}"; do
    if [ -e "${STAGING_DIR}/${excluded}" ]; then
      die "excluded path present in export: ${excluded}"
    fi
  done
  found="$(find "${STAGING_DIR}" -mindepth 1 \
    \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.ruff_cache' \
       -o -name '.mypy_cache' -o -name '.venv' -o -name 'target' \
       -o -name '.cordon-build-tmp' -o -name '.opencode' -o -name 'dist' \
       -o -name 'tea.db' -o -name 'tea.db-*' -o -name '*.pcap' -o -name '*.pcapng' \
       -o -name '*.pyc' -o -name '*.pyo' \) -print -quit)"
  if [ -n "${found}" ]; then
    die "stray artifact present in export: ${found#"${STAGING_DIR}"/}"
  fi
  log "verified: no excluded paths or stray artifacts in staging"
}

verify_no_excluded
run_gitleaks "${STAGING_DIR}"

if [ "${DRY_RUN}" -eq 1 ]; then
  log "PASS: dry run complete (staging verified, no export written)"
  exit 0
fi

if [ -e "${OUTPUT_DIR}" ] && [ -n "$(ls -A "${OUTPUT_DIR}" 2>/dev/null)" ]; then
  die "output directory exists and is not empty: ${OUTPUT_DIR}"
fi
mkdir -p "${OUTPUT_DIR}"

( shopt -s dotglob nullglob; mv "${STAGING_DIR}"/* "${OUTPUT_DIR}"/ )

git -C "${OUTPUT_DIR}" init -q -b main
git -C "${OUTPUT_DIR}" add -A
git -C "${OUTPUT_DIR}" \
  -c user.name="Cordon Public Export" \
  -c user.email="engineering@pycentric.co.za" \
  commit -q -m "Cordon AGPL-3.0-only open core: squashed public export"

log "PASS: public export written to ${OUTPUT_DIR} (single squashed commit on 'main')"
