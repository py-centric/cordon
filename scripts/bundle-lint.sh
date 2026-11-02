#!/usr/bin/env bash
# bundle-lint.sh: enforce public-bundle document hygiene rules on every
# publicly distributed document before it may leave the repository.
# Wired into CI via .github/workflows/ci.yml (lint job).
#
# Authority: the hygiene rules below implement the public-distribution
# expectations set out in NOTICE.md (open-core scope map) and CONTRIBUTING.md
# (public contribution surface). They supersede the previous bundle manifest
# controls; nothing here depends on non-published documents.
#
# Rules enforced:
#   1. No file:/// absolute links and no machine-absolute /home/<user>/... paths.
#   2. No markdown links from public documents into non-published (internal)
#      documents that are excluded works under NOTICE.md section 2.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUNDLE_DOCS=(
    README.md
    SECURITY.md
    docs/QUICKSTART.md
    docs/OPERATIONS_AND_WORKLOAD_GUIDE.md
    CHANGELOG.md
    LICENSE
)
BUNDLE_DIRS=(configs packaging/completions)
# Non-published link targets (excluded works, NOTICE.md section 2).
INTERNAL_PATTERN='FEASIBILITY_AND_STRATEGY|docs/legal/|docs/adr/|docs/newsletter/|docs/governance/|docs/PRD\.md|FLUTTER_UI_UX_SIGNOFF|AUDIENCE_MANIFEST'

fail=0

check_file() {
    local file="$1"
    if grep -nH "file:///" "$file"; then
        echo "BUNDLE-LINT FAIL: file:/// absolute link in ${file#"$ROOT_DIR"/}" >&2
        fail=1
    fi
    if grep -nE "/home/[A-Za-z0-9._-]+/" "$file"; then
        echo "BUNDLE-LINT FAIL: machine-absolute /home path in ${file#"$ROOT_DIR"/}" >&2
        fail=1
    fi
    if grep -nE "\]\([^)]*(${INTERNAL_PATTERN})" "$file"; then
        echo "BUNDLE-LINT FAIL: markdown link to non-published document in ${file#"$ROOT_DIR"/}" >&2
        fail=1
    fi
}

for doc in "${BUNDLE_DOCS[@]}"; do
    if [[ ! -f "${ROOT_DIR}/${doc}" ]]; then
        echo "BUNDLE-LINT FAIL: bundle document missing: ${doc}" >&2
        fail=1
        continue
    fi
    check_file "${ROOT_DIR}/${doc}"
done

for dir in "${BUNDLE_DIRS[@]}"; do
    while IFS= read -r file; do
        check_file "$file"
    done < <(find "${ROOT_DIR}/${dir}" -type f 2>/dev/null)
done

if [[ "$fail" -eq 0 ]]; then
    echo "bundle-lint: PASS (${#BUNDLE_DOCS[@]} documents + ${#BUNDLE_DIRS[@]} directories clean)"
fi
exit "$fail"
