#!/usr/bin/env bash
#
# scripts/setup-github.sh
#
# Idempotent GitHub repository bootstrap for py-centric/cordon. Uses the
# authenticated `gh` CLI against the origin repository. Safe to re-run at any
# time: every write is a full replace (PUT/PATCH), never an append.
#
# What it configures:
#   1. Branch protection on `main` (required checks strict, PR-only merges,
#      stale reviews dismissed, no force pushes, no deletions).
#   2. Explicit non-protection of `cla-signatures` (CLA signature store).
#   3. Repository metadata: exact description, topics, homepage unset.
#   4. Vulnerability alerts + Dependabot security updates (best effort).
#
# Constitution: ASCII hyphens and colons only. No unicode em/en dashes.
#
# Usage:
#   bash scripts/setup-github.sh
#   REVIEW_COUNT=1 bash scripts/setup-github.sh    # once external contributors arrive

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO="${REPO:-py-centric/cordon}"
BRANCH="${BRANCH:-main}"
CLA_BRANCH="${CLA_BRANCH:-cla-signatures}"

# Approving reviews required before merge.
# 0 today: solo founder, no second human exists to review. Raise to 1 as soon
# as the first external contributor lands, then keep it there.
REVIEW_COUNT="${REVIEW_COUNT:-0}"

# enforce_admins is INTENTIONALLY false: the sole maintainer must be able to
# hotfix `main` during a P1 incident without a second approver. Flip to true
# once an on-call rotation and a second maintainer exist. Documented deviation
# from full lockdown, agreed in the CTO ops runbook.
ENFORCE_ADMINS=false

DESCRIPTION="Cordon: zero-unsafe Rust Linux execution sandbox with a reproducible Cordonfile engine and L3-L7 network inspection (netns, AppArmor, bubblewrap, L7 egress policy, PCAP). AGPL-3.0-only."

# NOTE: the spec topic "agpl-3.0" is rejected by GitHub (HTTP 422: topics may
# only contain lowercase letters, numbers, and hyphens, so dots are illegal).
# "agpl-3" is the nearest compliant spelling.
TOPICS=(linux sandbox security apparmor bubblewrap network-namespace mitmproxy ai-agents egress-policy cordonfile rust agpl-3)

# Required status checks (strict: branch must be up to date before merge).
#
# NAMING NOTE: GitHub Actions reports every workflow job under its job `name:`
# display string, NOT its job ID, and branch protection matches that exact
# string. The mapping (job IDs and names are unchanged in the workflows) is:
#   lint        -> "Lint (rustfmt + clippy)"
#   test        -> "Test (Rust engine + Python reference stack)"
#   coverage    -> "Coverage (cargo llvm-cov)"
#   audit       -> "Dependency audit (cargo deny + cargo audit)"
#   secret-scan -> "Secret scan (gitleaks, full history)"
#   cla         -> "cla" (cla.yml job has no name: field, so ID == check name)
# If the ci.yml job `name:` fields are ever removed, replace these strings
# with the bare job IDs (lint, test, coverage, audit, secret-scan).
REQUIRED_CHECKS=(
  "Lint (rustfmt + clippy)"
  "Test (Rust engine + Python reference stack)"
  "Coverage (cargo llvm-cov)"
  "Dependency audit (cargo deny + cargo audit)"
  "Secret scan (gitleaks, full history)"
  "cla"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

step() { printf '\n==> %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

# Run an optional step; report the exact error but never abort the script.
optional() {
  local label="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    info "${label}: OK"
  else
    info "${label}: FAILED (continuing) -> ${out}"
  fi
}

command -v gh >/dev/null 2>&1 || die "gh CLI not found on PATH"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH (needed to build/verify payloads)"

step "0/5 Preconditions"
info "gh identity: $(gh api user --jq .login) (target repo: ${REPO})"
gh api "repos/${REPO}" --jq '"repository reachable: \(.full_name) (visibility: \(.visibility), default branch: \(.default_branch))"' | sed 's/^/    /'

# ---------------------------------------------------------------------------
# 1. Branch protection on main
# ---------------------------------------------------------------------------

step "1/5 Applying branch protection on '${BRANCH}' (full replace; idempotent)"

contexts_json="$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . | jq -s -c .)"
protection_payload="$(jq -n \
  --argjson contexts "${contexts_json}" \
  --argjson enforce_admins "${ENFORCE_ADMINS}" \
  --argjson review_count "${REVIEW_COUNT}" \
  '{
    required_status_checks: { strict: true, contexts: $contexts },
    enforce_admins: $enforce_admins,
    required_pull_request_reviews: {
      dismiss_stale_reviews: true,
      require_code_owner_reviews: false,
      required_approving_review_count: $review_count
    },
    restrictions: null,
    allow_force_pushes: false,
    allow_deletions: false
  }')"

gh api -X PUT "repos/${REPO}/branches/${BRANCH}/protection" --input - <<<"${protection_payload}" >/dev/null
info "protection applied"

step "1/5 Protection summary (read back from API)"
gh api "repos/${REPO}/branches/${BRANCH}/protection" --jq '{
  required_checks_strict: .required_status_checks.strict,
  required_checks: .required_status_checks.contexts,
  enforce_admins: .enforce_admins.enabled,
  prs_required: (.required_pull_request_reviews != null),
  approving_reviews_required: .required_pull_request_reviews.required_approving_review_count,
  dismiss_stale_reviews: .required_pull_request_reviews.dismiss_stale_reviews,
  force_pushes_blocked: (.allow_force_pushes.enabled | not),
  deletions_blocked: (.allow_deletions.enabled | not)
}' | sed 's/^/    /'

# ---------------------------------------------------------------------------
# 2. cla-signatures must stay UNPROTECTED (CLA Assistant pushes to it)
# ---------------------------------------------------------------------------

step "2/5 Verifying '${CLA_BRANCH}' is NOT protected"
if gh api "repos/${REPO}/branches/${CLA_BRANCH}" >/dev/null 2>&1; then
  if gh api "repos/${REPO}/branches/${CLA_BRANCH}/protection" >/dev/null 2>&1; then
    info "protection found on ${CLA_BRANCH}; removing it"
    gh api -X DELETE "repos/${REPO}/branches/${CLA_BRANCH}/protection" >/dev/null
    info "protection removed; ${CLA_BRANCH} is now unprotected"
  else
    info "${CLA_BRANCH} exists and is not protected (verified HTTP 404)"
  fi
else
  info "${CLA_BRANCH} does not exist yet (CLA Assistant creates it on first signature)"
  info "nothing to unprotect; do NOT add branch protection to it later"
fi

# ---------------------------------------------------------------------------
# 3. Repository metadata
# ---------------------------------------------------------------------------

step "3/5 Setting repository description, topics, homepage (homepage cleared)"
# description + homepage via PATCH. Topics MUST go through the dedicated
# PUT /repos/{owner}/{repo}/topics endpoint: the PATCH endpoint silently
# drops the topics field (verified 2026-11-02).
repo_payload="$(jq -n \
  --arg description "${DESCRIPTION}" \
  '{ description: $description, homepage: "" }')"
topics_payload="$(printf '%s\n' "${TOPICS[@]}" | jq -R . | jq -s -c '{names: .}')"

gh api -X PATCH "repos/${REPO}" --input - <<<"${repo_payload}" --jq '{
  description: .description,
  homepage: (.homepage // "")
}' | sed 's/^/    /'
gh api -X PUT "repos/${REPO}/topics" --input - <<<"${topics_payload}" --jq '"topics: \(.)"' | sed 's/^/    /'
info "wiki setting left at repository default (not modified)"

# ---------------------------------------------------------------------------
# 4. Security features (best effort: plan/API dependent)
# ---------------------------------------------------------------------------

step "4/5 Enabling vulnerability alerts + Dependabot security updates"
optional "vulnerability alerts enable" \
  gh api -X PUT "repos/${REPO}/vulnerability-alerts"
optional "Dependabot security updates enable" \
  gh api -X PUT "repos/${REPO}/automated-security-fixes"
optional "vulnerability alerts verify" \
  gh api "repos/${REPO}/vulnerability-alerts"
optional "Dependabot security updates verify" \
  gh api "repos/${REPO}/automated-security-fixes"

# ---------------------------------------------------------------------------
# 5. Final repository state
# ---------------------------------------------------------------------------

step "5/5 Final repository state"
gh api "repos/${REPO}" --jq '{
  description: .description,
  homepage: (.homepage // ""),
  topics: .topics,
  has_wiki: .has_wiki,
  default_branch: .default_branch,
  visibility: .visibility
}' | sed 's/^/    /'

printf '\nDone. All steps are idempotent; re-run this script at any time.\n'
