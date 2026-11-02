#!/usr/bin/env bash
# check-cla-sync.sh: CLA signing phrase synchronization gate.
#
# The PyCentric CLA signing phrase is matched LITERALLY by
# .github/workflows/cla.yml (contributor-assistant custom-pr-sign-comment).
# Any drift between CLA.md section 13, the workflow, and the public FAQ would
# leave contributors signing a phrase the tooling rejects. This gate asserts:
#
#   1. CLA.md section 13 declares exactly one signing phrase.
#   2. The version embedded in that phrase matches the CLA.md version header.
#   3. Every signing phrase occurrence in .github/workflows/cla.yml is byte
#      identical to the CLA.md phrase (at least one occurrence required).
#   4. docs/OPEN_CORE_FAQ.md contains no contradicting signing phrase.
#
# Usage: bash scripts/check-cla-sync.sh
#
# Constitutional typography: ASCII hyphens and colons only (no unicode dashes).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

CLA_FILE="CLA.md"
WORKFLOW_FILE=".github/workflows/cla.yml"
FAQ_FILE="docs/OPEN_CORE_FAQ.md"

# Signing phrase shape: "I have read the CLA Document (Version X.Y) and I
# hereby sign the CLA". Deliberately strict so version or wording drift is
# detected as a mismatch.
PHRASE_RE='I have read the CLA Document[[:space:]]*\([^)]*\)[[:space:]]*and I hereby sign the CLA'
MARKER_RE='I have read the CLA Document|I hereby sign the CLA'

pass() { echo "check-cla-sync: PASS: $*"; }
fail() { echo "check-cla-sync: FAIL: $*" >&2; exit 1; }

[ -f "${CLA_FILE}" ] || fail "missing required file: ${CLA_FILE}"
[ -f "${WORKFLOW_FILE}" ] || fail "missing required file: ${WORKFLOW_FILE}"

# --- 1. Extract the signing phrase from CLA.md section 13 ("## 13. How to Sign")
phrase="$(
  awk '
    /^## 13\./ { in_sign = 1; next }
    /^## / { in_sign = 0 }
    in_sign && /^> I have read the CLA Document/ {
      line = $0
      sub(/^> /, "", line)
      sub(/[[:space:]]+$/, "", line)
      print line
      exit
    }
  ' "${CLA_FILE}"
)"
[ -n "${phrase}" ] || fail "no signing phrase blockquote found in ${CLA_FILE} section 13"
echo "check-cla-sync: canonical phrase from ${CLA_FILE} section 13: ${phrase}"

printf '%s\n' "${phrase}" | grep -qE "^${PHRASE_RE}$" \
  || fail "extracted section 13 text is not a well-formed signing phrase: ${phrase}"

# Exactly one phrase-shaped occurrence may exist in CLA.md.
cla_phrase_count="$(grep -cE "${PHRASE_RE}" "${CLA_FILE}" || true)"
[ "${cla_phrase_count}" -eq 1 ] \
  || fail "${CLA_FILE} declares ${cla_phrase_count} signing phrase occurrence(s); expected exactly 1"

# --- 2. Version header must match the version embedded in the phrase.
header_version="$(grep -m1 -oE '^\*\*Version [0-9]+\.[0-9]+' "${CLA_FILE}" | grep -oE '[0-9]+\.[0-9]+' || true)"
phrase_version="$(printf '%s\n' "${phrase}" | grep -oE '\(Version [0-9]+\.[0-9]+\)' | grep -oE '[0-9]+\.[0-9]+' || true)"
[ -n "${header_version}" ] || fail "no '**Version X.Y' header found in ${CLA_FILE}"
[ -n "${phrase_version}" ] || fail "no '(Version X.Y)' embedded in the signing phrase"
[ "${header_version}" = "${phrase_version}" ] \
  || fail "version mismatch: ${CLA_FILE} header says ${header_version} but phrase says ${phrase_version}"
pass "version header and signing phrase agree (Version ${header_version})"

# --- 3. Every signing phrase occurrence in cla.yml must match byte-for-byte.
wf_matches="$(grep -oE "${PHRASE_RE}" "${WORKFLOW_FILE}" || true)"
[ -n "${wf_matches}" ] || fail "no signing phrase occurrence found in ${WORKFLOW_FILE}"
wf_bad=0
wf_count=0
while IFS= read -r match; do
  [ -z "${match}" ] && continue
  wf_count=$((wf_count + 1))
  if [ "${match}" != "${phrase}" ]; then
    echo "check-cla-sync: divergent occurrence in ${WORKFLOW_FILE}: ${match}" >&2
    wf_bad=1
  fi
done <<< "${wf_matches}"
[ "${wf_bad}" -eq 0 ] || fail "signing phrase occurrences in ${WORKFLOW_FILE} diverge from ${CLA_FILE}"
# Any marker-bearing line must embed the canonical phrase literally (catches
# reworded variants that the strict shape regex would not extract).
while IFS= read -r line; do
  [ -z "${line}" ] && continue
  text="${line#*:}"
  case "${text}" in
    *"${phrase}"*) ;;
    *)
      echo "check-cla-sync: marker line without canonical phrase in ${WORKFLOW_FILE}: ${text}" >&2
      fail "reworded signing phrase marker in ${WORKFLOW_FILE}"
      ;;
  esac
done <<< "$(grep -nE "${MARKER_RE}" "${WORKFLOW_FILE}" || true)"
pass "${WORKFLOW_FILE}: ${wf_count} occurrence(s) match ${CLA_FILE} section 13 exactly"

# --- 4. The public FAQ must not document a contradicting signing phrase.
if [ -f "${FAQ_FILE}" ]; then
  faq_bad=0
  while IFS= read -r match; do
    [ -z "${match}" ] && continue
    if [ "${match}" != "${phrase}" ]; then
      echo "check-cla-sync: contradicting signing phrase in ${FAQ_FILE}: ${match}" >&2
      faq_bad=1
    fi
  done <<< "$(grep -oE "${PHRASE_RE}" "${FAQ_FILE}" || true)"
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    text="${line#*:}"
    case "${text}" in
      *"${phrase}"*) ;;
      *)
        echo "check-cla-sync: signing phrase variant in ${FAQ_FILE}: ${text}" >&2
        faq_bad=1
        ;;
    esac
  done <<< "$(grep -nE "${MARKER_RE}" "${FAQ_FILE}" || true)"
  [ "${faq_bad}" -eq 0 ] || fail "${FAQ_FILE} contains a contradicting signing phrase"
  pass "${FAQ_FILE} contains no contradicting signing phrase"
else
  pass "${FAQ_FILE} not present; nothing to cross-check"
fi

pass "CLA signing phrase synchronized (CLA.md section 13, ${WORKFLOW_FILE}, ${FAQ_FILE}), Version ${header_version}"
