<!--
Thank you for contributing to Cordon (open core, AGPL-3.0-only).
Fill in every section. See CONTRIBUTING.md for the full workflow and
CLA.md for the Contributor License Agreement (Version 1.1).
-->

## Summary

<!-- One or two sentences describing what this PR does. -->

## Problem / Motivation

<!-- What problem does this solve? Link related issues with "Fixes #123" where applicable. -->

## Changes

<!-- Bullet list of the substantive changes in this PR. -->

-

## Testing

<!-- Check every gate you ran locally. All gates must pass before merge. -->

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `ruff check src tests`
- [ ] `pytest`
- [ ] `bash scripts/check-emdash.sh` (typography rule: ASCII hyphens and colons only, no unicode dashes)

## Checklist

- [ ] I have signed the CLA via the exact PR comment phrase (see CONTRIBUTING.md):
      "I have read the CLA Document (Version 1.1) and I hereby sign the CLA"
      (corporate signers: post that phrase first, then a second comment with the
      entity attestation per CLA.md)
- [ ] I have disclosed any material AI-generated content (CLA section 4.2)
- [ ] I added/updated tests where behavior changed
- [ ] I updated docs/CHANGELOG where user-facing
- [ ] This PR contains no excluded-works content (governance/commercial/legal docs)
- [ ] No secrets or credentials are included

## Notes for reviewers

<!-- Anything reviewers should focus on, design trade-offs, follow-ups, or rollout notes. -->
