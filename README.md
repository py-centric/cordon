# CLA signature store (managed branch)

This branch holds `signatures/cla.json`, the signature record for the PyCentric
Contributor License Agreement (see `CLA.md` on `main`), maintained automatically
by the CLA Assistant workflow (`.github/workflows/cla.yml`).

Rules:
- Do NOT create or edit `signatures/cla.json` manually: the workflow creates and
  updates it. Manual creation makes the workflow fail.
- Do NOT protect this branch: the workflow pushes signature commits to it.
- Protect `main` instead, with the "CLA" status check required.
