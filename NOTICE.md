# NOTICE: Cordon Licensing Scope Map

Copyright (c) 2026 PyCentric (Pty) Ltd.

Cordon is an open-core product. Licensing is split as follows. If a work is not
listed as an Excluded Work or a Branded Distribution Package below, it is licensed
under the GNU Affero General Public License version 3 only.

## 1. Open core: AGPL-3.0-only

SPDX-License-Identifier: `AGPL-3.0-only`. The full text is in [`LICENSE`](LICENSE).

Covered works (non-exhaustive; the default):

- Engine source: [`src/`](src) (Rust core and the Python mitmproxy L7 policy addon)
- Tests and fixtures: [`tests/`](tests), [`deploy/tests/`](deploy/tests)
- Deployment assets: [`deploy/`](deploy) (AppArmor profiles, netns scripts, sudoers, systemd assets)
- Packaging definitions: [`packaging/`](packaging), build and release tooling: [`scripts/`](scripts)
- Client surfaces: [`flutter_client/`](flutter_client)
- Configuration references: [`configs/`](configs)
- Operator documentation: [`README.md`](README.md), [`SECURITY.md`](SECURITY.md),
  [`CHANGELOG.md`](CHANGELOG.md), [`docs/QUICKSTART.md`](docs/QUICKSTART.md),
  [`docs/OPERATIONS_AND_WORKLOAD_GUIDE.md`](docs/OPERATIONS_AND_WORKLOAD_GUIDE.md)
- Plugin manifests: [`plugins/`](plugins)
- Dependency lockfiles: [`Cargo.lock`](Cargo.lock), [`uv.lock`](uv.lock), `flutter_client/pubspec.lock`
- Build and CI metadata: [`Taskfile.yml`](Taskfile.yml), [`Cargo.toml`](Cargo.toml),
  [`pyproject.toml`](pyproject.toml), [`deny.toml`](deny.toml), [`.github/`](.github)

Redistributions of covered works must keep the licence texts, this `NOTICE`
file, and all copyright, attribution, and licence notices intact.

Contributions are accepted under AGPL-3.0-only together with the PyCentric
Contributor License Agreement ([`CLA.md`](CLA.md)), under which contributors
grant PyCentric a broad copyright and patent license that permits dual
licensing (AGPL-3.0-only for the open core and proprietary/commercial terms for
branded distribution packages and future offerings). PyCentric (Pty) Ltd, as
copyright holder of its own code, may also offer the same code under separate
commercial terms.

## 2. Excluded Works: PyCentric proprietary (not AGPL)

Governed by [`LICENSE-PYCENTRIC.md`](LICENSE-PYCENTRIC.md). These works are
PyCentric internal and confidential and must never be redistributed:

- [`AUDIENCE_MANIFEST.md`](AUDIENCE_MANIFEST.md)
- [`FEASIBILITY_AND_STRATEGY.md`](FEASIBILITY_AND_STRATEGY.md)
- [`docs/legal/`](docs/legal) (founder IP assignment deed; never shared)
- [`docs/adr/`](docs/adr) (architecture decision records with enforcement internals)
- [`docs/governance/`](docs/governance) (commercial playbook, operating cadence, people plan, roadmaps)
- [`docs/newsletter/`](docs/newsletter) (publication staging artifacts)
- [`docs/PRD.md`](docs/PRD.md)
- [`docs/FLUTTER_UI_UX_SIGNOFF.md`](docs/FLUTTER_UI_UX_SIGNOFF.md)
- [`pc.toml`](pc.toml) and the PyCentric `pc` orchestrator integration

## 3. Branded Distribution Packages: the supported enterprise distribution (PyCentric proprietary)

PyCentric publishes a **supported enterprise distribution** of Cordon as the
`pycentric-cordon` distribution packages (the `.deb` and `.rpm` packages,
release tarballs, Python wheels, the `org.pycentric.app` Flatpak and AppImage
builds, and any equivalent branded build, including artifacts staged in
[`dist/`](dist)). These packages are built, tested, signed, and supported by
PyCentric as copyright owner and are distributed under the commercial terms in
[`LICENSE-PYCENTRIC.md`](LICENSE-PYCENTRIC.md) (Part B, the commercial EULA).
The commercial terms include a limited trade mark and branding grant (see
section 4), support and SLA entitlement, and compliance documentation for
enterprise procurement and audit. The AGPL-3.0-only grant in section 1 does not
apply to these branded packages; independent parties building the open core
from source receive the AGPL-3.0-only rights in section 1.

Community builds compiled from the open-core source are provided as-is under
AGPL-3.0-only and carry no support, SLA, maintenance, or indemnity obligation
from PyCentric.

Planned (not yet available, and not claimed as shipped today): PyCentric
intends to publish CI-built AGPL-3.0-only artifacts with `SHA256SUMS` as the
community download channel.

## 4. Trade marks

"PyCentric", "PyCentric Cordon", "Cordon", "pycentric-cordon", and "org.pycentric"
are trade marks or trade names of PyCentric (Pty) Ltd. No trade mark or branding
rights are granted by the AGPL grant (see AGPL-3.0 section 7(e)). Modified versions
built from the open core must not use PyCentric marks in a way that implies
endorsement or origin by PyCentric.

## 5. Third-party components

Third-party open-source components remain under their own license terms. See
`deny.toml` for the dependency license policy and `Cargo.lock` / `uv.lock` for
the pinned dependency set.
