# PYCENTRIC PROPRIETARY SOFTWARE LICENSE
# (Excluded Works and Branded Distribution Packages)

Copyright (c) 2026 PyCentric (Pty) Ltd. All rights reserved.

**Scope note (open-core release, Version 2.0, 2026-11-02).** The Cordon open core
is licensed under the GNU Affero General Public License version 3 only
(see [`LICENSE`](LICENSE), SPDX: `AGPL-3.0-only`). This proprietary license
applies to the works defined in Part A and Part B below (see [`NOTICE.md`](NOTICE.md)
for the full scope map):

1. **Excluded Works (internal governance, commercial, and legal material)**:
   [`AUDIENCE_MANIFEST.md`](AUDIENCE_MANIFEST.md), [`FEASIBILITY_AND_STRATEGY.md`](FEASIBILITY_AND_STRATEGY.md),
   [`docs/legal/`](docs/legal) (founder IP assignment deed; never shared),
   [`docs/adr/`](docs/adr) (architecture decision records with enforcement internals),
   [`docs/governance/`](docs/governance) (commercial playbook, operating cadence, people plan, roadmaps),
   [`docs/newsletter/`](docs/newsletter) (publication staging artifacts),
   [`docs/PRD.md`](docs/PRD.md), [`docs/FLUTTER_UI_UX_SIGNOFF.md`](docs/FLUTTER_UI_UX_SIGNOFF.md),
   and [`pc.toml`](pc.toml) (PyCentric `pc` orchestrator integration).
2. **PyCentric-branded distribution packages**: the `pycentric-cordon` distribution
   artifacts built and published by PyCentric (`.deb`, `.rpm`, release tarballs,
   Python wheels, `org.pycentric.app` Flatpak and AppImage builds, and equivalent
   branded builds, including artifacts staged in [`dist/`](dist)), together with
   all PyCentric branding, trade marks, and get-up.

Part A below governs the Excluded Works. Part B below governs the branded
distribution packages that PyCentric distributes commercially. If you obtained
the Cordon engine source code directly from the open-core repository, the
AGPL-3.0-only grant applies to that source code and Part B does not.

---

## Part A: Excluded Works (Confidential; No License Granted)

The Excluded Works listed in the scope note are the confidential information and
trade secrets of PyCentric (Pty) Ltd ("PyCentric"), a private company
incorporated in the Republic of South Africa.

1. **No License Granted.** No license or other right, express or implied, is
   granted to any person under any patent, copyright, trade secret, trademark,
   or other intellectual property right of PyCentric in the Excluded Works,
   except as expressly set out in a separate written agreement signed by an
   authorized representative of PyCentric.

2. **Internal Use Only.** Access to the Excluded Works is restricted to
   PyCentric personnel and to contractors or advisors who (a) are bound by a
   written confidentiality agreement with PyCentric and (b) have been expressly
   authorized by PyCentric, and then only for PyCentric's internal business
   purposes.

3. **Restrictions.** Except as expressly authorized in writing by PyCentric,
   you may not: (a) copy, modify, or create derivative works of the Excluded
   Works; (b) distribute, publish, sublicense, sell, lease, or otherwise make
   the Excluded Works available to any third party; (c) decompile, disassemble,
   or reverse engineer the Excluded Works, except to the extent that applicable
   law expressly permits this despite this limitation; or (d) remove or alter
   any proprietary or confidentiality notice.

4. **Confidentiality.** You must keep the Excluded Works confidential, protect
   them with at least a reasonable degree of care, and promptly notify PyCentric
   of any unauthorized access, use, or disclosure. On request, or when your
   authorization ends, you must stop using and securely destroy all copies of
   the Excluded Works in your possession or control.

5. **Ownership.** PyCentric retains all right, title, and interest in and to the
   Excluded Works and all modifications, feedback, and derivative works.

6. **Disclaimer.** THE EXCLUDED WORKS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF
   ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. TO
   THE MAXIMUM EXTENT PERMITTED BY LAW, PYCENTRIC SHALL NOT BE LIABLE FOR ANY
   CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM OR IN CONNECTION WITH THE
   EXCLUDED WORKS OR THEIR USE.

7. **Governing Law.** Part A is governed by the laws of the Republic of South
   Africa.

---

## Part B: PyCentric-Branded Distribution Packages (Commercial End-User License Terms)

In this Part B, the "Software" means the `pycentric-cordon` distribution
artifacts built and published by PyCentric (the `.deb` and `.rpm` packages,
release tarballs, Python wheels, `org.pycentric.app` Flatpak and AppImage
builds, and any equivalent branded build, including artifacts staged in
[`dist/`](dist)), together with all PyCentric branding, trade marks, and get-up.

1. **License Grant.** Subject to the terms of this Part B, PyCentric grants you
   a worldwide, non-exclusive, non-transferable license to install and use the
   Software on systems you own or control, for your own internal business and
   personal purposes. You may make copies of the Software as are reasonably
   necessary for installation, backup, and disaster recovery.

2. **Independent Open-Source Grant.** The source code corresponding to the
   Software is offered independently under `AGPL-3.0-only`. The exact source
   location for each package is given in the machine-readable file
   `SOURCE_OFFER.txt` shipped with the package (convention: the
   `https://github.com/pycentric/cordon` tree at the git tag matching the
   package version). Nothing in this Part B limits any rights you have in that
   source code under the AGPL, including the right to run, modify, and
   redistribute it under the AGPL terms.

3. **Restrictions.** Except as expressly permitted by applicable law or by an
   open source license identified in section 4, you may not: (a) reverse
   engineer, decompile, or disassemble the Software; (b) distribute, publish,
   sublicense, sell, lease, rent, or otherwise make the Software available to
   any third party (including by making it available as a hosted or managed
   service) without a separate written agreement with PyCentric; (c) remove or
   alter any proprietary, copyright, or licensing notice in the Software; or
   (d) use the Software in violation of any applicable law.

4. **Third-Party Components.** The Software depends on third-party open source
   components, either bundled within it or invoked as separate host processes at
   runtime. These include bubblewrap (LGPL-2.1-or-later), the tshark and
   Wireshark command-line utilities (GPL-2.0-or-later), and mitmproxy (MIT).
   The exact pinned dependency set of the source tree is recorded in
   `Cargo.lock`. Those components remain under their own license
   terms. This Part B does not relicense, restrict, or modify any rights granted
   to you by those licenses. Where a third-party license grants you rights to
   corresponding source code or license texts (for example GPL and LGPL
   components), that license governs those components, and copies of such
   notices as their licenses require are preserved with the Software and its
   source tree.

5. **Trade Marks.** "PyCentric", "PyCentric Cordon", "Cordon", "pycentric-cordon",
   and "org.pycentric" are trade marks or trade names of PyCentric. No trade mark
   or branding rights are granted by this Part B, except nominative reference to
   the unmodified Software.

6. **Support and Updates.** PyCentric has no obligation to provide support,
   maintenance, or updates. Support may be available under separate written
   terms (contact `support@pycentric.co.za`). Security reporting is governed by
   [`SECURITY.md`](SECURITY.md).

7. **Termination.** This Part B terminates automatically if you breach it.
   Sections 2, 4, 5, 8, 9, and 10 survive termination.

8. **Disclaimer of Warranty.** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
   WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
   WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
   NON-INFRINGEMENT.

9. **Limitation of Liability.** TO THE MAXIMUM EXTENT PERMITTED BY LAW,
   PYCENTRIC SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
   CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR FOR ANY LOSS OF DATA, PROFITS, OR
   BUSINESS, ARISING FROM OR IN CONNECTION WITH THE SOFTWARE OR ITS USE.
   Nothing in this Part B excludes or limits liability that cannot be excluded
   or limited under applicable law, including the Consumer Protection Act 68 of
   2008 where it applies.

10. **Governing Law.** Part B is governed by the laws of the Republic of South
    Africa, and the parties submit to the exclusive jurisdiction of the courts
    of the Republic of South Africa.

Third-party open-source components used by the Software remain subject to their
own license terms.

Contact: legal@pycentric.co.za
