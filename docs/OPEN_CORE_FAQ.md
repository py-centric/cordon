# Cordon Open Core FAQ

Plain-language answers about the Cordon licensing model. This document is part
of the open core and is licensed under the GNU Affero General Public License
version 3 only (`AGPL-3.0-only`). The authoritative scope map is
[`NOTICE.md`](../NOTICE.md); this FAQ adds no rights and states no terms beyond
the licence texts and [`README.md`](../README.md).

## Why AGPL-3.0-only?

Cordon is a security perimeter and audit tool: operators must be able to read,
run, verify, and modify it. `AGPL-3.0-only` keeps the engine free, and its
network-use clause (section 13) ensures that anyone offering Cordon to users
over a network also offers those users the source of their deployment, so
hosted wrappers cannot silently close the code.

## Why a CLA instead of a DCO?

Contributions are accepted under the PyCentric Contributor License Agreement
([`CLA.md`](../CLA.md)), under which contributors grant PyCentric broad
copyright and patent licences. That grant is what permits dual licensing: the
open core stays `AGPL-3.0-only` for everyone while PyCentric can also offer
branded builds under commercial terms. A DCO sign-off alone would not permit
that.

## What is free and what is paid?

Free (the `AGPL-3.0-only` open core): the engine and its 5-gate isolation
pipeline (ip netns, AppArmor 4.0, Bubblewrap, the mitmproxy L7 secret scan and
POST guard, and the tshark PCAP ring), the `Cordonfile` specification and
starter configs, the plugin system and built-in plugins, and community policy
packs.

Paid (commercial, via the supported enterprise distribution): compliance
evidence packs, fleet audit, a curated signature feed with an update SLA,
SSO/RBAC, managed L7, and support/indemnity. See
[`LICENSE-PYCENTRIC.md`](../LICENSE-PYCENTRIC.md) (Part B) and
[legal@pycentric.co.za](mailto:legal@pycentric.co.za).

## Can I run it internally?

Yes. Running Cordon internally, unmodified, creates no obligations beyond the
licence you already have. Obligations attach when you distribute a modified
version or make Cordon available to users over a network.

## Can I fork it?

Yes. You may fork, modify, and redistribute the open core under
`AGPL-3.0-only`, provided you keep the licence and notices intact and meet the
source obligations when you distribute or network-serve your modified version.
Do not use PyCentric trade marks on your fork (see below).

## Can a cloud provider wrap it?

If you make Cordon available to users over a network, AGPL section 13 requires
you to offer those users the Corresponding Source of your deployment. The
Corresponding Source for a running instance is available at
https://github.com/pycentric/cordon/tree/v<version> (the tag matching the
running version), and the same URL is exposed by `GET /api/v1/meta` on every
running instance.

## Can I use the PyCentric name?

No. "PyCentric", "PyCentric Cordon", "Cordon", `pycentric-cordon`, and
`org.pycentric` are trade marks or trade names of PyCentric (Pty) Ltd. The
AGPL grant conveys no trade mark or branding rights (AGPL section 7(e)).
Modified versions built from the open core must not use PyCentric marks in a
way that implies endorsement or origin by PyCentric.

## How do I get a commercial licence?

Contact [legal@pycentric.co.za](mailto:legal@pycentric.co.za). Commercial terms
for the supported enterprise distribution (the `pycentric-cordon` packages) are
in [`LICENSE-PYCENTRIC.md`](../LICENSE-PYCENTRIC.md) Part B.
