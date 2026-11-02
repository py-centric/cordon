"""Universal Programmable mitmproxy Layer 7 Policy Engine & Secret Scanner.

Reference entrypoint over the shared canonical core in cordon.policy_rules.
All rule table, evaluation, scanning, and event schema logic lives there so the
deploy-time addon (deploy/mitmproxy/agent_policy_addon.py) and this in-tree
addon enforce byte-identical policy.

This module can be imported directly as a pure-Python policy evaluator (for
unit tests and the Cordon FastAPI Control Plane) or loaded into mitmproxy via
`-s src/cordon/mitm_addon.py`.
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule and [INV-STDOUT-JSON].
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from cordon.policy_rules import (
    RULES_VERSION,
    CordonMitmAddon,
    PolicyConfig,
    PolicyEngine,
    PolicyResult,
    event_for_result,
)

if TYPE_CHECKING:
    from cordon.models import CordonProfile

MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

__all__ = [
    "CordonPolicyEvaluator",
    "MitmproxyCordonAddon",
    "PolicyConfig",
    "PolicyEngine",
    "addons",
]


def _config_from_profile(
    profile: CordonProfile,
    extra_allowed_domains: tuple[str, ...] = (),
) -> PolicyConfig:
    """Derives the canonical PolicyConfig from a Python CordonProfile."""
    merged_allowed = tuple(
        dict.fromkeys(
            [*(d.lower() for d in profile.allowed_domains), *(d.lower() for d in extra_allowed_domains)]
        )
    )
    return PolicyConfig(
        profile_name=str(profile.name),
        network_mode=str(profile.network_mode),
        strict_whitelist=profile.strict_whitelist,
        block_doh=True,
        inspect_body_secrets=True,
        allow_streamed_bodies=False,
        allowed_domains=merged_allowed,
        denied_domains=tuple(d.lower() for d in profile.denied_domains),
        post_allowed_hosts=tuple(d.lower() for d in profile.post_allowed_hosts),
    )


class CordonPolicyEvaluator:
    """Compatibility shim evaluating HTTP/HTTPS requests against a CordonProfile.

    Delegates to the shared canonical PolicyEngine and records canonical
    AuditEvents in a bounded in-memory buffer for the control plane.
    """

    def __init__(
        self,
        profile: CordonProfile | None = None,
        *,
        extra_allowed_domains: tuple[str, ...] = (),
    ) -> None:
        from cordon.models import WorkloadKind
        from cordon.profiles import get_profile

        env_profile = os.environ.get("CORDON_PROFILE", WorkloadKind.AI_AGENT.value)
        base_profile = profile or get_profile(env_profile)
        self.profile: CordonProfile = base_profile
        self.config: PolicyConfig = _config_from_profile(base_profile, extra_allowed_domains)
        self.engine = PolicyEngine(self.config)
        self.allowed_domains: frozenset[str] = frozenset(self.config.allowed_domains)
        self.post_allowed_hosts: frozenset[str] = frozenset(self.config.post_allowed_hosts)
        self.audit_buffer: list[Any] = []

    def is_domain_allowed(self, host: str) -> bool:
        """Checks whether host or a parent domain is in allowed_domains."""
        from cordon.policy_rules import domain_matches

        return any(domain_matches(host, allowed) for allowed in self.config.allowed_domains)

    def evaluate_request(
        self,
        *,
        host: str,
        method: str,
        url: str,
        path: str = "/",
        headers: dict[str, str] | None = None,
        body_text: str = "",
        body_streamed: bool = False,
    ) -> Any:
        """Evaluates an outbound HTTP/HTTPS request and records an AuditEvent."""
        from cordon.models import AuditEvent, PolicyDecision

        result: PolicyResult = self.engine.evaluate(
            method=method,
            url=url,
            headers=headers,
            body_text=body_text,
            body_streamed=body_streamed,
            host=host,
            path=path,
        )
        event_dict = event_for_result(result, self.config, self.engine.session_id)
        self.audit_buffer.append(AuditEvent(**event_dict))
        if len(self.audit_buffer) > 500:
            self.audit_buffer.pop(0)
        return PolicyDecision(
            allowed=result.allowed,
            status_code=result.status_code,
            reason=result.reason,
            profile=self.profile.name,
            host=result.host,
            method=result.method,
            url=result.url,
            rule_id=result.rule_id,
            rule_version=RULES_VERSION,
            secret_fingerprint=result.secret_fingerprint,
            matched_secret_pattern=(
                result.rule_id if result.rule_id.startswith("SECRET_") else None
            ),
        )


class MitmproxyCordonAddon(CordonMitmAddon):
    """Adapter hooking the canonical policy engine into mitmproxy / mitmweb.

    The fail-closed hook implementation lives in cordon.policy_rules.CordonMitmAddon;
    this subclass exists so in-repo deployments can keep the historical entrypoint.
    """


# Passing the CLASS (not an instance) defers construction until mitmproxy loads
# the addon, keeping this module side-effect free on import.
addons = [MitmproxyCordonAddon]
