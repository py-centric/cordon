"""Canonical Layer 7 policy rule table, evaluator, and event schema for Cordon.

This module is the SINGLE policy source for the Python enforcement plane. Both
mitmproxy addons (src/cordon/mitm_addon.py and deploy/mitmproxy/agent_policy_addon.py)
load these rules, and src/l7_policy.rs implements the identical semantics for the
Rust control plane. tests/golden/l7_corpus.json is the parity contract.

Pure standard library by design: the mitmdump runtime must not require pydantic.

Governance:
- Deny-list is enforced BEFORE the allow-list.
- Env overrides (CORDON_EXTRA_HOSTS and friends) never widen policy unless
  CORDON_ALLOW_INSECURE=1 is explicitly set, and every deviation is logged.
- Hooks fail closed: any evaluation error blocks the flow.
- JSONL events carry only canonical schema fields, NEVER raw payload bytes.

Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import sys
import uuid
import zlib
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Canonical schema and rule version constants
# ---------------------------------------------------------------------------

EVENT_SCHEMA_VERSION = 1
RULES_VERSION = 2
GATE_L7 = 4
PLANE_L7 = "mitmproxy"

POLICY_FILE_ENV = "CORDON_POLICY_FILE"
DEFAULT_POLICY_FILE = "/run/cordon/policy.json"
SESSION_ID_ENV = "CORDON_SESSION_ID"
INSECURE_ENV = "CORDON_ALLOW_INSECURE"
EXTRA_HOSTS_ENV = "CORDON_EXTRA_HOSTS"
LEGACY_EXTRA_HOSTS_ENV = "PYCENTRIC_SANDBOX_EXTRA_HOSTS"

# Canonical rule identifiers. Secret rules MUST keep the `SECRET_` prefix: the
# Rust api.rs severity logic keys on it (SECRET_ => CRITICAL).
RULE_SECRET_GITHUB_PAT = "SECRET_GITHUB_PAT"
RULE_SECRET_OPENAI_KEY = "SECRET_OPENAI_KEY"
RULE_SECRET_AWS_ACCESS_KEY = "SECRET_AWS_ACCESS_KEY"
RULE_SECRET_PRIVATE_KEY_PEM = "SECRET_PRIVATE_KEY_PEM"
RULE_SECRET_JWT_BEARER = "SECRET_JWT_BEARER"
RULE_SECRET_ENV_ASSIGNMENT = "SECRET_ENV_ASSIGNMENT"

RULE_NETWORK_MODE_NONE = "NETWORK_MODE_NONE"
RULE_DNS_OVER_HTTPS = "DOH_RESOLVER_BLOCK"
RULE_WEBSOCKET_UPGRADE = "WEBSOCKET_UPGRADE_BLOCK"
RULE_ALLOWLIST_MISS = "ALLOWLIST_MISS"
RULE_UNAUTHORIZED_MUTATING_METHOD = "UNAUTHORIZED_MUTATING_METHOD"
RULE_STREAMED_BODY_UNSCANNABLE = "STREAMED_BODY_UNSCANNABLE"
RULE_BODY_UNDECODABLE = "BODY_UNDECODABLE"
RULE_HOOK_FAILURE_FAIL_CLOSED = "HOOK_FAILURE_FAIL_CLOSED"
RULE_RESPONSE_OBSERVED = "RESPONSE_OBSERVED"
RULE_DEFAULT_ALLOW = "DEFAULT_ALLOW"
RULE_POLICY_SOURCE_DEGRADED = "POLICY_SOURCE_DEGRADED"
RULE_POLICY_ENV_WIDENED = "POLICY_ENV_WIDENED"
RULE_POLICY_ENV_IGNORED = "POLICY_ENV_OVERRIDE_IGNORED"

MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
DOH_PATH_PREFIXES: tuple[str, ...] = ("/dns-query", "/resolve")
KNOWN_DOH_HOSTS: frozenset[str] = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "dns.quad9.net",
        "doh.opendns.com",
    }
)

SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
MAX_B64_CANDIDATES = 16
MAX_B64_DECODED_BYTES = 65536
WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class SecretRule:
    """One secret signature in the canonical rule table."""

    rule_id: str
    pattern: re.Pattern[str]
    requires_digit: bool = False


def _compile(rule_id: str, pattern: str, *, requires_digit: bool = False) -> SecretRule:
    return SecretRule(
        rule_id=rule_id,
        pattern=re.compile(pattern),
        requires_digit=requires_digit,
    )


# Canonical ordered rule table. Order is part of the parity contract: the first
# matching rule wins and both language engines iterate in this exact order.
# All patterns are linear (no nested quantifiers, no lookaround) and therefore
# ReDoS-safe. Case-insensitive to defeat case-split evasion; the `requires_digit`
# guard stops prose false positives such as "task-ManagementSystem..." matching sk-.
SECRET_RULES: tuple[SecretRule, ...] = (
    _compile(
        RULE_SECRET_GITHUB_PAT,
        r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{22,})",
    ),
    _compile(RULE_SECRET_OPENAI_KEY, r"(?i)sk-[A-Za-z0-9_-]{20,}", requires_digit=True),
    _compile(RULE_SECRET_AWS_ACCESS_KEY, r"(?i)(?:AKIA|ASIA)[0-9A-Z]{16}", requires_digit=True),
    _compile(
        RULE_SECRET_PRIVATE_KEY_PEM,
        r"(?i)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
    ),
    _compile(
        RULE_SECRET_JWT_BEARER,
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    _compile(
        RULE_SECRET_ENV_ASSIGNMENT,
        r"(?i)(?:DATABASE_URL|FERNET_KEY|JWT_PRIVATE_KEY|AWS_SECRET_ACCESS_KEY"
        r"|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=",
    ),
)


# ---------------------------------------------------------------------------
# Host / URL normalization (parity with src/l7_policy.rs)
# ---------------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Lowercases, strips IPv6 brackets and :port, and trims trailing DNS dots."""
    cleaned = host.strip()
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end != -1:
            cleaned = cleaned[1:end]
    elif cleaned.count(":") == 1:
        name, _, port = cleaned.partition(":")
        if port.isdigit():
            cleaned = name
    return cleaned.rstrip(".").lower()


def split_url(url: str) -> tuple[str, str]:
    """Splits an absolute URL into (normalized host, path_with_query)."""
    remainder = SCHEME_RE.sub("", url, count=1)
    end = len(remainder)
    for sep in ("/", "?", "#"):
        idx = remainder.find(sep)
        if idx != -1:
            end = min(end, idx)
    authority = remainder[:end]
    path = remainder[end:] or "/"
    host_part = authority.rsplit("@", 1)[-1]
    return normalize_host(host_part), path


# ---------------------------------------------------------------------------
# Secret scanning (parity with src/l7_policy.rs)
# ---------------------------------------------------------------------------


def _collapse_whitespace(text: str) -> str:
    return WHITESPACE_RE.sub("", text)


def _span_has_digit(span: str) -> bool:
    return any(c in "0123456789" for c in span)


def _scan_variants(text: str) -> tuple[str, str] | None:
    for variant in (text, _collapse_whitespace(text)):
        for rule in SECRET_RULES:
            for match in rule.pattern.finditer(variant):
                span = match.group(0)
                if rule.requires_digit and not _span_has_digit(span):
                    continue
                return rule.rule_id, span
    return None


def _decode_base64_candidate(candidate: str) -> bytes | None:
    if len(candidate) % 4 != 0:
        return None
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded[:MAX_B64_DECODED_BYTES] or None


def scan_for_secret(text: str) -> tuple[str, str] | None:
    """Returns (rule_id, matched_span) for the first secret found in `text`.

    Scans the raw text plus a whitespace-collapsed variant (case/whitespace
    split evasion), then performs a bounded base64-decode-and-rescan pass.
    """
    hit = _scan_variants(text)
    if hit is not None:
        return hit
    candidates = 0
    for match in BASE64_CANDIDATE_RE.finditer(text):
        candidates += 1
        if candidates > MAX_B64_CANDIDATES:
            break
        decoded = _decode_base64_candidate(match.group(0))
        if decoded is None:
            continue
        decoded_text = decoded.decode("utf-8", errors="replace")
        hit = _scan_variants(decoded_text)
        if hit is not None:
            return hit
    return None


def secret_fingerprint(span: str) -> str:
    """Non-reversible fingerprint of a matched secret span: sha256 hex[:16]."""
    return hashlib.sha256(span.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Wire body decoding (adapter-layer parity helper)
# ---------------------------------------------------------------------------


class BodyDecodeError(ValueError):
    """Raised when a content-encoded body cannot be decoded for scanning."""


def decode_body(raw: bytes, content_encoding: str | None) -> str:
    """Decodes gzip/deflate/zlib content-encoding before scanning.

    Unknown or undecodable encodings raise BodyDecodeError; callers must fail
    closed (BLOCK) rather than pass unscanned content.
    """
    encoding = (content_encoding or "identity").strip().lower()
    if encoding in ("", "identity"):
        return raw.decode("utf-8", errors="replace")
    try:
        if encoding == "gzip":
            decoded = gzip.decompress(raw)
        elif encoding in ("deflate", "zlib"):
            try:
                decoded = zlib.decompress(raw)
            except zlib.error:
                decoded = zlib.decompress(raw, -zlib.MAX_WBITS)
        else:
            raise BodyDecodeError(f"Unsupported content-encoding '{encoding}'")
    except (OSError, EOFError, zlib.error) as exc:
        raise BodyDecodeError(f"Failed to decode content-encoding '{encoding}'") from exc
    return decoded[: 4 * MAX_B64_DECODED_BYTES].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_DOMAINS: tuple[str, ...] = (
    # Approved LLM inference providers (per PYC-POL-AI-S01)
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "api.deepinfra.com",
    "api.fireworks.ai",
    "api.together.xyz",
    "generativelanguage.googleapis.com",
    # Package managers and language registries
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "registry.npmjs.org",
    "proxy.golang.org",
    "sum.golang.org",
    "storage.googleapis.com",
    "pub.dev",
    # Git forges and verification targets
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "example.com",
)

DEFAULT_POST_ALLOWED_HOSTS: tuple[str, ...] = (
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "api.deepinfra.com",
    "api.fireworks.ai",
    "api.together.xyz",
    "generativelanguage.googleapis.com",
)


def _normalize_domain_list(values: Any) -> tuple[str, ...]:
    out: list[str] = []
    for item in values or ():
        cleaned = normalize_host(str(item))
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return tuple(out)


@dataclass(frozen=True)
class PolicyConfig:
    """Effective L7 enforcement policy for one sandbox session."""

    profile_name: str = "ai-agent"
    network_mode: str = "inspected"
    strict_whitelist: bool = True
    block_doh: bool = True
    inspect_body_secrets: bool = True
    allow_streamed_bodies: bool = False
    allowed_domains: tuple[str, ...] = DEFAULT_ALLOWED_DOMAINS
    denied_domains: tuple[str, ...] = ()
    post_allowed_hosts: tuple[str, ...] = DEFAULT_POST_ALLOWED_HOSTS

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> PolicyConfig:
        """Builds a config from a JSON policy file mapping (missing keys use safe defaults)."""
        return cls(
            profile_name=str(
                data.get("profile", data.get("profile_name", data.get("name", "ai-agent")))
            ),
            network_mode=str(data.get("network_mode", "inspected")),
            strict_whitelist=bool(data.get("strict_whitelist", True)),
            block_doh=bool(data.get("block_doh", True)),
            inspect_body_secrets=bool(data.get("inspect_body_secrets", True)),
            allow_streamed_bodies=bool(data.get("allow_streamed_bodies", False)),
            allowed_domains=_normalize_domain_list(data.get("allowed_domains")) or (),
            denied_domains=_normalize_domain_list(data.get("denied_domains")),
            post_allowed_hosts=_normalize_domain_list(data.get("post_allowed_hosts")) or (),
        )

    def to_mapping(self) -> dict[str, Any]:
        """Serializes the effective policy for /run/cordon/policy.json."""
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "rule_version": RULES_VERSION,
            "profile": self.profile_name,
            "network_mode": self.network_mode,
            "strict_whitelist": self.strict_whitelist,
            "block_doh": self.block_doh,
            "inspect_body_secrets": self.inspect_body_secrets,
            "allow_streamed_bodies": self.allow_streamed_bodies,
            "allowed_domains": list(self.allowed_domains),
            "denied_domains": list(self.denied_domains),
            "post_allowed_hosts": list(self.post_allowed_hosts),
        }

    def with_widened_hosts(self, extra_hosts: tuple[str, ...]) -> PolicyConfig:
        """Returns a copy with extra allow-listed hosts (only reachable via CORDON_ALLOW_INSECURE=1)."""
        merged = _normalize_domain_list((*self.allowed_domains, *extra_hosts))
        return replace(self, allowed_domains=merged)


def write_policy_file(config: PolicyConfig, path: str | os.PathLike[str] = DEFAULT_POLICY_FILE) -> str:
    """Writes the effective policy as JSON to a root-owned runtime file (0644)."""
    target = str(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    payload = json.dumps(config.to_mapping(), indent=2, sort_keys=True) + "\n"
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.chmod(target, 0o644)
    if hasattr(os, "chown"):
        try:
            os.chown(target, 0, 0)
        except (PermissionError, OSError):
            pass
    return target


def _policy_file_is_trusted(path: str) -> bool:
    """Trusts root-owned policy files (production) or self-owned files when unprivileged.

    In production the addon runs as root, so `st_uid == 0` is enforced exactly
    as before. When the addon runs unprivileged (development), a file owned by
    the current effective user is accepted; files owned by any other
    non-root user are always rejected. Group/other-writable files are never
    trusted.
    """
    try:
        stat = os.stat(path)
    except OSError:
        return False
    if stat.st_uid != 0 and stat.st_uid != os.geteuid():
        return False
    return (stat.st_mode & 0o022) == 0


def load_policy_file(path: str) -> PolicyConfig | None:
    """Loads a policy file if present and root-owned. Returns None when absent/untrusted."""
    if not os.path.isfile(path) or not _policy_file_is_trusted(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return PolicyConfig.from_mapping(data)


@dataclass(frozen=True)
class ResolvedPolicy:
    """Effective policy plus startup events describing any deviation."""

    config: PolicyConfig
    session_id: str
    events: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def resolve_runtime_policy(env: dict[str, str] | None = None) -> ResolvedPolicy:
    """Resolves the runtime policy from CORDON_POLICY_FILE with safe fallbacks.

    Env overrides never widen policy unless CORDON_ALLOW_INSECURE=1; both the
    applied and the ignored case are logged as events.
    """
    environ = dict(os.environ if env is None else env)
    events: list[dict[str, Any]] = []
    session_id = environ.get(SESSION_ID_ENV) or str(uuid.uuid4())
    policy_path = environ.get(POLICY_FILE_ENV, DEFAULT_POLICY_FILE)
    config = load_policy_file(policy_path)
    if config is None:
        config = PolicyConfig()
        events.append(
            build_event(
                config=config,
                severity="WARNING",
                verdict="BLOCK",
                host="",
                method="",
                url=f"file://{policy_path}",
                rule_id=RULE_POLICY_SOURCE_DEGRADED,
                reason=(
                    f"Policy file '{policy_path}' missing or untrusted; "
                    "falling back to default strict_whitelist policy."
                ),
                byte_count=0,
            )
        )

    raw_extra = environ.get(EXTRA_HOSTS_ENV) or environ.get(LEGACY_EXTRA_HOSTS_ENV) or ""
    extra_hosts = tuple(h for h in (x.strip() for x in raw_extra.split(",")) if h)
    if extra_hosts:
        if environ.get(INSECURE_ENV) == "1":
            config = config.with_widened_hosts(extra_hosts)
            events.append(
                build_event(
                    config=config,
                    severity="WARNING",
                    verdict="ALLOW",
                    host="",
                    method="",
                    url=f"file://{policy_path}",
                    rule_id=RULE_POLICY_ENV_WIDENED,
                    reason=(
                        f"CORDON_ALLOW_INSECURE=1: allow-list widened by "
                        f"{len(extra_hosts)} env override host(s)."
                    ),
                    byte_count=0,
                    session_id=session_id,
                )
            )
        else:
            events.append(
                build_event(
                    config=config,
                    severity="WARNING",
                    verdict="BLOCK",
                    host="",
                    method="",
                    url=f"file://{policy_path}",
                    rule_id=RULE_POLICY_ENV_IGNORED,
                    reason=(
                        f"Ignored {len(extra_hosts)} env override host(s): policy widening "
                        "requires explicit CORDON_ALLOW_INSECURE=1."
                    ),
                    byte_count=0,
                    session_id=session_id,
                )
            )
    return ResolvedPolicy(config=config, session_id=session_id, events=tuple(events))


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyResult:
    """Pure evaluation result for one HTTP request surface.

    Field split (canonical schema, mirrored by Rust `PolicyDecision.matched_rule`
    + `reason`): `rule_id` carries the STABLE machine identifier from the
    cross-language parity contract (`ALLOWLIST_MISS`,
    `UNAUTHORIZED_MUTATING_METHOD`, `DOH_RESOLVER_BLOCK`, `DENY_DOMAIN:<host>`,
    `SECRET_*`, `DEFAULT_ALLOW`, ...); `reason` carries the HUMAN-READABLE
    explanation. Secret rule ids keep the `SECRET_` prefix because Rust
    `api.rs` severity logic keys on it (SECRET_ => CRITICAL).
    """

    allowed: bool
    status_code: int
    reason: str
    rule_id: str
    rule_version: int
    host: str
    method: str
    url: str
    body_bytes: int
    secret_fingerprint: str | None = None

    @property
    def verdict(self) -> str:
        return "ALLOW" if self.allowed else "BLOCK"


def domain_matches(host: str, pattern: str) -> bool:
    """True when host equals pattern or is a subdomain of it (both pre-normalized)."""
    clean = normalize_host(pattern)
    normalized = normalize_host(host)
    return normalized == clean or normalized.endswith(f".{clean}")


def _matches_any(host: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        if domain_matches(host, pattern):
            return pattern
    return None


class PolicyEngine:
    """Canonical L7 evaluator shared by every Python enforcement entrypoint."""

    def __init__(self, config: PolicyConfig, *, session_id: str | None = None) -> None:
        self.config = config
        self.session_id = session_id or os.environ.get(SESSION_ID_ENV) or str(uuid.uuid4())

    def evaluate(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body_text: str = "",
        body_streamed: bool = False,
        host: str | None = None,
        path: str | None = None,
    ) -> PolicyResult:
        """Evaluates one request surface in canonical rule order.

        Order: NETWORK_MODE_NONE, DENY_DOMAIN, DOH_RESOLVER_BLOCK,
        WEBSOCKET_UPGRADE_BLOCK, ALLOWLIST_MISS, UNAUTHORIZED_MUTATING_METHOD,
        STREAMED_BODY_UNSCANNABLE, SECRET_*, DEFAULT_ALLOW.
        """
        norm_method = (method or "").strip().upper()
        norm_host = normalize_host(host) if host else split_url(url)[0]
        norm_path = path if path is not None else split_url(url)[1]
        norm_headers = {(k or "").strip().lower(): (v or "") for k, v in (headers or {}).items()}

        def result(
            allowed: bool,
            status_code: int,
            reason: str,
            rule_id: str,
            fingerprint: str | None = None,
        ) -> PolicyResult:
            return PolicyResult(
                allowed=allowed,
                status_code=status_code,
                reason=reason,
                rule_id=rule_id,
                rule_version=RULES_VERSION,
                host=norm_host,
                method=norm_method,
                url=url,
                body_bytes=len(body_text.encode("utf-8", errors="replace")),
                secret_fingerprint=fingerprint,
            )

        # 1. Airgapped / no-network profiles
        if self.config.network_mode.strip().lower() in ("airgapped", "none"):
            return result(
                False,
                403,
                "Outbound network is disabled for this Cordon profile.",
                RULE_NETWORK_MODE_NONE,
            )

        # 2. Explicit deny-list, enforced BEFORE the allow-list
        denied = _matches_any(norm_host, self.config.denied_domains)
        if denied is not None:
            return result(
                False,
                403,
                f"Host '{norm_host}' matched denied domain rule '{denied}'.",
                f"DENY_DOMAIN:{denied}",
            )

        # 3. DNS-over-HTTPS (DoH) bypass prevention (EC-07)
        if self.config.block_doh:
            accept = norm_headers.get("accept", "").lower()
            if (
                norm_host in KNOWN_DOH_HOSTS
                or any(norm_path.startswith(prefix) for prefix in DOH_PATH_PREFIXES)
                or accept == "application/dns-message"
            ):
                return result(
                    False,
                    403,
                    f"Blocked DNS-over-HTTPS (DoH) bypass attempt to '{norm_host}'.",
                    RULE_DNS_OVER_HTTPS,
                )

        # 4. WebSocket upgrades blocked by default
        upgrade = norm_headers.get("upgrade", "").strip().lower()
        connection = norm_headers.get("connection", "").strip().lower()
        if upgrade == "websocket" or "upgrade" in connection:
            return result(
                False,
                403,
                f"Blocked WebSocket upgrade to '{norm_host}' (blocked by default).",
                RULE_WEBSOCKET_UPGRADE,
            )

        # 5. Strict allow-list enforcement
        if self.config.strict_whitelist and not _matches_any(norm_host, self.config.allowed_domains):
            return result(
                False,
                403,
                f"Host '{norm_host}' is not in the profile's allowed_domains list.",
                RULE_ALLOWLIST_MISS,
            )

        # 6. Mutating HTTP methods restricted to post_allowed_hosts (FR-5.4)
        if norm_method in MUTATING_METHODS and not _matches_any(
            norm_host, self.config.post_allowed_hosts
        ):
            return result(
                False,
                403,
                f"Blocked mutating HTTP method '{norm_method}' to host '{norm_host}' (FR-5.4).",
                RULE_UNAUTHORIZED_MUTATING_METHOD,
            )

        # 7. Streamed bodies over the stream_large_bodies threshold cannot be scanned
        if body_streamed and self.config.inspect_body_secrets and not self.config.allow_streamed_bodies:
            return result(
                False,
                403,
                "Request body is streamed/unbuffered and cannot be scanned (fail closed).",
                RULE_STREAMED_BODY_UNSCANNABLE,
            )

        # 8. Secret exfiltration scan: body, URL/query, then headers (canonical order)
        if self.config.inspect_body_secrets:
            surfaces: list[str] = [body_text, url]
            for name in sorted(norm_headers):
                surfaces.append(norm_headers[name])
            for surface in surfaces:
                if not surface:
                    continue
                hit = scan_for_secret(surface)
                if hit is not None:
                    rule_id, span = hit
                    return result(
                        False,
                        403,
                        f"Blocked potential credential exfiltration matching rule '{rule_id}'.",
                        rule_id,
                        secret_fingerprint(span),
                    )

        return result(
            True,
            200,
            f"Permitted outbound {norm_method} request to '{norm_host}'.",
            RULE_DEFAULT_ALLOW,
        )


# ---------------------------------------------------------------------------
# Canonical JSONL event schema
# ---------------------------------------------------------------------------


def _severity_for(rule_id: str, verdict: str) -> str:
    if rule_id.startswith("SECRET_") or rule_id == RULE_HOOK_FAILURE_FAIL_CLOSED:
        return "CRITICAL"
    if verdict == "BLOCK":
        return "WARNING"
    return "INFO"


def build_event(
    *,
    config: PolicyConfig,
    severity: str,
    verdict: str,
    host: str,
    method: str,
    url: str,
    rule_id: str,
    reason: str,
    byte_count: int,
    secret_fingerprint: str | None = None,
    session_id: str | None = None,
    plane: str = PLANE_L7,
    gate: int = GATE_L7,
    status_code: int | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Builds one canonical JSONL telemetry event (NEVER includes raw payloads)."""
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp or datetime.now(tz=UTC).isoformat(),
        "plane": plane,
        "gate": gate,
        "severity": severity,
        "verdict": verdict,
        "profile": config.profile_name,
        "session_id": session_id or "unset",
        "host": host,
        "method": method,
        "url": url,
        "rule_id": rule_id,
        "rule_version": RULES_VERSION,
        "reason": reason,
        "bytes": int(byte_count),
        "secret_fingerprint": secret_fingerprint,
        "status_code": status_code,
    }


def event_for_result(result: PolicyResult, config: PolicyConfig, session_id: str) -> dict[str, Any]:
    """Builds the canonical event for one evaluated request."""
    return build_event(
        config=config,
        severity=_severity_for(result.rule_id, result.verdict),
        verdict=result.verdict,
        host=result.host,
        method=result.method,
        url=result.url,
        rule_id=result.rule_id,
        reason=result.reason,
        byte_count=result.body_bytes,
        secret_fingerprint=result.secret_fingerprint,
        session_id=session_id,
        status_code=result.status_code,
    )


def emit_event(event: dict[str, Any], *, stream: Any = None) -> None:
    """Writes one JSONL audit record to stdout (sink = systemd StandardOutput=append)."""
    out = stream if stream is not None else sys.stdout
    out.write(json.dumps(event, sort_keys=True) + "\n")
    out.flush()


# ---------------------------------------------------------------------------
# Shared mitmproxy hook adapter (used by BOTH addons)
# ---------------------------------------------------------------------------


class CordonMitmAddon:
    """Fail-closed mitmproxy addon enforcing the canonical L7 policy."""

    def __init__(self, engine: PolicyEngine | None = None) -> None:
        if engine is None:
            resolved = resolve_runtime_policy()
            engine = PolicyEngine(resolved.config, session_id=resolved.session_id)
            self.startup_events: list[dict[str, Any]] = list(resolved.events)
        else:
            self.startup_events = []
        self.engine = engine
        for event in self.startup_events:
            emit_event(event)

    def _emit_result(self, result: PolicyResult) -> None:
        emit_event(event_for_result(result, self.engine.config, self.engine.session_id))

    def request(self, flow: Any) -> None:
        """Inspects every outbound request; any error blocks the flow (fail closed)."""
        try:
            self._on_request(flow)
        except Exception as exc:  # noqa: BLE001 - fail closed on ANY hook error
            self._fail_closed(flow, "request", exc)

    def response(self, flow: Any) -> None:
        """Logs response status and byte count; any error suppresses the response."""
        try:
            self._on_response(flow)
        except Exception as exc:  # noqa: BLE001 - fail closed on ANY hook error
            self._fail_closed(flow, "response", exc)

    # -- internals ---------------------------------------------------------

    def _on_request(self, flow: Any) -> None:
        from mitmproxy import http as mitm_http

        raw = flow.request.raw_content
        body_streamed = raw is None
        body_text = ""
        if raw is not None:
            try:
                flow.request.decode()
                body_text = flow.request.get_text(strict=False) or ""
            except Exception as exc:  # noqa: BLE001 - undecodable body cannot be scanned
                result = PolicyResult(
                    allowed=False,
                    status_code=403,
                    reason=f"Request body content-encoding could not be decoded: {exc}",
                    rule_id=RULE_BODY_UNDECODABLE,
                    rule_version=RULES_VERSION,
                    host=normalize_host(flow.request.pretty_host),
                    method=(flow.request.method or "").strip().upper(),
                    url=flow.request.pretty_url,
                    body_bytes=len(raw),
                )
                self._emit_result(result)
                flow.response = mitm_http.Response.make(
                    403,
                    b'{"error": "CORDON_POLICY_VIOLATION", "rule_id": "BODY_UNDECODABLE"}',
                    {"Content-Type": "application/json; charset=utf-8"},
                )
                return

        result = self.engine.evaluate(
            method=flow.request.method,
            url=flow.request.pretty_url,
            headers=dict(flow.request.headers),
            body_text=body_text,
            body_streamed=body_streamed,
            host=flow.request.pretty_host,
            path=flow.request.path,
        )
        self._emit_result(result)
        if not result.allowed:
            error_payload = json.dumps(
                {
                    "error": "CORDON_POLICY_VIOLATION",
                    "rule_id": result.rule_id,
                    "rule_version": result.rule_version,
                    "reason": result.reason,
                }
            ).encode("utf-8")
            flow.response = mitm_http.Response.make(
                result.status_code,
                error_payload,
                {"Content-Type": "application/json; charset=utf-8"},
            )

    def _on_response(self, flow: Any) -> None:
        status_code = int(flow.response.status_code) if flow.response is not None else 0
        raw = flow.response.raw_content if flow.response is not None else None
        byte_count = len(raw) if raw is not None else -1
        event = build_event(
            config=self.engine.config,
            severity="INFO",
            verdict="AUDIT",
            host=normalize_host(flow.request.pretty_host),
            method=(flow.request.method or "").strip().upper(),
            url=flow.request.pretty_url,
            rule_id=RULE_RESPONSE_OBSERVED,
            reason=f"Upstream response observed with status {status_code}.",
            byte_count=byte_count,
            session_id=self.engine.session_id,
            status_code=status_code,
        )
        emit_event(event)

    def _fail_closed(self, flow: Any, hook: str, exc: Exception) -> None:
        event = build_event(
            config=self.engine.config,
            severity="CRITICAL",
            verdict="BLOCK",
            host="",
            method="",
            url="",
            rule_id=RULE_HOOK_FAILURE_FAIL_CLOSED,
            reason=f"Exception in {hook} hook; failing closed: {type(exc).__name__}: {exc}",
            byte_count=0,
            session_id=self.engine.session_id,
        )
        try:
            emit_event(event)
        except Exception:  # noqa: BLE001 - never raise out of the fail-closed path
            pass
        if hook != "request":
            return
        try:
            from mitmproxy import http as mitm_http

            flow.response = mitm_http.Response.make(
                403,
                b'{"error": "CORDON_POLICY_VIOLATION", "rule_id": "HOOK_FAILURE_FAIL_CLOSED"}',
                {"Content-Type": "application/json; charset=utf-8"},
            )
        except Exception:  # noqa: BLE001 - terminal fallback, nothing more we can do
            pass
