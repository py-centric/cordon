//! Serializable runtime L7 policy configuration (`/run/cordon/policy.json`) and trusted file I/O.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::normalize_host;
use super::runtime::{EVENT_SCHEMA_VERSION, RULES_VERSION};
use crate::domain::{CordonProfile, NetworkMode};
use crate::profiles::get_profile;

const fn default_schema_version() -> u32 {
    EVENT_SCHEMA_VERSION
}

const fn default_rule_version() -> u32 {
    RULES_VERSION
}

fn default_profile_name() -> String {
    "ai-agent".to_owned()
}

fn default_network_mode() -> String {
    "inspected".to_owned()
}

const fn default_true() -> bool {
    true
}

fn normalize_domain_vec<I, S>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for item in items {
        let cleaned = normalize_host(item.as_ref());
        if !cleaned.is_empty() && !out.contains(&cleaned) {
            out.push(cleaned);
        }
    }
    out
}

/// Serializable runtime L7 policy configuration (`/run/cordon/policy.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Wire schema version (`1`).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Rule table version (`2`).
    #[serde(default = "default_rule_version")]
    pub rule_version: u32,
    /// Active profile name (`ai-agent`, `package-build`, etc.).
    #[serde(
        default = "default_profile_name",
        alias = "profile_name",
        alias = "name"
    )]
    pub profile: String,
    /// Network enforcement mode (`inspected`, `allowlist_only`, `direct`, `none`).
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    /// Enforce default-deny domain allowlist.
    #[serde(default = "default_true")]
    pub strict_whitelist: bool,
    /// Block DNS-over-HTTPS (DoH) bypass attempts.
    #[serde(default = "default_true")]
    pub block_doh: bool,
    /// Scan request bodies, URLs, and headers for secret exfiltration.
    #[serde(default = "default_true")]
    pub inspect_body_secrets: bool,
    /// Allow streamed/unbuffered request bodies without scanning.
    #[serde(default)]
    pub allow_streamed_bodies: bool,
    /// Normalized allow-listed outbound domains.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Normalized deny-listed outbound domains (evaluated before `allowed_domains`).
    #[serde(default)]
    pub denied_domains: Vec<String>,
    /// Normalized hosts permitted to receive mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
    #[serde(default)]
    pub post_allowed_hosts: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let Ok(profile) = get_profile("ai-agent") else {
            return Self {
                schema_version: EVENT_SCHEMA_VERSION,
                rule_version: RULES_VERSION,
                profile: "ai-agent".to_owned(),
                network_mode: "inspected".to_owned(),
                strict_whitelist: true,
                block_doh: true,
                inspect_body_secrets: true,
                allow_streamed_bodies: false,
                allowed_domains: Vec::new(),
                denied_domains: Vec::new(),
                post_allowed_hosts: Vec::new(),
            };
        };
        Self::from_profile(&profile)
    }
}

impl PolicyConfig {
    /// Derives the runtime [`PolicyConfig`] from an effective [`CordonProfile`].
    #[must_use]
    pub fn from_profile(profile: &CordonProfile) -> Self {
        let network_mode = match profile.network_mode {
            NetworkMode::Inspected => "inspected",
            NetworkMode::AllowlistOnly => "allowlist_only",
            NetworkMode::Direct => "direct",
            NetworkMode::None => "none",
        };
        let strict_whitelist = profile.network_mode == NetworkMode::AllowlistOnly
            || !profile.allowed_domains.is_empty();
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            rule_version: RULES_VERSION,
            profile: profile.name.clone(),
            network_mode: network_mode.to_owned(),
            strict_whitelist,
            block_doh: profile.block_doh,
            inspect_body_secrets: profile.inspect_body_secrets,
            allow_streamed_bodies: false,
            allowed_domains: normalize_domain_vec(&profile.allowed_domains),
            denied_domains: normalize_domain_vec(&profile.denied_domains),
            post_allowed_hosts: normalize_domain_vec(&profile.post_allowed_hosts),
        }
    }

    /// Normalizes all domain lists in place.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.allowed_domains = normalize_domain_vec(&self.allowed_domains);
        self.denied_domains = normalize_domain_vec(&self.denied_domains);
        self.post_allowed_hosts = normalize_domain_vec(&self.post_allowed_hosts);
        self
    }

    /// Returns a copy with extra allow-listed hosts (only reachable via `CORDON_ALLOW_INSECURE=1`).
    #[must_use]
    pub fn with_widened_hosts(&self, extra_hosts: &[String]) -> Self {
        let mut merged = self.allowed_domains.clone();
        merged.extend_from_slice(extra_hosts);
        let mut copy = self.clone();
        copy.allowed_domains = normalize_domain_vec(&merged);
        copy
    }

    /// Converts this [`PolicyConfig`] into a [`CordonProfile`] suitable for [`super::CordonPolicyEvaluator`].
    #[must_use]
    pub fn to_profile(&self) -> CordonProfile {
        let mut profile = get_profile(&self.profile)
            .or_else(|_| get_profile("ai-agent"))
            .unwrap_or_else(|_| panic!("built-in ai-agent profile must exist"));
        profile.name.clone_from(&self.profile);
        profile.network_mode = match self.network_mode.trim().to_ascii_lowercase().as_str() {
            "airgapped" | "none" => NetworkMode::None,
            "direct" | "passthrough" => NetworkMode::Direct,
            "allowlist_only" => NetworkMode::AllowlistOnly,
            _ => {
                if self.strict_whitelist {
                    NetworkMode::AllowlistOnly
                } else {
                    NetworkMode::Inspected
                }
            }
        };
        profile.block_doh = self.block_doh;
        profile.inspect_body_secrets = self.inspect_body_secrets;
        profile.allowed_domains = normalize_domain_vec(&self.allowed_domains);
        profile.denied_domains = normalize_domain_vec(&self.denied_domains);
        profile.post_allowed_hosts = normalize_domain_vec(&self.post_allowed_hosts);
        profile
    }
}

/// Writes `config` as pretty-printed JSON to `path` with mode `0644`.
pub fn write_policy_file(config: &PolicyConfig, path: &Path) -> std::io::Result<PathBuf> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_string_pretty(&config.clone().normalized())
        .map_err(std::io::Error::other)?;
    std::fs::write(path, format!("{payload}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(path.to_path_buf())
}

#[cfg(unix)]
fn current_process_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|meta| meta.uid())
}

/// Returns `true` when `path` is a regular file owned by `root` (`uid == 0`) or the current
/// effective user and is not group- or world-writable (`(mode & 0o022) == 0`).
#[must_use]
pub fn policy_file_is_trusted(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = meta.uid();
        let self_uid = current_process_uid();
        if uid != 0 && self_uid != Some(uid) {
            return false;
        }
        if (meta.mode() & 0o022) != 0 {
            return false;
        }
    }
    true
}

/// Loads and validates a [`PolicyConfig`] from `path` if the file exists and passes ownership
/// and mode trust checks.
#[must_use]
pub fn load_policy_file(path: &Path) -> Option<PolicyConfig> {
    if !policy_file_is_trusted(path) {
        return None;
    }
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: PolicyConfig = serde_json::from_str(&raw).ok()?;
    Some(parsed.normalized())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{PolicyConfig, load_policy_file, policy_file_is_trusted, write_policy_file};
    use crate::l7_policy::NetworkMode;
    use crate::profiles::get_profile;

    #[test]
    fn policy_config_write_and_load_enforces_mode_trust() {
        let profile = get_profile("ai-agent").unwrap_or_else(|e| panic!("profile: {e}"));
        let cfg = PolicyConfig::from_profile(&profile);
        let round_trip = cfg.to_profile();
        assert_eq!(round_trip.name, "ai-agent");

        let tmp =
            std::env::temp_dir().join(format!("cordon-policy-test-{}.json", std::process::id()));
        write_policy_file(&cfg, &tmp).unwrap_or_else(|e| panic!("write: {e}"));
        assert!(policy_file_is_trusted(&tmp));
        assert!(load_policy_file(&tmp).is_some());

        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666));
        assert!(!policy_file_is_trusted(&tmp));
        assert!(load_policy_file(&tmp).is_none());

        let _ = std::fs::remove_file(&tmp);

        let minimal: PolicyConfig =
            serde_json::from_str("{}").unwrap_or_else(|e| panic!("deserialize minimal: {e}"));
        assert_eq!(minimal.profile, "ai-agent");
        assert!(minimal.strict_whitelist);

        let widened = cfg.with_widened_hosts(&["extra.example.com".to_owned()]);
        assert!(
            widened
                .allowed_domains
                .contains(&"extra.example.com".to_owned())
        );

        for (mode, strict, expected) in [
            ("airgapped", false, NetworkMode::None),
            ("direct", false, NetworkMode::Direct),
            ("allowlist_only", false, NetworkMode::AllowlistOnly),
            ("inspected", true, NetworkMode::AllowlistOnly),
            ("inspected", false, NetworkMode::Inspected),
        ] {
            let mut c = cfg.clone();
            c.network_mode = mode.to_owned();
            c.strict_whitelist = strict;
            assert_eq!(c.to_profile().network_mode, expected);
        }
    }
}
