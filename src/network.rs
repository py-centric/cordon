//! Linux Network Namespace (`ip netns`), `veth`, and `iptables` compiler for Cordon.

use crate::domain::CordonProfile;
use crate::ports::NetnsCompilerPort;

/// Generates idempotent shell commands to provision the isolated network namespace,
/// `veth` interface pair, NAT redirection to `mitmproxy`, DNS DNAT, and UDP 443 QUIC rejection.
pub fn generate_network_setup_commands(profile: &CordonProfile) -> Vec<String> {
    let ns = &profile.netns_name;
    let host_ip = &profile.host_veth_ip;
    let sb_ip = &profile.sandbox_veth_ip;
    let subnet = &profile.subnet_cidr;
    let port = profile.mitm_port;

    let mut cmds = vec![
        format!("ip netns add {ns} 2>/dev/null || true"),
        "ip link add veth-host type veth peer name veth-agent 2>/dev/null || true".to_owned(),
        format!("ip link set veth-agent netns {ns} 2>/dev/null || true"),
        format!("ip addr replace {host_ip}/24 dev veth-host"),
        "ip link set veth-host up".to_owned(),
        format!("ip netns exec {ns} ip addr replace {sb_ip}/24 dev veth-agent"),
        format!("ip netns exec {ns} ip link set veth-agent up"),
        format!("ip netns exec {ns} ip link set lo up"),
        format!("ip netns exec {ns} ip route replace default via {host_ip}"),
        format!("ip netns exec {ns} sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null"),
        format!("ip netns exec {ns} sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null"),
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null".to_owned(),
        "sysctl -w net.ipv4.conf.veth-host.route_localnet=1 >/dev/null".to_owned(),
        // Transparent HTTP/HTTPS redirection to mitmproxy (FR-4.2)
        format!(
            "iptables -t nat -C PREROUTING -i veth-host -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports {port} 2>/dev/null || iptables -t nat -A PREROUTING -i veth-host -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports {port}"
        ),
        // DNS DNAT enforcement to prevent direct external UDP/TCP 53 exfiltration (FR-4.4)
        format!(
            "iptables -t nat -C PREROUTING -i veth-host -p udp --dport 53 -j DNAT --to-destination {host_ip}:53 2>/dev/null || iptables -t nat -A PREROUTING -i veth-host -p udp --dport 53 -j DNAT --to-destination {host_ip}:53"
        ),
        format!(
            "iptables -t nat -C PREROUTING -i veth-host -p tcp --dport 53 -j DNAT --to-destination {host_ip}:53 2>/dev/null || iptables -t nat -A PREROUTING -i veth-host -p tcp --dport 53 -j DNAT --to-destination {host_ip}:53"
        ),
    ];

    if profile.block_quic_udp_443 {
        // Reject UDP 443 (QUIC/HTTP3) with ICMP port unreachable for instant RFC 9114 TCP fallback
        for chain in ["INPUT", "FORWARD"] {
            cmds.push(format!(
                "iptables -C {chain} -i veth-host -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || iptables -I {chain} 1 -i veth-host -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable"
            ));
        }
    }

    cmds.push(format!(
        "iptables -t nat -C POSTROUTING -s {subnet} ! -d {subnet} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} ! -d {subnet} -j MASQUERADE"
    ));

    // FR-4.3: Fail-closed egress firewall on FORWARD chain (drop non-redirected raw ports such as TV-07 TCP 9999)
    cmds.push(format!(
        "iptables -C FORWARD -i veth-host -p udp -d {host_ip} --dport 53 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i veth-host -p udp -d {host_ip} --dport 53 -j ACCEPT"
    ));
    cmds.push(format!(
        "iptables -C FORWARD -i veth-host -p tcp -d {host_ip} --dport 53 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i veth-host -p tcp -d {host_ip} --dport 53 -j ACCEPT"
    ));
    cmds.push(
        "iptables -C FORWARD -o veth-host -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o veth-host -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
            .to_owned(),
    );
    cmds.push(
        "iptables -C FORWARD -i veth-host -j DROP 2>/dev/null || iptables -A FORWARD -i veth-host -j DROP"
            .to_owned(),
    );
    cmds.push(
        "ip6tables -C FORWARD -i veth-host -j DROP 2>/dev/null || ip6tables -A FORWARD -i veth-host -j DROP"
            .to_owned(),
    );

    cmds
}

/// Builds the `mitmproxy` / `mitmweb` command line for transparent L7 TLS interception.
pub fn build_mitmproxy_command(
    profile: &CordonProfile,
    addon_script: &str,
    web_ui: bool,
) -> Vec<String> {
    let binary = if web_ui { "mitmweb" } else { "mitmdump" };
    vec![
        binary.to_owned(),
        "--mode".to_owned(),
        "transparent".to_owned(),
        "--showhost".to_owned(),
        "--listen-host".to_owned(),
        profile.host_veth_ip.clone(),
        "--listen-port".to_owned(),
        profile.mitm_port.to_string(),
        "--set".to_owned(),
        "stream_large_bodies=5m".to_owned(),
        "-s".to_owned(),
        addon_script.to_owned(),
    ]
}

/// Builds the `tshark` ring-buffer packet capture command for `veth-host`
/// (`-b filesize:102400 -b files:10`, approx. 1 GB cap per canonical constants).
pub fn build_tshark_command(_profile: &CordonProfile, pcap_dir: &str) -> Vec<String> {
    vec![
        "tshark".to_owned(),
        "-i".to_owned(),
        "veth-host".to_owned(),
        "-b".to_owned(),
        "filesize:102400".to_owned(),
        "-b".to_owned(),
        "files:10".to_owned(),
        "-w".to_owned(),
        format!("{pcap_dir}/cordon-veth-host.pcapng"),
    ]
}

/// Default stateless implementation of [`NetnsCompilerPort`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NetnsTopologyCompiler;

impl NetnsCompilerPort for NetnsTopologyCompiler {
    fn generate_network_setup_commands(&self, profile: &CordonProfile) -> Vec<String> {
        generate_network_setup_commands(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::get_profile;

    #[test]
    fn canonical_capture_and_mitm_constants_are_aligned() {
        let Ok(profile) = get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        let tshark = build_tshark_command(&profile, "/var/log/cordon");
        assert!(tshark.contains(&"filesize:102400".to_owned()));
        assert!(tshark.contains(&"files:10".to_owned()));
        let idx = tshark
            .iter()
            .position(|a| a == "filesize:102400")
            .unwrap_or(0);
        assert_eq!(tshark.get(idx + 2).map(String::as_str), Some("files:10"));

        let mitmdump = build_mitmproxy_command(&profile, "/etc/cordon/addon.py", false);
        let set_idx = mitmdump
            .iter()
            .position(|a| a == "--set")
            .unwrap_or(usize::MAX);
        assert_eq!(
            mitmdump.get(set_idx + 1).map(String::as_str),
            Some("stream_large_bodies=5m"),
            "mitmdump must set stream_large_bodies=5m"
        );
    }

    #[test]
    fn dns_dnat_targets_host_veth_resolver() {
        let Ok(profile) = get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        let joined = generate_network_setup_commands(&profile).join("\n");
        let expected = format!(
            "--dport 53 -j DNAT --to-destination {}:53",
            profile.host_veth_ip
        );
        assert!(joined.contains(&expected));
        assert!(joined.matches(&expected).count() >= 2, "udp and tcp DNS DNAT");
    }
}
