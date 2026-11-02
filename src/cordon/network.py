"""Network Namespace, iptables Firewall & tshark Ring-Buffer Generator for Cordon.

Implements FR-4.1..FR-4.3, FR-6.1..FR-6.2, EC-03 (RFC 9114 QUIC fallback),
and EC-07 (DNS DNAT interception to the host-local resolver 10.200.1.1:53).
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.

Canonical constants (parity with deploy/net/setup-sandbox-net.sh):
- DNS DNAT target: 10.200.1.1:53 (host-local resolver, e.g. dnsmasq-cordon.conf)
- tshark ring buffer: -b filesize:102400 -b files:10 (~1GB)
- INPUT chain on veth-host is fail-closed: only the mitm port and DNS are
  reachable; sandbox traffic to host loopback services (mitmweb :8081, control
  plane :8095) is dropped even when route_localnet is enabled elsewhere.
"""

from __future__ import annotations

import json


def generate_network_setup_commands(
    *,
    netns_name: str = "agent-net",
    veth_host: str = "veth-host",
    veth_agent: str = "veth-agent",
    host_ip: str = "10.200.1.1",
    agent_ip: str = "10.200.1.2",
    subnet_cidr: str = "10.200.1.0/24",
    mitm_port: int = 8080,
    dns_resolver: str = "10.200.1.1",
    pcap_dir: str = "/var/log/pycentric/cordon-pcap",
    ring_filesize_kb: int = 102400,
    ring_files_count: int = 10,
) -> tuple[str, ...]:
    """Returns the ordered sequence of shell commands to provision the network plane."""
    return (
        f"ip netns add {netns_name}",
        f"ip link add {veth_host} type veth peer name {veth_agent}",
        f"ip link set {veth_agent} netns {netns_name}",
        f"ip addr add {host_ip}/24 dev {veth_host}",
        f"ip link set {veth_host} up",
        f"ip netns exec {netns_name} ip link set lo up",
        f"ip netns exec {netns_name} ip addr add {agent_ip}/24 dev {veth_agent}",
        f"ip netns exec {netns_name} ip link set {veth_agent} up",
        f"ip netns exec {netns_name} ip route add default via {host_ip} dev {veth_agent}",
        f"ip netns exec {netns_name} sysctl -w net.ipv6.conf.all.disable_ipv6=1",
        f"ip netns exec {netns_name} sysctl -w net.ipv6.conf.default.disable_ipv6=1",
        "sysctl -w net.ipv4.ip_forward=1",
        # FR-4.2: Transparent TCP 80/443 redirection to mitmproxy.
        # REDIRECT rewrites the destination to the veth-host address (10.200.1.1),
        # so route_localnet is NOT required and must stay disabled.
        (
            f"iptables -t nat -A PREROUTING -i {veth_host} -p tcp "
            f"-m multiport --dports 80,443 -j REDIRECT --to-ports {mitm_port}"
        ),
        # EC-07: Force standard DNS queries through the host-local resolver
        (
            f"iptables -t nat -A PREROUTING -i {veth_host} -p udp --dport 53 "
            f"-j DNAT --to-destination {dns_resolver}:53"
        ),
        (
            f"iptables -t nat -A PREROUTING -i {veth_host} -p tcp --dport 53 "
            f"-j DNAT --to-destination {dns_resolver}:53"
        ),
        f"iptables -t nat -A POSTROUTING -s {subnet_cidr} ! -d {subnet_cidr} -j MASQUERADE",
        # INPUT chain fail-closed: the sandbox may only reach the L7 mitm port and
        # DNS on the host. This blocks sandbox -> 127.0.0.1:8081 (mitmweb) and
        # :8095 (control plane) even if route_localnet is enabled elsewhere.
        f"iptables -A INPUT -i {veth_host} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        f"iptables -A INPUT -i {veth_host} -p tcp --dport {mitm_port} -j ACCEPT",
        f"iptables -A INPUT -i {veth_host} -p udp --dport 53 -j ACCEPT",
        f"iptables -A INPUT -i {veth_host} -p tcp --dport 53 -j ACCEPT",
        f"iptables -A INPUT -i {veth_host} -j DROP",
        (
            f"ip6tables -A INPUT -i {veth_host} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        ),
        f"ip6tables -A INPUT -i {veth_host} -p tcp --dport {mitm_port} -j ACCEPT",
        f"ip6tables -A INPUT -i {veth_host} -p udp --dport 53 -j ACCEPT",
        f"ip6tables -A INPUT -i {veth_host} -p tcp --dport 53 -j ACCEPT",
        f"ip6tables -A INPUT -i {veth_host} -j DROP",
        # EC-03: Reject UDP 443 QUIC with icmp-port-unreachable (RFC 9114 TCP fallback)
        (
            f"iptables -A FORWARD -i {veth_host} -p udp --dport 443 "
            "-j REJECT --reject-with icmp-port-unreachable"
        ),
        # FR-4.3: Fail-closed FORWARD chain
        f"iptables -A FORWARD -i {veth_host} -p udp -d {dns_resolver} --dport 53 -j ACCEPT",
        f"iptables -A FORWARD -i {veth_host} -p tcp -d {dns_resolver} --dport 53 -j ACCEPT",
        f"iptables -A FORWARD -o {veth_host} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"iptables -A FORWARD -i {veth_host} -j DROP",
        f"ip6tables -A FORWARD -i {veth_host} -j DROP",
        # FR-6.1 & FR-6.2: tshark ring-buffer capture on veth-host (~1GB)
        (
            f"tshark -i {veth_host} -b filesize:{ring_filesize_kb} "
            f"-b files:{ring_files_count} -w {pcap_dir}/cordon-traffic.pcapng"
        ),
    )


def build_policy_file_commands(
    policy: dict[str, object],
    *,
    policy_path: str = "/run/cordon/policy.json",
) -> tuple[str, ...]:
    """Builds shell commands writing the effective L7 policy to a root-owned runtime file.

    The JSON payload is embedded with single-quote escaping so arbitrary domain
    lists cannot break out of the generated shell. File is created 0644 root:root.
    """
    payload = json.dumps(policy, indent=2, sort_keys=True)
    escaped = payload.replace("'", "'\\''")
    return (
        f"install -d -m 0755 {policy_path.rsplit('/', 1)[0]}",
        f"printf '%s\\n' '{escaped}' > {policy_path}",
        f"chmod 0644 {policy_path}",
        f"chown root:root {policy_path}",
    )


def build_mitmproxy_command(
    *,
    listen_host: str = "10.200.1.1",
    listen_port: int = 8080,
    web_host: str = "127.0.0.1",
    web_port: int = 8081,
    stream_large_bodies: str = "5m",
    addon_script_path: str = "src/cordon/mitm_addon.py",
    pinned_passthrough_hosts: tuple[str, ...] = (),
    use_web_ui: bool = True,
) -> tuple[str, ...]:
    """Builds the transparent mitmweb/mitmdump invocation command (FR-5.1, FR-5.3, EC-04)."""
    binary = "mitmweb" if use_web_ui else "mitmdump"
    cmd: list[str] = [
        binary,
        "--mode",
        "transparent",
        "--showhost",
        "--listen-host",
        listen_host,
        "--listen-port",
        str(listen_port),
        "--set",
        f"stream_large_bodies={stream_large_bodies}",
    ]
    if use_web_ui:
        cmd.extend(["--web-host", web_host, "--web-port", str(web_port)])
    for regex in pinned_passthrough_hosts:
        cmd.extend(["--ignore-hosts", regex])
    cmd.extend(["-s", addon_script_path])
    return tuple(cmd)
