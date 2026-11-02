#!/usr/bin/env bash
# =============================================================================
# PyCentric AI Agent Network Namespace, Firewall & Telemetry Provisioner
# Governing Spec: ADR-L0-SEC-02 (FR-4.1..FR-4.3, FR-6.1..FR-6.2, EC-03, EC-07)
# Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
#
# Provisions:
#   1. Linux Network Namespace: agent-net (10.200.1.2/24)
#   2. Virtual Ethernet Pair:   veth-agent (sandbox) <-> veth-host (10.200.1.1/24)
#   3. iptables PREROUTING:     TCP 80/443 -> mitmproxy (:8080)
#   4. iptables PREROUTING:     UDP/TCP 53 -> DNAT to host-local resolver (EC-07)
#   5. iptables INPUT:          FAIL CLOSED on veth-host. Only the mitm port and
#                               DNS are reachable; sandbox -> host loopback
#                               services (mitmweb :8081, control plane :8095) is
#                               dropped even if route_localnet is enabled.
#   6. iptables FORWARD:        Reject UDP 443 QUIC with icmp-port-unreachable (EC-03)
#                               Drop all other non-redirected traffic (FR-4.3)
#   7. DNS tunneling mitigation: drop TXT/NULL/ANY query types + per-source rate
#                               limit (see deploy/net/dnsmasq-cordon.conf docs)
#   8. tshark Ring Buffer:      L3/L4 PCAP on veth-host (-b filesize:102400 -b files:10, ~1GB)
#
# route_localnet is intentionally NOT enabled: the REDIRECT and DNAT targets are
# host-local veth addresses (10.200.1.1), never 127.0.0.0/8, so loopback
# routing is unnecessary and disabling it keeps host loopback unreachable.
# =============================================================================
set -euo pipefail

ACTION="${1:-up}"
NETNS_NAME="agent-net"
VETH_HOST="veth-host"
VETH_AGENT="veth-agent"
HOST_IP="10.200.1.1"
AGENT_IP="10.200.1.2"
SUBNET_CIDR="10.200.1.0/24"
MITM_PORT="${PYCENTRIC_MITM_PORT:-8080}"
DNS_RESOLVER="${PYCENTRIC_SANDBOX_DNS:-10.200.1.1}"
PCAP_DIR="${PYCENTRIC_SANDBOX_PCAP_DIR:-/var/log/pycentric/agent-pcap}"
PCAP_PID_FILE="/run/pycentric-agent-tshark.pid"
# DNS tunneling mitigation toggles (TXT/NULL/ANY qtype drop + rate limit)
DNS_QTYPE_BLOCK="${PYCENTRIC_SANDBOX_DNS_QTYPE_BLOCK:-1}"
DNS_RATE_LIMIT="${PYCENTRIC_SANDBOX_DNS_RATE_LIMIT:-1}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[setup-sandbox-net] ERROR: Must be executed as root (use sudo)." >&2
    exit 1
fi

teardown_network() {
    echo "[setup-sandbox-net] Tearing down sandbox network & telemetry plane..." >&2

    # Stop tshark ring-buffer daemon if running
    if [[ -f "$PCAP_PID_FILE" ]]; then
        kill "$(cat "$PCAP_PID_FILE")" 2>/dev/null || true
        rm -f "$PCAP_PID_FILE"
    fi

    # Remove iptables rules idempotently
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports "$MITM_PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p udp --dport 53 -j DNAT --to-destination "${DNS_RESOLVER}:53" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p tcp --dport 53 -j DNAT --to-destination "${DNS_RESOLVER}:53" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SUBNET_CIDR" ! -d "$SUBNET_CIDR" -j MASQUERADE 2>/dev/null || true

    # INPUT fail-closed chain
    iptables -D INPUT -i "$VETH_HOST" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p udp --dport 53 -m string --hex-string "|000a0001|" --algo bm -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p udp --dport 53 -m string --hex-string "|00100001|" --algo bm -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p udp --dport 53 -m string --hex-string "|00ff0001|" --algo bm -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p tcp --dport 53 -m string --hex-string "|000a0001|" --algo bm -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p tcp --dport 53 -m string --hex-string "|00100001|" --algo bm -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p tcp --dport 53 -m string --hex-string "|00ff0001|" --algo bm -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p udp --dport 53 -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name cordon-dns -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p tcp --dport 53 -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name cordon-dns-tcp -j DROP 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p tcp --dport "$MITM_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i "$VETH_HOST" -j DROP 2>/dev/null || true

    # ip6tables mirrors (IPv6 is disabled in the netns; mirrored for defense in depth)
    ip6tables -D INPUT -i "$VETH_HOST" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    ip6tables -D INPUT -i "$VETH_HOST" -p tcp --dport "$MITM_PORT" -j ACCEPT 2>/dev/null || true
    ip6tables -D INPUT -i "$VETH_HOST" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    ip6tables -D INPUT -i "$VETH_HOST" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    ip6tables -D INPUT -i "$VETH_HOST" -j DROP 2>/dev/null || true

    iptables -D FORWARD -i "$VETH_HOST" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -p udp -d "$DNS_RESOLVER" --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -p tcp -d "$DNS_RESOLVER" --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -j DROP 2>/dev/null || true
    ip6tables -D FORWARD -i "$VETH_HOST" -j DROP 2>/dev/null || true

    # Delete veth interface and network namespace
    ip link del "$VETH_HOST" 2>/dev/null || true
    ip netns del "$NETNS_NAME" 2>/dev/null || true

    echo "[setup-sandbox-net] Teardown complete." >&2
}

provision_network() {
    # Clean any stale resources first
    teardown_network 2>/dev/null || true

    echo "[setup-sandbox-net] Provisioning network namespace '${NETNS_NAME}' (${AGENT_IP}/24)..." >&2

    # FR-4.1: Create dedicated network namespace & veth pair
    ip netns add "$NETNS_NAME"
    ip link add "$VETH_HOST" type veth peer name "$VETH_AGENT"
    ip link set "$VETH_AGENT" netns "$NETNS_NAME"

    # Configure host side (veth-host: 10.200.1.1/24)
    ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    # Configure sandbox side (veth-agent: 10.200.1.2/24) and disable IPv6 bypass
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null || true
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null || true
    ip netns exec "$NETNS_NAME" ip link set lo up
    ip netns exec "$NETNS_NAME" ip addr add "${AGENT_IP}/24" dev "$VETH_AGENT"
    ip netns exec "$NETNS_NAME" ip link set "$VETH_AGENT" up
    ip netns exec "$NETNS_NAME" ip route add default via "$HOST_IP" dev "$VETH_AGENT"

    # Configure namespace-specific resolv.conf (EC-07)
    mkdir -p "/etc/netns/${NETNS_NAME}"
    cat > "/etc/netns/${NETNS_NAME}/resolv.conf" <<EOF
# Generated by setup-sandbox-net.sh (ADR-L0-SEC-02 EC-07)
nameserver ${DNS_RESOLVER}
options edns0 trust-ad
EOF

    # Enable IPv4 forwarding. route_localnet stays DISABLED on purpose: the
    # REDIRECT/DNAT targets are host-local veth addresses (10.200.1.1), never
    # loopback, so host loopback stays unreachable from the sandbox.
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w "net.ipv4.conf.${VETH_HOST}.route_localnet=0" >/dev/null 2>&1 || true

    # FR-4.2: Transparent Port Redirection (TCP 80 & 443 -> mitmproxy :8080)
    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports "$MITM_PORT"

    # EC-07: Force all standard DNS queries through the host-local resolver
    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p udp --dport 53 -j DNAT --to-destination "${DNS_RESOLVER}:53"
    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p tcp --dport 53 -j DNAT --to-destination "${DNS_RESOLVER}:53"
    iptables -t nat -A POSTROUTING -s "$SUBNET_CIDR" ! -d "$SUBNET_CIDR" -j MASQUERADE

    # INPUT fail-closed chain: sandbox may ONLY reach the L7 mitm port and DNS
    # on the host. Blocks sandbox -> 127.0.0.1:8081 (mitmweb UI) and :8095
    # (control plane), and prevents flipping mitmweb ignore_hosts (total bypass).
    iptables -A INPUT -i "$VETH_HOST" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # DNS tunneling mitigation: drop high-bandwidth covert query types
    # (TXT=0x0010, NULL=0x000a, ANY=0x00ff as QTYPE+QCLASS=IN) and rate limit.
    # NOTE: blocking TXT also blocks ACME dns-01 challenges from inside the
    # sandbox; disable with PYCENTRIC_SANDBOX_DNS_QTYPE_BLOCK=0 if required.
    if [[ "$DNS_QTYPE_BLOCK" == "1" ]]; then
        for proto in udp tcp; do
            iptables -A INPUT -i "$VETH_HOST" -p "$proto" --dport 53 -m string --hex-string "|000a0001|" --algo bm -j DROP
            iptables -A INPUT -i "$VETH_HOST" -p "$proto" --dport 53 -m string --hex-string "|00100001|" --algo bm -j DROP
            iptables -A INPUT -i "$VETH_HOST" -p "$proto" --dport 53 -m string --hex-string "|00ff0001|" --algo bm -j DROP
        done
    fi
    if [[ "$DNS_RATE_LIMIT" == "1" ]]; then
        iptables -A INPUT -i "$VETH_HOST" -p udp --dport 53 -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name cordon-dns -j DROP
        iptables -A INPUT -i "$VETH_HOST" -p tcp --dport 53 -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name cordon-dns-tcp -j DROP
    fi

    iptables -A INPUT -i "$VETH_HOST" -p tcp --dport "$MITM_PORT" -j ACCEPT
    iptables -A INPUT -i "$VETH_HOST" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$VETH_HOST" -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$VETH_HOST" -j DROP

    # ip6tables mirrors (IPv6 is disabled in the netns; mirrored for defense in depth)
    ip6tables -A INPUT -i "$VETH_HOST" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    ip6tables -A INPUT -i "$VETH_HOST" -p tcp --dport "$MITM_PORT" -j ACCEPT 2>/dev/null || true
    ip6tables -A INPUT -i "$VETH_HOST" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    ip6tables -A INPUT -i "$VETH_HOST" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    ip6tables -A INPUT -i "$VETH_HOST" -j DROP 2>/dev/null || true

    # EC-03: Explicitly REJECT UDP port 443 (HTTP/3 QUIC) with icmp-port-unreachable
    # Per RFC 9114, HTTP/3 clients immediately fall back to TCP port 443 -> mitmproxy.
    iptables -A FORWARD -i "$VETH_HOST" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable

    # FR-4.3: Fail-Closed Egress Firewall on FORWARD chain
    # Allow only DNAT-verified DNS (UDP/TCP 53) and established replies; DROP everything else.
    iptables -A FORWARD -i "$VETH_HOST" -p udp -d "$DNS_RESOLVER" --dport 53 -j ACCEPT
    iptables -A FORWARD -i "$VETH_HOST" -p tcp -d "$DNS_RESOLVER" --dport 53 -j ACCEPT
    iptables -A FORWARD -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$VETH_HOST" -j DROP
    ip6tables -A FORWARD -i "$VETH_HOST" -j DROP 2>/dev/null || true

    # FR-6.1 & FR-6.2: Start tshark ring-buffer capture on veth-host (~1GB)
    if command -v tshark >/dev/null 2>&1; then
        mkdir -p "$PCAP_DIR"
        chmod 0750 "$PCAP_DIR"
        nohup tshark -i "$VETH_HOST" \
            -b filesize:102400 \
            -b files:10 \
            -w "${PCAP_DIR}/agent-traffic.pcapng" \
            >/dev/null 2>&1 &
        echo $! > "$PCAP_PID_FILE"
        echo "[setup-sandbox-net] tshark ring buffer active on ${VETH_HOST} (PID $(cat "$PCAP_PID_FILE"), 10x100MB in ${PCAP_DIR})." >&2
    else
        echo "[setup-sandbox-net] WARNING: tshark binary not found; L3/L4 PCAP capture skipped." >&2
    fi

    echo "[setup-sandbox-net] Sandbox network '${NETNS_NAME}' ready. Redirecting TCP 80/443 -> ${HOST_IP}:${MITM_PORT}." >&2
}

case "$ACTION" in
    up|start)
        provision_network
        ;;
    down|stop)
        teardown_network
        ;;
    status)
        ip netns list | grep -E "^${NETNS_NAME}\b" || echo "Namespace ${NETNS_NAME} is DOWN"
        iptables -t nat -L PREROUTING -n -v | grep "$VETH_HOST" || true
        iptables -L INPUT -n -v | grep "$VETH_HOST" || true
        iptables -L FORWARD -n -v | grep "$VETH_HOST" || true
        ;;
    *)
        echo "Usage: $0 {up|down|status}" >&2
        exit 2
        ;;
esac
