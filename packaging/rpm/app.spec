Name:           pycentric-cordon
Version:        1.0.0
Release:        1%{?dist}
Summary:        Universal 5-Gate Host Sandbox and L3/L4/L7 Network Inspection Engine
License:        LicenseRef-PyCentric-Proprietary
URL:            https://pycentric.co.za
Requires:       bubblewrap >= 0.8.0, iproute, iptables

%description
Cordon enforces defense-in-depth containment for autonomous coding agents
(OpenCode, Antigravity, Claude Code), untrusted Python/uv scripts, and
isolated package builds using Bubblewrap namespaces, AppArmor 4.0 userns
mediation, Linux network namespaces, and L7 HTTP/HTTPS secret-leak inspection.

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/cordon/configs
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
mkdir -p %{buildroot}%{_datadir}/zsh/site-functions
mkdir -p %{buildroot}%{_datadir}/fish/vendor_completions.d
install -m 0755 target/release/cordon %{buildroot}%{_bindir}/cordon
install -m 0755 deploy/bin/agent-sandbox %{buildroot}%{_bindir}/agent-sandbox
install -m 0755 deploy/bin/agent-shell %{buildroot}%{_bindir}/agent-shell
install -m 0644 configs/* %{buildroot}%{_sysconfdir}/cordon/configs/
install -m 0644 packaging/systemd/*.service %{buildroot}%{_unitdir}/
mkdir -p %{buildroot}%{_sysconfdir}/sudoers.d
install -m 0440 deploy/bin/cordon.sudoers %{buildroot}%{_sysconfdir}/sudoers.d/cordon
mkdir -p %{buildroot}%{_prefix}/lib/cordon
install -m 0444 deploy/bin/cordon.sudoers %{buildroot}%{_prefix}/lib/cordon/cordon.sudoers
install -m 0644 packaging/completions/cordon.bash %{buildroot}%{_datadir}/bash-completion/completions/cordon
install -m 0644 packaging/completions/_cordon %{buildroot}%{_datadir}/zsh/site-functions/_cordon
install -m 0644 packaging/completions/cordon.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/cordon.fish

%pre
getent group cordon >/dev/null 2>&1 || groupadd --system cordon
getent passwd cordon >/dev/null 2>&1 || \
    useradd --system --gid cordon --home-dir /var/lib/cordon --no-create-home \
        --shell /usr/sbin/nologin cordon
exit 0

%files
%{_bindir}/cordon
%{_bindir}/agent-sandbox
%{_bindir}/agent-shell
%config(noreplace) %{_sysconfdir}/cordon/configs/*
%config(noreplace) %{_sysconfdir}/sudoers.d/cordon
%{_prefix}/lib/cordon/cordon.sudoers
%{_unitdir}/cordon-control-plane.service
%{_unitdir}/cordon-netns.service
%{_unitdir}/cordon-l7.service
%{_datadir}/bash-completion/completions/cordon
%{_datadir}/zsh/site-functions/_cordon
%{_datadir}/fish/vendor_completions.d/cordon.fish

