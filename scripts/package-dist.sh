#!/usr/bin/env bash
# ==============================================================================
# PyCentric Cordon Packaging & Distribution Pipeline
# Governing ADR: ADR-L0-SEC-02
# Produces:
#   - dist/pycentric-cordon-1.0.0-linux-x86_64.tar.gz
#   - dist/pycentric-cordon_1.0.0_amd64.deb (via dpkg-deb or ar/tar fallback)
#   - dist/SHA256SUMS
# ==============================================================================
set -euo pipefail

VERSION="1.0.0"
PKG_NAME="pycentric-cordon"
ARCH="x86_64"
DEB_ARCH="amd64"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/stage-${PKG_NAME}-${VERSION}"

ensure_release_binary() {
    if [[ ! -x "${ROOT_DIR}/target/release/cordon" ]]; then
        echo "[cordon-package] Building release binary target/release/cordon..."
        (cd "${ROOT_DIR}" && cargo build --release --offline)
    fi
}

ensure_completions() {
    ensure_release_binary
    mkdir -p "${ROOT_DIR}/packaging/completions"
    "${ROOT_DIR}/target/release/cordon" completions bash --output "${ROOT_DIR}/packaging/completions/cordon.bash" 2>/dev/null
    "${ROOT_DIR}/target/release/cordon" completions zsh --output "${ROOT_DIR}/packaging/completions/_cordon" 2>/dev/null
    "${ROOT_DIR}/target/release/cordon" completions fish --output "${ROOT_DIR}/packaging/completions/cordon.fish" 2>/dev/null
}

build_tarball() {
    ensure_completions
    mkdir -p "${DIST_DIR}"
    rm -rf "${STAGE_DIR}"
    mkdir -p "${STAGE_DIR}/bin"
    mkdir -p "${STAGE_DIR}/configs"
    mkdir -p "${STAGE_DIR}/completions"
    mkdir -p "${STAGE_DIR}/deploy/apparmor"
    mkdir -p "${STAGE_DIR}/deploy/net"
    mkdir -p "${STAGE_DIR}/deploy/mitmproxy"
    mkdir -p "${STAGE_DIR}/deploy/tests"
    mkdir -p "${STAGE_DIR}/systemd"
    mkdir -p "${STAGE_DIR}/docs"

    install -m 0755 "${ROOT_DIR}/target/release/cordon" "${STAGE_DIR}/bin/cordon"
    install -m 0755 "${ROOT_DIR}/deploy/bin/agent-sandbox" "${STAGE_DIR}/bin/agent-sandbox"
    install -m 0755 "${ROOT_DIR}/deploy/bin/agent-shell" "${STAGE_DIR}/bin/agent-shell"
    install -m 0644 "${ROOT_DIR}/configs/"* "${STAGE_DIR}/configs/"
    install -m 0644 "${ROOT_DIR}/packaging/completions/cordon.bash" "${STAGE_DIR}/completions/cordon.bash"
    install -m 0644 "${ROOT_DIR}/packaging/completions/_cordon" "${STAGE_DIR}/completions/_cordon"
    install -m 0644 "${ROOT_DIR}/packaging/completions/cordon.fish" "${STAGE_DIR}/completions/cordon.fish"
    install -m 0644 "${ROOT_DIR}/deploy/apparmor/usr.local.bin.agent-shell" "${STAGE_DIR}/deploy/apparmor/"
    install -m 0755 "${ROOT_DIR}/deploy/net/setup-sandbox-net.sh" "${STAGE_DIR}/deploy/net/"
    install -m 0644 "${ROOT_DIR}/deploy/mitmproxy/agent_policy_addon.py" "${STAGE_DIR}/deploy/mitmproxy/"
    install -m 0644 "${ROOT_DIR}/deploy/bin/cordon.sudoers" "${STAGE_DIR}/deploy/cordon.sudoers"
    install -m 0755 "${ROOT_DIR}/deploy/tests/verify_sandbox_tv.sh" "${STAGE_DIR}/deploy/tests/"
    install -m 0644 "${ROOT_DIR}/packaging/systemd/"*.service "${STAGE_DIR}/systemd/"
    install -m 0644 "${ROOT_DIR}/README.md" "${STAGE_DIR}/README.md"
    # Branded distribution package: ships the AGPL-3.0-only core licence (LICENSE),
    # the licensing scope map (NOTICE.md), and the proprietary terms that apply to
    # the PyCentric-branded package itself (LICENSE-PYCENTRIC.md).
    install -m 0644 "${ROOT_DIR}/LICENSE" "${STAGE_DIR}/LICENSE"
    install -m 0644 "${ROOT_DIR}/NOTICE.md" "${STAGE_DIR}/NOTICE.md"
    install -m 0644 "${ROOT_DIR}/LICENSE-PYCENTRIC.md" "${STAGE_DIR}/LICENSE-PYCENTRIC.md"
    install -m 0644 "${ROOT_DIR}/SECURITY.md" "${STAGE_DIR}/SECURITY.md"
    # AGPL section 6/13 source offer and DEP-5 copyright metadata ship with every
    # branded payload (LICENSE-PYCENTRIC.md Part B section 2).
    install -m 0644 "${ROOT_DIR}/packaging/SOURCE_OFFER.txt" "${STAGE_DIR}/SOURCE_OFFER.txt"
    install -m 0644 "${ROOT_DIR}/packaging/deb/copyright" "${STAGE_DIR}/docs/copyright"
    if [[ -f "${ROOT_DIR}/docs/OPERATIONS_AND_WORKLOAD_GUIDE.md" ]]; then
        install -m 0644 "${ROOT_DIR}/docs/OPERATIONS_AND_WORKLOAD_GUIDE.md" "${STAGE_DIR}/docs/"
    fi

    cat > "${STAGE_DIR}/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-/usr/local}"
DATADIR="${DATADIR:-/usr/share}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[cordon-install] Installing binaries to ${PREFIX}/bin..."
install -d "${PREFIX}/bin"
install -m 0755 "${HERE}/bin/cordon" "${PREFIX}/bin/cordon"
install -m 0755 "${HERE}/bin/agent-sandbox" "${PREFIX}/bin/agent-sandbox"
install -m 0755 "${HERE}/bin/agent-shell" "${PREFIX}/bin/agent-shell"

echo "[cordon-install] Installing starter Cordonfile configs to ${SYSCONFDIR}/cordon/configs..."
install -d "${SYSCONFDIR}/cordon/configs"
install -m 0644 "${HERE}/configs/"* "${SYSCONFDIR}/cordon/configs/"

echo "[cordon-install] Installing Bash, Zsh, and Fish completions to ${DATADIR}..."
install -d "${DATADIR}/bash-completion/completions"
install -d "${DATADIR}/zsh/site-functions"
install -d "${DATADIR}/fish/vendor_completions.d"
install -m 0644 "${HERE}/completions/cordon.bash" "${DATADIR}/bash-completion/completions/cordon"
install -m 0644 "${HERE}/completions/_cordon" "${DATADIR}/zsh/site-functions/_cordon"
install -m 0644 "${HERE}/completions/cordon.fish" "${DATADIR}/fish/vendor_completions.d/cordon.fish"

echo "[cordon-install] Installing sudoers policy (visudo-validated) to ${SYSCONFDIR}/sudoers.d/cordon..."
if command -v visudo >/dev/null 2>&1 && visudo -cf "${HERE}/deploy/cordon.sudoers" >/dev/null 2>&1; then
    install -d "${SYSCONFDIR}/sudoers.d"
    install -m 0440 "${HERE}/deploy/cordon.sudoers" "${SYSCONFDIR}/sudoers.d/cordon"
else
    echo "[cordon-install] WARNING: visudo unavailable or cordon.sudoers invalid; sudoers policy NOT installed." >&2
fi

echo "[cordon-install] Installation complete. Run 'cordon doctor' to verify host readiness."
EOF
    chmod 0755 "${STAGE_DIR}/install.sh"

    local tarball="${DIST_DIR}/${PKG_NAME}-${VERSION}-linux-${ARCH}.tar.gz"
    tar -C "${DIST_DIR}" -czf "${tarball}" "$(basename "${STAGE_DIR}")"
    rm -rf "${STAGE_DIR}"
    echo "[cordon-package] Created release tarball: ${tarball}"
}

build_deb() {
    ensure_completions
    mkdir -p "${DIST_DIR}"
    local deb_root="${DIST_DIR}/deb-root"
    rm -rf "${deb_root}"
    mkdir -p "${deb_root}/DEBIAN"
    mkdir -p "${deb_root}/usr/bin"
    mkdir -p "${deb_root}/usr/lib/cordon"
    mkdir -p "${deb_root}/usr/share/bash-completion/completions"
    mkdir -p "${deb_root}/usr/share/zsh/site-functions"
    mkdir -p "${deb_root}/usr/share/fish/vendor_completions.d"
    mkdir -p "${deb_root}/etc/cordon/configs"
    mkdir -p "${deb_root}/etc/apparmor.d"
    mkdir -p "${deb_root}/lib/systemd/system"

    install -m 0644 "${ROOT_DIR}/packaging/deb/control" "${deb_root}/DEBIAN/control"
    install -m 0755 "${ROOT_DIR}/packaging/deb/postinst" "${deb_root}/DEBIAN/postinst"
    install -m 0755 "${ROOT_DIR}/target/release/cordon" "${deb_root}/usr/bin/cordon"
    install -m 0755 "${ROOT_DIR}/deploy/bin/agent-sandbox" "${deb_root}/usr/bin/agent-sandbox"
    install -m 0755 "${ROOT_DIR}/deploy/bin/agent-shell" "${deb_root}/usr/bin/agent-shell"
    install -m 0644 "${ROOT_DIR}/packaging/completions/cordon.bash" "${deb_root}/usr/share/bash-completion/completions/cordon"
    install -m 0644 "${ROOT_DIR}/packaging/completions/_cordon" "${deb_root}/usr/share/zsh/site-functions/_cordon"
    install -m 0644 "${ROOT_DIR}/packaging/completions/cordon.fish" "${deb_root}/usr/share/fish/vendor_completions.d/cordon.fish"
    install -m 0755 "${ROOT_DIR}/deploy/net/setup-sandbox-net.sh" "${deb_root}/usr/lib/cordon/setup-sandbox-net.sh"
    install -m 0644 "${ROOT_DIR}/deploy/mitmproxy/agent_policy_addon.py" "${deb_root}/usr/lib/cordon/agent_policy_addon.py"
    install -m 0644 "${ROOT_DIR}/deploy/bin/cordon.sudoers" "${deb_root}/usr/lib/cordon/cordon.sudoers"
    install -m 0644 "${ROOT_DIR}/configs/"* "${deb_root}/etc/cordon/configs/"
    install -m 0644 "${ROOT_DIR}/deploy/apparmor/usr.local.bin.agent-shell" "${deb_root}/etc/apparmor.d/usr.local.bin.agent-shell"
    install -m 0644 "${ROOT_DIR}/packaging/systemd/"*.service "${deb_root}/lib/systemd/system/"
    mkdir -p "${deb_root}/usr/share/doc/${PKG_NAME}"
    # Debian Policy 12.5: DEP-5 copyright file, verbatim licence texts, and the
    # AGPL section 6/13 source offer in /usr/share/doc/<package>/.
    install -m 0644 "${ROOT_DIR}/packaging/deb/copyright" "${deb_root}/usr/share/doc/${PKG_NAME}/copyright"
    install -m 0644 "${ROOT_DIR}/LICENSE" "${deb_root}/usr/share/doc/${PKG_NAME}/LICENSE"
    install -m 0644 "${ROOT_DIR}/LICENSE-PYCENTRIC.md" "${deb_root}/usr/share/doc/${PKG_NAME}/LICENSE-PYCENTRIC.md"
    install -m 0644 "${ROOT_DIR}/NOTICE.md" "${deb_root}/usr/share/doc/${PKG_NAME}/NOTICE.md"
    install -m 0644 "${ROOT_DIR}/SECURITY.md" "${deb_root}/usr/share/doc/${PKG_NAME}/SECURITY.md"
    install -m 0644 "${ROOT_DIR}/packaging/SOURCE_OFFER.txt" "${deb_root}/usr/share/doc/${PKG_NAME}/SOURCE_OFFER.txt"

    local deb_out="${DIST_DIR}/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
    if command -v dpkg-deb >/dev/null 2>&1; then
        dpkg-deb --build --root-owner-group "${deb_root}" "${deb_out}"
    else
        # Fallback standard Debian ar archive builder (2.0 format) for non-Debian build hosts
        local work_deb="${DIST_DIR}/deb-work"
        rm -rf "${work_deb}"
        mkdir -p "${work_deb}"
        echo "2.0" > "${work_deb}/debian-binary"
        tar -C "${deb_root}/DEBIAN" --owner=0 --group=0 -czf "${work_deb}/control.tar.gz" .
        rm -rf "${deb_root}/DEBIAN"
        tar -C "${deb_root}" --owner=0 --group=0 -czf "${work_deb}/data.tar.gz" .
        rm -f "${deb_out}"
        (cd "${work_deb}" && ar rcs "${deb_out}" debian-binary control.tar.gz data.tar.gz)
        rm -rf "${work_deb}"
    fi
    rm -rf "${deb_root}"
    echo "[cordon-package] Created Debian package: ${deb_out}"
}

write_checksums() {
    mkdir -p "${DIST_DIR}"
    (
        cd "${DIST_DIR}"
        rm -f SHA256SUMS
        sha256sum ./*.tar.gz ./*.deb > SHA256SUMS 2>/dev/null || sha256sum ./*.tar.gz > SHA256SUMS
    )
    echo "[cordon-package] Generated SHA256SUMS in ${DIST_DIR}/SHA256SUMS"
}

install_user() {
    ensure_completions
    local dest_home="${USER_INSTALL_ROOT:-${HOME}}"
    local user_bin="${dest_home}/.local/bin"
    local user_cfg="${dest_home}/.config/cordon/configs"
    local bash_comp="${dest_home}/.local/share/bash-completion/completions"
    local zsh_comp="${dest_home}/.local/share/zsh/site-functions"
    local zsh_zfunc="${dest_home}/.zfunc"
    local fish_comp="${dest_home}/.config/fish/completions"
    mkdir -p "${user_bin}" "${user_cfg}" "${bash_comp}" "${zsh_comp}" "${zsh_zfunc}" "${fish_comp}"
    install -m 0755 "${ROOT_DIR}/target/release/cordon" "${user_bin}/cordon"
    install -m 0644 "${ROOT_DIR}/configs/"* "${user_cfg}/"
    install -m 0644 "${ROOT_DIR}/packaging/completions/cordon.bash" "${bash_comp}/cordon"
    install -m 0644 "${ROOT_DIR}/packaging/completions/_cordon" "${zsh_comp}/_cordon"
    install -m 0644 "${ROOT_DIR}/packaging/completions/_cordon" "${zsh_zfunc}/_cordon"
    install -m 0644 "${ROOT_DIR}/packaging/completions/cordon.fish" "${fish_comp}/cordon.fish"
    echo "[cordon-install] Installed ${user_bin}/cordon, starter configs in ${user_cfg}, and Bash/Zsh/Fish completions."
}

MODE="${1:-all}"
case "${MODE}" in
    tarball)
        build_tarball
        write_checksums
        ;;
    deb)
        build_deb
        write_checksums
        ;;
    completions)
        ensure_completions
        echo "[cordon-package] Generated Bash, Zsh, and Fish completions in packaging/completions/"
        ;;
    install-user)
        install_user
        ;;
    all)
        build_tarball
        build_deb
        write_checksums
        ;;
    *)
        echo "Usage: $0 {tarball|deb|completions|install-user|all}" >&2
        exit 2
        ;;
esac
