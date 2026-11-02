# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_cordon_global_optspecs
    string join \n json h/help V/version
end

function __fish_cordon_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_cordon_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_cordon_using_subcommand
    set -l cmd (__fish_cordon_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c cordon -n "__fish_cordon_needs_command" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_needs_command" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_needs_command" -s V -l version -d 'Print version'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "run" -d 'Compile and execute (or dry-run) any command or `Cordonfile` inside the 5-gate Cordon sandbox'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "exec" -d 'Compile and execute (or dry-run) any command or `Cordonfile` inside the 5-gate Cordon sandbox'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "shell" -d 'Launch an interactive sandboxed `/bin/bash --norc` shell inside Bubblewrap'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "repl" -d 'Start the interactive Cordon Sandbox Control & Execution REPL (`cordon repl`)'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "profiles" -d 'List all 6 built-in universal workload sandbox profiles'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "groups" -d 'List all 8 pre-populated command groups (`coreutils`, `search-tools`, etc.) and 6 directory groups (`xdg-config`, etc.)'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "plugin" -d 'Manage the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`)'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "plugins" -d 'Manage the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`)'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "config" -d 'Manage reproducible `Cordonfile` / `Cordonfile.toml` / `cordon.json` environment configs'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "inspect-cmd" -d 'Compile and inspect the Bubblewrap (`bwrap`) and `ip netns` launch plan'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "render-apparmor" -d 'Render the AppArmor 4.0 Mandatory Access Control profile'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "render-netns" -d 'Render the idempotent `ip netns`, `veth`, and `iptables` provisioning commands'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "evaluate-url" -d 'Evaluate an outbound HTTP/HTTPS request against L7 domain, DoH, and secret rules'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "doctor" -d 'Verify host kernel LSM capabilities and sandbox toolchain binaries'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "serve" -d 'Start the `axum` HTTP Control Plane and WCAG AA Web Dashboard'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "tui" -d 'Launch the interactive `ratatui` Terminal UI & Sandbox Session Launcher (or `--snapshot` for static frame)'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "completions" -d 'Generate shell completion scripts (`bash`, `zsh`, `fish`)'
complete -c cordon -n "__fish_cordon_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand run" -s p -l profile -d 'Workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`)' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand run" -s f -l config -d 'Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand run" -s w -l workspace -d 'Workspace directory to bind inside Bubblewrap' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand run" -s v -l volume -d 'Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`)' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand run" -l bind-ro -d 'Additional host paths to bind read-only (`--ro-bind`)' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand run" -l bind-rw -d 'Additional host paths to bind read-write (`--bind`)' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand run" -l mask-bin -d 'Additional host binary paths to mask with `/dev/null`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand run" -l allow-bin -d 'Expose/unmask specific host binaries inside the sandbox (`bat`, `rg`, `fd`, `jq`, etc.)' -r -f -a "(__fish_complete_command)"
complete -c cordon -n "__fish_cordon_using_subcommand run" -l allow-group -d 'Enable pre-populated command groups (`coreutils`, `shell-builtins`, `search-tools`, `vcs-git`, `rust-toolchain`, `python-uv`, `node-web`, `net-diag`)' -r -f -a "coreutils\t''
shell-builtins\t''
search-tools\t''
vcs-git\t''
rust-toolchain\t''
python-uv\t''
node-web\t''
net-diag\t''"
complete -c cordon -n "__fish_cordon_using_subcommand run" -l mount-group -d 'Mount pre-populated directory groups (`system-libs`, `ssl-certs`, `xdg-config`, `agent-state`, `toolchain-caches`, `temp-scratch`)' -r
complete -c cordon -n "__fish_cordon_using_subcommand run" -s e -l env -d 'Additional environment variables (`KEY=VALUE`) injected into the sandbox' -r
complete -c cordon -n "__fish_cordon_using_subcommand run" -l allow-domain -d 'Additional outbound domains permitted by L7 policy' -r -f -a "(__fish_print_hostnames)"
complete -c cordon -n "__fish_cordon_using_subcommand run" -l offline -d 'Force complete loopback air-gap (`bwrap --unshare-net`) regardless of profile default'
complete -c cordon -n "__fish_cordon_using_subcommand run" -l host-net -d 'Force direct host network namespace inside Bubblewrap (bypassing `ip netns exec`)'
complete -c cordon -n "__fish_cordon_using_subcommand run" -l dry-run -d 'Compile and print the 5-gate execution plan without spawning the child process'
complete -c cordon -n "__fish_cordon_using_subcommand run" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand run" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand exec" -s p -l profile -d 'Workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`)' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -s f -l config -d 'Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand exec" -s w -l workspace -d 'Workspace directory to bind inside Bubblewrap' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -s v -l volume -d 'Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`)' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l bind-ro -d 'Additional host paths to bind read-only (`--ro-bind`)' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l bind-rw -d 'Additional host paths to bind read-write (`--bind`)' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l mask-bin -d 'Additional host binary paths to mask with `/dev/null`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l allow-bin -d 'Expose/unmask specific host binaries inside the sandbox (`bat`, `rg`, `fd`, `jq`, etc.)' -r -f -a "(__fish_complete_command)"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l allow-group -d 'Enable pre-populated command groups (`coreutils`, `shell-builtins`, `search-tools`, `vcs-git`, `rust-toolchain`, `python-uv`, `node-web`, `net-diag`)' -r -f -a "coreutils\t''
shell-builtins\t''
search-tools\t''
vcs-git\t''
rust-toolchain\t''
python-uv\t''
node-web\t''
net-diag\t''"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l mount-group -d 'Mount pre-populated directory groups (`system-libs`, `ssl-certs`, `xdg-config`, `agent-state`, `toolchain-caches`, `temp-scratch`)' -r
complete -c cordon -n "__fish_cordon_using_subcommand exec" -s e -l env -d 'Additional environment variables (`KEY=VALUE`) injected into the sandbox' -r
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l allow-domain -d 'Additional outbound domains permitted by L7 policy' -r -f -a "(__fish_print_hostnames)"
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l offline -d 'Force complete loopback air-gap (`bwrap --unshare-net`) regardless of profile default'
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l host-net -d 'Force direct host network namespace inside Bubblewrap (bypassing `ip netns exec`)'
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l dry-run -d 'Compile and print the 5-gate execution plan without spawning the child process'
complete -c cordon -n "__fish_cordon_using_subcommand exec" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand exec" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand shell" -s p -l profile -d 'Workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`)' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand shell" -s f -l config -d 'Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand shell" -s w -l workspace -d 'Workspace directory to bind inside Bubblewrap' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand shell" -s v -l volume -d 'Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`)' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l allow-bin -d 'Expose/unmask specific host binaries inside the sandbox (`bat`, `rg`, `fd`, `jq`, etc.)' -r -f -a "(__fish_complete_command)"
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l allow-group -d 'Enable pre-populated command groups (`coreutils`, `shell-builtins`, `search-tools`, etc.)' -r -f -a "coreutils\t''
shell-builtins\t''
search-tools\t''
vcs-git\t''
rust-toolchain\t''
python-uv\t''
node-web\t''
net-diag\t''"
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l mount-group -d 'Mount pre-populated directory groups (`xdg-config`, `agent-state`, `toolchain-caches`, etc.)' -r
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l offline -d 'Force complete loopback air-gap (`bwrap --unshare-net`)'
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l host-net -d 'Force direct host network namespace inside Bubblewrap'
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l dry-run -d 'Print the prepared sandbox shell command without spawning'
complete -c cordon -n "__fish_cordon_using_subcommand shell" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand shell" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand repl" -s p -l profile -d 'Initial workload profile slug' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand repl" -s f -l config -d 'Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand repl" -s w -l workspace -d 'Initial workspace directory' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l allow-bin -d 'Expose/unmask specific host binaries in the REPL session (`bat`, `rg`, etc.)' -r -f -a "(__fish_complete_command)"
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l allow-group -d 'Enable pre-populated command groups in the REPL session (`coreutils`, `search-tools`, etc.)' -r -f -a "coreutils\t''
shell-builtins\t''
search-tools\t''
vcs-git\t''
rust-toolchain\t''
python-uv\t''
node-web\t''
net-diag\t''"
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l mount-group -d 'Mount pre-populated directory groups in the REPL session (`xdg-config`, `agent-state`, etc.)' -r
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l offline -d 'Start REPL in offline air-gap mode (`bwrap --unshare-net`)'
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l host-net -d 'Start REPL in direct host network mode'
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l dry-run -d 'Dry-run mode inside REPL (`run` / `!<cmd>` prints command instead of spawning)'
complete -c cordon -n "__fish_cordon_using_subcommand repl" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand repl" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand profiles" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand profiles" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand groups" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand groups" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and not __fish_seen_subcommand_from list info help" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and not __fish_seen_subcommand_from list info help" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and not __fish_seen_subcommand_from list info help" -f -a "list" -d 'List all available Cordon plugins (`cordon-fish`, `cordon-hud`, and custom `plugins/*/plugin.toml`)'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and not __fish_seen_subcommand_from list info help" -f -a "info" -d 'Inspect manifest details, features, groups, and aliases for a specific plugin'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and not __fish_seen_subcommand_from list info help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from list" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from info" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from help" -f -a "list" -d 'List all available Cordon plugins (`cordon-fish`, `cordon-hud`, and custom `plugins/*/plugin.toml`)'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from help" -f -a "info" -d 'Inspect manifest details, features, groups, and aliases for a specific plugin'
complete -c cordon -n "__fish_cordon_using_subcommand plugin; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and not __fish_seen_subcommand_from list info help" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and not __fish_seen_subcommand_from list info help" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and not __fish_seen_subcommand_from list info help" -f -a "list" -d 'List all available Cordon plugins (`cordon-fish`, `cordon-hud`, and custom `plugins/*/plugin.toml`)'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and not __fish_seen_subcommand_from list info help" -f -a "info" -d 'Inspect manifest details, features, groups, and aliases for a specific plugin'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and not __fish_seen_subcommand_from list info help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from list" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from info" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from help" -f -a "list" -d 'List all available Cordon plugins (`cordon-fish`, `cordon-hud`, and custom `plugins/*/plugin.toml`)'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from help" -f -a "info" -d 'Inspect manifest details, features, groups, and aliases for a specific plugin'
complete -c cordon -n "__fish_cordon_using_subcommand plugins; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand config; and not __fish_seen_subcommand_from list-templates init validate help" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand config; and not __fish_seen_subcommand_from list-templates init validate help" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand config; and not __fish_seen_subcommand_from list-templates init validate help" -f -a "list-templates" -d 'List built-in reproducible environment templates (`opencode`, `antigravity`, `python-sandbox`, `package-build`)'
complete -c cordon -n "__fish_cordon_using_subcommand config; and not __fish_seen_subcommand_from list-templates init validate help" -f -a "init" -d 'Scaffold a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json` from a template'
complete -c cordon -n "__fish_cordon_using_subcommand config; and not __fish_seen_subcommand_from list-templates init validate help" -f -a "validate" -d 'Validate a `Cordonfile`, `Cordonfile.toml`, or `cordon.json` and preview its 5-gate launch plan'
complete -c cordon -n "__fish_cordon_using_subcommand config; and not __fish_seen_subcommand_from list-templates init validate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from list-templates" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from list-templates" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from init" -s t -l template -d 'Template slug (`opencode`, `antigravity`, `python-sandbox`, `package-build`)' -r -f -a "opencode\t''
antigravity\t''
python-sandbox\t''
package-build\t''"
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from init" -s f -l format -d 'Output format (`cordonfile`, `toml`, `json`)' -r -f -a "cordonfile\t''
toml\t''
json\t''"
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from init" -s o -l output -d 'Optional output file path (prints to stdout when omitted)' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from init" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from validate" -s f -l file -d 'Path to the configuration file to validate' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from validate" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from validate" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "list-templates" -d 'List built-in reproducible environment templates (`opencode`, `antigravity`, `python-sandbox`, `package-build`)'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "init" -d 'Scaffold a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json` from a template'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "validate" -d 'Validate a `Cordonfile`, `Cordonfile.toml`, or `cordon.json` and preview its 5-gate launch plan'
complete -c cordon -n "__fish_cordon_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -s p -l profile -d 'Workload profile slug' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -s f -l config -d 'Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -s w -l workspace -d 'Workspace directory to bind' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -s v -l volume -d 'Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`)' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l bind-ro -d 'Additional host paths to bind read-only' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l bind-rw -d 'Additional host paths to bind read-write' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l mask-bin -d 'Additional host binary paths to mask with `/dev/null`' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l allow-bin -d 'Expose/unmask specific host binaries (`bat`, `rg`, etc.)' -r -f -a "(__fish_complete_command)"
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l allow-group -d 'Enable pre-populated command groups (`coreutils`, `search-tools`, etc.)' -r -f -a "coreutils\t''
shell-builtins\t''
search-tools\t''
vcs-git\t''
rust-toolchain\t''
python-uv\t''
node-web\t''
net-diag\t''"
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l mount-group -d 'Mount pre-populated directory groups (`xdg-config`, `agent-state`, etc.)' -r
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -s e -l env -d 'Additional environment variables (`KEY=VALUE`) injected into the sandbox' -r
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand inspect-cmd" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand render-apparmor" -s p -l profile -d 'Workload profile slug' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand render-apparmor" -l attach-path -d 'Binary path to attach the AppArmor profile to' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand render-apparmor" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand render-apparmor" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand render-netns" -s p -l profile -d 'Workload profile slug' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand render-netns" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand render-netns" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand evaluate-url" -s p -l profile -d 'Workload profile slug' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand evaluate-url" -s u -l url -d 'Outbound URL to inspect' -r -f
complete -c cordon -n "__fish_cordon_using_subcommand evaluate-url" -s m -l method -d 'HTTP method (`GET`, `POST`, etc.)' -r -f -a "GET\t''
POST\t''
PUT\t''
PATCH\t''
DELETE\t''
HEAD\t''"
complete -c cordon -n "__fish_cordon_using_subcommand evaluate-url" -s b -l body -d 'Optional HTTP request body to scan for leaked secrets' -r
complete -c cordon -n "__fish_cordon_using_subcommand evaluate-url" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand evaluate-url" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand doctor" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand doctor" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand serve" -l host -d 'Bind address' -r -f -a "(__fish_print_hostnames)"
complete -c cordon -n "__fish_cordon_using_subcommand serve" -l port -d 'Bind TCP port' -r
complete -c cordon -n "__fish_cordon_using_subcommand serve" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand serve" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand tui" -s p -l profile -d 'Initial workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`)' -r -f -a "ai-agent\t''
untrusted-code\t''
package-build\t''
network-audit\t''
gui-desktop\t''
airgapped\t''"
complete -c cordon -n "__fish_cordon_using_subcommand tui" -s w -l workspace -d 'Initial workspace directory' -r -f -a "(__fish_complete_directories)"
complete -c cordon -n "__fish_cordon_using_subcommand tui" -l snapshot -d 'Render a static non-interactive frame snapshot and exit immediately'
complete -c cordon -n "__fish_cordon_using_subcommand tui" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand tui" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand completions" -s o -l output -d 'Optional output file path to write the generated completion script' -r -F
complete -c cordon -n "__fish_cordon_using_subcommand completions" -l json -d 'Emit machine-parseable JSON to stdout while routing diagnostics to stderr'
complete -c cordon -n "__fish_cordon_using_subcommand completions" -s h -l help -d 'Print help'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "run" -d 'Compile and execute (or dry-run) any command or `Cordonfile` inside the 5-gate Cordon sandbox'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "shell" -d 'Launch an interactive sandboxed `/bin/bash --norc` shell inside Bubblewrap'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "repl" -d 'Start the interactive Cordon Sandbox Control & Execution REPL (`cordon repl`)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "profiles" -d 'List all 6 built-in universal workload sandbox profiles'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "groups" -d 'List all 8 pre-populated command groups (`coreutils`, `search-tools`, etc.) and 6 directory groups (`xdg-config`, etc.)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "plugin" -d 'Manage the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "config" -d 'Manage reproducible `Cordonfile` / `Cordonfile.toml` / `cordon.json` environment configs'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "inspect-cmd" -d 'Compile and inspect the Bubblewrap (`bwrap`) and `ip netns` launch plan'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "render-apparmor" -d 'Render the AppArmor 4.0 Mandatory Access Control profile'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "render-netns" -d 'Render the idempotent `ip netns`, `veth`, and `iptables` provisioning commands'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "evaluate-url" -d 'Evaluate an outbound HTTP/HTTPS request against L7 domain, DoH, and secret rules'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "doctor" -d 'Verify host kernel LSM capabilities and sandbox toolchain binaries'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "serve" -d 'Start the `axum` HTTP Control Plane and WCAG AA Web Dashboard'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "tui" -d 'Launch the interactive `ratatui` Terminal UI & Sandbox Session Launcher (or `--snapshot` for static frame)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "completions" -d 'Generate shell completion scripts (`bash`, `zsh`, `fish`)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and not __fish_seen_subcommand_from run shell repl profiles groups plugin config inspect-cmd render-apparmor render-netns evaluate-url doctor serve tui completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and __fish_seen_subcommand_from plugin" -f -a "list" -d 'List all available Cordon plugins (`cordon-fish`, `cordon-hud`, and custom `plugins/*/plugin.toml`)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and __fish_seen_subcommand_from plugin" -f -a "info" -d 'Inspect manifest details, features, groups, and aliases for a specific plugin'
complete -c cordon -n "__fish_cordon_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "list-templates" -d 'List built-in reproducible environment templates (`opencode`, `antigravity`, `python-sandbox`, `package-build`)'
complete -c cordon -n "__fish_cordon_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "init" -d 'Scaffold a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json` from a template'
complete -c cordon -n "__fish_cordon_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "validate" -d 'Validate a `Cordonfile`, `Cordonfile.toml`, or `cordon.json` and preview its 5-gate launch plan'

# PyCentric Cordon shell candidates & wrapper completions (agent-sandbox & agent-shell)
complete -c cordon -n "__fish_cordon_using_subcommand completions" -f -a "bash zsh fish elvish powershell"
complete -c agent-sandbox -w cordon
complete -c agent-shell -f -a "(__fish_complete_subcommand)"
