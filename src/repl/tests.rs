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
