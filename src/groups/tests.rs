use super::*;
use crate::profiles::get_profile;

#[test]
fn command_groups_contain_coreutils_builtins_and_search_tools() -> Result<(), CordonError> {
    let groups = list_command_groups();
    assert_eq!(groups.len(), 8);

    let core = get_command_group("coreutils")?;
    assert!(core.programs.contains(&"ls"));
    assert!(core.programs.contains(&"cat"));

    let builtins = get_command_group("shell-builtins")?;
    assert!(builtins.programs.contains(&"cd"));
    assert!(builtins.programs.contains(&"export"));

    let search = get_command_group("search-tools")?;
    assert!(search.programs.contains(&"bat"));
    assert!(search.programs.contains(&"rg"));
    assert!(search.programs.contains(&"ripgrep"));
    Ok(())
}

#[test]
fn allow_binary_unmasks_denied_binaries_and_resolves_host_tools() -> Result<(), CordonError> {
    let mut prof = get_profile("untrusted-code")?;
    assert!(prof.denied_binaries.contains(&"/usr/bin/curl".to_owned()));

    let _ = apply_allowed_binary_to_profile(&mut prof, "curl");
    assert!(!prof.denied_binaries.contains(&"/usr/bin/curl".to_owned()));

    let enabled = apply_command_group_to_profile(&mut prof, "search-tools")?;
    assert!(enabled.contains(&"bat".to_owned()));
    assert!(enabled.contains(&"rg".to_owned()));
    Ok(())
}

#[test]
fn directory_groups_mount_ro_and_rw_with_override() -> Result<(), CordonError> {
    let mut prof = get_profile("ai-agent")?;
    let readonly_paths = apply_directory_group_to_profile(&mut prof, "xdg-config", None)?;
    assert_eq!(readonly_paths.len(), 4);
    assert!(
        prof.extra_ro_binds
            .iter()
            .any(|p| p.ends_with(".config/bat"))
    );

    let writable_paths = apply_directory_group_to_profile(&mut prof, "xdg-config:rw", None)?;
    assert_eq!(writable_paths.len(), 4);
    assert!(
        prof.extra_rw_binds
            .iter()
            .any(|p| p.ends_with(".config/bat"))
    );
    Ok(())
}
