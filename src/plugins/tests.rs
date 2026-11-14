use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::error::CordonError;

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn make_tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cordon-plugins-{tag}-{}-{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    assert!(
        std::fs::create_dir_all(&dir).is_ok(),
        "failed to create temp dir {}",
        dir.display()
    );
    dir
}

fn write_manifest(dir: &Path, manifest: &str) {
    assert!(
        std::fs::create_dir_all(dir).is_ok(),
        "failed to create {}",
        dir.display()
    );
    assert!(
        std::fs::write(dir.join("plugin.toml"), manifest).is_ok(),
        "failed to write manifest in {}",
        dir.display()
    );
}

#[test]
fn resolves_builtin_fish_and_cordon_hud_plugins() -> Result<(), CordonError> {
    let fish = resolve_plugin("cordon-fish")?;
    assert!(fish.features.fish_autosuggest);
    assert!(fish.features.syntax_highlighting);

    let hud = resolve_plugin("cordon-plugins/cordon-hud")?;
    assert!(hud.features.powerline_prompt);
    assert_eq!(
        hud.aliases.get("ag").map(String::as_str),
        Some("./configs/Cordonfile.antigravity")
    );
    Ok(())
}

#[test]
fn parses_tmux_plugin_directive_and_abbreviates_paths() {
    assert_eq!(
        parse_tmux_plugin_directive("set -g @plugin 'cordon-plugins/cordon-fish'"),
        Some("cordon-plugins/cordon-fish".to_owned())
    );
    let p = Path::new("/opt/workspaces/cordon-engine");
    assert_eq!(abbreviate_fish_path(p), "/o/w/cordon-engine");
}

#[test]
fn hostile_workspace_manifest_cannot_shadow_builtins() {
    let tmp = make_tmp_dir("shadow");
    let hostile = tmp.join("cordon-fish");
    write_manifest(
        &hostile,
        "name = \"cordon-fish\"\nrepo_id = \"cordon-plugins/cordon-fish\"\nversion = \"9.9.9\"\n\
         [groups]\ndefault_command_groups = [\"net-diag\", \"coreutils\"]\n",
    );
    for allow_workspace in [false, true] {
        let resolved = resolve_plugin_in("cordon-fish", &tmp, allow_workspace)
            .unwrap_or_else(|e| panic!("builtin must resolve: {e}"));
        assert_eq!(resolved.version, "0.2.0");
        assert_eq!(resolved.repo_id, "cordon-plugins/cordon-fish");
        assert_eq!(
            resolved.default_command_groups,
            vec!["coreutils".to_owned(), "shell-builtins".to_owned()],
            "workspace manifest must not widen builtin policy (allow_workspace={allow_workspace})"
        );
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn workspace_plugins_denied_by_default_and_allowed_with_opt_in() {
    let tmp = make_tmp_dir("optin");
    write_manifest(
        &tmp.join("plugins").join("custom-thing"),
        "name = \"custom-thing\"\nrepo_id = \"cordon-plugins/custom-thing\"\nversion = \"1.2.3\"\n",
    );
    assert!(
        resolve_plugin_in("custom-thing", &tmp, false).is_err(),
        "workspace plugin must be denied by default"
    );
    let resolved = resolve_plugin_in("custom-thing", &tmp, true)
        .unwrap_or_else(|e| panic!("opt-in workspace plugin must resolve: {e}"));
    assert_eq!(resolved.name, "custom-thing");
    assert_eq!(resolved.version, "1.2.3");

    let denied_list = list_available_plugins_in(Some(&tmp), false);
    assert!(!denied_list.iter().any(|p| p.name == "custom-thing"));
    let allowed_list = list_available_plugins_in(Some(&tmp), true);
    assert!(allowed_list.iter().any(|p| p.name == "custom-thing"));
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn explicit_manifest_path_outside_trusted_roots_is_rejected() {
    let tmp = make_tmp_dir("explicit");
    write_manifest(
        &tmp.join("evil"),
        "name = \"evil\"\nrepo_id = \"cordon-plugins/evil\"\nversion = \"0.0.1\"\n",
    );
    assert!(
        resolve_plugin_in("evil/plugin.toml", &tmp, false).is_err(),
        "workspace-relative manifest path must be denied by default"
    );
    let resolved = resolve_plugin_in("evil/plugin.toml", &tmp, true)
        .unwrap_or_else(|e| panic!("opt-in manifest path must resolve: {e}"));
    assert_eq!(resolved.name, "evil");
    let _ = std::fs::remove_dir_all(&tmp);
}
