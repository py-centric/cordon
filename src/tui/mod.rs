//! Interactive Terminal UI (`ratatui` + `crossterm`) control center and session launcher for Cordon.
//!
//! Provides both:
//! - [`render_tui_snapshot`] for headless non-TTY snapshot rendering and automated tests.
//! - [`run_interactive_tui`] for full-screen interactive keyboard navigation, group/config
//!   customization, and live sandbox session launching (`Shell`, `REPL`, `Command`, `Cordonfile`).

mod input;
mod runner;
mod view;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;

pub use input::handle_tui_key_event;
pub use runner::{render_tui_snapshot, run_interactive_tui};
pub use view::draw_interactive_tui;

use crate::api::CordonControlPlane;
use crate::config::CordonEnvironmentConfig;
use crate::domain::{
    AuditEvent, CordonProfile, EnforcementPlane, SandboxLaunchPlan, Severity, Verdict,
};
use crate::error::CordonError;
use crate::groups::{
    apply_command_group_to_profile, apply_directory_group_to_profile, list_command_group_infos,
    list_directory_group_infos,
};
use crate::ports::{AuditSinkPort, ProfileCatalogPort, SandboxCompilerPort};
use crate::profiles::BuiltinProfileCatalog;
use crate::repl::ReplNetMode;
use crate::repl_editor::sanitize_terminal_line;
use crate::sandbox::BwrapSandboxCompiler;

/// Number of recent telemetry events shown in the TUI telemetry pane.
pub(super) const TELEMETRY_EVENT_WINDOW: usize = 25;

/// Sanitizes untrusted text for safe single-line terminal rendering inside the TUI.
pub(super) fn ts(value: &str) -> String {
    sanitize_terminal_line(value)
}

/// Returns a block title with a non-color focus marker when the pane is active.
pub(super) fn focus_title(active: bool, title: &str) -> String {
    if active {
        format!("> {title}")
    } else {
        title.to_owned()
    }
}

/// Active focus pane in the interactive Cordon TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiPane {
    /// Universal workload profiles (`ai-agent`, `untrusted-code`, etc.).
    Profiles,
    /// Reproducible `configs/*` files (`Cordonfile.opencode`, `Cordonfile.antigravity`, etc.).
    Configs,
    /// Pre-populated command and directory groups toggled with `Space`.
    Groups,
    /// Audit telemetry feed and live 5-Gate launch plan inspector.
    Telemetry,
}

impl TuiPane {
    /// Cycles to the next focus pane (`Tab` / `Right`).
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Profiles => Self::Configs,
            Self::Configs => Self::Groups,
            Self::Groups => Self::Telemetry,
            Self::Telemetry => Self::Profiles,
        }
    }

    /// Cycles to the previous focus pane (`BackTab` / `Left`).
    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Profiles => Self::Telemetry,
            Self::Configs => Self::Profiles,
            Self::Groups => Self::Configs,
            Self::Telemetry => Self::Groups,
        }
    }
}

/// Pending session launch request triggered from inside the interactive TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiLaunchAction {
    /// Launch an interactive sandboxed `/bin/bash --norc` shell (`s` or `Enter`).
    SandboxShell,
    /// Launch the interactive Cordon REPL preloaded with the current TUI settings (`r`).
    InteractiveRepl,
    /// Run a custom command inside the sandbox (`c` / `:`).
    CustomCommand(Vec<String>),
    /// Run the selected reproducible `configs/*` file (`x`).
    RunSelectedConfig,
}

/// Interactive state for the Cordon Terminal UI (`cordon tui`).
#[derive(Debug)]
pub struct TuiApp {
    /// Control plane holding the audit telemetry ring buffer.
    pub plane: CordonControlPlane,
    /// Hexagonal profile catalog port implementation.
    pub catalog: BuiltinProfileCatalog,
    /// Hexagonal sandbox compiler port implementation.
    pub sandbox: BwrapSandboxCompiler,
    /// Available built-in workload profiles.
    pub profiles: Vec<CordonProfile>,
    /// Selected index in `profiles`.
    pub selected_profile_idx: usize,
    /// Discovered config entries (`None` = use selected profile directly, `Some(path)` = load config file).
    pub config_entries: Vec<Option<PathBuf>>,
    /// Selected index in `config_entries`.
    pub selected_config_idx: usize,
    /// Available group entries (`(is_dir_group, slug, summary)`).
    pub group_entries: Vec<(bool, String, String)>,
    /// Selected index in `group_entries`.
    pub selected_group_idx: usize,
    /// Enabled command group slugs (`coreutils`, `search-tools`, etc.).
    pub enabled_command_groups: Vec<String>,
    /// Enabled directory group specs (`xdg-config:ro`, `agent-state:rw`, etc.).
    pub enabled_directory_groups: Vec<String>,
    /// Selected scroll offset in the audit telemetry feed.
    pub telemetry_scroll: usize,
    /// Current focused pane.
    pub active_pane: TuiPane,
    /// Active network execution mode (`Auto`, `Airgap`, `Direct`).
    pub net_mode: ReplNetMode,
    /// Active workspace directory.
    pub workspace: PathBuf,
    /// Whether the inline command prompt (`c` / `:`) is currently open.
    pub input_mode: bool,
    /// Current text buffer in the inline command prompt.
    pub command_input: String,
    /// Status banner message displayed in the footer.
    pub status_message: String,
    /// Flag indicating the user requested to exit the TUI (`q` / `Esc`).
    pub should_quit: bool,
    /// Pending session launch action to execute outside raw mode.
    pub pending_launch: Option<TuiLaunchAction>,
}

impl TuiApp {
    /// Initializes a new [`TuiApp`] scanning `./configs` and preloading default groups.
    pub fn new(initial_profile: &str, workspace: Option<PathBuf>) -> Self {
        let plane = CordonControlPlane::new();
        let catalog = BuiltinProfileCatalog;
        let sandbox = BwrapSandboxCompiler;
        let profiles = catalog.list_profiles();
        let selected_profile_idx = profiles
            .iter()
            .position(|p| p.name == initial_profile)
            .unwrap_or(0);

        let mut config_entries: Vec<Option<PathBuf>> = vec![None];
        if let Ok(entries) = std::fs::read_dir("configs") {
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            paths.sort();
            for p in paths {
                config_entries.push(Some(p));
            }
        }

        let mut group_entries = Vec::new();
        for cg in list_command_group_infos() {
            group_entries.push((false, cg.slug, cg.summary));
        }
        for dg in list_directory_group_infos() {
            group_entries.push((true, format!("{}:{}", dg.slug, dg.default_mode), dg.summary));
        }

        let ws = workspace
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));

        Self {
            plane,
            catalog,
            sandbox,
            profiles,
            selected_profile_idx,
            config_entries,
            selected_config_idx: 0,
            group_entries,
            selected_group_idx: 0,
            enabled_command_groups: vec![
                "coreutils".to_owned(),
                "shell-builtins".to_owned(),
                "search-tools".to_owned(),
                "vcs-git".to_owned(),
            ],
            enabled_directory_groups: vec!["xdg-config:ro".to_owned()],
            telemetry_scroll: 0,
            active_pane: TuiPane::Profiles,
            net_mode: ReplNetMode::Auto,
            workspace: ws,
            input_mode: false,
            command_input: String::new(),
            status_message: "Ready. Keys: [Tab] Switch Pane | [Up/Down] Select | [Space] Toggle Group | [s/Enter] Start Shell | [r] Start REPL | [c] Run Cmd | [n] Net Mode | [q] Quit".to_owned(),
            should_quit: false,
            pending_launch: None,
        }
    }

    /// Returns the currently selected profile slug.
    pub fn active_profile_name(&self) -> &str {
        self.profiles
            .get(self.selected_profile_idx)
            .map_or("ai-agent", |p| p.name.as_str())
    }

    /// Returns the currently selected optional config file path.
    pub fn active_config_path(&self) -> Option<&Path> {
        self.config_entries
            .get(self.selected_config_idx)
            .and_then(|opt| opt.as_deref())
    }

    /// Returns the maximum valid `telemetry_scroll` offset for the current event list.
    pub fn max_telemetry_scroll(&self) -> usize {
        self.plane
            .recent_events(TELEMETRY_EVENT_WINDOW)
            .len()
            .saturating_sub(1)
    }

    /// Clamps `telemetry_scroll` to the bounds of the current telemetry list.
    pub fn clamp_telemetry_scroll(&mut self) {
        let max_scroll = self.max_telemetry_scroll();
        if self.telemetry_scroll > max_scroll {
            self.telemetry_scroll = max_scroll;
        }
    }

    /// Builds the effective [`CordonProfile`] and [`SandboxLaunchPlan`] for the current TUI selections.
    pub fn compile_active_plan(
        &self,
        command: &[String],
    ) -> Result<(CordonProfile, SandboxLaunchPlan), CordonError> {
        let mut effective_cmd = command.to_vec();
        let mut profile = if let Some(cfg_path) = self.active_config_path() {
            let cfg = CordonEnvironmentConfig::from_file(cfg_path)?;
            if effective_cmd.is_empty() && !cfg.command.is_empty() {
                effective_cmd.clone_from(&cfg.command);
            }
            cfg.build_profile()?
        } else {
            self.catalog.get_profile(self.active_profile_name())?
        };

        if effective_cmd.is_empty() {
            effective_cmd = vec!["/bin/bash".to_owned(), "--norc".to_owned()];
        }

        for cg in &self.enabled_command_groups {
            apply_command_group_to_profile(&mut profile, cg)?;
        }
        for dg_spec in &self.enabled_directory_groups {
            apply_directory_group_to_profile(&mut profile, dg_spec, None)?;
        }

        let plan = self.sandbox.compile_launch_plan(
            &profile,
            &self.workspace,
            &effective_cmd,
            &[],
            &[],
        )?;
        Ok((profile, plan))
    }

    /// Toggles the currently highlighted command or directory group in `TuiPane::Groups`.
    pub fn toggle_selected_group(&mut self) {
        let Some((is_dir, slug, _)) = self.group_entries.get(self.selected_group_idx).cloned()
        else {
            return;
        };
        if is_dir {
            if let Some(pos) = self
                .enabled_directory_groups
                .iter()
                .position(|g| g == &slug)
            {
                self.enabled_directory_groups.remove(pos);
                self.status_message = format!("Unmounted directory group '{slug}'.");
            } else {
                self.enabled_directory_groups.push(slug.clone());
                self.status_message = format!("Mounted directory group '{slug}'.");
            }
        } else if let Some(pos) = self.enabled_command_groups.iter().position(|g| g == &slug) {
            self.enabled_command_groups.remove(pos);
            self.status_message = format!("Disabled command group '{slug}'.");
        } else {
            self.enabled_command_groups.push(slug.clone());
            self.status_message = format!("Enabled command group '{slug}'.");
        }
    }

    /// Records a custom audit telemetry event into the control plane buffer.
    pub fn record_event(&self, verdict: Verdict, subject: &str, reason: &str) {
        let mut details = BTreeMap::new();
        details.insert("reason".to_owned(), reason.to_owned());
        self.plane.record_event(AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: EnforcementPlane::Bwrap,
            severity: if verdict == Verdict::Block {
                Severity::Warning
            } else {
                Severity::Info
            },
            verdict,
            profile: self.active_profile_name().to_owned(),
            subject: subject.to_owned(),
            details,
        });
    }
}
