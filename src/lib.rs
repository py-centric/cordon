//! Cordon: Type-safe Rust execution sandbox and L3-L7 network telemetry engine.
//!
//! Engineered and Governed by PyCentric under `ADR-L0-SEC-02`.

pub mod api;
pub mod apparmor;
pub mod cli;
pub mod config;
pub mod dashboard;
pub mod domain;
pub mod error;
pub mod groups;
pub mod l7_policy;
pub mod network;
pub mod plugins;
pub mod ports;
pub mod profiles;
pub mod repl;
pub mod repl_editor;
pub mod sandbox;
pub mod tui;
