//! Provides configuration types for Wasmer.

pub mod app;
pub mod cargo_annotations;
pub mod hash;
#[cfg(feature = "network-rules")]
pub mod network_rules;
pub mod package;
