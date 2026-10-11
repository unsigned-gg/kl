//! kl (Kernel Layer Primitives)
//!
//! Direct, pure-Rust bindings for Linux Landlock LSM, seccomp BPF syscall filtering, and cgroup v2 resource limits without C runtime dependencies.
//!
//! # Architecture
//! Anchored in the systems principles of **Bryan Cantrill**.

pub use kl_domain::*;

/// Initializes the `kl` systems engine.
pub fn init() -> anyhow::Result<KlState> {
    Ok(KlState::default())
}
