// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Linux Landlock LSM runtime sandboxing interface.

use std::fs::File;
use std::path::Path;

use landlock::{
    Access, AccessFs, BitFlags, CompatLevel, Compatible, LandlockStatus, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, ABI,
};
use thiserror::Error;

use kl_domain::{AccessFs as DomainAccessFs, LandlockAbiVersion, LandlockRulesetDescriptor};

/// Errors encountered during Landlock LSM configuration.
#[derive(Debug, Error)]
pub enum LandlockError {
    /// Landlock is not enabled in this Linux kernel.
    #[error("landlock is unsupported or disabled in the current kernel")]
    Unsupported,
    /// Path canonicalization or resolution failed.
    #[error("failed to open path '{0}': {1}")]
    PathError(String, std::io::Error),
    /// Failed to create Landlock ruleset.
    #[error("landlock ruleset creation failed: {0}")]
    CreateFailed(landlock::RulesetError),
    /// Failed to add path rule to ruleset.
    #[error("landlock add rule failed for '{0}': {1}")]
    AddRuleFailed(String, String),
    /// Failed to restrict thread via Landlock.
    #[error("landlock restriction failed: {0}")]
    RestrictFailed(landlock::RulesetError),
    /// Probe thread failure.
    #[error("probe thread failed: {0}")]
    ProbeThread(String),
}

/// Detects the highest Landlock ABI version supported by the running kernel.
///
/// Probes on a scratch thread so the calling process remains completely unrestricted.
#[must_use]
pub fn probe_kernel_abi() -> Option<LandlockAbiVersion> {
    let handle = std::thread::Builder::new()
        .name("kl-landlock-probe".into())
        .spawn(probe_on_scratch_thread)
        .ok()?;

    handle.join().ok()?
}

fn probe_on_scratch_thread() -> Option<LandlockAbiVersion> {
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V1))
        .ok()?
        .create()
        .ok()?
        .restrict_self()
        .ok()?;

    match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => match effective_abi {
            ABI::V5 => Some(LandlockAbiVersion::V5),
            ABI::V4 => Some(LandlockAbiVersion::V4),
            ABI::V3 => Some(LandlockAbiVersion::V3),
            ABI::V2 => Some(LandlockAbiVersion::V2),
            ABI::V1 => Some(LandlockAbiVersion::V1),
            _ => Some(LandlockAbiVersion::V1),
        },
        _ => None,
    }
}

/// Convert domain access set to landlock `BitFlags<AccessFs>`.
fn access_to_flags(domain_set: &kl_domain::AccessFsSet) -> BitFlags<AccessFs> {
    let mut flags = BitFlags::EMPTY;
    if domain_set.contains(DomainAccessFs::Execute) {
        flags |= AccessFs::Execute;
    }
    if domain_set.contains(DomainAccessFs::WriteFile) {
        flags |= AccessFs::WriteFile;
    }
    if domain_set.contains(DomainAccessFs::ReadFile) {
        flags |= AccessFs::ReadFile;
    }
    if domain_set.contains(DomainAccessFs::ReadDir) {
        flags |= AccessFs::ReadDir;
    }
    if domain_set.contains(DomainAccessFs::RemoveDir) {
        flags |= AccessFs::RemoveDir;
    }
    if domain_set.contains(DomainAccessFs::RemoveFile) {
        flags |= AccessFs::RemoveFile;
    }
    if domain_set.contains(DomainAccessFs::MakeChar) {
        flags |= AccessFs::MakeChar;
    }
    if domain_set.contains(DomainAccessFs::MakeDir) {
        flags |= AccessFs::MakeDir;
    }
    if domain_set.contains(DomainAccessFs::MakeReg) {
        flags |= AccessFs::MakeReg;
    }
    if domain_set.contains(DomainAccessFs::MakeSock) {
        flags |= AccessFs::MakeSock;
    }
    if domain_set.contains(DomainAccessFs::MakeFifo) {
        flags |= AccessFs::MakeFifo;
    }
    if domain_set.contains(DomainAccessFs::MakeBlock) {
        flags |= AccessFs::MakeBlock;
    }
    if domain_set.contains(DomainAccessFs::MakeSym) {
        flags |= AccessFs::MakeSym;
    }
    flags
}

/// Compiles and applies a `LandlockRulesetDescriptor` to the calling process.
///
/// # Errors
/// Returns `LandlockError` if Landlock is unsupported or if ruleset installation fails.
pub fn apply_ruleset(desc: &LandlockRulesetDescriptor) -> Result<(), LandlockError> {
    let handled_flags = access_to_flags(&desc.handled_access_fs);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(handled_flags)
        .map_err(LandlockError::CreateFailed)?
        .create()
        .map_err(LandlockError::CreateFailed)?;

    for rule in &desc.path_rules {
        let p = Path::new(&rule.path);
        if !p.exists() {
            continue;
        }

        let file = File::open(p).map_err(|e| LandlockError::PathError(rule.path.clone(), e))?;
        let flags = access_to_flags(&rule.allowed_access);
        ruleset = ruleset
            .add_rule(PathBeneath::new(file, flags))
            .map_err(|e| LandlockError::AddRuleFailed(rule.path.clone(), e.to_string()))?;
    }

    ruleset
        .restrict_self()
        .map_err(LandlockError::RestrictFailed)?;

    Ok(())
}
