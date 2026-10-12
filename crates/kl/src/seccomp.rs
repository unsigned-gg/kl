// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Linux seccomp-BPF system call filtering compilation and installation.

use std::collections::BTreeMap;

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction as CAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule,
};
use thiserror::Error;

use kl_domain::{ComparisonOp, SeccompAction, SeccompFilterDescriptor, SystemArch};

/// Errors encountered while configuring seccomp filters.
#[derive(Debug, Error)]
pub enum SeccompError {
    /// Kernel architecture translation failed.
    #[error("failed to determine target architecture: {0}")]
    ArchError(String),
    /// Failed to compile seccomp-BPF filter program.
    #[error("failed to compile seccomp filter: {0}")]
    CompileError(String),
    /// PR_SET_NO_NEW_PRIVS prctl failed.
    #[error("prctl(PR_SET_NO_NEW_PRIVS) failed: {0}")]
    NoNewPrivsFailed(std::io::Error),
    /// seccomp filter installation syscall failed.
    #[error("failed to install seccomp filter: {0}")]
    InstallFailed(seccompiler::Error),
}

/// Sets `PR_SET_NO_NEW_PRIVS` on the calling thread.
///
/// This is mandatory before unprivileged seccomp filter installation.
///
/// # Errors
/// Returns `SeccompError::NoNewPrivsFailed` if the prctl call fails.
#[allow(unsafe_code)]
pub fn enable_no_new_privs() -> Result<(), SeccompError> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes plain integer arguments and is memory safe.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(SeccompError::NoNewPrivsFailed(
            std::io::Error::last_os_error(),
        ))
    }
}

fn to_caction(action: SeccompAction) -> CAction {
    match action {
        SeccompAction::Allow => CAction::Allow,
        SeccompAction::Errno(code) => CAction::Errno(code.into()),
        SeccompAction::KillProcess => CAction::KillProcess,
        SeccompAction::KillThread => CAction::KillThread,
        SeccompAction::Trap => CAction::Trap,
        SeccompAction::Log => CAction::Log,
        SeccompAction::Trace(msg) => CAction::Trace(msg.into()),
    }
}

/// Compiles a domain `SeccompFilterDescriptor` into a low-level BPF program.
///
/// # Errors
/// Returns `SeccompError` if compilation or target architecture detection fails.
pub fn compile_filter(filter_desc: &SeccompFilterDescriptor) -> Result<BpfProgram, SeccompError> {
    let arch_str = match filter_desc.arch {
        SystemArch::X86_64 => "x86_64",
        SystemArch::Aarch64 => "aarch64",
        SystemArch::Riscv64 => "riscv64",
    };
    let arch = arch_str
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::ArchError(e.to_string()))?;

    let mut rules_map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    for rule in &filter_desc.rules {
        let mut conds = Vec::new();
        for comp in &rule.comparisons {
            let op = match comp.op {
                ComparisonOp::Equal => SeccompCmpOp::Eq,
                ComparisonOp::MaskedEqual => SeccompCmpOp::MaskedEq(comp.mask.unwrap_or(0)),
                ComparisonOp::NotEqual => SeccompCmpOp::Ne,
                ComparisonOp::GreaterThan => SeccompCmpOp::Gt,
                ComparisonOp::GreaterOrEqual => SeccompCmpOp::Ge,
                ComparisonOp::LessThan => SeccompCmpOp::Lt,
                ComparisonOp::LessOrEqual => SeccompCmpOp::Le,
            };
            if let Ok(c) =
                SeccompCondition::new(comp.arg_index, SeccompCmpArgLen::Dword, op, comp.value)
            {
                conds.push(c);
            }
        }

        if conds.is_empty() {
            rules_map.entry(rule.syscall_nr as i64).or_default();
        } else if let Ok(seccomp_rule) = SeccompRule::new(conds) {
            rules_map
                .entry(rule.syscall_nr as i64)
                .or_default()
                .push(seccomp_rule);
        }
    }

    let mismatch_action = to_caction(filter_desc.default_action);
    let match_action = filter_desc
        .rules
        .first()
        .map(|r| to_caction(r.action))
        .unwrap_or(CAction::Errno(libc::EPERM as u32));

    let filter = SeccompFilter::new(rules_map, mismatch_action, match_action, arch)
        .map_err(|e| SeccompError::CompileError(e.to_string()))?;

    let bpf_program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::CompileError(e.to_string()))?;

    Ok(bpf_program)
}

/// Applies a seccomp BPF program to the calling thread.
///
/// Automatically enables `PR_SET_NO_NEW_PRIVS`.
///
/// # Errors
/// Returns `SeccompError` if `no_new_privs` or filter application fails.
pub fn apply_filter_descriptor(filter_desc: &SeccompFilterDescriptor) -> Result<(), SeccompError> {
    enable_no_new_privs()?;
    let program = compile_filter(filter_desc)?;
    apply_filter(&program).map_err(SeccompError::InstallFailed)?;
    Ok(())
}
