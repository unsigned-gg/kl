// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Linux process containment coordinator.

use thiserror::Error;

use kl_domain::IsolationPlan;

use crate::landlock::{apply_ruleset, LandlockError};
use crate::seccomp::{apply_filter_descriptor, SeccompError};

/// Errors encountered while applying an isolation plan.
#[derive(Debug, Error)]
pub enum IsolationError {
    /// Invariant validation failed before execution.
    #[error("isolation plan has invariant violations: {0:?}")]
    InvariantViolations(Vec<String>),
    /// Namespace unsharing failed.
    #[error("unshare syscall failed: {0}")]
    UnshareFailed(std::io::Error),
    /// Seccomp installation failed.
    #[error("seccomp configuration error: {0}")]
    Seccomp(#[from] SeccompError),
    /// Landlock configuration failed.
    #[error("landlock configuration error: {0}")]
    Landlock(#[from] LandlockError),
}

/// Applies an `IsolationPlan` to the calling process.
///
/// Order of operations:
/// 1. Validate invariants.
/// 2. Unshare namespaces (e.g. `CLONE_NEWNET`) if requested.
/// 3. Enable `no_new_privs` and install seccomp-BPF filters.
/// 4. Compile and enforce Landlock filesystem ruleset.
///
/// # Errors
/// Returns `IsolationError` if any containment step fails.
#[allow(unsafe_code)]
pub fn apply_isolation(plan: &IsolationPlan) -> Result<(), IsolationError> {
    let violations = plan.validate_invariants();
    if !violations.is_empty() {
        return Err(IsolationError::InvariantViolations(violations));
    }

    // Unshare namespaces if requested
    let mut flags = 0;
    if plan.namespaces.new_net {
        flags |= libc::CLONE_NEWNET;
    }
    if plan.namespaces.new_ipc {
        flags |= libc::CLONE_NEWIPC;
    }
    if plan.namespaces.new_uts {
        flags |= libc::CLONE_NEWUTS;
    }

    if flags != 0 {
        // SAFETY: unshare with valid CLONE_NEW* flags is memory-safe.
        let ret = unsafe { libc::unshare(flags) };
        if ret != 0 {
            // Note: If unprivileged user namespaces are not configured, unshare may return EPERM.
            // We record this error faithfully.
            return Err(IsolationError::UnshareFailed(
                std::io::Error::last_os_error(),
            ));
        }
    }

    // Apply seccomp filter if rules are configured
    if !plan.seccomp.rules.is_empty() {
        apply_filter_descriptor(&plan.seccomp)?;
    }

    // Apply Landlock ruleset if rules are configured
    if !plan.landlock.path_rules.is_empty() {
        apply_ruleset(&plan.landlock)?;
    }

    Ok(())
}
