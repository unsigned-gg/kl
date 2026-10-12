// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Zero-I/O domain models for Linux process isolation and containment plans.

use serde::{Deserialize, Serialize};

use crate::landlock::{LandlockAbiVersion, LandlockRulesetDescriptor};
use crate::seccomp::{SeccompAction, SeccompFilterDescriptor, SystemArch};

/// Linux namespace isolation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamespaceConfig {
    /// Isolate network stack (`CLONE_NEWNET`).
    pub new_net: bool,
    /// Isolate IPC namespace (`CLONE_NEWIPC`).
    pub new_ipc: bool,
    /// Isolate UTS (hostname) namespace (`CLONE_NEWUTS`).
    pub new_uts: bool,
    /// Isolate PID namespace (`CLONE_NEWPID`).
    pub new_pid: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            new_net: true,
            new_ipc: true,
            new_uts: true,
            new_pid: false,
        }
    }
}

/// Complete declarative containment plan for an agent process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationPlan {
    /// Namespace configuration.
    pub namespaces: NamespaceConfig,
    /// Mandatory `PR_SET_NO_NEW_PRIVS` flag to prevent privilege escalation via setuid.
    pub no_new_privs: bool,
    /// Filesystem access boundaries via Landlock LSM.
    pub landlock: LandlockRulesetDescriptor,
    /// Syscall filtering profile via seccomp-BPF.
    pub seccomp: SeccompFilterDescriptor,
}

impl Default for IsolationPlan {
    fn default() -> Self {
        Self {
            namespaces: NamespaceConfig::default(),
            no_new_privs: true,
            landlock: LandlockRulesetDescriptor::new(LandlockAbiVersion::V1),
            seccomp: SeccompFilterDescriptor::new(SystemArch::X86_64, SeccompAction::Allow),
        }
    }
}

impl IsolationPlan {
    /// Validates the internal consistency and invariants of the isolation plan.
    ///
    /// Returns a list of invariant violations if any are found.
    #[must_use]
    pub fn validate_invariants(&self) -> Vec<String> {
        let mut violations = Vec::new();

        if !self.no_new_privs {
            violations.push("no_new_privs must be enabled for unprivileged sandboxing".to_owned());
        }

        if let Err(err) = self.landlock.validate() {
            violations.push(format!("landlock ruleset invalid: {err}"));
        }

        if let Err(err) = self.seccomp.validate() {
            violations.push(format!("seccomp filter invalid: {err}"));
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_isolation_plan_invariants() {
        let plan = IsolationPlan::default();
        let violations = plan.validate_invariants();
        assert!(violations.is_empty(), "violations: {violations:?}");
        assert!(plan.no_new_privs);
        assert!(plan.namespaces.new_net);
    }
}
