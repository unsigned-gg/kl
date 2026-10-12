//! Landlock LSM ruleset descriptors and path confinement rules.

use crate::error::DomainError;
use crate::landlock::abi::LandlockAbiVersion;
use crate::landlock::access::{AccessFs, AccessFsSet};
use serde::{Deserialize, Serialize};

/// Path rule defining allowable filesystem accesses under a directory tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRuleDescriptor {
    /// Canonical filesystem path (must be an absolute path).
    pub path: String,
    /// Permitted access rights granted to this path hierarchy.
    pub allowed_access: AccessFsSet,
}

impl PathRuleDescriptor {
    /// Creates a new path rule granting specific access rights.
    pub fn new(path: impl Into<String>, allowed_access: AccessFsSet) -> Self {
        Self {
            path: path.into(),
            allowed_access,
        }
    }

    /// Validates path invariants against forbidden security violations.
    ///
    /// Idunn's Hard Rule: Prohibits granting access to `/proc`, `/sys`, or sensitive hardware devices.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.path.is_empty() || !self.path.starts_with('/') {
            return Err(DomainError::ProhibitedPathRule {
                path: self.path.clone(),
                reason: "path rule must be an absolute path starting with '/'",
            });
        }

        let normalized = self.path.trim_end_matches('/');

        // Strictly ban /proc traversal and sensitive mounts
        if normalized == "/proc" || normalized.starts_with("/proc/") {
            return Err(DomainError::ProhibitedPathRule {
                path: self.path.clone(),
                reason: "access to /proc is strictly prohibited to prevent memory exfiltration and fd snooping",
            });
        }

        // Strictly ban /sys modification or inspection
        if (normalized == "/sys" || normalized.starts_with("/sys/"))
            && (self.allowed_access.contains(AccessFs::WriteFile)
                || self.allowed_access.contains(AccessFs::MakeReg)
                || self.allowed_access.contains(AccessFs::RemoveFile))
        {
            return Err(DomainError::ProhibitedPathRule {
                path: self.path.clone(),
                reason: "write operations to /sys are strictly prohibited under LSM confinement",
            });
        }

        // Strictly ban character/block device creation on general directories
        if self.allowed_access.contains(AccessFs::MakeChar)
            || self.allowed_access.contains(AccessFs::MakeBlock)
        {
            return Err(DomainError::ProhibitedPathRule {
                path: self.path.clone(),
                reason:
                    "creation of raw character or block devices is forbidden in sandboxed paths",
            });
        }

        Ok(())
    }
}

/// Pure descriptor representing a complete Landlock LSM confinement ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockRulesetDescriptor {
    /// Target ABI version.
    pub abi_version: LandlockAbiVersion,
    /// Set of filesystem operations handled (restricted) by this ruleset.
    pub handled_access_fs: AccessFsSet,
    /// Collection of path hierarchy exceptions granting specific accesses.
    pub path_rules: Vec<PathRuleDescriptor>,
    /// Whether process is prohibited from obtaining new privileges (`prctl(PR_SET_NO_NEW_PRIVS)`).
    pub enforce_no_new_privs: bool,
}

impl LandlockRulesetDescriptor {
    /// Creates a new ruleset descriptor targeting the specified Landlock ABI version.
    pub fn new(abi_version: LandlockAbiVersion) -> Self {
        Self {
            abi_version,
            handled_access_fs: AccessFsSet::all_for_abi(abi_version),
            path_rules: Vec::new(),
            enforce_no_new_privs: true,
        }
    }

    /// Adds a path exception rule to the ruleset.
    pub fn add_path_rule(&mut self, rule: PathRuleDescriptor) {
        self.path_rules.push(rule);
    }

    /// Validates the complete ruleset descriptor against kernel security invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.handled_access_fs.is_empty() {
            return Err(DomainError::EmptyRuleset);
        }

        for rule in &self.path_rules {
            rule.validate()?;

            // Ensure rule does not attempt to grant access rights not handled by the ruleset
            let unhandled = rule.allowed_access.0 & !self.handled_access_fs.0;
            if unhandled != 0 {
                return Err(DomainError::ProhibitedPathRule {
                    path: rule.path.clone(),
                    reason: "rule grants access rights that are not declared in handled_access_fs",
                });
            }
        }

        Ok(())
    }
}
