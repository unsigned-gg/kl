//! High-level confinement policy profiles for Landlock LSM sandboxing.

use crate::error::DomainError;
use crate::landlock::abi::LandlockAbiVersion;
use crate::landlock::access::AccessFsSet;
use crate::landlock::ruleset::{LandlockRulesetDescriptor, PathRuleDescriptor};
use serde::{Deserialize, Serialize};

/// High-level confinement policy preset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfinementPolicy {
    /// Strict sandbox: Read-only access to system binaries and libraries (`/usr`, `/lib`, `/bin`),
    /// read-write access confined strictly to designated workspace directory, `/proc` forbidden.
    StrictSandbox {
        /// Dedicated workspace directory granted read-write access.
        workspace_dir: String,
    },
    /// Isolated worker: Fully unprivileged execution, read-only system libraries, no write access anywhere.
    IsolatedWorker,
    /// Read-only root filesystem with custom read-write paths.
    ReadOnlyRootWithWorkspace {
        /// Explicit paths allowed for write access.
        writable_paths: Vec<String>,
    },
}

impl ConfinementPolicy {
    /// Compiles the policy into a concrete Landlock ruleset descriptor.
    pub fn compile_ruleset(
        &self,
        abi: LandlockAbiVersion,
    ) -> Result<LandlockRulesetDescriptor, DomainError> {
        let mut ruleset = LandlockRulesetDescriptor::new(abi);

        match self {
            Self::StrictSandbox { workspace_dir } => {
                // Grant read+execute to system binaries and shared libraries
                ruleset.add_path_rule(PathRuleDescriptor::new("/usr", AccessFsSet::read_execute()));
                ruleset.add_path_rule(PathRuleDescriptor::new("/lib", AccessFsSet::read_execute()));
                ruleset.add_path_rule(PathRuleDescriptor::new(
                    "/lib64",
                    AccessFsSet::read_execute(),
                ));
                ruleset.add_path_rule(PathRuleDescriptor::new("/bin", AccessFsSet::read_execute()));

                // Grant read-write to designated workspace
                ruleset.add_path_rule(PathRuleDescriptor::new(
                    workspace_dir,
                    AccessFsSet::read_write(),
                ));
            }
            Self::IsolatedWorker => {
                ruleset.add_path_rule(PathRuleDescriptor::new("/usr", AccessFsSet::read_execute()));
                ruleset.add_path_rule(PathRuleDescriptor::new("/lib", AccessFsSet::read_execute()));
                ruleset.add_path_rule(PathRuleDescriptor::new("/etc", AccessFsSet::read_only()));
            }
            Self::ReadOnlyRootWithWorkspace { writable_paths } => {
                ruleset.add_path_rule(PathRuleDescriptor::new("/", AccessFsSet::read_only()));
                for path in writable_paths {
                    ruleset.add_path_rule(PathRuleDescriptor::new(path, AccessFsSet::read_write()));
                }
            }
        }

        ruleset.validate()?;
        Ok(ruleset)
    }
}
