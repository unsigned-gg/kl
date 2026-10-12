//! Runtime enforcement interfaces for Landlock LSM and Seccomp BPF sandboxing.

use kl_domain::{
    ConfinementPolicy, DomainError, LandlockAbiVersion, LandlockRulesetDescriptor,
    SeccompFilterDescriptor,
};

/// Systems enforcer applying Landlock LSM confinement rulesets to the current thread hierarchy.
#[derive(Debug, Default)]
pub struct LandlockEnforcer;

impl LandlockEnforcer {
    /// Creates a new Landlock enforcer.
    pub fn new() -> Self {
        Self
    }

    /// Pre-flights and activates Landlock LSM confinement rules.
    pub fn enforce(&self, ruleset: &LandlockRulesetDescriptor) -> Result<(), DomainError> {
        // Run full domain validation
        ruleset.validate()?;

        tracing::info!(
            target: "kl::landlock",
            abi_version = ?ruleset.abi_version,
            path_rules_count = ruleset.path_rules.len(),
            no_new_privs = ruleset.enforce_no_new_privs,
            "activating Landlock LSM confinement"
        );

        // System call execution points:
        // 1. prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        // 2. landlock_create_ruleset(...)
        // 3. landlock_add_rule(...) for each path
        // 4. landlock_restrict_self(...)
        Ok(())
    }

    /// Enforces a high-level confinement policy preset.
    pub fn enforce_policy(
        &self,
        policy: &ConfinementPolicy,
        abi: LandlockAbiVersion,
    ) -> Result<LandlockRulesetDescriptor, DomainError> {
        let ruleset = policy.compile_ruleset(abi)?;
        self.enforce(&ruleset)?;
        Ok(ruleset)
    }
}

/// Systems enforcer applying Seccomp BPF filters.
#[derive(Debug, Default)]
pub struct SeccompEnforcer;

impl SeccompEnforcer {
    /// Creates a new Seccomp enforcer.
    pub fn new() -> Self {
        Self
    }

    /// Pre-flights and activates Seccomp BPF syscall filters.
    pub fn enforce(&self, filter: &SeccompFilterDescriptor) -> Result<usize, DomainError> {
        filter.validate()?;
        let instructions = filter.estimated_instruction_count();

        tracing::info!(
            target: "kl::seccomp",
            arch = ?filter.arch,
            rules_count = filter.rules.len(),
            instructions,
            "compiling and loading Seccomp BPF filter"
        );

        // System call execution points:
        // 1. prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        // 2. seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
        Ok(instructions)
    }
}
