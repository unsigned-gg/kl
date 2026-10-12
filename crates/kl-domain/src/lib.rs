// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Zero-I/O domain models and invariants for `kl` (Kernel Layer Primitives).
//!
//! # Architecture & Invariants
//! Contains zero system call wrappers, zero filesystem operations, and zero network calls.
//! Provides pure domain models for Linux Landlock LSM rulesets, seccomp-BPF system call
//! deny policies, eBPF map/probe descriptors, priority clamping, and process containment plans.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod ebpf;
pub mod error;
pub mod isolation;
pub mod landlock;
pub mod priority;
pub mod seccomp;

pub use ebpf::{
    EbpfMapDescriptor, MapLifecycleState, MapType, ProbeAttachmentState, ProbeDescriptor,
    ProbeTarget, ProbeType, RingBufferDescriptor, VerifierBounds,
};
pub use error::DomainError;
pub use isolation::{IsolationPlan, NamespaceConfig};
pub use landlock::{
    AccessFs, AccessFsSet, ConfinementPolicy, LandlockAbiVersion, LandlockRulesetDescriptor,
    PathRuleDescriptor,
};
pub use priority::{PriorityClamp, PriorityInversionGuard, SchedPolicy};
pub use seccomp::{
    ArgComparison, ComparisonOp, SeccompAction, SeccompFilterDescriptor, SyscallRule, SystemArch,
};

/// Canonical state representation for `kl`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KlState {
    /// Protocol version.
    pub version: u32,
    /// Identifier.
    pub id: String,
}

impl Default for KlState {
    fn default() -> Self {
        Self {
            version: 1,
            id: String::from("initial"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_probe_validation() {
        let bounds = VerifierBounds::default();
        let mut probe = ProbeDescriptor::new(
            "kprobe_vfs_read",
            ProbeType::Kprobe,
            ProbeTarget::KernelSymbol("vfs_read".to_string()),
        );

        assert_eq!(probe.state, ProbeAttachmentState::Declared);
        assert!(probe.validate(&bounds).is_ok());
        assert_eq!(probe.state, ProbeAttachmentState::Validated);

        // Transition through lifecycle
        let state = probe
            .state
            .transition_to(ProbeAttachmentState::Loaded)
            .unwrap();
        assert_eq!(state, ProbeAttachmentState::Loaded);
        let state = state.transition_to(ProbeAttachmentState::Attached).unwrap();
        assert_eq!(state, ProbeAttachmentState::Attached);
        let state = state.transition_to(ProbeAttachmentState::Detached).unwrap();
        assert_eq!(state, ProbeAttachmentState::Detached);
        let state = state.transition_to(ProbeAttachmentState::Unloaded).unwrap();
        assert_eq!(state, ProbeAttachmentState::Unloaded);

        // Invalid transition: Unloaded to Attached
        assert!(state.transition_to(ProbeAttachmentState::Attached).is_err());
    }

    #[test]
    fn test_ebpf_verifier_instruction_and_stack_limits() {
        let bounds = VerifierBounds::default();

        // 1,000,000 instructions allowed, 1,000,001 fails
        assert!(bounds.check_instruction_budget(1_000_000).is_ok());
        assert!(matches!(
            bounds.check_instruction_budget(1_000_001),
            Err(DomainError::VerifierInstructionLimitExceeded {
                budget: 1_000_001,
                max: 1_000_000
            })
        ));

        // 512 bytes stack allowed, 513 fails
        assert!(bounds.check_stack_bytes(512).is_ok());
        assert!(matches!(
            bounds.check_stack_bytes(513),
            Err(DomainError::StackSizeLimitExceeded {
                bytes: 513,
                max: 512
            })
        ));

        // 33 tail calls allowed, 34 fails
        assert!(bounds.check_tail_call_depth(33).is_ok());
        assert!(matches!(
            bounds.check_tail_call_depth(34),
            Err(DomainError::TailCallDepthExceeded { depth: 34, max: 33 })
        ));
    }

    #[test]
    fn test_ringbuf_capacity_validation() {
        let rb_valid = RingBufferDescriptor::new("events", 65536);
        assert!(rb_valid.validate().is_ok());
        assert_eq!(rb_valid.index_mask(), 65535);

        let rb_invalid = RingBufferDescriptor::new("events_bad", 50000);
        assert!(rb_invalid.validate().is_err());

        let rb_too_small = RingBufferDescriptor::new("events_small", 2048);
        assert!(rb_too_small.validate().is_err());
    }

    #[test]
    fn test_ebpf_map_lifecycle_and_validation() {
        let map = EbpfMapDescriptor::new_hash("session_map", 8, 64, 1024);
        assert!(map.validate().is_ok());
        assert_eq!(map.state, MapLifecycleState::Declared);

        let state = map
            .state
            .transition_to(MapLifecycleState::Allocated)
            .unwrap();
        let state = state.transition_to(MapLifecycleState::Verified).unwrap();
        let state = state.transition_to(MapLifecycleState::Active).unwrap();
        let state = state.transition_to(MapLifecycleState::Drained).unwrap();
        let state = state.transition_to(MapLifecycleState::Closed).unwrap();
        assert_eq!(state, MapLifecycleState::Closed);

        let zero_entries = EbpfMapDescriptor::new_hash("bad_map", 8, 64, 0);
        assert!(zero_entries.validate().is_err());
    }

    #[test]
    fn test_landlock_prohibits_proc_traversal() {
        let valid_rule = PathRuleDescriptor::new("/tmp/workspace", AccessFsSet::read_write());
        assert!(valid_rule.validate().is_ok());

        let proc_rule = PathRuleDescriptor::new("/proc", AccessFsSet::read_only());
        assert!(matches!(
            proc_rule.validate(),
            Err(DomainError::ProhibitedPathRule { .. })
        ));

        let proc_mem_rule = PathRuleDescriptor::new("/proc/1/mem", AccessFsSet::read_only());
        assert!(matches!(
            proc_mem_rule.validate(),
            Err(DomainError::ProhibitedPathRule { .. })
        ));
    }

    #[test]
    fn test_landlock_policy_compilation() {
        let policy = ConfinementPolicy::StrictSandbox {
            workspace_dir: "/srv/sandboxed/app".to_string(),
        };

        let ruleset = policy.compile_ruleset(LandlockAbiVersion::V3).unwrap();
        assert_eq!(ruleset.abi_version, LandlockAbiVersion::V3);
        assert_eq!(ruleset.path_rules.len(), 5);
        assert!(ruleset.validate().is_ok());
    }

    #[test]
    fn test_seccomp_filter_descriptor() {
        let mut filter =
            SeccompFilterDescriptor::new(SystemArch::X86_64, SeccompAction::KillProcess);
        filter.add_rule(SyscallRule::unconditional(0, SeccompAction::Allow));
        filter.add_rule(SyscallRule::unconditional(1, SeccompAction::Allow));

        let clone_rule = SyscallRule::unconditional(56, SeccompAction::Errno(1))
            .with_comparison(ArgComparison::masked_equal(0, 0x00010000, 0x00010000));
        filter.add_rule(clone_rule);

        assert!(filter.validate().is_ok());
        assert!(filter.estimated_instruction_count() > 5);
    }

    #[test]
    fn test_priority_clamp_and_inversion_guard() {
        let cfs_clamp = PriorityClamp::cfs_nice(5).unwrap();
        assert!(cfs_clamp.validate().is_ok());

        let rt_clamp = PriorityClamp::realtime_fifo(50).unwrap();
        assert!(rt_clamp.validate().is_ok());

        assert!(PriorityInversionGuard::check_producer_consumer(&rt_clamp, &cfs_clamp).is_err());

        let high_rt = PriorityClamp::realtime_fifo(90).unwrap();
        assert!(PriorityInversionGuard::check_producer_consumer(&rt_clamp, &high_rt).is_ok());
    }

    #[test]
    fn test_default_state() {
        let state = KlState::default();
        assert_eq!(state.version, 1);
        assert_eq!(state.id, "initial");
    }
}
