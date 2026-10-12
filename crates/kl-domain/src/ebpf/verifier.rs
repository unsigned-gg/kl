//! Invariants and verification bounds enforced by the Linux kernel eBPF verifier.

use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// Canonical Linux kernel verifier bounds and execution constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierBounds {
    /// Maximum allowable verified instructions (Linux 5.2+ complexity limit: 1,000,000).
    pub max_instructions: u32,
    /// Maximum allowable stack allocation per BPF program (512 bytes).
    pub max_stack_bytes: u32,
    /// Maximum allowable tail call chain depth (33 invocations).
    pub max_tail_call_depth: u32,
    /// Target execution cycle budget in nanoseconds (<= 50ns probe execution target).
    pub target_latency_budget_ns: u64,
}

impl Default for VerifierBounds {
    fn default() -> Self {
        Self {
            max_instructions: 1_000_000,
            max_stack_bytes: 512,
            max_tail_call_depth: 33,
            target_latency_budget_ns: 50,
        }
    }
}

impl VerifierBounds {
    /// Validate program instruction budget against the kernel verifier ceiling.
    pub fn check_instruction_budget(&self, requested: u32) -> Result<(), DomainError> {
        if requested > self.max_instructions {
            Err(DomainError::VerifierInstructionLimitExceeded {
                budget: requested,
                max: self.max_instructions,
            })
        } else {
            Ok(())
        }
    }

    /// Validate program stack usage against the fixed 512-byte hardware verifier frame.
    pub fn check_stack_bytes(&self, bytes: u32) -> Result<(), DomainError> {
        if bytes > self.max_stack_bytes {
            Err(DomainError::StackSizeLimitExceeded {
                bytes,
                max: self.max_stack_bytes,
            })
        } else {
            Ok(())
        }
    }

    /// Validate tail call recursion depth.
    pub fn check_tail_call_depth(&self, depth: u32) -> Result<(), DomainError> {
        if depth > self.max_tail_call_depth {
            Err(DomainError::TailCallDepthExceeded {
                depth,
                max: self.max_tail_call_depth,
            })
        } else {
            Ok(())
        }
    }
}
