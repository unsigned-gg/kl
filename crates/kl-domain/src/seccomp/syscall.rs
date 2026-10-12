//! Seccomp syscall rules and argument evaluation constraints.

use crate::seccomp::action::SeccompAction;
use serde::{Deserialize, Serialize};

/// Relational comparison operators for syscall argument evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComparisonOp {
    /// Exact match (`==`).
    Equal,
    /// Inequality (`!=`).
    NotEqual,
    /// Strictly greater than (`>`).
    GreaterThan,
    /// Strictly less than (`<`).
    LessThan,
    /// Greater than or equal (`>=`).
    GreaterOrEqual,
    /// Less than or equal (`<=`).
    LessOrEqual,
    /// Masked equality (`(arg & mask) == value`).
    MaskedEqual,
}

/// Comparison rule evaluated against a 64-bit syscall argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArgComparison {
    /// 0-indexed argument index (0 through 5).
    pub arg_index: u8,
    /// Comparison operator.
    pub op: ComparisonOp,
    /// Value operand.
    pub value: u64,
    /// Optional bitmask for `MaskedEqual`.
    pub mask: Option<u64>,
}

impl ArgComparison {
    /// Creates an equality check on an argument.
    pub fn equal(arg_index: u8, value: u64) -> Self {
        Self {
            arg_index,
            op: ComparisonOp::Equal,
            value,
            mask: None,
        }
    }

    /// Creates a masked equality check on an argument: `(arg & mask) == value`.
    pub fn masked_equal(arg_index: u8, mask: u64, value: u64) -> Self {
        Self {
            arg_index,
            op: ComparisonOp::MaskedEqual,
            value,
            mask: Some(mask),
        }
    }
}

/// Syscall matching rule and corresponding action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallRule {
    /// Target architecture-specific syscall number.
    pub syscall_nr: i32,
    /// Action taken when syscall matches all argument comparisons.
    pub action: SeccompAction,
    /// Argument comparisons (all must evaluate to true).
    pub comparisons: Vec<ArgComparison>,
}

impl SyscallRule {
    /// Creates an unconditional syscall rule.
    pub fn unconditional(syscall_nr: i32, action: SeccompAction) -> Self {
        Self {
            syscall_nr,
            action,
            comparisons: Vec::new(),
        }
    }

    /// Adds an argument comparison constraint to this syscall rule.
    pub fn with_comparison(mut self, comparison: ArgComparison) -> Self {
        self.comparisons.push(comparison);
        self
    }
}
