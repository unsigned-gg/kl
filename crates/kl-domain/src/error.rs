//! Pure domain error types for `kl-domain`.

use thiserror::Error;

/// Error conditions originating within domain validation, verifier limits, or state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainError {
    /// eBPF verifier instruction budget exceeded.
    #[error("verifier instruction budget exceeded: requested {budget} instructions, maximum allowed is {max}")]
    VerifierInstructionLimitExceeded {
        /// Requested or evaluated instruction budget.
        budget: u32,
        /// Maximum instruction budget supported by kernel verifier.
        max: u32,
    },

    /// eBPF stack size limit exceeded (512 bytes limit).
    #[error(
        "eBPF stack allocation limit exceeded: requested {bytes} bytes, maximum allowed is {max}"
    )]
    StackSizeLimitExceeded {
        /// Requested stack bytes.
        bytes: u32,
        /// Maximum allowable stack bytes (512 bytes).
        max: u32,
    },

    /// Tail call depth limit exceeded.
    #[error("eBPF tail call depth limit exceeded: requested {depth}, maximum allowed is {max}")]
    TailCallDepthExceeded {
        /// Evaluated tail call depth.
        depth: u32,
        /// Maximum allowable tail call depth (33).
        max: u32,
    },

    /// Invalid ring buffer sizing (must be power of two, page-aligned).
    #[error("invalid ring buffer capacity: {bytes} bytes ({reason})")]
    InvalidRingBufferSize {
        /// Buffer capacity in bytes.
        bytes: u32,
        /// Rationale for failure.
        reason: &'static str,
    },

    /// Invalid map layout or dimension parameters.
    #[error("invalid eBPF map dimensions: {reason}")]
    InvalidMapDimensions {
        /// Rationale for failure.
        reason: &'static str,
    },

    /// Illegal state transition in an algebraic state machine.
    #[error("illegal state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Starting state.
        from: &'static str,
        /// Attempted destination state.
        to: &'static str,
    },

    /// Prohibited path rule in Landlock LSM confinement (e.g. attempting to grant access to /proc).
    #[error("prohibited path confinement rule for '{path}': {reason}")]
    ProhibitedPathRule {
        /// Offending path.
        path: String,
        /// Security rationale for prohibition.
        reason: &'static str,
    },

    /// Empty Landlock ruleset specification.
    #[error("landlock ruleset must contain at least one handled access flag")]
    EmptyRuleset,

    /// Landlock ABI version unsupported or unavailable.
    #[error("requested Landlock ABI version {requested:?} requires feature not supported by ABI")]
    UnsupportedLandlockFeature {
        /// ABI version.
        requested: u32,
        /// Feature description.
        feature: &'static str,
    },

    /// Invalid Seccomp filter configuration.
    #[error("invalid seccomp filter: {reason}")]
    InvalidSeccompFilter {
        /// Failure explanation.
        reason: &'static str,
    },

    /// Invalid priority or niceness value out of bounds.
    #[error(
        "priority parameter '{field}' out of bounds: value {value}, allowable range [{min}, {max}]"
    )]
    InvalidPriorityBounds {
        /// Target field name.
        field: &'static str,
        /// Supplied value.
        value: i32,
        /// Minimum bound.
        min: i32,
        /// Maximum bound.
        max: i32,
    },

    /// Potential priority inversion detected.
    #[error("priority inversion hazard detected: {reason}")]
    PriorityInversionHazard {
        /// Explanation of inversion risk.
        reason: String,
    },
}
