//! Pure domain models for process and thread priority clamping.

pub mod clamp;

pub use clamp::{PriorityClamp, PriorityInversionGuard, SchedPolicy};
