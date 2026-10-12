//! Pure domain models for Linux priority clamping and scheduler policies.

use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// Linux scheduling policies supported for thread priority clamping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchedPolicy {
    /// Standard completely fair scheduler (`SCHED_OTHER`).
    Other,
    /// Batch processing policy (`SCHED_BATCH`).
    Batch,
    /// Very low priority background processing (`SCHED_IDLE`).
    Idle,
    /// First-in, first-out realtime policy (`SCHED_FIFO`).
    Fifo,
    /// Round-robin realtime policy (`SCHED_RR`).
    Rr,
    /// Earliest deadline first policy (`SCHED_DEADLINE`).
    Deadline,
}

/// Clamped priority specification for bounded thread and probe execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PriorityClamp {
    /// Scheduler policy.
    pub policy: SchedPolicy,
    /// Standard UNIX nice level (-20 to 19, where lower is higher priority).
    pub nice: i8,
    /// Realtime priority level (1 to 99 for FIFO/RR, 0 for OTHER/BATCH/IDLE).
    pub rt_priority: u32,
    /// Maximum allowed execution latency budget in nanoseconds (< 50ns probe execution target).
    pub latency_budget_ns: u64,
}

impl Default for PriorityClamp {
    fn default() -> Self {
        Self {
            policy: SchedPolicy::Other,
            nice: 0,
            rt_priority: 0,
            latency_budget_ns: 50,
        }
    }
}

impl PriorityClamp {
    /// Creates a realtime FIFO priority clamp.
    pub fn realtime_fifo(rt_priority: u32) -> Result<Self, DomainError> {
        let clamp = Self {
            policy: SchedPolicy::Fifo,
            nice: -20,
            rt_priority,
            latency_budget_ns: 50,
        };
        clamp.validate()?;
        Ok(clamp)
    }

    /// Creates a CFS nice clamp.
    pub fn cfs_nice(nice: i8) -> Result<Self, DomainError> {
        let clamp = Self {
            policy: SchedPolicy::Other,
            nice,
            rt_priority: 0,
            latency_budget_ns: 50,
        };
        clamp.validate()?;
        Ok(clamp)
    }

    /// Validates priority boundaries according to Linux kernel scheduler contracts.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.nice < -20 || self.nice > 19 {
            return Err(DomainError::InvalidPriorityBounds {
                field: "nice",
                value: self.nice as i32,
                min: -20,
                max: 19,
            });
        }

        match self.policy {
            SchedPolicy::Fifo | SchedPolicy::Rr => {
                if self.rt_priority == 0 || self.rt_priority > 99 {
                    return Err(DomainError::InvalidPriorityBounds {
                        field: "rt_priority",
                        value: self.rt_priority as i32,
                        min: 1,
                        max: 99,
                    });
                }
            }
            SchedPolicy::Other | SchedPolicy::Batch | SchedPolicy::Idle => {
                if self.rt_priority != 0 {
                    return Err(DomainError::InvalidPriorityBounds {
                        field: "rt_priority (must be 0 for non-realtime policy)",
                        value: self.rt_priority as i32,
                        min: 0,
                        max: 0,
                    });
                }
            }
            SchedPolicy::Deadline => {
                // Sched deadline uses period/runtime parameters rather than static priority
            }
        }

        Ok(())
    }
}

/// Analysis guard preventing priority inversion edge cases between probes and consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityInversionGuard;

impl PriorityInversionGuard {
    /// Asserts that the consumer priority is high enough relative to producers to prevent queue starvation.
    pub fn check_producer_consumer(
        producer_priority: &PriorityClamp,
        consumer_priority: &PriorityClamp,
    ) -> Result<(), DomainError> {
        // If producer is realtime FIFO/RR and consumer is standard CFS, consumer can be starved
        let producer_is_rt = matches!(
            producer_priority.policy,
            SchedPolicy::Fifo | SchedPolicy::Rr
        );
        let consumer_is_rt = matches!(
            consumer_priority.policy,
            SchedPolicy::Fifo | SchedPolicy::Rr
        );

        if producer_is_rt && !consumer_is_rt {
            return Err(DomainError::PriorityInversionHazard {
                reason: "realtime probe producer will starve non-realtime ring-buffer consumer, causing buffer drop events".to_string(),
            });
        }

        if producer_is_rt
            && consumer_is_rt
            && consumer_priority.rt_priority < producer_priority.rt_priority
        {
            return Err(DomainError::PriorityInversionHazard {
                reason: format!(
                    "consumer RT priority ({}) is lower than producer RT priority ({})",
                    consumer_priority.rt_priority, producer_priority.rt_priority
                ),
            });
        }

        Ok(())
    }
}
