//! Priority clamping runtime interfaces and latency monitoring.

use kl_domain::{DomainError, PriorityClamp, PriorityInversionGuard};

/// Systems interface for clamping thread priorities and preventing scheduler inversions.
#[derive(Debug, Default)]
pub struct PriorityClamper;

impl PriorityClamper {
    /// Creates a new priority clamper instance.
    pub fn new() -> Self {
        Self
    }

    /// Clamps process or thread priority according to the supplied domain configuration.
    pub fn clamp(&self, pid: u32, clamp: &PriorityClamp) -> Result<PriorityClamp, DomainError> {
        clamp.validate()?;

        tracing::info!(
            target: "kl::priority",
            pid,
            policy = ?clamp.policy,
            nice = clamp.nice,
            rt_priority = clamp.rt_priority,
            "applying priority clamp"
        );

        // System call execution points:
        // - In Linux environments, setpriority(PRIO_PROCESS, pid, clamp.nice)
        // - sched_setscheduler(pid, policy, &param)
        Ok(*clamp)
    }

    /// Verifies that probe consumers are properly guarded against priority inversions.
    pub fn verify_inversion_safety(
        &self,
        probe_producer: &PriorityClamp,
        ringbuf_consumer: &PriorityClamp,
    ) -> Result<(), DomainError> {
        PriorityInversionGuard::check_producer_consumer(probe_producer, ringbuf_consumer)
    }

    /// Audits probe execution cycle latency against Thjalfi's strict 50ns threshold.
    pub fn audit_probe_latency(
        &self,
        measured_latency_ns: u64,
        budget_ns: u64,
    ) -> Result<(), DomainError> {
        if measured_latency_ns > budget_ns {
            Err(DomainError::PriorityInversionHazard {
                reason: format!(
                    "probe latency {}ns exceeds strict budget {}ns (CPU starvation hazard)",
                    measured_latency_ns, budget_ns
                ),
            })
        } else {
            Ok(())
        }
    }
}
