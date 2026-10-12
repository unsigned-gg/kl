// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `kl` — Kernel Layer Primitives for Linux Landlock LSM, seccomp-BPF, eBPF probes, and containment.
//!
//! Provides pure-Rust interfaces for configuring fine-grained process isolation boundaries,
//! probe attachment lifecycles, and priority clamping without C runtime dependencies.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod attachment;
pub mod confinement;
pub mod isolation;
pub mod landlock;
pub mod priority;
pub mod seccomp;

pub use attachment::{AttachmentManager, LinkStatus, ProbeLink, RingBufferConsumer};
pub use confinement::{LandlockEnforcer, SeccompEnforcer};
pub use isolation::{apply_isolation, IsolationError};
pub use landlock::{apply_ruleset, probe_kernel_abi, LandlockError};
pub use priority::PriorityClamper;
pub use seccomp::{apply_filter_descriptor, compile_filter, enable_no_new_privs, SeccompError};

pub use kl_domain::*;

/// Top-level runtime handle for `kl`.
#[derive(Debug, Default)]
pub struct KlRuntime {
    /// Probe attachment manager.
    pub attachment_mgr: AttachmentManager,
    /// Priority clamper.
    pub priority_clamper: PriorityClamper,
    /// Landlock enforcer.
    pub landlock_enforcer: LandlockEnforcer,
    /// Seccomp enforcer.
    pub seccomp_enforcer: SeccompEnforcer,
}

impl KlRuntime {
    /// Creates a new `kl` runtime instance.
    pub fn new() -> Self {
        Self {
            attachment_mgr: AttachmentManager::new(),
            priority_clamper: PriorityClamper::new(),
            landlock_enforcer: LandlockEnforcer::new(),
            seccomp_enforcer: SeccompEnforcer::new(),
        }
    }

    /// Attaches an eBPF probe to its target hook.
    pub fn attach_probe(&mut self, descriptor: ProbeDescriptor) -> Result<ProbeLink, DomainError> {
        self.attachment_mgr.attach(descriptor)
    }

    /// Detaches an active probe link.
    pub fn detach_probe(&mut self, link_id: u64) -> Result<(), DomainError> {
        self.attachment_mgr.detach(link_id)
    }

    /// Clamps process or thread priority.
    pub fn clamp_priority(
        &self,
        pid: u32,
        clamp: &PriorityClamp,
    ) -> Result<PriorityClamp, DomainError> {
        self.priority_clamper.clamp(pid, clamp)
    }

    /// Enforces a Landlock LSM confinement ruleset.
    pub fn enforce_landlock(&self, ruleset: &LandlockRulesetDescriptor) -> Result<(), DomainError> {
        self.landlock_enforcer.enforce(ruleset)
    }

    /// Enforces a Landlock confinement policy preset.
    pub fn enforce_policy(
        &self,
        policy: &ConfinementPolicy,
        abi: LandlockAbiVersion,
    ) -> Result<LandlockRulesetDescriptor, DomainError> {
        self.landlock_enforcer.enforce_policy(policy, abi)
    }

    /// Enforces a Seccomp BPF filter.
    pub fn enforce_seccomp(&self, filter: &SeccompFilterDescriptor) -> Result<usize, DomainError> {
        self.seccomp_enforcer.enforce(filter)
    }
}

/// Initializes the `kl` systems engine and runtime.
pub fn init() -> anyhow::Result<KlRuntime> {
    Ok(KlRuntime::new())
}

/// Probes kernel capabilities and returns a diagnostic summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelProbeReport {
    /// Linux kernel Landlock ABI version if supported.
    pub landlock_abi: Option<u32>,
    /// Architecture identified by seccomp compiler.
    pub architecture: String,
    /// Seccomp BPF support confirmed.
    pub seccomp_available: bool,
}

/// Probes host kernel security subsystems.
#[must_use]
pub fn probe_kernel() -> KernelProbeReport {
    let landlock_abi = probe_kernel_abi().map(|a| a.version_number());
    let architecture = std::env::consts::ARCH.to_owned();

    // Verify seccomp compiler can generate filters on this architecture
    let mut dummy_filter = SeccompFilterDescriptor::new(SystemArch::X86_64, SeccompAction::Allow);
    dummy_filter.add_rule(SyscallRule::unconditional(
        libc::SYS_ptrace as i32,
        SeccompAction::Errno(libc::EPERM as u16),
    ));
    let seccomp_available = compile_filter(&dummy_filter).is_ok();

    KernelProbeReport {
        landlock_abi,
        architecture,
        seccomp_available,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_compile() {
        let mut filter = SeccompFilterDescriptor::new(SystemArch::X86_64, SeccompAction::Allow);
        filter.add_rule(SyscallRule::unconditional(
            libc::SYS_ptrace as i32,
            SeccompAction::Errno(libc::EPERM as u16),
        ));
        let res = compile_filter(&filter);
        assert!(res.is_ok(), "compile error: {:?}", res.err());
    }

    #[test]
    fn test_runtime_initialization() {
        let runtime = init().expect("runtime should initialize cleanly");
        assert_eq!(runtime.attachment_mgr.active_link_count(), 0);
    }

    #[test]
    fn test_probe_attachment_and_detachment() {
        let mut runtime = init().unwrap();
        let probe = ProbeDescriptor::new(
            "kprobe_tcp_connect",
            ProbeType::Kprobe,
            ProbeTarget::KernelSymbol("tcp_connect".to_string()),
        );

        let mut link = runtime
            .attach_probe(probe)
            .expect("probe attach must succeed");
        assert_eq!(link.status, LinkStatus::Active);
        assert_eq!(link.descriptor.state, ProbeAttachmentState::Attached);
        assert_eq!(runtime.attachment_mgr.active_link_count(), 1);

        link.detach().expect("link detach must succeed");
        assert_eq!(link.status, LinkStatus::Detached);
        assert_eq!(link.descriptor.state, ProbeAttachmentState::Detached);
    }

    #[test]
    fn test_ringbuf_event_streaming() {
        let rb_desc = RingBufferDescriptor::new("perf_ring", 8192);
        let mut consumer = RingBufferConsumer::new(rb_desc).expect("consumer init must succeed");

        consumer
            .submit_event(b"event_1: tcp_connect syn sent")
            .unwrap();
        consumer.submit_event(b"event_2: tcp_established").unwrap();
        assert!(consumer.unconsumed_bytes() > 0);

        let mut collected = Vec::new();
        let drained = consumer.drain_events(|data| {
            collected.push(String::from_utf8_lossy(data).to_string());
        });

        assert_eq!(drained, 2);
        assert_eq!(consumer.unconsumed_bytes(), 0);
        assert_eq!(collected[0], "event_1: tcp_connect syn sent");
        assert_eq!(collected[1], "event_2: tcp_established");
    }

    #[test]
    fn test_priority_clamping_and_audit() {
        let runtime = init().unwrap();
        let clamp = PriorityClamp::cfs_nice(-10).unwrap();
        let applied = runtime.clamp_priority(1234, &clamp).unwrap();
        assert_eq!(applied.nice, -10);

        assert!(runtime.priority_clamper.audit_probe_latency(42, 50).is_ok());
        assert!(runtime
            .priority_clamper
            .audit_probe_latency(65, 50)
            .is_err());
    }

    #[test]
    fn test_confinement_enforcement() {
        let runtime = init().unwrap();
        let policy = ConfinementPolicy::StrictSandbox {
            workspace_dir: "/tmp/app_sandbox".to_string(),
        };

        let ruleset = runtime
            .enforce_policy(&policy, LandlockAbiVersion::V4)
            .expect("policy enforcement should succeed");

        assert_eq!(ruleset.path_rules.len(), 5);
    }
}
