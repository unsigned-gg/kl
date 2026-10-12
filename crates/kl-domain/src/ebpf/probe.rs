//! eBPF probe descriptors and algebraic lifecycle state machines.

use crate::ebpf::verifier::VerifierBounds;
use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// Canonical eBPF program and probe types supported by `kl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeType {
    /// Kernel function dynamic entry probe.
    Kprobe,
    /// Kernel function dynamic return probe.
    Kretprobe,
    /// Static kernel tracepoint.
    Tracepoint,
    /// Raw kernel tracepoint (zero-copy context access).
    RawTracepoint,
    /// User-space binary entry probe.
    Uprobe,
    /// User-space binary return probe.
    Uretprobe,
    /// eXpress Data Path packet processing hook.
    Xdp,
    /// Classic socket filter BPF program.
    SocketFilter,
    /// Cgroup socket buffer ingress/egress filter.
    CgroupSkb,
    /// Linux Security Module (LSM) security hook.
    Lsm,
}

/// Target symbol, binary path, or subsystem hook for probe attachment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeTarget {
    /// Kernel symbol name (e.g. `vfs_read`, `sys_enter_execve`).
    KernelSymbol(String),
    /// Tracepoint subsystem and event name (e.g. `sched`, `sched_switch`).
    Tracepoint {
        /// Subsystem name.
        category: String,
        /// Event name.
        name: String,
    },
    /// User-space binary path and byte offset.
    UprobeTarget {
        /// Path to ELF binary or shared library.
        binary_path: String,
        /// Instruction offset from binary base.
        offset: u64,
    },
    /// Network interface name (e.g. `eth0`).
    NetworkInterface(String),
    /// Cgroup v2 hierarchical directory path.
    CgroupPath(String),
    /// Linux Security Module hook name (e.g. `bprm_check_security`).
    LsmHook(String),
}

/// Strict finite state machine governing probe lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeAttachmentState {
    /// Probe definition declared in memory.
    Declared,
    /// Probe validated against verifier instruction, stack, and complexity limits.
    Validated,
    /// eBPF bytecode loaded and verified into kernel memory via `bpf(BPF_PROG_LOAD)`.
    Loaded,
    /// Probe actively attached to kernel hook via `bpf_link` or perf event fd.
    Attached,
    /// Probe cleanly detached from kernel hook, bytecode retained.
    Detached,
    /// Probe unloaded, file descriptors closed, maps released.
    Unloaded,
}

impl ProbeAttachmentState {
    /// Validates and executes an atomic state transition.
    pub fn transition_to(self, next: Self) -> Result<Self, DomainError> {
        let valid = matches!(
            (self, next),
            (Self::Declared, Self::Validated)
                | (Self::Validated, Self::Loaded)
                | (Self::Loaded, Self::Attached)
                | (Self::Attached, Self::Detached)
                | (Self::Detached, Self::Attached)
                | (Self::Detached, Self::Unloaded)
                | (Self::Loaded, Self::Unloaded)
                | (Self::Validated, Self::Unloaded)
                | (Self::Declared, Self::Unloaded)
        );

        if valid {
            Ok(next)
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            })
        }
    }

    /// String representation of the state for logs and error reporting.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "Declared",
            Self::Validated => "Validated",
            Self::Loaded => "Loaded",
            Self::Attached => "Attached",
            Self::Detached => "Detached",
            Self::Unloaded => "Unloaded",
        }
    }
}

/// Pure domain descriptor for an eBPF probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeDescriptor {
    /// Canonical identifier for the probe.
    pub name: String,
    /// Hook probe type.
    pub probe_type: ProbeType,
    /// Target attachment point in kernel or user-space.
    pub target: ProbeTarget,
    /// Bound on maximum instructions for this probe.
    pub instruction_budget: u32,
    /// Bound on maximum stack bytes for this probe.
    pub max_stack_bytes: u32,
    /// Flag indicating whether event streaming leverages zero-copy ring-buffer memory.
    pub zero_copy_ringbuf: bool,
    /// Current lifecycle state.
    pub state: ProbeAttachmentState,
}

impl ProbeDescriptor {
    /// Creates a new declared probe descriptor with default verifier bounds.
    pub fn new(name: impl Into<String>, probe_type: ProbeType, target: ProbeTarget) -> Self {
        Self {
            name: name.into(),
            probe_type,
            target,
            instruction_budget: 100_000,
            max_stack_bytes: 256,
            zero_copy_ringbuf: true,
            state: ProbeAttachmentState::Declared,
        }
    }

    /// Validates the probe descriptor against verifier limits and invariants.
    pub fn validate(&mut self, bounds: &VerifierBounds) -> Result<(), DomainError> {
        bounds.check_instruction_budget(self.instruction_budget)?;
        bounds.check_stack_bytes(self.max_stack_bytes)?;
        self.state = self.state.transition_to(ProbeAttachmentState::Validated)?;
        Ok(())
    }
}
