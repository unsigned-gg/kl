//! Seccomp filter actions and return codes.

use serde::{Deserialize, Serialize};

/// Canonical Seccomp actions returned by BPF filter programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeccompAction {
    /// Kill entire process immediately (`SECCOMP_RET_KILL_PROCESS`).
    KillProcess,
    /// Kill current calling thread (`SECCOMP_RET_KILL_THREAD`).
    KillThread,
    /// Send SIGSYS signal to calling thread (`SECCOMP_RET_TRAP`).
    Trap,
    /// Return errno directly to user without executing syscall (`SECCOMP_RET_ERRNO`).
    Errno(u16),
    /// Notify ptrace tracer (`SECCOMP_RET_TRACE`).
    Trace(u16),
    /// Allow syscall but log invocation (`SECCOMP_RET_LOG`).
    Log,
    /// Permit syscall execution normally (`SECCOMP_RET_ALLOW`).
    Allow,
}

impl SeccompAction {
    /// Returns the raw 32-bit integer code according to `<linux/seccomp.h>`.
    pub const fn to_bpf_ret(self) -> u32 {
        match self {
            Self::KillProcess => 0x8000_0000,
            Self::KillThread => 0x0000_0000,
            Self::Trap => 0x0003_0000,
            Self::Errno(err) => 0x0005_0000 | (err as u32 & 0xFFFF),
            Self::Trace(val) => 0x7ff0_0000 | (val as u32 & 0xFFFF),
            Self::Log => 0x7ffc_0000,
            Self::Allow => 0x7fff_0000,
        }
    }
}
