//! Pure domain models for eBPF maps and finite state machine lifecycles.

use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// Canonical Linux eBPF map types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MapType {
    /// Generic key/value hash map.
    Hash,
    /// Fast direct-indexed integer array map.
    Array,
    /// BPF program jump table array map (tail calls).
    ProgArray,
    /// Legacy perf ring-buffer event array.
    PerfEventArray,
    /// Per-CPU isolated hash map (lockless reads/writes).
    PerCpuHash,
    /// Per-CPU direct-indexed array map (lockless).
    PerCpuArray,
    /// Stack trace recording map.
    StackTrace,
    /// Linux 5.8+ mmap-capable multi-producer single-consumer zero-copy ring-buffer.
    RingBuf,
    /// Least-recently-used evicting hash map.
    LruHash,
    /// Longest prefix match trie map (routing / CIDR).
    LpmTrie,
}

/// Strict finite state machine governing BPF map lifecycle (Gullveig's algebraic model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MapLifecycleState {
    /// Map declared and memory topology specified.
    Declared,
    /// Kernel file descriptor allocated via `bpf(BPF_MAP_CREATE)`.
    Allocated,
    /// Map memory pointers and types verified by kernel verifier.
    Verified,
    /// Map actively receiving probe events and serving user lookups.
    Active,
    /// Map processing incoming events, user ingestion suspended for teardown.
    Drained,
    /// Map file descriptor closed and kernel memory freed.
    Closed,
}

impl MapLifecycleState {
    /// Validates and executes an atomic state transition.
    pub fn transition_to(self, next: Self) -> Result<Self, DomainError> {
        let valid = matches!(
            (self, next),
            (Self::Declared, Self::Allocated)
                | (Self::Allocated, Self::Verified)
                | (Self::Verified, Self::Active)
                | (Self::Active, Self::Drained)
                | (Self::Drained, Self::Closed)
                | (Self::Allocated, Self::Closed)
                | (Self::Verified, Self::Closed)
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

    /// String representation of state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "Declared",
            Self::Allocated => "Allocated",
            Self::Verified => "Verified",
            Self::Active => "Active",
            Self::Drained => "Drained",
            Self::Closed => "Closed",
        }
    }
}

/// Pure domain descriptor for an eBPF map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfMapDescriptor {
    /// Map identifier.
    pub name: String,
    /// Map storage type.
    pub map_type: MapType,
    /// Key size in bytes (0 for RingBuf).
    pub key_size: u32,
    /// Value size in bytes (0 for RingBuf).
    pub value_size: u32,
    /// Maximum entries (or buffer capacity for RingBuf).
    pub max_entries: u32,
    /// Map creation flags (e.g. `BPF_F_NO_PREALLOC`).
    pub flags: u32,
    /// Finite state machine lifecycle state.
    pub state: MapLifecycleState,
}

impl EbpfMapDescriptor {
    /// Creates a declared hash map descriptor.
    pub fn new_hash(
        name: impl Into<String>,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Self {
        Self {
            name: name.into(),
            map_type: MapType::Hash,
            key_size,
            value_size,
            max_entries,
            flags: 0,
            state: MapLifecycleState::Declared,
        }
    }

    /// Creates a declared per-CPU array map descriptor.
    pub fn new_percpu_array(name: impl Into<String>, value_size: u32, max_entries: u32) -> Self {
        Self {
            name: name.into(),
            map_type: MapType::PerCpuArray,
            key_size: 4, // 32-bit index
            value_size,
            max_entries,
            flags: 0,
            state: MapLifecycleState::Declared,
        }
    }

    /// Creates a declared ring-buffer map descriptor.
    pub fn new_ringbuf(name: impl Into<String>, capacity_bytes: u32) -> Self {
        Self {
            name: name.into(),
            map_type: MapType::RingBuf,
            key_size: 0,
            value_size: 0,
            max_entries: capacity_bytes,
            flags: 0,
            state: MapLifecycleState::Declared,
        }
    }

    /// Validates map structural invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.max_entries == 0 {
            return Err(DomainError::InvalidMapDimensions {
                reason: "max_entries must be strictly greater than 0",
            });
        }

        match self.map_type {
            MapType::RingBuf => {
                if self.key_size != 0 || self.value_size != 0 {
                    return Err(DomainError::InvalidMapDimensions {
                        reason: "ringbuf map key_size and value_size must be 0",
                    });
                }
                if !self.max_entries.is_power_of_two() || self.max_entries < 4096 {
                    return Err(DomainError::InvalidRingBufferSize {
                        bytes: self.max_entries,
                        reason: "ringbuf capacity must be a power of two and at least 4096 bytes (page size)",
                    });
                }
            }
            MapType::Array | MapType::PerCpuArray | MapType::ProgArray => {
                if self.key_size != 4 {
                    return Err(DomainError::InvalidMapDimensions {
                        reason: "array-indexed maps require 4-byte u32 key size",
                    });
                }
                if self.value_size == 0 && self.map_type != MapType::ProgArray {
                    return Err(DomainError::InvalidMapDimensions {
                        reason: "array value_size must be non-zero",
                    });
                }
            }
            _ => {
                if self.key_size == 0 || self.value_size == 0 {
                    return Err(DomainError::InvalidMapDimensions {
                        reason: "key_size and value_size must be non-zero for hash maps",
                    });
                }
            }
        }

        Ok(())
    }
}
