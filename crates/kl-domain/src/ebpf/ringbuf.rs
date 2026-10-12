//! Pure domain models for Linux eBPF zero-copy ring-buffers (`BPF_MAP_TYPE_RINGBUF`).

use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// Page size on target architecture (4096 bytes).
pub const PAGE_SIZE: u32 = 4096;

/// Pure descriptor for an eBPF zero-copy ring-buffer channel.
///
/// Designed around Bryan Cantrill's machine sympathy principles and Sindri's zero-copy requirements:
/// - Eliminates kernel-to-userspace memory copies.
/// - Memory-mapped read interface with contiguous virtual address wrapping via dual-page mapping.
/// - Multi-producer single-consumer lockless concurrency model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingBufferDescriptor {
    /// Canonical channel identifier.
    pub name: String,
    /// Total buffer capacity in bytes (must be a power of two and a multiple of PAGE_SIZE).
    pub capacity_bytes: u32,
    /// Optional wakeup watermark in bytes (0 or None means immediate wakeup on event submission).
    pub watermark_bytes: Option<u32>,
    /// Enforce strictly zero-copy memory access via direct mmap pointers.
    pub zero_copy: bool,
}

impl RingBufferDescriptor {
    /// Creates a new zero-copy ring-buffer descriptor with requested capacity.
    pub fn new(name: impl Into<String>, capacity_bytes: u32) -> Self {
        Self {
            name: name.into(),
            capacity_bytes,
            watermark_bytes: None,
            zero_copy: true,
        }
    }

    /// Set an event wakeup watermark threshold.
    pub fn with_watermark(mut self, watermark: u32) -> Self {
        self.watermark_bytes = Some(watermark);
        self
    }

    /// Validates the ring buffer descriptor invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.capacity_bytes < PAGE_SIZE {
            return Err(DomainError::InvalidRingBufferSize {
                bytes: self.capacity_bytes,
                reason: "capacity must be at least one 4096-byte hardware page",
            });
        }

        if !self.capacity_bytes.is_power_of_two() {
            return Err(DomainError::InvalidRingBufferSize {
                bytes: self.capacity_bytes,
                reason: "capacity must be an exact power of two for bitwise ring index wrapping",
            });
        }

        if let Some(wm) = self.watermark_bytes {
            if wm > self.capacity_bytes {
                return Err(DomainError::InvalidRingBufferSize {
                    bytes: self.capacity_bytes,
                    reason: "watermark cannot exceed total buffer capacity",
                });
            }
        }

        Ok(())
    }

    /// Calculate bitmask for fast ring buffer index wrapping without division: `index & mask`.
    pub fn index_mask(&self) -> u32 {
        self.capacity_bytes - 1
    }
}
