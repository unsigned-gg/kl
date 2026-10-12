//! eBPF probe attachment helpers, link lifecycles, and zero-copy ring-buffer consumers.

use kl_domain::{
    DomainError, ProbeAttachmentState, ProbeDescriptor, RingBufferDescriptor, VerifierBounds,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Operational status of an eBPF kernel link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinkStatus {
    /// Link actively attached to hook point and filtering/tracing events.
    Active,
    /// Link suspended; probe remains in memory but execution is disabled.
    Suspended,
    /// Link detached from hook point.
    Detached,
}

/// Handle representing an attached eBPF link in kernel space.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProbeLink {
    /// Unique identifier for this link.
    pub link_id: u64,
    /// Associated probe descriptor.
    pub descriptor: ProbeDescriptor,
    /// Link operational status.
    pub status: LinkStatus,
    /// Timestamp (epoch milliseconds) when the link was attached.
    pub attached_at_millis: u64,
}

impl ProbeLink {
    /// Detaches the probe link from the kernel hook point.
    pub fn detach(&mut self) -> Result<(), DomainError> {
        if self.status == LinkStatus::Detached {
            return Ok(());
        }
        self.descriptor.state = self
            .descriptor
            .state
            .transition_to(ProbeAttachmentState::Detached)?;
        self.status = LinkStatus::Detached;
        Ok(())
    }
}

/// High-level manager coordinating eBPF probe attachments and links.
#[derive(Debug, Default)]
pub struct AttachmentManager {
    links: HashMap<u64, ProbeLink>,
    next_link_id: AtomicU64,
    bounds: VerifierBounds,
}

impl AttachmentManager {
    /// Creates a new attachment manager with default kernel verifier bounds.
    pub fn new() -> Self {
        Self {
            links: HashMap::new(),
            next_link_id: AtomicU64::new(1),
            bounds: VerifierBounds::default(),
        }
    }

    /// Attaches an eBPF probe to its designated target hook point.
    pub fn attach(&mut self, mut descriptor: ProbeDescriptor) -> Result<ProbeLink, DomainError> {
        // Validate probe invariants against kernel verifier instruction and stack bounds
        descriptor.validate(&self.bounds)?;

        // Simulate kernel BPF_PROG_LOAD transition
        descriptor.state = descriptor
            .state
            .transition_to(ProbeAttachmentState::Loaded)?;

        // Simulate kernel bpf_link attachment transition
        descriptor.state = descriptor
            .state
            .transition_to(ProbeAttachmentState::Attached)?;

        let link_id = self.next_link_id.fetch_add(1, Ordering::Relaxed);
        let link = ProbeLink {
            link_id,
            descriptor,
            status: LinkStatus::Active,
            attached_at_millis: 1770678000000, // Deterministic timestamp
        };

        self.links.insert(link_id, link.clone());
        Ok(link)
    }

    /// Detaches a probe link by its link ID.
    pub fn detach(&mut self, link_id: u64) -> Result<(), DomainError> {
        if let Some(link) = self.links.get_mut(&link_id) {
            link.detach()?;
            Ok(())
        } else {
            Err(DomainError::InvalidStateTransition {
                from: "Unknown",
                to: "Detached",
            })
        }
    }

    /// Returns the number of currently active attached links.
    pub fn active_link_count(&self) -> usize {
        self.links
            .values()
            .filter(|l| l.status == LinkStatus::Active)
            .count()
    }
}

/// Zero-copy ring-buffer reader interface.
///
/// Implements Sindri's zero-copy architecture:
/// Events are read directly from page-mapped shared memory without copying into intermediate buffers.
#[derive(Debug)]
pub struct RingBufferConsumer {
    descriptor: RingBufferDescriptor,
    consumer_pos: u64,
    producer_pos: u64,
    buffer: Vec<u8>,
}

impl RingBufferConsumer {
    /// Creates a new ring-buffer consumer initialized with the given descriptor.
    pub fn new(descriptor: RingBufferDescriptor) -> Result<Self, DomainError> {
        descriptor.validate()?;
        let cap = descriptor.capacity_bytes as usize;
        Ok(Self {
            descriptor,
            consumer_pos: 0,
            producer_pos: 0,
            buffer: vec![0u8; cap],
        })
    }

    /// Simulates a kernel probe writing an event into the ring-buffer.
    pub fn submit_event(&mut self, data: &[u8]) -> Result<(), DomainError> {
        let cap = self.descriptor.capacity_bytes as usize;
        let event_len = data.len();

        // 8-byte header: length (4 bytes) + flags (4 bytes)
        let total_needed = 8 + event_len;
        let available = cap - ((self.producer_pos - self.consumer_pos) as usize);

        if total_needed > available {
            return Err(DomainError::InvalidRingBufferSize {
                bytes: total_needed as u32,
                reason: "ring buffer full; event dropped by kernel probe",
            });
        }

        let mask = self.descriptor.index_mask() as usize;
        let write_idx = (self.producer_pos as usize) & mask;

        // Write header
        let len_bytes = (event_len as u32).to_ne_bytes();
        for (i, &b) in len_bytes.iter().enumerate() {
            self.buffer[(write_idx + i) & mask] = b;
        }

        // Write payload
        for (i, &b) in data.iter().enumerate() {
            self.buffer[(write_idx + 8 + i) & mask] = b;
        }

        self.producer_pos += total_needed as u64;
        Ok(())
    }

    /// Consumes all available events using zero-copy slice iteration.
    pub fn drain_events<F>(&mut self, mut handler: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let mut events_processed = 0;
        let mask = self.descriptor.index_mask() as usize;

        while self.consumer_pos < self.producer_pos {
            let read_idx = (self.consumer_pos as usize) & mask;

            // Read 4-byte length
            let mut len_bytes = [0u8; 4];
            for (i, b) in len_bytes.iter_mut().enumerate() {
                *b = self.buffer[(read_idx + i) & mask];
            }
            let event_len = u32::from_ne_bytes(len_bytes) as usize;
            let total_entry = 8 + event_len;

            // Extract event payload
            let start = (read_idx + 8) & mask;
            let end = (start + event_len) & mask;

            if start <= end && start + event_len <= self.buffer.len() {
                // Contiguous slice: zero-copy read directly from backing memory
                handler(&self.buffer[start..start + event_len]);
            } else {
                // Wrapped slice: fallback copy across dual-page boundary
                let mut temp = vec![0u8; event_len];
                for (i, b) in temp.iter_mut().enumerate() {
                    *b = self.buffer[(start + i) & mask];
                }
                handler(&temp);
            }

            self.consumer_pos += total_entry as u64;
            events_processed += 1;
        }

        events_processed
    }

    /// Returns unconsumed byte count currently residing in the ring-buffer.
    pub fn unconsumed_bytes(&self) -> u64 {
        self.producer_pos - self.consumer_pos
    }
}
