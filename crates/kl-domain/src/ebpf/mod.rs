//! Pure domain models for Linux eBPF subsystems.

pub mod map;
pub mod probe;
pub mod ringbuf;
pub mod verifier;

pub use map::{EbpfMapDescriptor, MapLifecycleState, MapType};
pub use probe::{ProbeAttachmentState, ProbeDescriptor, ProbeTarget, ProbeType};
pub use ringbuf::{RingBufferDescriptor, PAGE_SIZE};
pub use verifier::VerifierBounds;
