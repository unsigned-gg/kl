//! Pure domain models for Linux Landlock LSM confinement.

pub mod abi;
pub mod access;
pub mod policy;
pub mod ruleset;

pub use abi::LandlockAbiVersion;
pub use access::{AccessFs, AccessFsSet};
pub use policy::ConfinementPolicy;
pub use ruleset::{LandlockRulesetDescriptor, PathRuleDescriptor};
