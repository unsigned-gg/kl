//! Linux Landlock LSM ABI version representations.

use serde::{Deserialize, Serialize};

/// Landlock ABI versions supported by Linux kernel releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LandlockAbiVersion {
    /// ABI V1 (Linux 5.13): Basic filesystem access rights (read, write, execute, make nodes).
    V1 = 1,
    /// ABI V2 (Linux 5.19): Added `LANDLOCK_ACCESS_FS_REFER` for file linking/renaming across directories.
    V2 = 2,
    /// ABI V3 (Linux 6.2): Added `LANDLOCK_ACCESS_FS_TRUNCATE` for file truncation control.
    V3 = 3,
    /// ABI V4 (Linux 6.7): Added network TCP port access controls (`LANDLOCK_ACCESS_NET_BIND_TCP`, `CONNECT_TCP`).
    V4 = 4,
    /// ABI V5 (Linux 6.10): Added `LANDLOCK_ACCESS_FS_IOCTL_DEV` for character and block device ioctl controls.
    V5 = 5,
}

impl LandlockAbiVersion {
    /// Returns the integer version number.
    pub const fn version_number(self) -> u32 {
        self as u32
    }

    /// Returns the maximum ABI version currently supported by `kl`.
    pub const fn latest() -> Self {
        Self::V5
    }
}
