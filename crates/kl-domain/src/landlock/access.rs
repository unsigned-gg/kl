//! Landlock filesystem access rights and flag sets.

use crate::landlock::abi::LandlockAbiVersion;
use serde::{Deserialize, Serialize};

/// Canonical Landlock filesystem access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessFs {
    /// Execute an executable binary (`LANDLOCK_ACCESS_FS_EXECUTE`).
    Execute = 1 << 0,
    /// Open a file with write access (`LANDLOCK_ACCESS_FS_WRITE_FILE`).
    WriteFile = 1 << 1,
    /// Open a file with read access (`LANDLOCK_ACCESS_FS_READ_FILE`).
    ReadFile = 1 << 2,
    /// Open a directory or list its content (`LANDLOCK_ACCESS_FS_READ_DIR`).
    ReadDir = 1 << 3,
    /// Remove an empty directory (`LANDLOCK_ACCESS_FS_REMOVE_DIR`).
    RemoveDir = 1 << 4,
    /// Unlink or remove a file (`LANDLOCK_ACCESS_FS_REMOVE_FILE`).
    RemoveFile = 1 << 5,
    /// Create a character device file (`LANDLOCK_ACCESS_FS_MAKE_CHAR`).
    MakeChar = 1 << 6,
    /// Create a new directory (`LANDLOCK_ACCESS_FS_MAKE_DIR`).
    MakeDir = 1 << 7,
    /// Create a regular file (`LANDLOCK_ACCESS_FS_MAKE_REG`).
    MakeReg = 1 << 8,
    /// Create a UNIX domain socket (`LANDLOCK_ACCESS_FS_MAKE_SOCK`).
    MakeSock = 1 << 9,
    /// Create a named pipe FIFO (`LANDLOCK_ACCESS_FS_MAKE_FIFO`).
    MakeFifo = 1 << 10,
    /// Create a block device file (`LANDLOCK_ACCESS_FS_MAKE_BLOCK`).
    MakeBlock = 1 << 11,
    /// Create a symbolic link (`LANDLOCK_ACCESS_FS_MAKE_SYM`).
    MakeSym = 1 << 12,
    /// Link or rename a file across parent directories (ABI V2+: `LANDLOCK_ACCESS_FS_REFER`).
    Refer = 1 << 13,
    /// Truncate file length (ABI V3+: `LANDLOCK_ACCESS_FS_TRUNCATE`).
    Truncate = 1 << 14,
    /// Invoke device ioctls (ABI V5+: `LANDLOCK_ACCESS_FS_IOCTL_DEV`).
    IoctlDev = 1 << 15,
}

/// Bitmask set of Landlock filesystem access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
pub struct AccessFsSet(pub u32);

impl AccessFsSet {
    /// Empty set of access rights.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Set containing all ABI V1 rights.
    pub const fn all_v1() -> Self {
        Self(0x1FFF)
    }

    /// Set containing all filesystem rights supported by the given ABI version.
    pub fn all_for_abi(abi: LandlockAbiVersion) -> Self {
        let max_mask = match abi {
            LandlockAbiVersion::V1 => 0x1FFF,
            LandlockAbiVersion::V2 => 0x3FFF,
            LandlockAbiVersion::V3 => 0x7FFF,
            LandlockAbiVersion::V4 => 0x7FFF,
            LandlockAbiVersion::V5 => 0xFFFF,
        };
        Self(max_mask)
    }

    /// Set containing read-only access (ReadFile, ReadDir).
    pub const fn read_only() -> Self {
        Self((AccessFs::ReadFile as u32) | (AccessFs::ReadDir as u32))
    }

    /// Set containing read-write file access without directory modifications.
    pub const fn read_write() -> Self {
        Self(
            (AccessFs::ReadFile as u32)
                | (AccessFs::ReadDir as u32)
                | (AccessFs::WriteFile as u32)
                | (AccessFs::Truncate as u32),
        )
    }

    /// Set containing execute and read rights.
    pub const fn read_execute() -> Self {
        Self((AccessFs::ReadFile as u32) | (AccessFs::ReadDir as u32) | (AccessFs::Execute as u32))
    }

    /// Insert an access right into the set.
    pub fn insert(&mut self, access: AccessFs) {
        self.0 |= access as u32;
    }

    /// Check if set contains an access right.
    pub const fn contains(&self, access: AccessFs) -> bool {
        (self.0 & (access as u32)) != 0
    }

    /// Remove an access right.
    pub fn remove(&mut self, access: AccessFs) {
        self.0 &= !(access as u32);
    }

    /// Bitwise union of two access sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Bitwise intersection of two access sets.
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Check if set is empty.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Mask access set to the maximum rights supported by a specific ABI version.
    pub fn mask_for_abi(self, abi: LandlockAbiVersion) -> Self {
        let max_mask = match abi {
            LandlockAbiVersion::V1 => 0x1FFF, // bits 0..=12
            LandlockAbiVersion::V2 => 0x3FFF, // bits 0..=13
            LandlockAbiVersion::V3 => 0x7FFF, // bits 0..=14
            LandlockAbiVersion::V4 => 0x7FFF, // V4 adds network, fs mask unchanged
            LandlockAbiVersion::V5 => 0xFFFF, // bits 0..=15
        };
        Self(self.0 & max_mask)
    }
}
