// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! G68 Platform Substrate Abstraction — eliminate silicon deism beyond transport.
//!
//! Three abstraction layers:
//! - **L1 Links**: [`platform_link()`] — symlink on Unix, junction/hard-link on Windows
//! - **L2 Permissions**: [`PlatformAccess`] — POSIX mode bits on Unix, ACL-compatible on Windows
//! - **L3 Device backends**: trait-based (not needed for skunkBat — no hardware I/O)
//!
//! `#[cfg(unix)]` belongs here and in the transport layer. Business logic calls
//! these functions and gets the right behavior on any platform.
//!
//! Reference: sourDough `crates/sourdough-core/src/platform_substrate.rs`

use std::io;
use std::path::Path;

// ─── L1: Links ─────────────────────────────────────────────────────────────

/// Create a platform-appropriate link from `original` to `link`.
///
/// - **Unix**: symbolic link
/// - **Windows**: `symlink_file` / `symlink_dir` (fallback: `hard_link`)
/// - **Other**: `hard_link`
///
/// # Errors
///
/// Returns `io::Error` if the link creation fails.
pub fn platform_link(original: &Path, link: &Path) -> io::Result<()> {
    platform_link_impl(original, link)
}

#[cfg(unix)]
fn platform_link_impl(original: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

#[cfg(windows)]
fn platform_link_impl(original: &Path, link: &Path) -> io::Result<()> {
    if original.is_dir() {
        std::os::windows::fs::symlink_dir(original, link)
    } else {
        std::os::windows::fs::symlink_file(original, link)
            .or_else(|_| std::fs::hard_link(original, link))
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_link_impl(original: &Path, link: &Path) -> io::Result<()> {
    std::fs::hard_link(original, link)
}

/// Check if a path is a symbolic link (platform-aware).
#[must_use]
pub fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

// ─── L2: Permissions ───────────────────────────────────────────────────────

/// Platform-neutral access level for filesystem objects.
///
/// Maps to POSIX mode bits on Unix, and to equivalent access semantics
/// on Windows (where exact mode bits don't exist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformAccess {
    /// Owner-only read+write (0o600 on Unix).
    OwnerReadWrite,
    /// Owner read+write+execute (0o700 on Unix).
    OwnerFull,
    /// Owner read+write, group+other read (0o644 on Unix).
    PublicRead,
    /// Owner read+write+execute, group+other read+execute (0o755 on Unix).
    PublicExecute,
    /// No access for anyone except owner read (0o400 on Unix).
    Readonly,
    /// Custom Unix mode bits (no-op on non-Unix).
    #[cfg(unix)]
    Custom(u32),
}

impl PlatformAccess {
    /// Apply this access level to the file at `path`.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the permission change fails.
    pub fn apply(&self, path: &Path) -> io::Result<()> {
        apply_access(path, *self)
    }
}

#[cfg(unix)]
fn apply_access(path: &Path, access: PlatformAccess) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match access {
        PlatformAccess::OwnerReadWrite => 0o600,
        PlatformAccess::OwnerFull => 0o700,
        PlatformAccess::PublicRead => 0o644,
        PlatformAccess::PublicExecute => 0o755,
        PlatformAccess::Readonly => 0o400,
        PlatformAccess::Custom(m) => m,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn apply_access(path: &Path, access: PlatformAccess) -> io::Result<()> {
    let readonly = matches!(access, PlatformAccess::Readonly);
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_readonly(readonly);
    std::fs::set_permissions(path, perms)
}

/// Query the effective access level of a file.
///
/// # Errors
///
/// Returns `io::Error` if metadata cannot be read.
pub fn query_access(path: &Path) -> io::Result<PlatformAccess> {
    query_access_impl(path)
}

#[cfg(unix)]
fn query_access_impl(path: &Path) -> io::Result<PlatformAccess> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    Ok(match mode {
        0o600 => PlatformAccess::OwnerReadWrite,
        0o700 => PlatformAccess::OwnerFull,
        0o644 => PlatformAccess::PublicRead,
        0o755 => PlatformAccess::PublicExecute,
        0o400 => PlatformAccess::Readonly,
        other => PlatformAccess::Custom(other),
    })
}

#[cfg(not(unix))]
fn query_access_impl(path: &Path) -> io::Result<PlatformAccess> {
    let perms = std::fs::metadata(path)?.permissions();
    if perms.readonly() {
        Ok(PlatformAccess::Readonly)
    } else {
        Ok(PlatformAccess::PublicRead)
    }
}

// ─── L2 Helpers ────────────────────────────────────────────────────────────

/// Ensure a directory exists with the specified access level.
///
/// # Errors
///
/// Returns `io::Error` on filesystem failures.
pub fn ensure_dir_with_access(path: &Path, access: PlatformAccess) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    access.apply(path)
}

/// Ensure a file's parent directory exists with owner-only access.
///
/// # Errors
///
/// Returns `io::Error` on filesystem failures.
pub fn ensure_secure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir_with_access(parent, PlatformAccess::OwnerFull)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn platform_link_creates_link() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.txt");
        std::fs::write(&original, "hello").unwrap();

        let link_path = dir.path().join("link.txt");
        platform_link(&original, &link_path).unwrap();

        let content = std::fs::read_to_string(&link_path).unwrap();
        assert_eq!(content, "hello");
    }

    #[cfg(unix)]
    #[test]
    fn platform_link_is_symlink_on_unix() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("orig.txt");
        std::fs::write(&original, "data").unwrap();

        let link_path = dir.path().join("sym.txt");
        platform_link(&original, &link_path).unwrap();

        assert!(is_symlink(&link_path));
    }

    #[test]
    fn is_symlink_false_for_regular_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("regular.txt");
        std::fs::write(&file, "content").unwrap();
        assert!(!is_symlink(&file));
    }

    #[cfg(unix)]
    #[test]
    fn apply_owner_read_write() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, "secret").unwrap();

        PlatformAccess::OwnerReadWrite.apply(&file).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn query_access_roundtrip() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "x").unwrap();

        PlatformAccess::OwnerFull.apply(&file).unwrap();
        assert_eq!(query_access(&file).unwrap(), PlatformAccess::OwnerFull);

        PlatformAccess::PublicRead.apply(&file).unwrap();
        assert_eq!(query_access(&file).unwrap(), PlatformAccess::PublicRead);
    }

    #[test]
    fn ensure_dir_with_access_creates_nested() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        ensure_dir_with_access(&nested, PlatformAccess::OwnerFull).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn ensure_secure_parent_creates_parent() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("secure_dir").join("key.pem");
        ensure_secure_parent(&file).unwrap();
        assert!(file.parent().unwrap().exists());
    }

    #[test]
    fn apply_readonly() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("readonly.txt");
        std::fs::write(&file, "frozen").unwrap();

        PlatformAccess::Readonly.apply(&file).unwrap();
        assert!(std::fs::metadata(&file).unwrap().permissions().readonly());

        #[cfg(unix)]
        PlatformAccess::OwnerReadWrite.apply(&file).unwrap();
        #[cfg(not(unix))]
        {
            let mut p = std::fs::metadata(&file).unwrap().permissions();
            p.set_readonly(false);
            std::fs::set_permissions(&file, p).unwrap();
        }
    }
}
