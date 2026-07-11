//! File position tracking for crash-safe log tailing.
//!
//! Stores the byte offset in a small state file so the tailer can resume
//! after a restart without reprocessing the entire log.

use std::path::Path;

use tokio::fs;

/// Load the last-read byte offset from the cursor file.
///
/// Returns 0 if the file doesn't exist or is unreadable.
pub async fn load(path: &Path) -> u64 {
    fs::read_to_string(path)
        .await
        .map_or(0, |s| s.trim().parse().unwrap_or(0))
}

/// Persist the current byte offset to the cursor file.
pub async fn save(path: &Path, offset: u64) -> std::io::Result<()> {
    fs::write(path, offset.to_string()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn round_trip_cursor() {
        let dir = std::env::temp_dir().join("skunky-ingest-test-cursor");
        let _ = fs::create_dir_all(&dir).await;
        let path = dir.join("cursor.pos");

        save(&path, 42_000).await.expect("save");
        let loaded = load(&path).await;
        assert_eq!(loaded, 42_000);

        let _ = fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn missing_file_returns_zero() {
        let path = PathBuf::from("/tmp/skunky-ingest-nonexistent-cursor-file");
        assert_eq!(load(&path).await, 0);
    }
}
