// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Primal lifecycle management.
//!
//! Every primal has a lifecycle: it starts, runs, and eventually stops.

use super::error::PrimalError;
use serde::{Deserialize, Serialize};

/// State of a primal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrimalState {
    /// Not yet started.
    Created,
    /// Starting up.
    Starting,
    /// Running normally.
    Running,
    /// Stopping.
    Stopping,
    /// Stopped.
    Stopped,
    /// Failed.
    Failed,
}

impl PrimalState {
    /// Check if the primal is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if the primal can be started.
    #[must_use]
    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Created | Self::Stopped | Self::Failed)
    }

    /// Check if the primal can be stopped.
    #[must_use]
    pub const fn can_stop(&self) -> bool {
        matches!(self, Self::Running)
    }
}

impl std::fmt::Display for PrimalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Lifecycle trait for primals.
///
/// Implement this trait to define how your primal starts, stops, and reloads.
pub trait PrimalLifecycle: Send + Sync {
    /// Get the current state.
    fn state(&self) -> PrimalState;

    /// Start the primal.
    ///
    /// # Errors
    ///
    /// Returns an error if startup fails.
    fn start(&mut self) -> impl std::future::Future<Output = Result<(), PrimalError>> + Send;

    /// Stop the primal.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), PrimalError>> + Send;

    /// Reload configuration.
    ///
    /// Default implementation stops and restarts.
    ///
    /// # Errors
    ///
    /// Returns an error if reload fails.
    fn reload(&mut self) -> impl std::future::Future<Output = Result<(), PrimalError>> + Send {
        async {
            self.stop().await?;
            self.start().await
        }
    }

    /// Handle a shutdown signal.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    fn shutdown(&mut self) -> impl std::future::Future<Output = Result<(), PrimalError>> + Send {
        async { self.stop().await }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions() {
        assert!(PrimalState::Created.can_start());
        assert!(!PrimalState::Created.can_stop());
        assert!(!PrimalState::Created.is_running());

        assert!(!PrimalState::Running.can_start());
        assert!(PrimalState::Running.can_stop());
        assert!(PrimalState::Running.is_running());

        assert!(PrimalState::Stopped.can_start());
        assert!(!PrimalState::Stopped.can_stop());

        assert!(PrimalState::Failed.can_start());
        assert!(!PrimalState::Failed.can_stop());
    }

    #[test]
    fn state_display() {
        assert_eq!(PrimalState::Created.to_string(), "created");
        assert_eq!(PrimalState::Running.to_string(), "running");
        assert_eq!(PrimalState::Failed.to_string(), "failed");
    }

    #[test]
    fn state_serialization() {
        let state = PrimalState::Running;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""running""#);
        let deserialized: PrimalState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn state_serde_all_variants_lowercase() {
        let cases = [
            (PrimalState::Created, r#""created""#),
            (PrimalState::Starting, r#""starting""#),
            (PrimalState::Running, r#""running""#),
            (PrimalState::Stopping, r#""stopping""#),
            (PrimalState::Stopped, r#""stopped""#),
            (PrimalState::Failed, r#""failed""#),
        ];
        for (state, expected) in &cases {
            let json = serde_json::to_string(state).unwrap();
            assert_eq!(&json, expected, "Serialize {state:?}");
            let parsed: PrimalState = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, state, "Deserialize {expected}");
        }
    }

    struct MockPrimal {
        state: PrimalState,
    }

    impl MockPrimal {
        fn new() -> Self {
            Self {
                state: PrimalState::Created,
            }
        }
    }

    impl PrimalLifecycle for MockPrimal {
        fn state(&self) -> PrimalState {
            self.state
        }

        async fn start(&mut self) -> Result<(), PrimalError> {
            if !self.state.can_start() {
                return Err(PrimalError::lifecycle(format!(
                    "cannot start from state: {}",
                    self.state
                )));
            }
            self.state = PrimalState::Running;
            Ok(())
        }

        async fn stop(&mut self) -> Result<(), PrimalError> {
            if !self.state.can_stop() {
                return Err(PrimalError::lifecycle(format!(
                    "cannot stop from state: {}",
                    self.state
                )));
            }
            self.state = PrimalState::Stopped;
            Ok(())
        }
    }

    #[tokio::test]
    async fn lifecycle_start_stop() {
        let mut primal = MockPrimal::new();
        assert_eq!(primal.state(), PrimalState::Created);

        primal.start().await.unwrap();
        assert_eq!(primal.state(), PrimalState::Running);

        primal.stop().await.unwrap();
        assert_eq!(primal.state(), PrimalState::Stopped);
    }

    #[tokio::test]
    async fn lifecycle_reload() {
        let mut primal = MockPrimal::new();
        primal.start().await.unwrap();
        primal.reload().await.unwrap();
        assert_eq!(primal.state(), PrimalState::Running);
    }

    #[tokio::test]
    async fn lifecycle_shutdown() {
        let mut primal = MockPrimal::new();
        primal.start().await.unwrap();
        primal.shutdown().await.unwrap();
        assert_eq!(primal.state(), PrimalState::Stopped);
    }
}
