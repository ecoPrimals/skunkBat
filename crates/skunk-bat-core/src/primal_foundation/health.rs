// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Health check traits for observability.

use super::error::PrimalError;
use super::types::Timestamp;
use serde::{Deserialize, Serialize};

/// Overall health status of a primal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Healthy and ready to serve requests.
    Healthy,
    /// Unhealthy but may recover.
    Degraded {
        /// Reason for degraded status.
        reason: String,
    },
    /// Unhealthy and not serving requests.
    Unhealthy {
        /// Reason for unhealthy status.
        reason: String,
    },
    /// Health unknown (e.g., startup in progress).
    Unknown,
}

impl HealthStatus {
    /// Check if the status is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Check if the status allows serving requests.
    #[must_use]
    pub const fn is_serving(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded { .. })
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded { reason } => write!(f, "degraded: {reason}"),
            Self::Unhealthy { reason } => write!(f, "unhealthy: {reason}"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Health of a dependency.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyHealth {
    /// Name of the dependency.
    pub name: String,
    /// Type of dependency (e.g., "database", "service", "file").
    pub dependency_type: String,
    /// Health status.
    pub status: HealthStatus,
    /// Latency to the dependency (optional).
    pub latency_ms: Option<u64>,
    /// Last check time.
    pub last_check: Timestamp,
}

impl DependencyHealth {
    /// Create a healthy dependency.
    #[must_use]
    pub fn healthy(name: impl Into<String>, dep_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dependency_type: dep_type.into(),
            status: HealthStatus::Healthy,
            latency_ms: None,
            last_check: Timestamp::now(),
        }
    }

    /// Create an unhealthy dependency.
    #[must_use]
    pub fn unhealthy(
        name: impl Into<String>,
        dep_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            dependency_type: dep_type.into(),
            status: HealthStatus::Unhealthy {
                reason: reason.into(),
            },
            latency_ms: None,
            last_check: Timestamp::now(),
        }
    }

    /// Set latency.
    #[must_use]
    pub const fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }
}

/// Full health report for a primal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthReport {
    /// Primal name.
    pub name: String,
    /// Primal version.
    pub version: String,
    /// Overall status.
    pub status: HealthStatus,
    /// Liveness (is the process alive?).
    pub liveness: bool,
    /// Readiness (can it serve requests?).
    pub readiness: bool,
    /// Dependency health.
    pub dependencies: Vec<DependencyHealth>,
    /// Report timestamp.
    pub timestamp: Timestamp,
    /// Additional details.
    pub details: std::collections::HashMap<String, String>,
}

impl HealthReport {
    /// Create a new health report.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            status: HealthStatus::Unknown,
            liveness: true,
            readiness: false,
            dependencies: Vec::new(),
            timestamp: Timestamp::now(),
            details: std::collections::HashMap::new(),
        }
    }

    /// Set status.
    #[must_use]
    pub fn with_status(mut self, status: HealthStatus) -> Self {
        self.readiness = status.is_serving();
        self.status = status;
        self
    }

    /// Add a dependency.
    #[must_use]
    pub fn with_dependency(mut self, dep: DependencyHealth) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Add a detail.
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// Health check trait for primals.
pub trait PrimalHealth: Send + Sync {
    /// Get the current health status (quick check).
    fn health_status(&self) -> HealthStatus;

    /// Perform a full health check (may be expensive).
    ///
    /// # Errors
    ///
    /// Returns an error if the health check itself fails (not if unhealthy).
    fn health_check(
        &self,
    ) -> impl std::future::Future<Output = Result<HealthReport, PrimalError>> + Send;

    /// Check liveness (is the process alive?).
    fn is_live(&self) -> bool {
        true
    }

    /// Check readiness (can it serve requests?).
    fn is_ready(&self) -> bool {
        self.health_status().is_serving()
    }

    /// Get dependency health (optional).
    fn dependency_health(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<DependencyHealth>, PrimalError>> + Send {
        async { Ok(Vec::new()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_variants() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(HealthStatus::Healthy.is_serving());

        let degraded = HealthStatus::Degraded {
            reason: "slow".to_owned(),
        };
        assert!(!degraded.is_healthy());
        assert!(degraded.is_serving());

        let unhealthy = HealthStatus::Unhealthy {
            reason: "down".to_owned(),
        };
        assert!(!unhealthy.is_healthy());
        assert!(!unhealthy.is_serving());

        assert!(!HealthStatus::Unknown.is_healthy());
        assert!(!HealthStatus::Unknown.is_serving());
    }

    #[test]
    fn health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(
            HealthStatus::Degraded {
                reason: "slow".to_owned()
            }
            .to_string(),
            "degraded: slow"
        );
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn health_status_serialization() {
        let status = HealthStatus::Degraded {
            reason: "slow".to_owned(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }

    #[test]
    fn dependency_health_builder() {
        let dep = DependencyHealth::healthy("postgres", "database").with_latency(50);
        assert_eq!(dep.name, "postgres");
        assert_eq!(dep.latency_ms, Some(50));
        assert!(dep.status.is_healthy());
    }

    #[test]
    fn dependency_health_unhealthy() {
        let dep = DependencyHealth::unhealthy("redis", "cache", "connection refused");
        assert!(!dep.status.is_healthy());
    }

    #[test]
    fn health_report_builder() {
        let report = HealthReport::new("test-primal", "1.0.0")
            .with_status(HealthStatus::Healthy)
            .with_dependency(DependencyHealth::healthy("db", "database"))
            .with_detail("uptime", "1h");

        assert_eq!(report.name, "test-primal");
        assert!(report.readiness);
        assert_eq!(report.dependencies.len(), 1);
        assert_eq!(report.details.get("uptime"), Some(&"1h".to_owned()));
    }

    #[test]
    fn health_report_readiness_tracks_status() {
        let healthy = HealthReport::new("t", "1").with_status(HealthStatus::Healthy);
        assert!(healthy.readiness);

        let unhealthy = HealthReport::new("t", "1").with_status(HealthStatus::Unhealthy {
            reason: "down".to_owned(),
        });
        assert!(!unhealthy.readiness);
    }
}
