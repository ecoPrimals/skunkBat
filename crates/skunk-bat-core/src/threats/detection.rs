// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Detection implementations for each threat category.
//!
//! Called by [`super::ThreatDetector::detect`] — one function per category.

use super::ThreatDetector;
use super::traits::{BaselineProfiler, LineageVerifier, TopologyValidator};
use super::types::{Severity, Threat, ThreatType};
use crate::config::ThreatThresholds;
use crate::error::SkunkBatError;
use std::time::SystemTime;

impl<L: LineageVerifier, B: BaselineProfiler> ThreatDetector<L, B> {
    pub(super) async fn detect_genetic_threats(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let Some(ref my_lineage) = self.lineage_id else {
            tracing::debug!("Genetic threat detection: no lineage_id configured");
            return Ok(Vec::new());
        };

        match self.lineage_verifier.is_family(my_lineage).await {
            Ok(true) => {
                tracing::debug!("Lineage verification passed for {my_lineage}");
                Ok(Vec::new())
            }
            Ok(false) => {
                tracing::warn!("Lineage verification FAILED for {my_lineage}");
                Ok(vec![Threat {
                    id: format!("genetic-lineage-{}", Self::threat_id_suffix()),
                    threat_type: ThreatType::UnknownLineage {
                        peer_id: my_lineage.clone(),
                        lineage: None,
                    },
                    source: my_lineage.clone(),
                    target: "self".to_owned(),
                    severity: Severity::Critical,
                    confidence: self.thresholds.genetic_confidence,
                    description: format!(
                        "Lineage verification failed — identity '{my_lineage}' not recognized"
                    ),
                    detected_at: SystemTime::now(),
                }])
            }
            Err(e) => {
                tracing::warn!("Lineage verifier unavailable: {e} — degraded genetic detection");
                Ok(vec![Threat {
                    id: format!("genetic-degraded-{}", Self::threat_id_suffix()),
                    threat_type: ThreatType::UnknownLineage {
                        peer_id: my_lineage.clone(),
                        lineage: None,
                    },
                    source: "verifier-unavailable".to_owned(),
                    target: "self".to_owned(),
                    severity: Severity::Medium,
                    confidence: 0.5,
                    description: format!(
                        "Lineage verifier unavailable ({e}) — unable to confirm family membership"
                    ),
                    detected_at: SystemTime::now(),
                }])
            }
        }
    }

    pub(super) async fn detect_behavioral_anomalies(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let profiler = self.baseline_profiler.read().await;

        if !profiler.is_established() {
            tracing::debug!("Baseline not established, learning normal behavior");
            return Ok(Vec::new());
        }

        let observation = match profiler.latest_observation() {
            Some(obs) => obs.clone(),
            None => return Ok(Vec::new()),
        };

        let anomalies = profiler.detect_anomalies(&observation).await?;
        drop(profiler);

        let threats = anomalies
            .into_iter()
            .map(|a| {
                let severity = anomaly_severity(&self.thresholds, a.deviation);
                Threat {
                    id: format!("anomaly-{}", Self::threat_id_suffix()),
                    description: format!("Behavioral anomaly detected: {}", a.behavior),
                    confidence: a.confidence,
                    threat_type: ThreatType::BehaviorAnomaly {
                        deviation: a.deviation,
                        behavior: a.behavior,
                    },
                    severity,
                    source: "network".to_owned(),
                    target: "local".to_owned(),
                    detected_at: SystemTime::now(),
                }
            })
            .collect();

        Ok(threats)
    }

    pub(super) async fn detect_intrusions(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let mut threats = Vec::new();
        let obs = {
            let profiler = self.baseline_profiler.read().await;
            profiler.latest_observation().cloned()
        };

        if let Some(obs) = obs.as_ref() {
            let sensitive = &self.thresholds.intrusion_sensitive_ports;
            let suspicious_ports: Vec<u16> = obs
                .ports_accessed
                .iter()
                .copied()
                .filter(|p| sensitive.contains(p))
                .collect();

            if suspicious_ports.len() >= 2 {
                threats.push(Threat {
                    id: format!("intrusion-portscan-{}", Self::threat_id_suffix()),
                    threat_type: ThreatType::IntrusionAttempt {
                        attack_type: "port-scan".to_owned(),
                        signature: format!("sensitive-ports:{suspicious_ports:?}"),
                    },
                    severity: Severity::High,
                    source: "network".to_owned(),
                    target: "local".to_owned(),
                    detected_at: SystemTime::now(),
                    description: format!(
                        "Access to multiple sensitive ports detected: {suspicious_ports:?}"
                    ),
                    confidence: self.thresholds.intrusion_portscan_confidence,
                });
            }

            if obs.connection_rate > 0.0
                && obs.traffic_volume > self.thresholds.intrusion_exfil_volume
            {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "volume fits in f64 mantissa for practical traffic values"
                )]
                let ratio = obs.traffic_volume as f64 / obs.connection_rate;
                if ratio > self.thresholds.intrusion_exfil_ratio {
                    threats.push(Threat {
                        id: format!("intrusion-exfil-{}", Self::threat_id_suffix()),
                        threat_type: ThreatType::IntrusionAttempt {
                            attack_type: "data-exfiltration".to_owned(),
                            signature: format!("high-volume-ratio:{ratio:.0}"),
                        },
                        severity: Severity::Medium,
                        source: "network".to_owned(),
                        target: "local".to_owned(),
                        detected_at: SystemTime::now(),
                        description: format!(
                            "High traffic-to-connection ratio ({ratio:.0}) suggests bulk transfer"
                        ),
                        confidence: self.thresholds.intrusion_exfil_confidence,
                    });
                }
            }
        }

        Ok(threats)
    }

    #[expect(
        clippy::unused_async,
        reason = "async signature for future async system metrics"
    )]
    pub(super) async fn detect_resource_exhaustion(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let load = check_system_load();
        if load > self.thresholds.dos_load_threshold {
            return Ok(vec![Threat {
                id: format!("dos-{}", Self::threat_id_suffix()),
                threat_type: ThreatType::DenialOfService {
                    resource: "cpu".to_owned(),
                    current_level: load,
                },
                severity: Severity::High,
                source: "unknown".to_owned(),
                target: "local".to_owned(),
                detected_at: SystemTime::now(),
                description: format!("High CPU usage detected: {:.1}%", load * 100.0),
                confidence: self.thresholds.dos_confidence,
            }]);
        }
        Ok(Vec::new())
    }

    pub(super) async fn detect_topology_threats(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let Some(ref validator) = self.topology_validator else {
            return Ok(Vec::new());
        };

        let paths = {
            let mut guard = self
                .observed_paths
                .lock()
                .map_err(|_| SkunkBatError::Internal("observed_paths lock poisoned".into()))?;
            std::mem::take(&mut *guard)
        };

        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let mut threats = Vec::new();
        for path in &paths {
            let validation = validator.validate_path(path).await?;
            if !validation.is_valid {
                threats.push(Threat {
                    id: format!("topology-violation-{}", Self::threat_id_suffix()),
                    threat_type: ThreatType::TopologyViolation {
                        expected_path: validation.expected_path,
                        actual_path: validation.actual_path,
                        bypassed_layers: validation.bypassed_layers.clone(),
                    },
                    severity: if validation.bypassed_layers.is_empty() {
                        Severity::Medium
                    } else {
                        Severity::High
                    },
                    source: "transport".to_owned(),
                    target: "local".to_owned(),
                    detected_at: SystemTime::now(),
                    description: format!(
                        "Connection bypassed layers {:?}",
                        validation.bypassed_layers
                    ),
                    confidence: 0.9,
                });
            }
        }

        Ok(threats)
    }
}

fn anomaly_severity(thresholds: &ThreatThresholds, deviation: f64) -> Severity {
    if deviation > thresholds.severity_high_deviation {
        Severity::High
    } else if deviation > thresholds.severity_medium_deviation {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn check_system_load() -> f64 {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0);

        #[expect(clippy::cast_precision_loss, reason = "CPU count fits in f64")]
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get() as f64)
            .unwrap_or(1.0);

        (raw / cpus).min(1.0)
    }

    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("uptime")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.rsplit("load average")
                    .next()?
                    .trim_start_matches([':', ' '])
                    .split(',')
                    .next()?
                    .trim()
                    .parse::<f64>()
                    .ok()
            })
            .map(|raw| {
                #[expect(clippy::cast_precision_loss, reason = "CPU count fits in f64")]
                let cpus = std::thread::available_parallelism()
                    .map(|n| n.get() as f64)
                    .unwrap_or(1.0);
                (raw / cpus).min(1.0)
            })
            .unwrap_or(0.0)
    }
}
