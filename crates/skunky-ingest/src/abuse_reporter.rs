// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Abuse reporter — cytokine signaling layer.
//!
//! ## Biological Parallel: Cytokines
//!
//! Cytokines are signaling molecules that recruit immune cells from
//! elsewhere in the body. They don't attack the pathogen directly —
//! they signal to other systems that something is wrong here, and
//! those systems bring their own capabilities.
//!
//! The abuse reporter generates reports for hosting providers when
//! fleet detection identifies persistent scanner ASNs. Reports are
//! queued for manual review before sending — the cytokine signal
//! must pass through a checkpoint before it recruits outside help.
//!
//! ## Manual Review Gate
//!
//! Reports are NEVER auto-sent. They queue in `/run/membrane/abuse-queue/`
//! as JSON files with `PendingReview` status. A human reviews them via
//! northgate before approving for delivery. This prevents:
//! - False positives from triggering abuse complaints
//! - Strategic timing issues (sometimes we want to observe, not report)
//! - Accidental exposure of investigation intelligence

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// An abuse report queued for review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseReport {
    /// Unique report ID (date + behavioral hash prefix).
    pub report_id: String,
    /// Target abuse contact email (from RDAP or WHOIS).
    pub abuse_contact: String,
    /// ASN of the scanner fleet.
    pub asn: String,
    /// ASN organization name.
    pub asn_org: String,
    /// Behavioral hash of the fleet (links to opsonize tags).
    pub behavioral_hash: String,
    /// Number of unique IPs observed from this ASN.
    pub ip_count: u32,
    /// Total requests from this ASN in the observation period.
    pub total_requests: u64,
    /// What the scanner was probing for.
    pub probe_categories: Vec<String>,
    /// Observation period start (ISO 8601).
    pub period_start: String,
    /// Observation period end (ISO 8601).
    pub period_end: String,
    /// Generated X-ARF report body.
    pub xarf_body: String,
    /// Review status — manual gate before sending.
    pub status: ReportStatus,
    /// Timestamp when the report was generated.
    pub generated_at: String,
}

/// Report review status — manual gate before sending.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportStatus {
    /// Queued for human review on northgate.
    PendingReview,
    /// Approved for sending.
    Approved,
    /// Rejected (false positive, strategic hold, etc.).
    Rejected,
    /// Sent to the abuse contact.
    Sent,
}

/// Queue directory for abuse reports.
pub struct AbuseReportQueue {
    queue_dir: PathBuf,
}

impl AbuseReportQueue {
    /// Create a new abuse report queue, creating the directory if needed.
    pub fn new(queue_dir: &Path) -> Self {
        if let Err(e) = std::fs::create_dir_all(queue_dir) {
            tracing::warn!(
                error = %e,
                path = %queue_dir.display(),
                "failed to create abuse queue directory"
            );
        }
        Self {
            queue_dir: queue_dir.to_path_buf(),
        }
    }

    /// Queue a new abuse report for review.
    pub fn enqueue(&self, report: &AbuseReport) -> Result<(), std::io::Error> {
        let filename = format!("{}.json", report.report_id);
        let path = self.queue_dir.join(&filename);

        let json = serde_json::to_string_pretty(report)
            .map_err(|e| std::io::Error::other(format!("report serialization failed: {e}")))?;

        std::fs::write(&path, json)?;

        tracing::info!(
            report_id = %report.report_id,
            asn = %report.asn,
            asn_org = %report.asn_org,
            ips = report.ip_count,
            path = %path.display(),
            "📨 abuse report queued for review"
        );

        Ok(())
    }

    /// List all pending reports.
    pub fn list_pending(&self) -> Vec<AbuseReport> {
        self.list_by_status(ReportStatus::PendingReview)
    }

    /// List reports by status.
    fn list_by_status(&self, status: ReportStatus) -> Vec<AbuseReport> {
        let dir = match std::fs::read_dir(&self.queue_dir) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        dir.filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "json")
            })
            .filter_map(|entry| {
                let content = std::fs::read_to_string(entry.path()).ok()?;
                let report: AbuseReport = serde_json::from_str(&content).ok()?;
                if report.status == status {
                    Some(report)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Number of queued reports awaiting review.
    pub fn pending_count(&self) -> usize {
        self.list_pending().len()
    }

    /// Update a report's status (approve, reject, mark sent).
    pub fn update_status(
        &self,
        report_id: &str,
        new_status: ReportStatus,
    ) -> Result<(), std::io::Error> {
        let filename = format!("{report_id}.json");
        let path = self.queue_dir.join(&filename);

        let content = std::fs::read_to_string(&path)?;
        let mut report: AbuseReport = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::other(format!("parse failed: {e}")))?;

        report.status = new_status;

        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| std::io::Error::other(format!("serialize failed: {e}")))?;

        std::fs::write(&path, json)?;
        Ok(())
    }
}

/// Generate an X-ARF formatted abuse report body.
///
/// X-ARF (Extended Abuse Reporting Format) is the standard format for
/// reporting network abuse to hosting providers. It's machine-parseable
/// and widely supported by abuse desk software.
pub fn generate_xarf_report(report: &AbuseReport) -> String {
    format!(
        "Subject: Abuse Report — Coordinated Scanning Activity from AS{asn}\n\
         \n\
         Dear Abuse Team,\n\
         \n\
         We are writing to report coordinated vulnerability scanning activity\n\
         originating from your network (AS{asn}, {org}).\n\
         \n\
         SUMMARY\n\
         -------\n\
         - Behavioral Hash: {bhash}\n\
         - Unique IPs Observed: {ips}\n\
         - Total Requests: {reqs}\n\
         - Observation Period: {start} to {end}\n\
         - Probe Categories: {categories}\n\
         \n\
         BEHAVIOR DESCRIPTION\n\
         --------------------\n\
         Multiple IPs from your network exhibited coordinated scanning behavior\n\
         targeting our web infrastructure. The fleet demonstrated:\n\
         \n\
         - IP rotation across {ips} addresses (coordinated pool)\n\
         - Uniform request patterns across all IPs (behavioral hash: {bhash})\n\
         - Systematic probing of credential and configuration paths\n\
         - Continued scanning after receiving 403/429 rejection responses\n\
         \n\
         This pattern is consistent with automated vulnerability scanning\n\
         using a distributed IP pool to evade per-IP rate limits.\n\
         \n\
         NO IP ADDRESSES INCLUDED\n\
         ------------------------\n\
         We have intentionally omitted specific IP addresses from this report.\n\
         The behavioral hash above uniquely identifies the scanning pattern\n\
         and can be matched against your own logs. We believe this approach\n\
         better serves privacy while providing actionable intelligence.\n\
         \n\
         If you require specific IP addresses for investigation, please\n\
         contact us and we can provide them through a secure channel.\n\
         \n\
         ACTION REQUESTED\n\
         ----------------\n\
         Please investigate the scanning activity originating from AS{asn}\n\
         and take appropriate action per your Acceptable Use Policy.\n\
         \n\
         This report was generated by an automated defense system.\n\
         For questions, contact: security@primals.eco\n\
         \n\
         ---\n\
         Report ID: {report_id}\n\
         Generated: {generated}\n",
        asn = report.asn,
        org = report.asn_org,
        bhash = report.behavioral_hash,
        ips = report.ip_count,
        reqs = report.total_requests,
        start = report.period_start,
        end = report.period_end,
        categories = report.probe_categories.join(", "),
        report_id = report.report_id,
        generated = report.generated_at,
    )
}

/// Build an abuse report from fleet observation data.
///
/// Creates the report in `PendingReview` status. It will NOT be sent
/// until a human reviews and approves it on northgate.
pub fn build_report(
    behavioral_hash: &str,
    asn: &str,
    asn_org: &str,
    ip_count: u32,
    total_requests: u64,
    probe_categories: Vec<String>,
    period_start: &str,
    period_end: &str,
) -> AbuseReport {
    let now = chrono::Utc::now();
    let hash_prefix = &behavioral_hash[..behavioral_hash.len().min(16)];
    let report_id = format!("{}-{}", now.format("%Y%m%d-%H%M%S%.3f"), hash_prefix);

    let mut report = AbuseReport {
        report_id,
        abuse_contact: format!("abuse@{}", asn_org.split_whitespace().next().unwrap_or("unknown")),
        asn: asn.to_string(),
        asn_org: asn_org.to_string(),
        behavioral_hash: behavioral_hash.to_string(),
        ip_count,
        total_requests,
        probe_categories,
        period_start: period_start.to_string(),
        period_end: period_end.to_string(),
        xarf_body: String::new(),
        status: ReportStatus::PendingReview,
        generated_at: now.to_rfc3339(),
    };

    report.xarf_body = generate_xarf_report(&report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_queue_report() {
        let dir = tempfile::tempdir().unwrap();
        let queue = AbuseReportQueue::new(dir.path());

        let report = build_report(
            "abc123def456",
            "AS12345",
            "ExampleHost LLC",
            150,
            45000,
            vec!["credential-scanning".to_string(), "path-traversal".to_string()],
            "2026-10-06T00:00:00Z",
            "2026-10-06T23:59:59Z",
        );

        assert_eq!(report.status, ReportStatus::PendingReview);
        assert!(report.xarf_body.contains("AS12345"));
        assert!(report.xarf_body.contains("abc123def456"));
        assert!(report.xarf_body.contains("ExampleHost LLC"));

        queue.enqueue(&report).unwrap();
        assert_eq!(queue.pending_count(), 1);

        let pending = queue.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].asn, "AS12345");
    }

    #[test]
    fn xarf_report_format() {
        let report = build_report(
            "deadbeef01234567",
            "AS99999",
            "Scanner Corp",
            500,
            100000,
            vec!["vulnerability-scanning".to_string()],
            "2026-10-05T00:00:00Z",
            "2026-10-06T00:00:00Z",
        );

        let body = &report.xarf_body;
        assert!(body.contains("Abuse Report"));
        assert!(body.contains("AS99999"));
        assert!(body.contains("Scanner Corp"));
        assert!(body.contains("deadbeef01234567"));
        assert!(body.contains("500"));
        assert!(body.contains("NO IP ADDRESSES INCLUDED"));
        assert!(body.contains("security@primals.eco"));
    }

    #[test]
    fn empty_queue() {
        let dir = tempfile::tempdir().unwrap();
        let queue = AbuseReportQueue::new(dir.path());
        assert_eq!(queue.pending_count(), 0);
        assert!(queue.list_pending().is_empty());
    }

    #[test]
    fn update_report_status() {
        let dir = tempfile::tempdir().unwrap();
        let queue = AbuseReportQueue::new(dir.path());

        let report = build_report(
            "abc123",
            "AS11111",
            "TestHost",
            10,
            500,
            vec!["scanning".to_string()],
            "2026-10-06T00:00:00Z",
            "2026-10-06T12:00:00Z",
        );

        let report_id = report.report_id.clone();
        queue.enqueue(&report).unwrap();
        assert_eq!(queue.pending_count(), 1);

        queue.update_status(&report_id, ReportStatus::Approved).unwrap();
        assert_eq!(queue.pending_count(), 0);

        let approved = queue.list_by_status(ReportStatus::Approved);
        assert_eq!(approved.len(), 1);
    }

    #[test]
    fn multiple_reports_queue() {
        let dir = tempfile::tempdir().unwrap();
        let queue = AbuseReportQueue::new(dir.path());

        for i in 0..3 {
            let report = build_report(
                &format!("hash_{i:04}"),
                &format!("AS{}", 10000 + i),
                &format!("Host{i}"),
                (i + 1) * 50,
                (i as u64 + 1) * 10000,
                vec!["scanning".to_string()],
                "2026-10-06T00:00:00Z",
                "2026-10-06T23:59:59Z",
            );
            queue.enqueue(&report).unwrap();
        }

        assert_eq!(queue.pending_count(), 3);
    }

    #[test]
    fn report_no_pii() {
        let report = build_report(
            "behavioral_hash_value",
            "AS55555",
            "CloudProvider Inc",
            1200,
            500000,
            vec!["credential-probing".to_string()],
            "2026-10-06T00:00:00Z",
            "2026-10-06T23:59:59Z",
        );

        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("57.141"), "leaked IP range");
        assert!(!json.contains("10.13.37"), "leaked WireGuard range");
        assert!(!json.contains("162.226"), "leaked WAN IP");
    }
}
