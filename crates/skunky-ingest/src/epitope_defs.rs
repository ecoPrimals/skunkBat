// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Shared conserved epitope definitions (Wave 166f).
//!
//! Six population-level behavioral invariants that identify scraping fleets.
//! Each epitope costs more to evade than the last — the terminal epitope
//! (reading pauses) would reduce throughput to human levels.

// ── Epitope identifiers ──

pub(crate) const SEC_FETCH_MONOTONE: &str = "sec_fetch_monotone";
pub(crate) const READING_DEFICIT: &str = "reading_deficit";
pub(crate) const UA_POOL_POVERTY: &str = "ua_pool_poverty";
pub(crate) const SESSION_ABSENT: &str = "session_absent";
pub(crate) const REFERER_SELF_LOOP: &str = "referer_self_loop";
pub(crate) const BURST_RATIO: &str = "burst_ratio";

/// All six conserved epitopes in detection-priority order.
pub(crate) const EPITOPE_NAMES: &[&str] = &[
    SEC_FETCH_MONOTONE,
    READING_DEFICIT,
    UA_POOL_POVERTY,
    SESSION_ABSENT,
    REFERER_SELF_LOOP,
    BURST_RATIO,
];

// ── Detection thresholds (entity_classifier) ──

/// Same Sec-Fetch triplet on >95% of requests triggers monotone epitope.
pub(crate) const SEC_FETCH_MONOTONE_THRESHOLD: f64 = 95.0;

/// Reading pauses: intervals longer than this count as "reading".
pub(crate) const READING_PAUSE_SECONDS: f64 = 8.0;

/// <10% of intervals with reading pauses triggers reading_deficit.
pub(crate) const READING_DEFICIT_THRESHOLD: f64 = 10.0;

/// UA pool must be at least max(10, total * 0.05) to avoid ua_pool_poverty.
pub(crate) const UA_POOL_MIN_ABSOLUTE: usize = 10;
pub(crate) const UA_POOL_MIN_RATIO: f64 = 0.05;

/// Cookies on <5% of requests triggers session_absent.
pub(crate) const SESSION_ABSENT_THRESHOLD: f64 = 5.0;

/// External referers on <2% of requests triggers referer_self_loop.
pub(crate) const REFERER_SELF_LOOP_THRESHOLD: f64 = 2.0;

/// Intervals shorter than this count as bursts.
pub(crate) const BURST_INTERVAL_SECONDS: f64 = 3.0;

/// >50% of intervals under burst threshold triggers burst_ratio.
pub(crate) const BURST_RATIO_THRESHOLD: f64 = 50.0;

// ── Minimum sample sizes for epitope evaluation ──

pub(crate) const MIN_REQUESTS_SEC_FETCH: u64 = 10;
pub(crate) const MIN_INTERVALS: usize = 10;
pub(crate) const MIN_REQUESTS_UA_POOL: u64 = 50;
pub(crate) const MIN_REQUESTS_SESSION: u64 = 20;
pub(crate) const MIN_REQUESTS_REFERER: u64 = 20;
