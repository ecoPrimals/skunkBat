// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

/// riboCipher clear-text JSON-RPC signal prefix.
/// Canonical source: swarmvine-core/src/ribocipher.rs
///
/// The hex representation is the epitope sort that makes protocol taxonomy
/// visible (Paper 48 §6.4): upper nybble 0xE = transport genus,
/// lower nybble C/D/E = tier species (Beacon/Mito/Genetic).
pub(crate) const CLEAR_JSONRPC: [u8; 2] = [0xEC, 0x01];
