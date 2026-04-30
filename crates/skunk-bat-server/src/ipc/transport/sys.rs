// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Platform-specific helpers — delegates to `skunk_bat_core::platform`.

pub fn proc_uid() -> u32 {
    skunk_bat_core::platform::proc_uid()
}
