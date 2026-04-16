// SPDX-License-Identifier: AGPL-3.0-or-later

//! Binary integration tests for the skunkBat `UniBin`.
//!
//! Uses `assert_cmd` to exercise the CLI subcommands and validate
//! `UniBin` compliance: `--help`, `--version`, `health`, `scan`, `detect`.

use assert_cmd::Command;

fn skunkbat() -> Command {
    Command::cargo_bin("skunkbat").expect("binary exists")
}

#[test]
fn help_exits_zero() {
    skunkbat().arg("--help").assert().success();
}

#[test]
fn version_exits_zero() {
    skunkbat().arg("--version").assert().success();
}

#[test]
fn health_subcommand() {
    skunkbat()
        .arg("health")
        .assert()
        .success()
        .stdout(predicates::str::contains("status"));
}

#[test]
fn scan_subcommand() {
    skunkbat()
        .arg("scan")
        .assert()
        .success()
        .stdout(predicates::str::contains("nodes"));
}

#[test]
fn detect_subcommand() {
    skunkbat().arg("detect").assert().success();
}

#[test]
fn no_subcommand_shows_help() {
    skunkbat()
        .assert()
        .failure()
        .stderr(predicates::str::contains("Usage"));
}

#[test]
fn unknown_subcommand_fails() {
    skunkbat()
        .arg("bogus")
        .assert()
        .failure()
        .stderr(predicates::str::contains("error"));
}
