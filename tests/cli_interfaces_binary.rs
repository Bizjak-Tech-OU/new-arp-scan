//! Integration tests for the `interfaces` subcommand (binary subprocess).

use std::path::PathBuf;

fn new_arp_scan_binary_path() -> PathBuf {
    for environment_key in ["CARGO_BIN_EXE_new_arp_scan", "CARGO_BIN_EXE_new-arp-scan"] {
        if let Some(path) = std::env::var_os(environment_key) {
            return PathBuf::from(path);
        }
    }

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(profile);
    path.push(if cfg!(target_os = "windows") {
        "new-arp-scan.exe"
    } else {
        "new-arp-scan"
    });
    path
}

#[test]
fn binary_interfaces_exits_successfully() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["interfaces"])
        .output()
        .expect("spawning interfaces subcommand should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "interfaces should exit successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn binary_interfaces_help_exits_successfully() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["interfaces", "--help"])
        .output()
        .expect("spawning interfaces --help should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "interfaces --help should exit successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("interfaces") || stdout.contains("Interfaces"),
        "interfaces help should describe the subcommand, got: {stdout}"
    );
}
