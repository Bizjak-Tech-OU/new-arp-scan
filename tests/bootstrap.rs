//! Integration smoke tests for repository bootstrap.

use new_arp_scan::{AppError, ApplicationCommand, run};

#[cfg(not(target_os = "linux"))]
#[test]
fn run_scan_returns_unsupported_platform_on_non_linux() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: "eth0".to_string(),
    };

    // Act
    let outcome = run(command);

    // Assert
    assert!(
        matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
        "public scan API should report unsupported platform on non-linux, got: {outcome:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn run_scan_rejects_loopback_interface_on_linux() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: "lo".to_string(),
    };

    // Act
    let outcome = run(command);

    // Assert
    assert!(
        matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
        "public scan API should reject loopback before raw socket, got: {outcome:?}"
    );
}
