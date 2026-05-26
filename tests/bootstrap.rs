//! Integration smoke tests for repository bootstrap.

use new_arp_scan::{
    AppError, ApplicationCommand, ApplicationOutcome, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING,
    DEFAULT_SCAN_TIMEOUT, run,
};

#[cfg(not(target_os = "linux"))]
#[test]
fn run_scan_returns_unsupported_platform_on_non_linux() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: Some("eth0".to_string()),
        target_ipv4_address: None,
        timeout: DEFAULT_SCAN_TIMEOUT,
        pacing: DEFAULT_SCAN_PACING,
        attempts: DEFAULT_SCAN_ATTEMPTS,
    };

    // Act
    let outcome = run(command);

    // Assert
    assert!(
        matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
        "public scan API should report unsupported platform on non-linux, got: {outcome:?}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn run_usable_interfaces_list_returns_unsupported_platform_on_non_linux() {
    // Arrange
    let command = ApplicationCommand::UsableInterfacesList;

    // Act
    let outcome = run(command);

    // Assert
    assert!(
        matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
        "public interfaces list API should report unsupported platform on non-linux, got: {outcome:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn run_usable_interfaces_list_returns_outcome_on_linux() {
    // Arrange
    let command = ApplicationCommand::UsableInterfacesList;

    // Act
    let outcome = run(command);

    // Assert
    let outcome = outcome.expect("usable interfaces listing should succeed on Linux");
    match outcome {
        ApplicationOutcome::UsableInterfacesList(listing) => {
            let table = listing.format_plain_columns_table();
            assert!(
                table.contains("no usable interfaces found")
                    || (table.contains("NAME") && table.contains("INDEX")),
                "public listing should print either the empty-operator message or a header row, got:\n{table}"
            );
        }
        ApplicationOutcome::Scan(_) => {
            panic!("expected usable interfaces list outcome, got scan outcome");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn run_scan_rejects_loopback_interface_on_linux() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: Some("lo".to_string()),
        target_ipv4_address: None,
        timeout: DEFAULT_SCAN_TIMEOUT,
        pacing: DEFAULT_SCAN_PACING,
        attempts: DEFAULT_SCAN_ATTEMPTS,
    };

    // Act
    let outcome = run(command);

    // Assert
    assert!(
        matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
        "public scan API should reject loopback before raw socket, got: {outcome:?}"
    );
}
