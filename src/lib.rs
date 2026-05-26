//! Library entry points for the new ARP scan tool.

pub mod application_command;
pub mod application_outcome;
pub mod cli;
pub mod error;
pub mod mac_address;

#[cfg(target_os = "linux")]
mod ethernet_frame;
mod interface_validation;
mod ipv4_cidr;
mod ipv4_subnet;

#[cfg(target_os = "linux")]
mod address_resolution_protocol;
#[cfg(target_os = "linux")]
mod linux_interface_discovery;
#[cfg(target_os = "linux")]
mod linux_packet;
#[cfg(target_os = "linux")]
mod linux_scanner;
#[cfg(target_os = "linux")]
mod linux_socket;
#[cfg(target_os = "linux")]
mod linux_system_call;

pub use application_command::{
    ApplicationCommand, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING, DEFAULT_SCAN_TIMEOUT,
};
pub use application_outcome::ApplicationOutcome;
pub use application_outcome::DiscoveredHost;
pub use application_outcome::ScanOutcome;
pub use application_outcome::ScanTimingSummary;
pub use application_outcome::UsableInterfaceListingRow;
pub use application_outcome::UsableInterfacesListOutcome;
pub use error::AppError;
pub use ipv4_cidr::Ipv4Cidr;
pub use ipv4_cidr::Ipv4HostAddressIterator;
pub use mac_address::{MacAddress, MacAddressParseError};

#[cfg(target_os = "linux")]
pub use linux_scanner::perform_arp_probe;

/// Runs the application logic for a parsed [`ApplicationCommand`].
///
/// On Linux, [`ApplicationCommand::Scan`] performs address resolution scanning on the resolved
/// interface and returns discovered hosts. When `target_ipv4_address` is [`None`], the library
/// scans the full interior host set for that interface subnet. When it is [`Some`], the library
/// sends requests only for that address (which must be strictly interior on the subnet) and
/// records replies only from that sender IPv4. The `timeout` field bounds the global receive
/// window after the last request is sent; the `pacing` field sleeps after each full round of target
/// sends except the last round; the `attempts` field is how many such rounds run. When the scan
/// command omits an interface name, the library selects an interface automatically only when
/// exactly one usable interface exists. On Linux, successful scans populate
/// [`application_outcome::ScanOutcome::timing_summary`] with wall-clock timing, the resolved
/// interface name, round count, and discovered host count for operator-facing summaries.
///
/// On Linux, [`ApplicationCommand::UsableInterfacesList`] returns interfaces that pass the same
/// usability rules as automatic scan selection.
///
/// On other operating systems, Linux-only commands return [`AppError::UnsupportedPlatform`].
///
/// # Errors
///
/// Returns [`AppError`] for invalid input, unsupported platforms, interface validation failures,
/// discovery failures, socket failures, and fatal receive or poll failures.
///
/// # Examples
///
/// ```
/// use new_arp_scan::{
///     run, ApplicationCommand, AppError, ApplicationOutcome, DEFAULT_SCAN_ATTEMPTS,
///     DEFAULT_SCAN_PACING, DEFAULT_SCAN_TIMEOUT,
/// };
///
/// let outcome = run(ApplicationCommand::Scan {
///     interface_name: Some("eth0".to_string()),
///     target_ipv4_address: None,
///     timeout: DEFAULT_SCAN_TIMEOUT,
///     pacing: DEFAULT_SCAN_PACING,
///     attempts: DEFAULT_SCAN_ATTEMPTS,
/// });
///
/// # #[cfg(not(target_os = "linux"))]
/// assert!(
///     matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
///     "expected unsupported platform off Linux, got: {outcome:?}"
/// );
/// # #[cfg(target_os = "linux")]
/// # {
/// #     let _ = outcome;
/// # }
/// ```
pub fn run(command: ApplicationCommand) -> Result<ApplicationOutcome, AppError> {
    match command {
        ApplicationCommand::Scan {
            interface_name,
            target_ipv4_address,
            timeout,
            pacing,
            attempts,
        } => {
            if let Some(interface_name) = interface_name.as_deref() {
                interface_validation::validate_interface_name_for_linux_packet_socket(
                    interface_name,
                )?;
            }

            #[cfg(target_os = "linux")]
            {
                let resolved_interface_name =
                    linux_interface_discovery::resolve_scan_interface_name(
                        interface_name.as_deref(),
                    )?;
                let scan_wall_clock_started = std::time::Instant::now();
                let scan_outcome = match target_ipv4_address {
                    Some(target_ipv4_address) => linux_scanner::perform_arp_probe(
                        &resolved_interface_name,
                        target_ipv4_address,
                        timeout,
                        pacing,
                        attempts,
                    )?,
                    None => linux_scanner::perform_arp_scan(
                        &resolved_interface_name,
                        timeout,
                        pacing,
                        attempts,
                    )?,
                };
                let scan_outcome = scan_outcome.with_scan_timing_summary(
                    resolved_interface_name,
                    scan_wall_clock_started.elapsed(),
                    attempts,
                );
                Ok(ApplicationOutcome::Scan(scan_outcome))
            }

            #[cfg(not(target_os = "linux"))]
            {
                Err(AppError::UnsupportedPlatform {
                    operating_system: std::env::consts::OS.to_string(),
                })
            }
        }
        ApplicationCommand::UsableInterfacesList => {
            #[cfg(target_os = "linux")]
            {
                let candidates =
                    linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates()?;
                let entries = candidates
                    .into_iter()
                    .map(|candidate| application_outcome::UsableInterfaceListingRow {
                        interface_name: candidate.interface_name,
                        interface_index: candidate.interface_index,
                        ipv4_address: candidate.source_ipv4_address,
                        ipv4_netmask: candidate.ipv4_netmask,
                        media_access_control_address: candidate.source_mac_address,
                    })
                    .collect();

                Ok(ApplicationOutcome::UsableInterfacesList(
                    application_outcome::UsableInterfacesListOutcome { entries },
                ))
            }

            #[cfg(not(target_os = "linux"))]
            {
                Err(AppError::UnsupportedPlatform {
                    operating_system: std::env::consts::OS.to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use super::ApplicationCommand;
    use super::DEFAULT_SCAN_ATTEMPTS;
    use super::DEFAULT_SCAN_PACING;
    use super::DEFAULT_SCAN_TIMEOUT;
    use super::run;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_invalid_interface_name_when_interface_name_is_empty_on_non_linux_even_with_target() {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some(String::new()),
            target_ipv4_address: Some(Ipv4Addr::new(1, 1, 1, 1)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty interface name should be rejected before platform checks even with a target, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_invalid_interface_name_when_interface_name_is_empty_on_non_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some(String::new()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty interface name should be rejected before platform checks, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_unsupported_platform_when_scanning_on_non_linux() {
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
            "non-linux hosts should report unsupported platform, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_unsupported_platform_when_scanning_on_non_linux_even_with_custom_scan_timing() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: std::time::Duration::from_secs(60),
            pacing: std::time::Duration::from_millis(999),
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "custom scan timing must not bypass unsupported platform handling, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_unsupported_platform_when_scanning_on_non_linux_with_target_ipv4_address_set() {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(9, 9, 9, 9)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "non-linux hosts should reject scan before Linux-only probe dispatch, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_unsupported_platform_when_listing_interfaces_on_non_linux() {
        // Arrange
        let command = ApplicationCommand::UsableInterfacesList;

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "non-linux hosts should report unsupported platform, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_unsupported_platform_when_scanning_without_interface_name_on_non_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: None,
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
            "automatic selection should still hit unsupported platform off Linux, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_interface_on_linux() {
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
            "loopback should be rejected before opening a raw socket, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_on_linux_even_with_non_default_scan_timing() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: None,
            timeout: std::time::Duration::from_millis(1),
            pacing: std::time::Duration::from_millis(5),
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "custom scan timing must not bypass loopback rejection, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_on_linux_even_with_high_attempt_count() {
        // Arrange
        use std::num::NonZeroU64;

        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: NonZeroU64::new(99).expect("ninety-nine is non-zero"),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "high attempt count must not bypass loopback rejection, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scan_outcome_struct_round_trips_for_documentation() {
        // Arrange
        use super::ApplicationOutcome;
        use std::net::Ipv4Addr;

        let host = super::application_outcome::DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
            media_access_control_address: super::MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
        };
        let scan = super::application_outcome::ScanOutcome {
            discovered_hosts: vec![host],
            warnings: vec!["fixture warning".to_string()],
            timing_summary: None,
        };

        // Act
        let outcome = ApplicationOutcome::Scan(scan.clone());

        // Assert
        assert_eq!(
            outcome,
            ApplicationOutcome::Scan(scan),
            "scan outcome should round-trip for equality"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_scan_without_interface_name_follows_usable_candidate_count() {
        // Arrange
        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidate_count = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts")
            .len();

        let command = ApplicationCommand::Scan {
            interface_name: None,
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        match candidate_count {
            0 => assert!(
                matches!(outcome, Err(AppError::AutomaticInterfaceSelectionNoneFound)),
                "zero usable interfaces should make automatic selection fail deterministically, got: {outcome:?}"
            ),
            1 => assert!(
                !matches!(
                    &outcome,
                    Err(AppError::AutomaticInterfaceSelectionNoneFound
                        | AppError::AutomaticInterfaceSelectionAmbiguous { .. })
                ),
                "exactly one usable interface must pass automatic selection (scan may still fail for capabilities or I/O), got: {outcome:?}"
            ),
            _ => assert!(
                matches!(
                    outcome,
                    Err(AppError::AutomaticInterfaceSelectionAmbiguous { .. })
                ),
                "multiple usable interfaces should make automatic selection ambiguous, got: {outcome:?}"
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_invalid_interface_name_when_scan_interface_name_is_empty_on_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some(String::new()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty interface name should be rejected before raw socket setup, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_on_linux_even_with_single_target_ipv4_address_set()
    {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: Some(Ipv4Addr::LOCALHOST),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback should be rejected before single-target validation, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_single_scan_target_rejected_when_probe_target_is_subnet_network_on_linux() {
        // Arrange
        use std::net::Ipv4Addr;

        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidates = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts");
        let Some(first) = candidates.first() else {
            // No Ethernet+IPv4 usable interfaces in this environment (for example CI without a
            // configured LAN): nothing to exercise against a real interface name.
            return;
        };
        let mask_bits = first.ipv4_netmask.to_bits();
        let network_ipv4_address =
            Ipv4Addr::from_bits(first.source_ipv4_address.to_bits() & mask_bits);
        let command = ApplicationCommand::Scan {
            interface_name: Some(first.interface_name.clone()),
            target_ipv4_address: Some(network_ipv4_address),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::SingleScanTargetRejected { .. })),
            "network address as single target should be rejected before socket, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_single_scan_target_rejected_when_probe_target_is_subnet_broadcast_on_linux() {
        // Arrange
        use std::net::Ipv4Addr;

        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidates = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts");
        let Some(first) = candidates.first() else {
            // No usable interfaces in this environment: see network-address probe test.
            return;
        };
        let mask_bits = first.ipv4_netmask.to_bits();
        let network_bits = first.source_ipv4_address.to_bits() & mask_bits;
        let broadcast_ipv4_address = Ipv4Addr::from_bits(network_bits | !mask_bits);
        let command = ApplicationCommand::Scan {
            interface_name: Some(first.interface_name.clone()),
            target_ipv4_address: Some(broadcast_ipv4_address),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::SingleScanTargetRejected { .. })),
            "broadcast address as single target should be rejected before socket, got: {outcome:?}"
        );
    }
}
