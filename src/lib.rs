//! Library entry points for the new ARP scan tool.

pub mod application_command;
pub mod application_outcome;
pub mod cli;
pub mod error;
pub mod mac_address;

#[cfg(target_os = "linux")]
mod ethernet_frame;
mod interface_validation;
#[cfg(target_os = "linux")]
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

pub use application_command::ApplicationCommand;
pub use application_outcome::ApplicationOutcome;
pub use error::AppError;
pub use mac_address::{MacAddress, MacAddressParseError};

/// Runs the application logic for a parsed [`ApplicationCommand`].
///
/// On Linux, [`ApplicationCommand::Scan`] performs address resolution scanning on the selected
/// interface and returns discovered hosts. On other operating systems, scanning is not supported.
///
/// # Errors
///
/// Returns [`AppError`] for invalid input, unsupported platforms, interface validation failures,
/// discovery failures, socket failures, and fatal receive or poll failures.
///
/// # Examples
///
/// ```
/// use new_arp_scan::{run, ApplicationCommand, AppError, ApplicationOutcome};
///
/// let outcome = run(ApplicationCommand::Scan {
///     interface_name: "eth0".to_string(),
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
        ApplicationCommand::Scan { interface_name } => {
            interface_validation::validate_interface_name_for_linux_packet_socket(&interface_name)?;

            #[cfg(target_os = "linux")]
            {
                let scan_outcome = linux_scanner::perform_arp_scan(&interface_name)?;
                Ok(ApplicationOutcome::Scan(scan_outcome))
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
    use super::run;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_invalid_interface_name_when_interface_name_is_empty_on_non_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: String::new(),
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
            interface_name: "eth0".to_string(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "non-linux hosts should report unsupported platform, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_interface_on_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: "lo".to_string(),
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
}
