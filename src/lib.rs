//! Library entry points for the new ARP scan tool.

pub mod application_command;
pub mod cli;
pub mod error;

mod interface_validation;

#[cfg(target_os = "linux")]
mod linux_packet;
#[cfg(target_os = "linux")]
mod linux_socket;

pub use application_command::ApplicationCommand;
pub use error::AppError;

/// Runs the application logic for a parsed [`ApplicationCommand`].
///
/// Today this wires up Linux `AF_PACKET` socket initialization for [`ApplicationCommand::Scan`]
/// and then returns [`AppError::ScanningNotImplemented`] after the socket is successfully bound.
///
/// # Errors
///
/// Returns [`AppError`] for invalid input, unsupported platforms, interface validation failures,
/// socket failures, and the intentional [`AppError::ScanningNotImplemented`] placeholder.
///
/// # Examples
///
/// ```
/// use new_arp_scan::{run, ApplicationCommand, AppError};
///
/// let outcome = run(ApplicationCommand::Scan {
///     interface_name: "eth0".to_string(),
/// });
///
/// assert!(
///     matches!(
///         outcome,
///         Err(AppError::UnsupportedPlatform { .. })
///             | Err(AppError::InvalidInterfaceName { .. })
///             | Err(AppError::InterfaceLookupFailed { .. })
///             | Err(AppError::InterfaceFlagsQueryFailed { .. })
///             | Err(AppError::InterfaceRejectedForScanning { .. })
///             | Err(AppError::RawSocketOpenFailed { .. })
///             | Err(AppError::SocketBindFailed { .. })
///             | Err(AppError::ScanningNotImplemented)
///     ),
///     "expected a deterministic scan outcome, got: {outcome:?}"
/// );
/// ```
pub fn run(command: ApplicationCommand) -> Result<(), AppError> {
    match command {
        ApplicationCommand::Scan { interface_name } => {
            interface_validation::validate_interface_name_for_linux_packet_socket(&interface_name)?;

            #[cfg(target_os = "linux")]
            {
                linux_socket::initialize_raw_arp_socket_for_scanning(&interface_name)?;
                Err(AppError::ScanningNotImplemented)
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
}
