//! Application commands accepted by [`crate::run`].

use std::time::Duration;

/// Default global receive window after the last address resolution request is sent.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(3);

/// Default delay between sequential target sends (no pacing).
pub const DEFAULT_SCAN_PACING: Duration = Duration::ZERO;

/// A command dispatched from the binary after command-line parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationCommand {
    /// Scan the given data-link interface’s local IPv4 subnet using address resolution protocol.
    Scan {
        /// Operating system name of the network interface (for example `eth0`), or [`None`] to
        /// select automatically when exactly one usable interface exists.
        interface_name: Option<String>,
        /// Global receive window after the final request transmission.
        timeout: Duration,
        /// Delay after each target send except the last.
        pacing: Duration,
    },
    /// List interfaces that are usable for ARP scanning on Linux.
    UsableInterfacesList,
}

#[cfg(test)]
mod tests {
    use super::{ApplicationCommand, DEFAULT_SCAN_PACING, DEFAULT_SCAN_TIMEOUT};
    use std::time::Duration;

    #[test]
    fn default_scan_timeout_matches_three_seconds() {
        // Arrange
        // Act
        let timeout = DEFAULT_SCAN_TIMEOUT;

        // Assert
        assert_eq!(
            timeout,
            Duration::from_secs(3),
            "default scan timeout should match historical three-second receive window"
        );
    }

    #[test]
    fn default_scan_pacing_is_zero() {
        // Arrange
        // Act
        let pacing = DEFAULT_SCAN_PACING;

        // Assert
        assert_eq!(
            pacing,
            Duration::ZERO,
            "default scan pacing should impose no delay between sends"
        );
    }

    #[test]
    fn scan_command_variants_compare_equal_when_fields_match() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: Duration::from_millis(500),
            pacing: Duration::from_millis(1),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: Duration::from_millis(500),
            pacing: Duration::from_millis(1),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            equal,
            "scan commands with identical fields should compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_timeout_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: Duration::from_secs(1),
            pacing: Duration::ZERO,
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: Duration::from_secs(2),
            pacing: Duration::ZERO,
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different timeout values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_pacing_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: Duration::from_millis(1),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: Duration::from_millis(2),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different pacing values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_interface_name_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth1".to_string()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different interface names must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_explicit_interface_differs_from_automatic_none() {
        // Arrange
        let automatic = ApplicationCommand::Scan {
            interface_name: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
        };
        let explicit = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
        };

        // Act
        let equal = automatic == explicit;

        // Assert
        assert!(
            !equal,
            "automatic versus explicit interface selection should not compare equal"
        );
    }
}
