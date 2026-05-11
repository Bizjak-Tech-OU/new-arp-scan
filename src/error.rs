//! Application-wide error types.

/// Represents failures surfaced by the library and binary.
#[derive(Debug)]
pub enum AppError {
    /// An underlying input/output operation failed.
    Io(std::io::Error),
    /// The host operating system does not support Linux packet sockets.
    UnsupportedPlatform {
        /// Value of `std::env::consts::OS` for the current process.
        operating_system: String,
    },
    /// The interface name violates basic Linux naming rules.
    InvalidInterfaceName {
        /// Human-readable explanation for operators.
        message: String,
    },
    /// The kernel could not resolve the interface name to an interface index.
    InterfaceLookupFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Reading interface flags through `ioctl` failed.
    InterfaceFlagsQueryFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// The interface is not suitable for ARP scanning with a raw packet socket.
    InterfaceRejectedForScanning {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Human-readable reason (for example loopback, administratively down, or `NOARP`).
        reason: String,
    },
    /// Creating the raw `AF_PACKET` socket failed.
    RawSocketOpenFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Binding the raw `AF_PACKET` socket to the interface failed.
    SocketBindFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// ARP scanning is not implemented yet (socket initialization succeeded).
    ScanningNotImplemented,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Io(error) => write!(formatter, "input/output error: {error}"),
            AppError::UnsupportedPlatform { operating_system } => write!(
                formatter,
                "this command requires Linux packet sockets; host operating system is {operating_system}"
            ),
            AppError::InvalidInterfaceName { message } => {
                write!(formatter, "invalid interface name: {message}")
            }
            AppError::InterfaceLookupFailed {
                interface_name,
                source,
            } => write!(
                formatter,
                "failed to look up interface index for `{interface_name}`: {source}"
            ),
            AppError::InterfaceFlagsQueryFailed {
                interface_name,
                source,
            } => write!(
                formatter,
                "failed to read interface flags for `{interface_name}`: {source}"
            ),
            AppError::InterfaceRejectedForScanning {
                interface_name,
                reason,
            } => write!(
                formatter,
                "interface `{interface_name}` is not suitable for ARP scanning: {reason}"
            ),
            AppError::RawSocketOpenFailed { source } => {
                write!(formatter, "failed to open raw packet socket: {source}")
            }
            AppError::SocketBindFailed { source } => {
                write!(formatter, "failed to bind raw packet socket: {source}")
            }
            AppError::ScanningNotImplemented => write!(
                formatter,
                "ARP scanning is not implemented yet (socket initialization succeeded)"
            ),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(error) => Some(error),
            AppError::InterfaceLookupFailed { source, .. }
            | AppError::InterfaceFlagsQueryFailed { source, .. }
            | AppError::RawSocketOpenFailed { source }
            | AppError::SocketBindFailed { source } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        AppError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use std::error::Error as _;

    #[test]
    fn display_includes_message_for_io_error() {
        // Arrange
        let inner = std::io::Error::other("fixture message");
        let application_error = AppError::Io(inner);

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("fixture message"),
            "display should include inner message, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_io_error() {
        // Arrange
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let application_error = AppError::Io(inner);

        // Act
        let source = application_error
            .source()
            .expect("Io variant should expose io::Error as source");

        // Assert
        let source_display = source.to_string();
        assert!(
            source_display.contains("denied"),
            "source should be the inner error, got: {source_display}"
        );
    }

    #[test]
    fn display_handles_empty_io_message_without_panicking() {
        // Arrange
        let inner = std::io::Error::other("");
        let application_error = AppError::Io(inner);

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("input/output error"),
            "display should still describe the variant, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_operating_system_for_unsupported_platform() {
        // Arrange
        let application_error = AppError::UnsupportedPlatform {
            operating_system: "fixture-os".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("fixture-os"),
            "display should include operating system, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_unsupported_platform() {
        // Arrange
        let application_error = AppError::UnsupportedPlatform {
            operating_system: "fixture-os".to_string(),
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "unsupported platform should not chain a source error"
        );
    }

    #[test]
    fn display_includes_message_for_invalid_interface_name() {
        // Arrange
        let application_error = AppError::InvalidInterfaceName {
            message: "too long".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("too long"),
            "display should include message, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_lookup_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceLookupFailed {
            interface_name: "missing0".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("missing0"),
            "display should include interface name, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_lookup_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceLookupFailed {
            interface_name: "missing0".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("lookup failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_flags_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(22);
        let application_error = AppError::InterfaceFlagsQueryFailed {
            interface_name: "eth0".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("eth0"),
            "display should include interface name, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_flags_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(22);
        let application_error = AppError::InterfaceFlagsQueryFailed {
            interface_name: "eth0".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("flags query failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_reason_for_interface_rejected_for_scanning() {
        // Arrange
        let application_error = AppError::InterfaceRejectedForScanning {
            interface_name: "lo".to_string(),
            reason: "loopback interface".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("loopback"),
            "display should include reason, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_interface_rejected_for_scanning() {
        // Arrange
        let application_error = AppError::InterfaceRejectedForScanning {
            interface_name: "lo".to_string(),
            reason: "loopback interface".to_string(),
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "interface rejection should not chain a source error"
        );
    }

    #[test]
    fn display_includes_context_for_raw_socket_open_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(1);
        let application_error = AppError::RawSocketOpenFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("raw packet socket"),
            "display should describe failure, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_raw_socket_open_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(1);
        let application_error = AppError::RawSocketOpenFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("raw socket failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_context_for_socket_bind_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(99);
        let application_error = AppError::SocketBindFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("bind"),
            "display should describe bind failure, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_socket_bind_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(99);
        let application_error = AppError::SocketBindFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("bind failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_mentions_scanning_not_implemented() {
        // Arrange
        let application_error = AppError::ScanningNotImplemented;

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("not implemented"),
            "display should mention missing implementation, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_scanning_not_implemented() {
        // Arrange
        let application_error = AppError::ScanningNotImplemented;

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "scanning not implemented should not chain a source error"
        );
    }
}
