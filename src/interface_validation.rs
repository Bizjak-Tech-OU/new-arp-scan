//! Validates Linux network interface names before issuing syscalls.

use crate::error::AppError;

/// Matches Linux `IFNAMSIZ` from `linux/if.h`.
pub const INTERFACE_NAME_BUFFER_SIZE: usize = 16;

/// Maximum number of non-null bytes in an interface name (excluding the terminator).
pub const INTERFACE_NAME_MAXIMUM_BYTES: usize = INTERFACE_NAME_BUFFER_SIZE - 1;

/// Returns [`AppError::InvalidInterfaceName`] when `interface_name` cannot be used with Linux
/// packet socket APIs.
///
/// # Errors
///
/// Returns [`AppError::InvalidInterfaceName`] when the name is empty, too long, contains a
/// slash, or contains an interior NUL byte.
pub fn validate_interface_name_for_linux_packet_socket(
    interface_name: &str,
) -> Result<(), AppError> {
    if interface_name.is_empty() {
        return Err(AppError::InvalidInterfaceName {
            message: "interface name must not be empty".to_string(),
        });
    }

    if interface_name.len() > INTERFACE_NAME_MAXIMUM_BYTES {
        return Err(AppError::InvalidInterfaceName {
            message: format!(
                "interface name must be at most {INTERFACE_NAME_MAXIMUM_BYTES} bytes, got {}",
                interface_name.len()
            ),
        });
    }

    if interface_name.contains('/') {
        return Err(AppError::InvalidInterfaceName {
            message: "interface name must not contain '/'".to_string(),
        });
    }

    if interface_name.as_bytes().contains(&0) {
        return Err(AppError::InvalidInterfaceName {
            message: "interface name must not contain a NUL byte".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::INTERFACE_NAME_MAXIMUM_BYTES;
    use super::validate_interface_name_for_linux_packet_socket;
    use crate::error::AppError;

    #[test]
    fn returns_error_when_interface_name_is_empty() {
        // Arrange
        let interface_name = "";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty name should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_name_exceeds_maximum_length() {
        // Arrange
        let interface_name = "a".repeat(INTERFACE_NAME_MAXIMUM_BYTES + 1);

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(&interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "oversized name should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_name_contains_slash() {
        // Arrange
        let interface_name = "eth0/1";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "slash should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_name_contains_nul_byte() {
        // Arrange
        let interface_name = "eth\0";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "NUL should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn accepts_valid_interface_name() {
        // Arrange
        let interface_name = "eth0";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "valid interface name should be accepted, got: {outcome:?}"
        );
    }

    #[test]
    fn accepts_interface_name_at_maximum_byte_length() {
        // Arrange
        let interface_name = "a".repeat(INTERFACE_NAME_MAXIMUM_BYTES);

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(&interface_name);

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "IFNAMSIZ-1 byte names are valid on Linux, got: {outcome:?}"
        );
    }
}
