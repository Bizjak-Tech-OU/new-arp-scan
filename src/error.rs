//! Application-wide error types.

/// Represents failures surfaced by the library and binary.
#[derive(Debug)]
pub enum AppError {
    /// An underlying input/output operation failed.
    Io(std::io::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Io(error) => write!(formatter, "input/output error: {error}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(error) => Some(error),
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
}
