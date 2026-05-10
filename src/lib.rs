//! Library entry points for the new ARP scan tool.

pub mod error;

pub use error::AppError;

/// Runs the application logic.
///
/// This entry point is reserved for future ARP scanning behaviour. At bootstrap it
/// completes successfully without performing network operations.
///
/// # Errors
///
/// Returns [`AppError`] when a recoverable application error occurs. The bootstrap
/// implementation does not currently produce errors.
///
/// # Examples
///
/// ```
/// use new_arp_scan::run;
///
/// let outcome = run();
/// assert!(matches!(outcome, Ok(())));
/// ```
pub fn run() -> Result<(), AppError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn returns_ok_when_invoked() {
        // Arrange
        // Act
        let outcome = run();

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "bootstrap run should succeed, got: {outcome:?}"
        );
    }

    #[test]
    fn succeeds_when_invoked_repeatedly() {
        // Arrange
        // Act
        let first_outcome = run();
        let second_outcome = run();

        // Assert
        assert!(
            matches!(first_outcome, Ok(())),
            "first invocation should succeed, got: {first_outcome:?}"
        );
        assert!(
            matches!(second_outcome, Ok(())),
            "second invocation should succeed, got: {second_outcome:?}"
        );
    }
}
