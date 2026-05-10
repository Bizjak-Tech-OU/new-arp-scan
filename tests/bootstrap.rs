//! Integration smoke tests for repository bootstrap.

#[test]
fn run_returns_ok_in_integration_smoke_test() {
    // Arrange
    // Act
    let outcome = new_arp_scan::run();

    // Assert
    assert!(
        matches!(outcome, Ok(())),
        "public run API should succeed at bootstrap, got: {outcome:?}"
    );
}
