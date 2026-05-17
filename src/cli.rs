//! Command-line interface definitions for the `new-arp-scan` binary.

use clap::{Args, Parser, Subcommand};

/// Help footer examples appended to `--help` output.
const EXAMPLES: &str = "\
EXAMPLES:
  List interfaces usable for ARP scanning on Linux:
    new-arp-scan interfaces

  Scan the local IPv4 subnet on Linux (requires CAP_NET_RAW or equivalent):
    new-arp-scan scan --interface eth0

  Scan using automatic interface selection when exactly one usable interface exists:
    new-arp-scan scan

  Scan with a custom receive window and pacing between sends (milliseconds):
    new-arp-scan scan --interface eth0 --timeout-ms 5000 --pacing-ms 10
";

/// Root command-line interface for `new-arp-scan`.
#[derive(Debug, Parser)]
#[command(
    name = "new-arp-scan",
    version,
    about = "Inspect local networks using ARP scanning (under active development).",
    after_help = EXAMPLES
)]
pub struct CliRoot {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub subcommand: Option<CliSubcommand>,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum CliSubcommand {
    /// Scan the interface's local IPv4 subnet using address resolution protocol requests.
    Scan(ScanArguments),
    /// List interfaces that are usable for ARP scanning on Linux.
    Interfaces,
}

/// Arguments for [`CliSubcommand::Scan`].
#[derive(Debug, Args)]
pub struct ScanArguments {
    /// Network interface name (for example `eth0`). When omitted, a single usable interface must
    /// exist or automatic selection fails.
    #[arg(long = "interface", value_name = "NAME", visible_alias = "iface")]
    pub interface_name: Option<String>,
    /// Milliseconds to wait for address resolution replies after the last request is sent.
    #[arg(
        long = "timeout-ms",
        value_name = "MILLISECONDS",
        default_value_t = 3000
    )]
    pub timeout_milliseconds: u64,
    /// Milliseconds to sleep after each target send except the last.
    #[arg(long = "pacing-ms", value_name = "MILLISECONDS", default_value_t = 0)]
    pub pacing_milliseconds: u64,
}

#[cfg(test)]
mod tests {
    use super::CliRoot;
    use clap::CommandFactory;
    use clap::Parser;

    #[test]
    fn parses_scan_subcommand_with_interface_name() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.interface_name.as_deref(),
                    Some("eth0"),
                    "interface name should match flag value"
                );
                assert_eq!(
                    scan.timeout_milliseconds, 3000,
                    "omitted timeout should use default milliseconds"
                );
                assert_eq!(
                    scan.pacing_milliseconds, 0,
                    "omitted pacing should use default milliseconds"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_iface_visible_alias() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--iface", "enp0s1"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.interface_name.as_deref(),
                    Some("enp0s1"),
                    "visible alias --iface should populate interface name"
                );
                assert_eq!(
                    scan.timeout_milliseconds, 3000,
                    "omitted timeout should use default milliseconds"
                );
                assert_eq!(
                    scan.pacing_milliseconds, 0,
                    "omitted pacing should use default milliseconds"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_without_interface_name() {
        // Arrange
        let arguments = ["new-arp-scan", "scan"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.interface_name, None,
                    "omitted interface flag should yield None"
                );
                assert_eq!(
                    scan.timeout_milliseconds, 3000,
                    "omitted timeout should use default milliseconds"
                );
                assert_eq!(
                    scan.pacing_milliseconds, 0,
                    "omitted pacing should use default milliseconds"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_interfaces_subcommand() {
        // Arrange
        let arguments = ["new-arp-scan", "interfaces"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        assert!(
            matches!(subcommand, super::CliSubcommand::Interfaces),
            "expected interfaces subcommand, got: {subcommand:?}"
        );
    }

    #[test]
    fn returns_error_for_unknown_subcommand() {
        // Arrange
        let arguments = ["new-arp-scan", "unknown"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "unknown subcommand should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_unknown_flag() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--not-a-defined-flag"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "undefined scan flags should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_explicit_timeout_milliseconds_and_pacing_milliseconds() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--timeout-ms",
            "5000",
            "--pacing-ms",
            "12",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.timeout_milliseconds, 5000,
                    "explicit timeout should parse"
                );
                assert_eq!(scan.pacing_milliseconds, 12, "explicit pacing should parse");
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_non_numeric_timeout_milliseconds() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--timeout-ms", "not-a-number"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "non-numeric timeout should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_negative_timeout_milliseconds_token() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--timeout-ms", "-1"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "negative timeout token should fail parsing for unsigned field, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_negative_pacing_milliseconds_token() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--pacing-ms", "-1"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "negative pacing token should fail parsing for unsigned field, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interfaces_subcommand_receives_trailing_token() {
        // Arrange
        let arguments = ["new-arp-scan", "interfaces", "extra"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "interfaces subcommand should not accept stray positional arguments, got: {outcome:?}"
        );
    }

    #[test]
    fn help_command_factory_builds_without_panicking() {
        // Arrange
        // Act
        let mut command = CliRoot::command();

        // Assert
        let help = command.render_help().to_string();
        assert!(
            help.contains("scan") && help.contains("interfaces"),
            "help should mention scan and interfaces subcommands, got: {help}"
        );
    }

    #[test]
    fn rendered_help_includes_examples_footer() {
        // Arrange
        let mut command = CliRoot::command();

        // Act
        let help = command.render_help().to_string();

        // Assert
        assert!(
            help.contains("EXAMPLES:") && help.contains("new-arp-scan scan"),
            "after_help should surface operator examples, got: {help}"
        );
    }

    #[test]
    fn renders_scan_subcommand_long_help_including_timing_flags_and_defaults() {
        // Arrange
        let mut root_command = CliRoot::command();
        let scan_command = root_command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should exist for operator help");

        // Act
        let help = scan_command.render_long_help().to_string();

        // Assert
        assert!(
            help.contains("--timeout-ms") && help.contains("--pacing-ms"),
            "scan long help should name timing flags, got:\n{help}"
        );
        assert!(
            help.contains("3000"),
            "scan long help should document default timeout milliseconds, got:\n{help}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_zero_timeout_milliseconds() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--timeout-ms",
            "0",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.timeout_milliseconds, 0,
                    "explicit zero timeout should parse as immediate poll loop"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_large_timeout_milliseconds() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--timeout-ms",
            "18446744073709551615",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.timeout_milliseconds,
                    u64::MAX,
                    "maximum u64 timeout should parse for library clamping downstream"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_timeout_milliseconds_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--timeout-ms",
            "100",
            "--timeout-ms",
            "250",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate timeout flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_pacing_milliseconds_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--pacing-ms",
            "1",
            "--pacing-ms",
            "2",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate pacing flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_explicit_zero_pacing_milliseconds_alongside_custom_timeout() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--timeout-ms",
            "1",
            "--pacing-ms",
            "0",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.timeout_milliseconds, 1);
                assert_eq!(scan.pacing_milliseconds, 0);
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_non_numeric_pacing_milliseconds() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--pacing-ms", "x"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "non-numeric pacing should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_empty_timeout_milliseconds() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--timeout-ms", ""];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "empty timeout token should fail parsing, got: {outcome:?}"
        );
    }
}
