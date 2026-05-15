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
}
