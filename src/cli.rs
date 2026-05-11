//! Command-line interface definitions for the `new-arp-scan` binary.

use clap::{Args, Parser, Subcommand};

/// Help footer examples appended to `--help` output.
const EXAMPLES: &str = "\
EXAMPLES:
  Initialize a raw ARP packet socket on Linux (requires CAP_NET_RAW or equivalent):
    new-arp-scan scan --interface eth0
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
    /// Initialize a raw ARP packet socket on an interface (scanning not implemented yet).
    Scan(ScanArguments),
}

/// Arguments for [`CliSubcommand::Scan`].
#[derive(Debug, Args)]
pub struct ScanArguments {
    /// Network interface name (for example `eth0`).
    #[arg(long = "interface", value_name = "NAME", visible_alias = "iface")]
    pub interface_name: String,
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
                    scan.interface_name, "eth0",
                    "interface name should match flag value"
                );
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_missing_interface_flag() {
        // Arrange
        let arguments = ["new-arp-scan", "scan"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "missing required flag should fail parsing, got: {outcome:?}"
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
    fn help_command_factory_builds_without_panicking() {
        // Arrange
        // Act
        let mut command = CliRoot::command();

        // Assert
        let help = command.render_help().to_string();
        assert!(
            help.contains("scan"),
            "help should mention scan subcommand, got: {help}"
        );
    }
}
