//! Binary entry point for the new ARP scan tool.

use std::time::Duration;

use clap::CommandFactory;
use clap::Parser;

use new_arp_scan::application_command::ApplicationCommand;
use new_arp_scan::cli::{CliRoot, CliSubcommand};

fn main() {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if arguments.len() <= 1 {
        let mut command = CliRoot::command();
        if command.print_help().is_err() {
            std::process::exit(1);
        }
        return;
    }

    match CliRoot::try_parse_from(arguments.as_slice()) {
        Ok(parsed) => match parsed.subcommand {
            Some(CliSubcommand::Scan(scan)) => {
                match new_arp_scan::run(ApplicationCommand::Scan {
                    interface_name: scan.interface_name,
                    target_ipv4_address: scan.host_ipv4_address,
                    timeout: Duration::from_millis(scan.timeout_milliseconds),
                    pacing: Duration::from_millis(scan.pacing_milliseconds),
                    attempts: std::num::NonZeroU64::new(scan.attempts).expect(
                        "clap should reject zero attempts before reaching the application run path",
                    ),
                }) {
                    Ok(outcome) => {
                        let mut standard_output = std::io::stdout().lock();
                        let mut standard_error = std::io::stderr().lock();
                        outcome
                            .write_operator_streams(&mut standard_output, &mut standard_error)
                            .expect(
                                "writing operator output to standard streams should succeed for a CLI binary",
                            );
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                }
            }
            Some(CliSubcommand::Interfaces) => {
                match new_arp_scan::run(ApplicationCommand::UsableInterfacesList) {
                    Ok(outcome) => {
                        let mut standard_output = std::io::stdout().lock();
                        let mut standard_error = std::io::stderr().lock();
                        outcome
                            .write_operator_streams(&mut standard_output, &mut standard_error)
                            .expect(
                                "writing operator output to standard streams should succeed for a CLI binary",
                            );
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                let mut command = CliRoot::command();
                command
                    .print_help()
                    .expect("printing help should succeed for a CLI binary");
            }
        },
        Err(error) => error.exit(),
    }
}

#[cfg(test)]
mod tests {
    use new_arp_scan::mac_address::MacAddress;

    #[test]
    fn mac_address_display_matches_lowercase_colon_format() {
        // Arrange
        let address = MacAddress::from_octets([0x00u8, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);

        // Act
        let formatted = address.to_string();

        // Assert
        assert_eq!(
            formatted, "00:1a:2b:3c:4d:5e",
            "output should be stable lowercase colon-separated Ethernet notation"
        );
    }
}
