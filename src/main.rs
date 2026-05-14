//! Binary entry point for the new ARP scan tool.

use clap::CommandFactory;
use clap::Parser;

use new_arp_scan::application_command::ApplicationCommand;
use new_arp_scan::application_outcome::ApplicationOutcome;
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
                }) {
                    Ok(outcome) => {
                        print_application_outcome(outcome);
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

fn print_application_outcome(outcome: ApplicationOutcome) {
    match outcome {
        ApplicationOutcome::Scan(scan_outcome) => {
            for warning in &scan_outcome.warnings {
                eprintln!("warning: {warning}");
            }

            if scan_outcome.discovered_hosts.is_empty() {
                println!("no hosts found");
                return;
            }

            for host in &scan_outcome.discovered_hosts {
                println!(
                    "{} {}",
                    host.ipv4_address, host.media_access_control_address
                );
            }
        }
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
