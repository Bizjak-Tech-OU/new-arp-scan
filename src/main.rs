//! Binary entry point for the new ARP scan tool.

use std::time::Duration;

use clap::CommandFactory;
use clap::Parser;

use new_arp_scan::Ieee8021qVlanIdentifier;
use new_arp_scan::application_command::{
    ApplicationCommand, ArpSenderProtocolAddress, ScanWireOptions,
};
use new_arp_scan::cli::{CliRoot, CliSubcommand};
use new_arp_scan::mac_vendor_registry::MacVendorRegistry;

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
                let mac_vendor_registry =
                    match load_mac_vendor_registry(scan.mac_vendor_file.as_deref()) {
                        Ok(registry) => registry,
                        Err(error) => {
                            eprintln!("{error}");
                            std::process::exit(1);
                        }
                    };
                match new_arp_scan::run(ApplicationCommand::Scan {
                    interface_name: scan.interface_name,
                    target_ipv4_address: scan.host_ipv4_address,
                    timeout: Duration::from_millis(scan.timeout_milliseconds),
                    pacing: Duration::from_millis(scan.pacing_milliseconds),
                    attempts: std::num::NonZeroU64::new(scan.attempts).expect(
                        "clap should reject zero attempts before reaching the application run path",
                    ),
                    wire: ScanWireOptions {
                        vlan_identifier: scan.vlan_identifier.map(|vlan_identifier| {
                            Ieee8021qVlanIdentifier::new(vlan_identifier).expect(
                                "clap should reject VLAN identifiers above 4095 before reaching the application run path",
                            )
                        }),
                        sender_protocol_address: scan
                            .sender_protocol_address
                            .unwrap_or(ArpSenderProtocolAddress::Interface),
                        llc_snap: scan.llc_snap,
                    },
                }) {
                    Ok(outcome) => {
                        let mut standard_output = std::io::stdout().lock();
                        let mut standard_error = std::io::stderr().lock();
                        outcome
                            .write_operator_streams_with_mac_vendor_registry(
                                &mut standard_output,
                                &mut standard_error,
                                mac_vendor_registry.as_ref(),
                            )
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

fn load_mac_vendor_registry(
    explicit_path: Option<&std::path::Path>,
) -> Result<Option<MacVendorRegistry>, String> {
    match explicit_path {
        Some(path) => MacVendorRegistry::load_from_path(path)
            .map(Some)
            .map_err(|error| format!("failed to load MAC vendor file {}: {error}", path.display())),
        None => MacVendorRegistry::load_default_file_if_present().map_err(|error| {
            format!("failed to load default MAC vendor file ieee-oui.txt: {error}")
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::load_mac_vendor_registry;
    use new_arp_scan::mac_address::MacAddress;
    use std::io::Write;

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

    #[test]
    fn load_mac_vendor_registry_reads_explicit_file() {
        // Arrange
        let directory = std::env::temp_dir();
        let path = directory.join("new-arp-scan-mac-vendor-fixture.txt");
        let mut file = std::fs::File::create(&path).expect("temp mapping file should create");
        file.write_all(b"001122\tFixture Vendor\n")
            .expect("temp mapping file should write");
        drop(file);

        // Act
        let registry = load_mac_vendor_registry(Some(&path)).expect("explicit file should load");

        // Assert
        let registry = registry.expect("explicit path should yield Some");
        let address = MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1]);
        assert_eq!(registry.vendor_name_for(address), Some("Fixture Vendor"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_mac_vendor_registry_reports_missing_explicit_file() {
        // Arrange
        let path = std::path::Path::new("/no/such/new-arp-scan-ieee-oui.txt");

        // Act
        let outcome = load_mac_vendor_registry(Some(path));

        // Assert
        let error = outcome.expect_err("missing explicit file should fail");
        assert!(
            error.contains("failed to load MAC vendor file"),
            "error should name the load failure, got: {error}"
        );
    }
}
