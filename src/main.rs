//! Binary entry point for the new ARP scan tool.

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
                if let Err(error) = new_arp_scan::run(ApplicationCommand::Scan {
                    interface_name: scan.interface_name,
                }) {
                    eprintln!("{error}");
                    std::process::exit(1);
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
