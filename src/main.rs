//! Binary entry point for the new ARP scan tool.

fn main() {
    if let Err(error) = new_arp_scan::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
