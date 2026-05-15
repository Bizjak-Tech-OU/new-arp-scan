//! Application commands accepted by [`crate::run`].

/// A command dispatched from the binary after command-line parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationCommand {
    /// Scan the given data-link interface’s local IPv4 subnet using address resolution protocol.
    Scan {
        /// Operating system name of the network interface (for example `eth0`), or [`None`] to
        /// select automatically when exactly one usable interface exists.
        interface_name: Option<String>,
    },
    /// List interfaces that are usable for ARP scanning on Linux.
    UsableInterfacesList,
}
