//! Application commands accepted by [`crate::run`].

/// A command dispatched from the binary after command-line parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationCommand {
    /// Scan the given data-link interface (socket initialization only today).
    Scan {
        /// Operating system name of the network interface (for example `eth0`).
        interface_name: String,
    },
}
