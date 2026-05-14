//! Successful outcomes returned from [`crate::run`].
//!
//! The binary prints [`ScanOutcome::discovered_hosts`] to standard output and
//! [`ScanOutcome::warnings`] to standard error.

use std::net::Ipv4Addr;

use crate::mac_address::MacAddress;

/// A host observed on the local data-link segment during an address resolution scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredHost {
    /// IPv4 address reported in the address resolution reply.
    pub ipv4_address: Ipv4Addr,
    /// Ethernet media access control address reported in the address resolution reply.
    pub media_access_control_address: MacAddress,
}

/// Outcome of an address resolution scan (discovered hosts and non-fatal warnings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Hosts discovered during scanning, sorted by IPv4 ascending.
    pub discovered_hosts: Vec<DiscoveredHost>,
    /// Non-fatal warnings (for example malformed frames or per-target send failures).
    pub warnings: Vec<String>,
}

/// Successful outcome of [`crate::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationOutcome {
    /// Completed scan on Linux.
    Scan(ScanOutcome),
}
