//! Successful outcomes returned from [`crate::run`].
//!
//! The binary prints [`ScanOutcome::discovered_hosts`] to standard output and
//! [`ScanOutcome::warnings`] to standard error. Usable-interface listings are printed as a plain
//! table on standard output.

use std::fmt::Write;
use std::net::Ipv4Addr;

use crate::mac_address::MacAddress;

const USABLE_INTERFACE_TABLE_NAME_WIDTH: usize = 16;
const USABLE_INTERFACE_TABLE_INDEX_WIDTH: usize = 6;
const USABLE_INTERFACE_TABLE_IPV4_WIDTH: usize = 15;
const USABLE_INTERFACE_TABLE_NETMASK_WIDTH: usize = 15;

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
    /// Non-fatal warnings (for example malformed frames, per-target send failures, or conflicting duplicate address resolution replies for the same IPv4).
    pub warnings: Vec<String>,
}

/// One row in the usable-interface listing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsableInterfaceListingRow {
    /// Operating system interface name.
    pub interface_name: String,
    /// Linux interface index.
    pub interface_index: u32,
    /// Primary IPv4 address.
    pub ipv4_address: Ipv4Addr,
    /// IPv4 netmask.
    pub ipv4_netmask: Ipv4Addr,
    /// Ethernet hardware address.
    pub media_access_control_address: MacAddress,
}

/// Outcome of listing interfaces that are usable for ARP scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsableInterfacesListOutcome {
    /// Usable interfaces, sorted by interface index then name.
    pub entries: Vec<UsableInterfaceListingRow>,
}

impl UsableInterfacesListOutcome {
    /// Formats a plain-text table with aligned columns, or a single message when there are no
    /// entries.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn format_plain_columns_table(&self) -> String {
        if self.entries.is_empty() {
            return "no usable interfaces found\n".to_string();
        }

        let mut lines = String::new();
        // `String` implements `std::fmt::Write` without allocation failure; `writeln!` only returns
        // `Err` on formatting errors, which cannot occur for these arguments.
        let _ = writeln!(
            lines,
            "{:<name_width$} {:>index_width$} {:<ipv4_width$} {:<netmask_width$} MAC",
            "NAME",
            "INDEX",
            "IPV4",
            "NETMASK",
            name_width = USABLE_INTERFACE_TABLE_NAME_WIDTH,
            index_width = USABLE_INTERFACE_TABLE_INDEX_WIDTH,
            ipv4_width = USABLE_INTERFACE_TABLE_IPV4_WIDTH,
            netmask_width = USABLE_INTERFACE_TABLE_NETMASK_WIDTH,
        );
        for entry in &self.entries {
            let _ = writeln!(
                lines,
                "{:<name_width$} {:>index_width$} {:<ipv4_width$} {:<netmask_width$} {}",
                entry.interface_name,
                entry.interface_index,
                entry.ipv4_address,
                entry.ipv4_netmask,
                entry.media_access_control_address,
                name_width = USABLE_INTERFACE_TABLE_NAME_WIDTH,
                index_width = USABLE_INTERFACE_TABLE_INDEX_WIDTH,
                ipv4_width = USABLE_INTERFACE_TABLE_IPV4_WIDTH,
                netmask_width = USABLE_INTERFACE_TABLE_NETMASK_WIDTH,
            );
        }
        lines.push('\n');
        lines
    }
}

/// Successful outcome of [`crate::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationOutcome {
    /// Completed scan on Linux.
    Scan(ScanOutcome),
    /// Listed interfaces usable for ARP scanning on Linux.
    UsableInterfacesList(UsableInterfacesListOutcome),
}

#[cfg(test)]
mod tests {
    use super::UsableInterfaceListingRow;
    use super::UsableInterfacesListOutcome;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;

    #[test]
    fn format_plain_columns_table_returns_message_when_entries_empty() {
        // Arrange
        let outcome = UsableInterfacesListOutcome { entries: vec![] };

        // Act
        let formatted = outcome.format_plain_columns_table();

        // Assert
        assert_eq!(
            formatted, "no usable interfaces found\n",
            "empty listing should print the agreed operator message"
        );
    }

    #[test]
    fn format_plain_columns_table_includes_header_and_rows() {
        // Arrange
        let outcome = UsableInterfacesListOutcome {
            entries: vec![UsableInterfaceListingRow {
                interface_name: "eth0".to_string(),
                interface_index: 2,
                ipv4_address: Ipv4Addr::new(192, 168, 1, 10),
                ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                media_access_control_address: MacAddress::from_octets([
                    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                ]),
            }],
        };

        // Act
        let formatted = outcome.format_plain_columns_table();

        // Assert
        assert!(
            formatted.contains("NAME") && formatted.contains("INDEX"),
            "table should include column headers, got:\n{formatted}"
        );
        assert!(
            formatted.contains("eth0") && formatted.contains("192.168.1.10"),
            "table should include fixture row content, got:\n{formatted}"
        );
    }

    #[test]
    fn format_plain_columns_table_preserves_row_order_from_entries_vector() {
        // Arrange
        let outcome = UsableInterfacesListOutcome {
            entries: vec![
                UsableInterfaceListingRow {
                    interface_name: "z_second_row".to_string(),
                    interface_index: 99,
                    ipv4_address: Ipv4Addr::new(10, 0, 0, 2),
                    ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                    media_access_control_address: MacAddress::from_octets([
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
                    ]),
                },
                UsableInterfaceListingRow {
                    interface_name: "a_first_row".to_string(),
                    interface_index: 5,
                    ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
                    ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                    media_access_control_address: MacAddress::from_octets([
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                    ]),
                },
            ],
        };

        // Act
        let formatted = outcome.format_plain_columns_table();

        // Assert
        let first_position = formatted
            .find("z_second_row")
            .expect("first fixture row should appear in output");
        let second_position = formatted
            .find("a_first_row")
            .expect("second fixture row should appear in output");
        assert!(
            first_position < second_position,
            "table rows should follow `entries` order (not lexical sort), got:\n{formatted}"
        );
    }
}
