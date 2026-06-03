//! Discovers macOS network interfaces and IPv4 configuration usable for ARP scanning.
//!
//! Interface data is gathered once through [`crate::macos_system_call::collect_interface_address_records`]
//! and classified here with the same operator semantics as the Linux backend: Ethernet-capable,
//! administratively up, not loopback, not `NOARP`, with an IPv4 address, netmask, and a non-zero
//! Ethernet hardware address. The classification is pure so it can be unit tested with fixture
//! records instead of live system calls.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::net::Ipv4Addr;

use crate::error::AppError;
use crate::interface_validation;
use crate::link_layer_backend::{ArpScanInterfaceCandidate, InterfaceScanAddresses};
use crate::mac_address::MacAddress;
use crate::macos_packet::{
    INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP, INTERFACE_TYPE_ETHERNET,
};
use crate::macos_system_call::{self, InterfaceAddressPayload, InterfaceAddressRecord};

/// One macOS interface that passed every ARP scan usability rule, before its index is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassifiedScanInterface {
    interface_name: String,
    source_ipv4_address: Ipv4Addr,
    ipv4_netmask: Ipv4Addr,
    source_mac_address: MacAddress,
}

/// Returns `true` when `interface_flags` indicate an interface that is administratively up, not
/// loopback, and does not have `NOARP` set.
///
/// Mirrors the Linux rule in [`crate::linux_interface_discovery`] without allocating error strings.
#[must_use]
fn interface_flags_allow_arp_scanning(interface_flags: libc::c_uint) -> bool {
    let up = INTERFACE_FLAG_UP.cast_unsigned();
    let loopback = INTERFACE_FLAG_LOOPBACK.cast_unsigned();
    let no_arp = INTERFACE_FLAG_NO_ARP.cast_unsigned();
    (interface_flags & loopback) == 0
        && (interface_flags & no_arp) == 0
        && (interface_flags & up) != 0
}

/// Aggregated address state for one interface name while folding `getifaddrs(3)` records.
#[derive(Default)]
struct InterfaceAccumulator {
    interface_flags: libc::c_uint,
    source_ipv4_address: Option<Ipv4Addr>,
    ipv4_netmask: Option<Ipv4Addr>,
    link_layer: Option<(u8, [u8; 6])>,
}

/// Folds `getifaddrs(3)` records into one [`InterfaceAccumulator`] per interface name.
///
/// Names that fail the shared interface-name rules are skipped. Pure over its input.
fn accumulate_interface_records(
    records: &[InterfaceAddressRecord],
) -> BTreeMap<String, InterfaceAccumulator> {
    let mut interfaces_by_name: BTreeMap<String, InterfaceAccumulator> = BTreeMap::new();

    for record in records {
        if interface_validation::validate_interface_name_for_linux_packet_socket(
            &record.interface_name,
        )
        .is_err()
        {
            continue;
        }

        let accumulator = interfaces_by_name
            .entry(record.interface_name.clone())
            .or_default();
        accumulator.interface_flags = record.interface_flags;

        match &record.payload {
            InterfaceAddressPayload::Ipv4 { address, netmask } => {
                if accumulator.source_ipv4_address.is_none() {
                    accumulator.source_ipv4_address = Some(*address);
                    accumulator.ipv4_netmask = *netmask;
                }
            }
            InterfaceAddressPayload::LinkLayer {
                interface_type,
                hardware_address,
            } => {
                if let Some(octets) = hardware_address {
                    accumulator.link_layer = Some((*interface_type, *octets));
                }
            }
        }
    }

    interfaces_by_name
}

/// Applies the ARP scan usability rules to one accumulated interface.
///
/// Returns the usable interface, or a specific [`AppError`] explaining why it was rejected, using
/// the same operator-facing reasons as the Linux backend where the platforms agree.
fn classify_accumulator(
    interface_name: &str,
    accumulator: &InterfaceAccumulator,
) -> Result<ClassifiedScanInterface, AppError> {
    if !interface_flags_allow_arp_scanning(accumulator.interface_flags) {
        let reason = if (accumulator.interface_flags & INTERFACE_FLAG_LOOPBACK.cast_unsigned()) != 0
        {
            "loopback interface"
        } else if (accumulator.interface_flags & INTERFACE_FLAG_NO_ARP.cast_unsigned()) != 0 {
            "interface has NOARP set"
        } else {
            "interface is not UP"
        };
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: reason.to_string(),
        });
    }

    let (Some(source_ipv4_address), Some(ipv4_netmask)) =
        (accumulator.source_ipv4_address, accumulator.ipv4_netmask)
    else {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "interface has no IPv4 address and netmask".to_string(),
        });
    };

    let Some((interface_type, octets)) = accumulator.link_layer else {
        return Err(AppError::InterfaceHardwareAddressUnsupported {
            interface_name: interface_name.to_string(),
            reason: "interface has no Ethernet hardware address".to_string(),
        });
    };
    if interface_type != INTERFACE_TYPE_ETHERNET {
        return Err(AppError::InterfaceHardwareAddressUnsupported {
            interface_name: interface_name.to_string(),
            reason: format!("link-layer type {interface_type} is not Ethernet"),
        });
    }
    let source_mac_address = MacAddress::from_octets(octets);
    if source_mac_address.is_zero() {
        return Err(AppError::InterfaceHardwareAddressUnsupported {
            interface_name: interface_name.to_string(),
            reason: "hardware address is all zero".to_string(),
        });
    }

    Ok(ClassifiedScanInterface {
        interface_name: interface_name.to_string(),
        source_ipv4_address,
        ipv4_netmask,
        source_mac_address,
    })
}

/// Groups address records by interface name and keeps the usable ARP scan interfaces.
///
/// Pure over its input so the usability rules can be exercised with fixture records.
fn classify_usable_scan_interfaces(
    records: &[InterfaceAddressRecord],
) -> Vec<ClassifiedScanInterface> {
    accumulate_interface_records(records)
        .into_iter()
        .filter_map(|(interface_name, accumulator)| {
            classify_accumulator(&interface_name, &accumulator).ok()
        })
        .collect()
}

/// Enumerates local interfaces that are usable for ARP scanning on macOS.
///
/// Applies the same usability rules as Linux automatic selection and returns the same
/// [`ArpScanInterfaceCandidate`] shape, sorted by interface index then name.
///
/// # Errors
///
/// Returns [`AppError::InterfaceEnumerationFailed`] when `getifaddrs(3)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn enumerate_usable_arp_scan_interface_candidates()
-> Result<Vec<ArpScanInterfaceCandidate>, AppError> {
    let records = macos_system_call::collect_interface_address_records()
        .map_err(|source| AppError::InterfaceEnumerationFailed { source })?;

    let mut candidates = Vec::new();
    for interface in classify_usable_scan_interfaces(&records) {
        let Ok(interface_name_c) = CString::new(interface.interface_name.as_str()) else {
            continue;
        };
        let Ok(interface_index) = macos_system_call::interface_index_from_name(&interface_name_c)
        else {
            continue;
        };
        candidates.push(ArpScanInterfaceCandidate {
            interface_name: interface.interface_name,
            interface_index,
            source_ipv4_address: interface.source_ipv4_address,
            ipv4_netmask: interface.ipv4_netmask,
            source_mac_address: interface.source_mac_address,
        });
    }

    candidates.sort_by(|left, right| {
        left.interface_index
            .cmp(&right.interface_index)
            .then_with(|| left.interface_name.cmp(&right.interface_name))
    });

    Ok(candidates)
}

/// Reads [`InterfaceScanAddresses`] for `interface_name` from `getifaddrs(3)`.
///
/// # Errors
///
/// Returns [`AppError::InvalidInterfaceName`] for an unusable name, [`AppError::InterfaceLookupFailed`]
/// when the interface is not present, [`AppError::InterfaceRejectedForScanning`] when it is loopback,
/// down, `NOARP`, or has no IPv4 address, or [`AppError::InterfaceHardwareAddressUnsupported`] when
/// it has no usable Ethernet hardware address.
///
/// # Panics
///
/// This function does not panic.
pub fn discover_interface_scan_addresses(
    interface_name: &str,
) -> Result<InterfaceScanAddresses, AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;

    let records = macos_system_call::collect_interface_address_records()
        .map_err(|source| AppError::InterfaceEnumerationFailed { source })?;
    let accumulator = accumulate_interface_records(&records);
    let Some(interface_accumulator) = accumulator.get(interface_name) else {
        return Err(AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "interface not present in getifaddrs output",
            ),
        });
    };

    let classified = classify_accumulator(interface_name, interface_accumulator)?;
    Ok(InterfaceScanAddresses {
        source_ipv4_address: classified.source_ipv4_address,
        ipv4_netmask: classified.ipv4_netmask,
        source_mac_address: classified.source_mac_address,
    })
}

/// Resolves which interface name to use for scanning on macOS.
///
/// When `explicit_interface_name` is [`Some`], that name is validated the same way as a direct scan
/// request. When it is [`None`], this function requires exactly one usable interface.
///
/// # Errors
///
/// Returns [`AppError`] for invalid names, interface rejection, discovery failures, or ambiguous
/// automatic selection.
///
/// # Panics
///
/// This function does not panic.
pub fn resolve_scan_interface_name(
    explicit_interface_name: Option<&str>,
) -> Result<String, AppError> {
    if let Some(interface_name) = explicit_interface_name {
        discover_interface_scan_addresses(interface_name)?;
        return Ok(interface_name.to_string());
    }

    let candidates = enumerate_usable_arp_scan_interface_candidates()?;
    match candidates.len() {
        0 => Err(AppError::AutomaticInterfaceSelectionNoneFound),
        1 => Ok(candidates[0].interface_name.clone()),
        _ => Err(AppError::AutomaticInterfaceSelectionAmbiguous {
            interface_names: candidates
                .into_iter()
                .map(|candidate| candidate.interface_name)
                .collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClassifiedScanInterface, classify_usable_scan_interfaces,
        enumerate_usable_arp_scan_interface_candidates, interface_flags_allow_arp_scanning,
    };
    use crate::mac_address::MacAddress;
    use crate::macos_packet::{
        INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP, INTERFACE_TYPE_ETHERNET,
    };
    use crate::macos_system_call::{InterfaceAddressPayload, InterfaceAddressRecord};
    use std::net::Ipv4Addr;

    fn flags_up() -> libc::c_uint {
        INTERFACE_FLAG_UP.cast_unsigned()
    }

    fn ipv4_record(
        name: &str,
        flags: libc::c_uint,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> InterfaceAddressRecord {
        InterfaceAddressRecord {
            interface_name: name.to_string(),
            interface_flags: flags,
            payload: InterfaceAddressPayload::Ipv4 {
                address,
                netmask: Some(netmask),
            },
        }
    }

    fn link_record(
        name: &str,
        flags: libc::c_uint,
        interface_type: u8,
        octets: [u8; 6],
    ) -> InterfaceAddressRecord {
        InterfaceAddressRecord {
            interface_name: name.to_string(),
            interface_flags: flags,
            payload: InterfaceAddressPayload::LinkLayer {
                interface_type,
                hardware_address: Some(octets),
            },
        }
    }

    #[test]
    fn classifies_up_ethernet_interface_with_ipv4_and_mac_as_usable() {
        // Arrange
        let octets = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let records = vec![
            ipv4_record(
                "en0",
                flags_up(),
                Ipv4Addr::new(192, 168, 1, 20),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            link_record("en0", flags_up(), INTERFACE_TYPE_ETHERNET, octets),
        ];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert_eq!(
            classified,
            vec![ClassifiedScanInterface {
                interface_name: "en0".to_string(),
                source_ipv4_address: Ipv4Addr::new(192, 168, 1, 20),
                ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                source_mac_address: MacAddress::from_octets(octets),
            }],
            "an up Ethernet interface with IPv4, netmask, and a non-zero MAC should be usable"
        );
    }

    #[test]
    fn excludes_loopback_interface() {
        // Arrange
        let flags = INTERFACE_FLAG_UP.cast_unsigned() | INTERFACE_FLAG_LOOPBACK.cast_unsigned();
        let records = vec![
            ipv4_record(
                "lo0",
                flags,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::new(255, 0, 0, 0),
            ),
            link_record("lo0", flags, INTERFACE_TYPE_ETHERNET, [1, 2, 3, 4, 5, 6]),
        ];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "loopback interfaces must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn excludes_interface_with_noarp_flag() {
        // Arrange
        let flags = INTERFACE_FLAG_UP.cast_unsigned() | INTERFACE_FLAG_NO_ARP.cast_unsigned();
        let records = vec![
            ipv4_record(
                "en5",
                flags,
                Ipv4Addr::new(10, 0, 0, 5),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            link_record("en5", flags, INTERFACE_TYPE_ETHERNET, [1, 2, 3, 4, 5, 6]),
        ];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "NOARP interfaces must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn excludes_interface_that_is_not_up() {
        // Arrange
        let flags = 0;
        let records = vec![
            ipv4_record(
                "en6",
                flags,
                Ipv4Addr::new(10, 0, 0, 6),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            link_record("en6", flags, INTERFACE_TYPE_ETHERNET, [1, 2, 3, 4, 5, 6]),
        ];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "interfaces that are not up must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn excludes_non_ethernet_interface_type() {
        // Arrange
        let other_link_type = 0x18; // IFT_LOOP-style non-Ethernet medium.
        let records = vec![
            ipv4_record(
                "utun0",
                flags_up(),
                Ipv4Addr::new(10, 9, 9, 9),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            link_record("utun0", flags_up(), other_link_type, [1, 2, 3, 4, 5, 6]),
        ];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "non-Ethernet link types must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn excludes_interface_without_ipv4_address() {
        // Arrange
        let records = vec![link_record(
            "en7",
            flags_up(),
            INTERFACE_TYPE_ETHERNET,
            [1, 2, 3, 4, 5, 6],
        )];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "interfaces without an IPv4 address must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn excludes_interface_without_link_layer_address() {
        // Arrange
        let records = vec![ipv4_record(
            "en8",
            flags_up(),
            Ipv4Addr::new(10, 0, 0, 8),
            Ipv4Addr::new(255, 255, 255, 0),
        )];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "interfaces without an Ethernet address must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn excludes_interface_with_all_zero_mac() {
        // Arrange
        let records = vec![
            ipv4_record(
                "en9",
                flags_up(),
                Ipv4Addr::new(10, 0, 0, 9),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            link_record("en9", flags_up(), INTERFACE_TYPE_ETHERNET, [0; 6]),
        ];

        // Act
        let classified = classify_usable_scan_interfaces(&records);

        // Assert
        assert!(
            classified.is_empty(),
            "all-zero hardware addresses must be excluded, got: {classified:?}"
        );
    }

    #[test]
    fn interface_flags_allow_arp_scanning_accepts_up_non_loopback_without_no_arp() {
        // Arrange
        let flags = INTERFACE_FLAG_UP.cast_unsigned();

        // Act
        let outcome = interface_flags_allow_arp_scanning(flags);

        // Assert
        assert!(
            outcome,
            "up, non-loopback, ARP-capable interfaces are allowed"
        );
    }

    #[test]
    fn interface_flags_allow_arp_scanning_rejects_loopback_and_noarp_and_down() {
        // Arrange
        let loopback = INTERFACE_FLAG_UP.cast_unsigned() | INTERFACE_FLAG_LOOPBACK.cast_unsigned();
        let no_arp = INTERFACE_FLAG_UP.cast_unsigned() | INTERFACE_FLAG_NO_ARP.cast_unsigned();
        let down = 0;

        // Act / Assert
        assert!(
            !interface_flags_allow_arp_scanning(loopback),
            "loopback should be rejected"
        );
        assert!(
            !interface_flags_allow_arp_scanning(no_arp),
            "NOARP should be rejected"
        );
        assert!(
            !interface_flags_allow_arp_scanning(down),
            "interfaces that are not up should be rejected"
        );
    }

    #[test]
    fn enumerate_usable_arp_scan_interface_candidates_succeeds_on_macos_host() {
        // Act
        let outcome = enumerate_usable_arp_scan_interface_candidates();

        // Assert
        let candidates = outcome.expect("enumeration should succeed on macOS test hosts");
        for candidate in &candidates {
            assert!(
                !candidate.interface_name.is_empty(),
                "every candidate should carry a non-empty interface name, got: {candidate:?}"
            );
            assert_ne!(
                candidate.interface_index, 0,
                "resolved interface index should be non-zero, got: {candidate:?}"
            );
        }
    }
}
