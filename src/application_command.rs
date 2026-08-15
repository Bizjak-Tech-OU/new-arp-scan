//! Application commands accepted by [`crate::run`].

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::address_resolution_protocol::{
    ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH, ARP_HARDWARE_TYPE_ETHERNET,
    ARP_IPV4_PROTOCOL_ADDRESS_LENGTH, ARP_OPERATION_REQUEST, AddressResolutionRequestLayout,
};
use crate::ethernet_frame::{ETHERNET_PROTOCOL_IPV4, Ieee8021qVlanIdentifier};
use crate::mac_address::MacAddress;

/// How transmitted ARP requests fill RFC 826 `ar$spa`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpSenderProtocolAddress {
    /// Use the scanning interface IPv4 address (RFC 826 default, original `arp-scan` default).
    Interface,
    /// Override `ar$spa` with this address. [`Ipv4Addr::UNSPECIFIED`] (`0.0.0.0`) is an RFC 5227
    /// ARP Probe.
    Explicit(Ipv4Addr),
    /// Set `ar$spa` to each target's IPv4 address (RFC 5227 ARP Announcement / original `arp-scan`
    /// `--arpspa dest`).
    DestinationTarget,
}

impl ArpSenderProtocolAddress {
    /// Parses an `--arpspa` token: dotted-quad IPv4, or `dest` (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns a message when `token` is neither `dest` nor a dotted-quad IPv4 address.
    pub fn parse_cli_token(token: &str) -> Result<Self, String> {
        if token.eq_ignore_ascii_case("dest") {
            return Ok(Self::DestinationTarget);
        }
        token.parse::<Ipv4Addr>().map(Self::Explicit).map_err(|_| {
            format!("invalid --arpspa value '{token}': expected a dotted-quad IPv4 address or dest")
        })
    }

    /// Returns the `ar$spa` value for one transmitted request.
    #[must_use]
    pub fn ipv4_address_for_target(
        self,
        interface_ipv4_address: Ipv4Addr,
        target_ipv4_address: Ipv4Addr,
    ) -> Ipv4Addr {
        match self {
            Self::Interface => interface_ipv4_address,
            Self::Explicit(address) => address,
            Self::DestinationTarget => target_ipv4_address,
        }
    }
}

/// Parses a decimal or `0x`-prefixed hexadecimal unsigned integer for ARP header CLI flags.
///
/// # Errors
///
/// Returns a message when `token` is not a decimal or hexadecimal integer in range for `T`.
pub fn parse_u16_cli_token(token: &str) -> Result<u16, String> {
    parse_cli_integer(token, "16-bit")
}

/// Parses a decimal or `0x`-prefixed hexadecimal octet for `ar$hln` / `ar$pln`.
///
/// # Errors
///
/// Returns a message when `token` is not a decimal or hexadecimal integer in `0..=255`.
pub fn parse_u8_cli_token(token: &str) -> Result<u8, String> {
    parse_cli_integer(token, "8-bit")
}

fn parse_cli_integer<T>(token: &str, width_name: &str) -> Result<T, String>
where
    T: TryFrom<u128>,
{
    let trimmed = token.trim();
    let parsed = if let Some(hexadecimal) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u128::from_str_radix(hexadecimal, 16).map_err(|_| {
            format!("invalid hexadecimal integer '{token}': expected a {width_name} value")
        })?
    } else {
        trimmed.parse::<u128>().map_err(|_| {
            format!(
                "invalid integer '{token}': expected a decimal or 0x-prefixed {width_name} value"
            )
        })?
    };
    T::try_from(parsed).map_err(|_| format!("integer '{token}' is outside the {width_name} range"))
}

/// On-wire options for transmitted ARP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanWireOptions {
    /// When set, transmit a single IEEE 802.1Q tag with this VLAN identifier (PCP and DEI zero).
    pub vlan_identifier: Option<Ieee8021qVlanIdentifier>,
    /// Value encoded in RFC 826 `ar$spa`.
    pub sender_protocol_address: ArpSenderProtocolAddress,
    /// When true, encapsulate ARP in IEEE 802.3 with RFC 1042 LLC/SNAP instead of Ethernet II.
    pub llc_snap: bool,
    /// Ethernet destination. [`None`] means the broadcast address.
    pub ethernet_destination: Option<MacAddress>,
    /// Ethernet source. [`None`] means the scanning interface MAC.
    pub ethernet_source: Option<MacAddress>,
    /// RFC 826 `ar$hrd` (default Ethernet / 1).
    pub arp_hardware_type: u16,
    /// RFC 826 `ar$pro` (default IPv4 / `0x0800`).
    pub arp_protocol_type: u16,
    /// RFC 826 `ar$hln` (default 6). Does not change encoded SHA/THA widths.
    pub arp_hardware_length: u8,
    /// RFC 826 `ar$pln` (default 4). Does not change encoded SPA/TPA widths.
    pub arp_protocol_length: u8,
    /// RFC 826 `ar$op` (default request / 1).
    pub arp_operation: u16,
    /// RFC 826 `ar$sha`. [`None`] means the scanning interface MAC.
    pub arp_sender_hardware: Option<MacAddress>,
    /// RFC 826 `ar$tha`. [`None`] means all zeroes.
    pub arp_target_hardware: Option<MacAddress>,
}

impl Default for ScanWireOptions {
    fn default() -> Self {
        Self {
            vlan_identifier: None,
            sender_protocol_address: ArpSenderProtocolAddress::Interface,
            llc_snap: false,
            ethernet_destination: None,
            ethernet_source: None,
            arp_hardware_type: ARP_HARDWARE_TYPE_ETHERNET,
            arp_protocol_type: ETHERNET_PROTOCOL_IPV4,
            arp_hardware_length: ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH,
            arp_protocol_length: ARP_IPV4_PROTOCOL_ADDRESS_LENGTH,
            arp_operation: ARP_OPERATION_REQUEST,
            arp_sender_hardware: None,
            arp_target_hardware: None,
        }
    }
}

impl ScanWireOptions {
    /// Resolves CLI/library wire options against one interface and target into an on-wire layout.
    #[must_use]
    pub(crate) fn address_resolution_request_layout(
        self,
        interface_mac_address: MacAddress,
        sender_protocol_address: Ipv4Addr,
        target_protocol_address: Ipv4Addr,
    ) -> AddressResolutionRequestLayout {
        AddressResolutionRequestLayout {
            ethernet_destination: self.ethernet_destination.unwrap_or(MacAddress::BROADCAST),
            ethernet_source: self.ethernet_source.unwrap_or(interface_mac_address),
            vlan_identifier: self.vlan_identifier,
            llc_snap: self.llc_snap,
            hardware_type: self.arp_hardware_type,
            protocol_type: self.arp_protocol_type,
            hardware_length: self.arp_hardware_length,
            protocol_length: self.arp_protocol_length,
            opcode: self.arp_operation,
            sender_hardware: self.arp_sender_hardware.unwrap_or(interface_mac_address),
            sender_protocol: sender_protocol_address,
            target_hardware: self.arp_target_hardware.unwrap_or(MacAddress::ZERO),
            target_protocol: target_protocol_address,
        }
    }
}

/// Default global receive window after the last address resolution request is sent.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(3);

/// Default delay between full scan rounds (no pacing between rounds).
pub const DEFAULT_SCAN_PACING: Duration = Duration::ZERO;

/// Default number of times each target address receives at least one address resolution request.
pub const DEFAULT_SCAN_ATTEMPTS: NonZeroU64 = NonZeroU64::MIN;

/// A command dispatched from the binary after command-line parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationCommand {
    /// Scan the given data-link interface’s local IPv4 subnet using address resolution protocol.
    Scan {
        /// Operating system name of the network interface (for example `eth0`), or [`None`] to
        /// select automatically when exactly one usable interface exists.
        interface_name: Option<String>,
        /// When set, probe only this IPv4 address (strictly interior on the interface subnet).
        target_ipv4_address: Option<Ipv4Addr>,
        /// Global receive window after the final request transmission.
        timeout: Duration,
        /// Delay after each full round of target sends except the last round.
        pacing: Duration,
        /// Total request rounds: each round sends one broadcast request per target.
        attempts: NonZeroU64,
        /// IEEE 802.1Q tag, RFC 826 field overrides, Ethernet addressing, and RFC 1042 LLC/SNAP.
        wire: ScanWireOptions,
    },
    /// List interfaces that are usable for ARP scanning on Linux.
    UsableInterfacesList,
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationCommand, ArpSenderProtocolAddress, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING,
        DEFAULT_SCAN_TIMEOUT, ScanWireOptions, parse_u8_cli_token, parse_u16_cli_token,
    };
    use crate::ethernet_frame::Ieee8021qVlanIdentifier;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::time::Duration;

    #[test]
    fn default_scan_timeout_matches_three_seconds() {
        // Arrange
        // Act
        let timeout = DEFAULT_SCAN_TIMEOUT;

        // Assert
        assert_eq!(
            timeout,
            Duration::from_secs(3),
            "default scan timeout should match historical three-second receive window"
        );
    }

    #[test]
    fn default_scan_pacing_is_zero() {
        // Arrange
        // Act
        let pacing = DEFAULT_SCAN_PACING;

        // Assert
        assert_eq!(
            pacing,
            Duration::ZERO,
            "default scan pacing should impose no delay between scan rounds"
        );
    }

    #[test]
    fn default_scan_attempts_is_one() {
        // Arrange
        // Act
        let attempts = DEFAULT_SCAN_ATTEMPTS;

        // Assert
        assert_eq!(
            attempts.get(),
            1,
            "default scan attempts should preserve historical single-round behavior"
        );
    }

    #[test]
    fn scan_command_variants_compare_equal_when_fields_match() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_millis(500),
            pacing: Duration::from_millis(1),
            attempts: NonZeroU64::new(2).expect("two is non-zero"),
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_millis(500),
            pacing: Duration::from_millis(1),
            attempts: NonZeroU64::new(2).expect("two is non-zero"),
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            equal,
            "scan commands with identical fields should compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_timeout_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_secs(1),
            pacing: Duration::ZERO,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_secs(2),
            pacing: Duration::ZERO,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different timeout values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_pacing_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: Duration::from_millis(1),
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: Duration::from_millis(2),
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different pacing values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_interface_name_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth1".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different interface names must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_explicit_interface_differs_from_automatic_none() {
        // Arrange
        let automatic = ApplicationCommand::Scan {
            interface_name: None,
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let explicit = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = automatic == explicit;

        // Assert
        assert!(
            !equal,
            "automatic versus explicit interface selection should not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_attempts_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: NonZeroU64::new(1).expect("one is non-zero"),
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: NonZeroU64::new(3).expect("three is non-zero"),
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different attempts values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_target_ipv4_address_differs() {
        // Arrange
        use std::net::Ipv4Addr;

        let subnet_only = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let single_target = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 50)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = subnet_only == single_target;

        // Assert
        assert!(
            !equal,
            "scan commands with different target IPv4 addresses must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_equal_when_target_ipv4_address_is_some_on_both_sides() {
        // Arrange
        use std::net::Ipv4Addr;

        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 7)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 7)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            equal,
            "scan commands with identical non-None targets should compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_both_targets_are_some_but_ipv4_differs() {
        // Arrange
        use std::net::Ipv4Addr;

        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 2)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different Some targets must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_vlan_identifier_differs() {
        // Arrange
        let untagged = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let tagged = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions {
                vlan_identifier: Ieee8021qVlanIdentifier::new(10),
                ..ScanWireOptions::default()
            },
        };

        // Act
        let equal = untagged == tagged;

        // Assert
        assert!(
            !equal,
            "scan commands with different VLAN identifiers must not compare equal"
        );
    }

    #[test]
    fn parse_cli_token_accepts_dest_case_insensitively() {
        // Arrange
        // Act
        let lower = ArpSenderProtocolAddress::parse_cli_token("dest");
        let upper = ArpSenderProtocolAddress::parse_cli_token("DEST");
        let mixed = ArpSenderProtocolAddress::parse_cli_token("Dest");

        // Assert
        assert_eq!(
            lower,
            Ok(ArpSenderProtocolAddress::DestinationTarget),
            "lowercase dest should select each target as ar$spa"
        );
        assert_eq!(upper, Ok(ArpSenderProtocolAddress::DestinationTarget));
        assert_eq!(mixed, Ok(ArpSenderProtocolAddress::DestinationTarget));
    }

    #[test]
    fn parse_cli_token_accepts_dotted_quad_including_unspecified() {
        // Arrange
        // Act
        let unspecified = ArpSenderProtocolAddress::parse_cli_token("0.0.0.0");
        let explicit = ArpSenderProtocolAddress::parse_cli_token("10.0.0.9");

        // Assert
        assert_eq!(
            unspecified,
            Ok(ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED)),
            "0.0.0.0 is an RFC 5227 ARP Probe sender protocol address"
        );
        assert_eq!(
            explicit,
            Ok(ArpSenderProtocolAddress::Explicit(Ipv4Addr::new(
                10, 0, 0, 9
            )))
        );
    }

    #[test]
    fn parse_cli_token_rejects_unknown_tokens() {
        // Arrange
        // Act
        let destination_word = ArpSenderProtocolAddress::parse_cli_token("destination");
        let not_ipv4 = ArpSenderProtocolAddress::parse_cli_token("not-an-address");

        // Assert
        let destination_error = destination_word.expect_err("destination is not dest");
        assert!(
            destination_error.contains("invalid --arpspa"),
            "error should name the flag, got: {destination_error}"
        );
        assert!(
            not_ipv4.is_err(),
            "non-IPv4 tokens should fail, got: {not_ipv4:?}"
        );
    }

    #[test]
    fn ipv4_address_for_target_selects_interface_explicit_or_destination() {
        // Arrange
        let interface = Ipv4Addr::new(192, 168, 1, 1);
        let target = Ipv4Addr::new(192, 168, 1, 50);
        let override_address = Ipv4Addr::new(10, 0, 0, 9);

        // Act
        let from_interface =
            ArpSenderProtocolAddress::Interface.ipv4_address_for_target(interface, target);
        let from_explicit = ArpSenderProtocolAddress::Explicit(override_address)
            .ipv4_address_for_target(interface, target);
        let from_probe = ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED)
            .ipv4_address_for_target(interface, target);
        let from_destination =
            ArpSenderProtocolAddress::DestinationTarget.ipv4_address_for_target(interface, target);

        // Assert
        assert_eq!(from_interface, interface);
        assert_eq!(from_explicit, override_address);
        assert_eq!(from_probe, Ipv4Addr::UNSPECIFIED);
        assert_eq!(from_destination, target);
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_sender_protocol_address_or_llc_snap_differs() {
        // Arrange
        let default = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions::default(),
        };
        let probe = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions {
                sender_protocol_address: ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED),
                ..ScanWireOptions::default()
            },
        };
        let llc_snap = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            wire: ScanWireOptions {
                llc_snap: true,
                ..ScanWireOptions::default()
            },
        };

        // Act
        let probe_differs = default == probe;
        let llc_differs = default == llc_snap;

        // Assert
        assert!(
            !probe_differs,
            "RFC 5227 Probe SPA must distinguish Scan commands"
        );
        assert!(
            !llc_differs,
            "RFC 1042 LLC/SNAP framing must distinguish Scan commands"
        );
    }

    #[test]
    fn parse_u16_cli_token_accepts_decimal_and_hexadecimal() {
        // Arrange
        // Act
        let decimal = parse_u16_cli_token("6");
        let hexadecimal = parse_u16_cli_token("0x0800");
        let too_large = parse_u16_cli_token("0x10000");

        // Assert
        assert_eq!(decimal, Ok(6));
        assert_eq!(hexadecimal, Ok(0x0800));
        assert!(
            too_large
                .expect_err("0x10000 exceeds u16")
                .contains("range"),
            "overflow should mention the integer range"
        );
    }

    #[test]
    fn parse_u8_cli_token_rejects_values_above_255() {
        // Arrange
        // Act
        let maximum = parse_u8_cli_token("0xff");
        let overflow = parse_u8_cli_token("256");

        // Assert
        assert_eq!(maximum, Ok(255));
        assert!(overflow.is_err(), "256 is outside an 8-bit field");
    }

    #[test]
    fn request_layout_uses_broadcast_and_interface_mac_by_default() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let spa = Ipv4Addr::new(192, 168, 1, 1);
        let tpa = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let layout =
            ScanWireOptions::default().address_resolution_request_layout(interface_mac, spa, tpa);

        // Assert
        assert_eq!(layout.ethernet_destination, MacAddress::BROADCAST);
        assert_eq!(layout.ethernet_source, interface_mac);
        assert_eq!(layout.sender_hardware, interface_mac);
        assert_eq!(layout.target_hardware, MacAddress::ZERO);
        assert_eq!(layout.hardware_type, 1);
        assert_eq!(layout.opcode, 1);
        assert_eq!(layout.sender_protocol, spa);
        assert_eq!(layout.target_protocol, tpa);
    }

    #[test]
    fn request_layout_applies_ethernet_and_arp_hardware_overrides() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let destination = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ethernet_source = MacAddress::from_octets([0x0A; 6]);
        let sender_hardware = MacAddress::from_octets([0xBB; 6]);
        let target_hardware = MacAddress::from_octets([0xCC; 6]);
        let wire = ScanWireOptions {
            ethernet_destination: Some(destination),
            ethernet_source: Some(ethernet_source),
            arp_hardware_type: 6,
            arp_operation: 1,
            arp_sender_hardware: Some(sender_hardware),
            arp_target_hardware: Some(target_hardware),
            ..ScanWireOptions::default()
        };

        // Act
        let layout = wire.address_resolution_request_layout(
            interface_mac,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );

        // Assert
        assert_eq!(layout.ethernet_destination, destination);
        assert_eq!(layout.ethernet_source, ethernet_source);
        assert_eq!(layout.sender_hardware, sender_hardware);
        assert_eq!(layout.target_hardware, target_hardware);
        assert_eq!(layout.hardware_type, 6);
        assert_ne!(layout.ethernet_source, layout.sender_hardware);
    }
}
