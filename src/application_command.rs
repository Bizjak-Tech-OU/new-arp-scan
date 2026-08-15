//! Application commands accepted by [`crate::run`].

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::ethernet_frame::Ieee8021qVlanIdentifier;

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

/// On-wire options for transmitted ARP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanWireOptions {
    /// When set, transmit a single IEEE 802.1Q tag with this VLAN identifier (PCP and DEI zero).
    pub vlan_identifier: Option<Ieee8021qVlanIdentifier>,
    /// Value encoded in RFC 826 `ar$spa`.
    pub sender_protocol_address: ArpSenderProtocolAddress,
    /// When true, encapsulate ARP in IEEE 802.3 with RFC 1042 LLC/SNAP instead of Ethernet II.
    pub llc_snap: bool,
}

impl Default for ScanWireOptions {
    fn default() -> Self {
        Self {
            vlan_identifier: None,
            sender_protocol_address: ArpSenderProtocolAddress::Interface,
            llc_snap: false,
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
        /// IEEE 802.1Q tag, RFC 826 `ar$spa` override, and RFC 1042 LLC/SNAP framing.
        wire: ScanWireOptions,
    },
    /// List interfaces that are usable for ARP scanning on Linux.
    UsableInterfacesList,
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationCommand, ArpSenderProtocolAddress, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING,
        DEFAULT_SCAN_TIMEOUT, ScanWireOptions,
    };
    use crate::ethernet_frame::Ieee8021qVlanIdentifier;
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
}
