//! macOS link-layer constants used for interface classification.
//!
//! Mirrors the role of [`crate::linux_packet`] for the Berkeley Packet Filter backend: it holds
//! the interface-flag and hardware-type constants the macOS discovery code compares against, with
//! `libc` cross-checks where the platform exposes an authoritative value.

/// `IFF_UP` from `net/if.h` (interface is administratively up).
pub const INTERFACE_FLAG_UP: libc::c_int = libc::IFF_UP;

/// `IFF_LOOPBACK` from `net/if.h`.
pub const INTERFACE_FLAG_LOOPBACK: libc::c_int = libc::IFF_LOOPBACK;

/// `IFF_NOARP` from `net/if.h` (no address resolution protocol on this interface).
pub const INTERFACE_FLAG_NO_ARP: libc::c_int = libc::IFF_NOARP;

/// `IFT_ETHER` from `net/if_types.h` (Ethernet CSMA/CD link-layer type).
///
/// `libc` does not expose this constant on Apple targets, so it is defined here against the stable
/// BSD value and documented for auditing.
pub const INTERFACE_TYPE_ETHERNET: u8 = 0x06;

#[cfg(test)]
mod tests {
    use super::{INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP};

    #[test]
    fn interface_flag_constants_match_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            INTERFACE_FLAG_UP,
            libc::IFF_UP,
            "INTERFACE_FLAG_UP should match libc::IFF_UP"
        );
        assert_eq!(
            INTERFACE_FLAG_LOOPBACK,
            libc::IFF_LOOPBACK,
            "INTERFACE_FLAG_LOOPBACK should match libc::IFF_LOOPBACK"
        );
        assert_eq!(
            INTERFACE_FLAG_NO_ARP,
            libc::IFF_NOARP,
            "INTERFACE_FLAG_NO_ARP should match libc::IFF_NOARP"
        );
    }
}
