//! Linux packet socket constants and the `sockaddr_ll` layout used with `bind(2)`.
/// Ethernet protocol identifier for ARP (`ETH_P_ARP` in `linux/if_ether.h`).
pub const ETHERNET_PROTOCOL_ARP: u16 = 0x0806;

/// ARP hardware type for Ethernet (`ARPHRD_ETHER` in `linux/if_arp.h`).
pub const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;

/// ARP opcode for a request (`ARPOP_REQUEST` in `linux/if_arp.h`).
pub const ARP_OPERATION_REQUEST: u16 = 1;

/// ARP opcode for a reply (`ARPOP_REPLY` in `linux/if_arp.h`).
pub const ARP_OPERATION_REPLY: u16 = 2;

const _: () = {
    assert!(ARP_OPERATION_REQUEST == 1);
    assert!(ARP_OPERATION_REPLY == 2);
};

/// `IFF_UP` from `linux/if.h` (interface is administratively up).
pub const INTERFACE_FLAG_UP: i32 = 0x0001;

/// `IFF_LOOPBACK` from `linux/if.h`.
pub const INTERFACE_FLAG_LOOPBACK: i32 = 0x0008;

/// `IFF_NOARP` from `linux/if.h`.
pub const INTERFACE_FLAG_NO_ARP: i32 = 0x0080;

/// Device-independent link-layer socket address (`struct sockaddr_ll` in `linux/if_packet.h`).
///
/// Field order and primitive widths match Linux `sockaddr_ll` as exposed by `libc`.
#[repr(C)]
pub struct SockAddressLinkLayer {
    /// Address family; always `AF_PACKET` when used with packet sockets.
    pub socket_address_family: libc::c_ushort,
    /// Physical-layer protocol in network byte order (for example [`ETHERNET_PROTOCOL_ARP`]).
    pub link_layer_protocol: libc::c_ushort,
    /// Interface index (`ifindex`).
    pub interface_index: libc::c_int,
    /// ARP hardware type (`ARPHRD_*`).
    pub hardware_type: libc::c_ushort,
    /// Packet type (`PACKET_*`, primarily for received packets).
    pub packet_type: libc::c_uchar,
    /// Length of [`Self::hardware_address`] bytes that are valid.
    pub hardware_address_length: libc::c_uchar,
    /// Physical-layer address bytes (for Ethernet, typically 6 octets used).
    pub hardware_address: [libc::c_uchar; 8],
}

impl SockAddressLinkLayer {
    /// Borrows this structure as a [`libc::sockaddr_ll`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn as_libc_sockaddr_link_layer(&self) -> &libc::sockaddr_ll {
        // SAFETY: `SockAddressLinkLayer` is `repr(C)` and matches `libc::sockaddr_ll` layout on
        // Linux targets where unit tests assert size, alignment, and field offsets.
        unsafe { &*std::ptr::from_ref(self).cast::<libc::sockaddr_ll>() }
    }
}

#[cfg(test)]
mod tests {
    use super::SockAddressLinkLayer;
    use super::{
        ARP_HARDWARE_TYPE_ETHERNET, ARP_OPERATION_REPLY, ARP_OPERATION_REQUEST,
        ETHERNET_PROTOCOL_ARP, INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP,
    };
    use std::mem::offset_of;

    #[test]
    fn sockaddr_ll_mirror_matches_libc_size_and_alignment() {
        // Arrange
        // Act
        let expected_size = std::mem::size_of::<libc::sockaddr_ll>();
        let expected_alignment = std::mem::align_of::<libc::sockaddr_ll>();
        let actual_size = std::mem::size_of::<SockAddressLinkLayer>();
        let actual_alignment = std::mem::align_of::<SockAddressLinkLayer>();

        // Assert
        assert_eq!(
            actual_size, expected_size,
            "SockAddressLinkLayer size should match libc::sockaddr_ll"
        );
        assert_eq!(
            actual_alignment, expected_alignment,
            "SockAddressLinkLayer alignment should match libc::sockaddr_ll"
        );
    }

    #[test]
    fn sockaddr_ll_mirror_matches_libc_field_offsets() {
        // Arrange
        // Act
        let pairs = [
            (
                offset_of!(SockAddressLinkLayer, socket_address_family),
                offset_of!(libc::sockaddr_ll, sll_family),
                "socket_address_family",
            ),
            (
                offset_of!(SockAddressLinkLayer, link_layer_protocol),
                offset_of!(libc::sockaddr_ll, sll_protocol),
                "link_layer_protocol",
            ),
            (
                offset_of!(SockAddressLinkLayer, interface_index),
                offset_of!(libc::sockaddr_ll, sll_ifindex),
                "interface_index",
            ),
            (
                offset_of!(SockAddressLinkLayer, hardware_type),
                offset_of!(libc::sockaddr_ll, sll_hatype),
                "hardware_type",
            ),
            (
                offset_of!(SockAddressLinkLayer, packet_type),
                offset_of!(libc::sockaddr_ll, sll_pkttype),
                "packet_type",
            ),
            (
                offset_of!(SockAddressLinkLayer, hardware_address_length),
                offset_of!(libc::sockaddr_ll, sll_halen),
                "hardware_address_length",
            ),
            (
                offset_of!(SockAddressLinkLayer, hardware_address),
                offset_of!(libc::sockaddr_ll, sll_addr),
                "hardware_address",
            ),
        ];

        // Assert
        for (ours, libc_offset, label) in pairs {
            assert_eq!(
                ours, libc_offset,
                "field offset mismatch for {label}: ours={ours} libc={libc_offset}"
            );
        }
    }

    #[test]
    fn ethernet_protocol_arp_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            ETHERNET_PROTOCOL_ARP as libc::c_int,
            libc::ETH_P_ARP,
            "ETHERNET_PROTOCOL_ARP should match libc::ETH_P_ARP"
        );
    }

    #[test]
    fn arp_hardware_type_ethernet_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            ARP_HARDWARE_TYPE_ETHERNET,
            libc::ARPHRD_ETHER,
            "ARP_HARDWARE_TYPE_ETHERNET should match libc::ARPHRD_ETHER"
        );
    }

    #[test]
    fn arp_operation_constants_match_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            ARP_OPERATION_REQUEST,
            libc::ARPOP_REQUEST,
            "ARP_OPERATION_REQUEST should match libc::ARPOP_REQUEST"
        );
        assert_eq!(
            ARP_OPERATION_REPLY,
            libc::ARPOP_REPLY,
            "ARP_OPERATION_REPLY should match libc::ARPOP_REPLY"
        );
    }

    #[test]
    fn interface_name_buffer_size_matches_libc() {
        // Arrange
        use crate::interface_validation;

        // Act
        let libc_value = libc::IFNAMSIZ as usize;

        // Assert
        assert_eq!(
            interface_validation::INTERFACE_NAME_BUFFER_SIZE,
            libc_value,
            "INTERFACE_NAME_BUFFER_SIZE should match libc::IFNAMSIZ"
        );
    }

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
