//! Ethernet framing and address resolution protocol helpers for IPv4 over Ethernet.

use std::net::Ipv4Addr;

/// Ethernet protocol identifier for ARP (`ETH_P_ARP` in `linux/if_ether.h`).
const ETHERNET_PROTOCOL_ARP: u16 = 0x0806;

/// ARP hardware type for Ethernet (`ARPHRD_ETHER` / `1`).
const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;

/// ARP opcode for a request (`ARPOP_REQUEST`).
const ARP_OPERATION_REQUEST: u16 = 1;

/// ARP opcode for a reply (`ARPOP_REPLY`).
const ARP_OPERATION_REPLY: u16 = 2;

/// Length of an Ethernet header (destination, source, `EtherType`).
pub const ETHERNET_HEADER_LENGTH: usize = 14;

/// Length of a minimal Ethernet payload carrying IPv4 address resolution protocol data.
pub const ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH: usize = 28;

/// Minimum Ethernet frame length excluding the frame check sequence (see IEEE 802.3).
pub const MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE: usize = 60;

/// `EtherType` for IPv4 (`ETH_P_IP` / `0x0800`).
pub const ETHERNET_PROTOCOL_IPV4: u16 = 0x0800;

/// Broadcast Ethernet destination address.
pub const ETHERNET_BROADCAST_MAC_ADDRESS: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Zero-filled Ethernet hardware address used in address resolution requests.
pub const ZERO_ETHERNET_MAC_ADDRESS: [u8; 6] = [0x00; 6];

/// Builds a minimum-length Ethernet frame carrying an IPv4 address resolution protocol request.
///
/// # Panics
///
/// This function does not panic.
pub fn build_address_resolution_request_ethernet_frame(
    source_mac_address: [u8; 6],
    source_ipv4_address: Ipv4Addr,
    target_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    let mut frame = [0u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE];
    frame[0..6].copy_from_slice(&ETHERNET_BROADCAST_MAC_ADDRESS);
    frame[6..12].copy_from_slice(&source_mac_address);
    frame[12] = (ETHERNET_PROTOCOL_ARP >> 8) as u8;
    frame[13] = (ETHERNET_PROTOCOL_ARP & 0xFF) as u8;

    let arp_offset = ETHERNET_HEADER_LENGTH;
    let arp = &mut frame[arp_offset..arp_offset + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
    arp[0..2].copy_from_slice(&ARP_HARDWARE_TYPE_ETHERNET.to_be_bytes());
    arp[2..4].copy_from_slice(&ETHERNET_PROTOCOL_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_OPERATION_REQUEST.to_be_bytes());
    arp[8..14].copy_from_slice(&source_mac_address);
    arp[14..18].copy_from_slice(&source_ipv4_address.octets());
    arp[18..24].copy_from_slice(&ZERO_ETHERNET_MAC_ADDRESS);
    arp[24..28].copy_from_slice(&target_ipv4_address.octets());

    frame
}

/// Attempts to parse an IPv4 address resolution protocol reply from `frame`.
///
/// Returns the sender protocol address and sender hardware address when `frame` is a well-formed
/// Ethernet payload carrying an IPv4 reply.
///
/// # Panics
///
/// This function does not panic.
pub fn try_parse_address_resolution_reply_ipv4_over_ethernet(
    frame: &[u8],
) -> Result<(Ipv4Addr, [u8; 6]), &'static str> {
    if frame.len() < ETHERNET_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH {
        return Err("frame is shorter than Ethernet header plus address resolution payload");
    }

    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != ETHERNET_PROTOCOL_ARP {
        return Err("EtherType is not address resolution protocol");
    }

    let arp = &frame[ETHERNET_HEADER_LENGTH..];
    let hardware_type = u16::from_be_bytes([arp[0], arp[1]]);
    if hardware_type != ARP_HARDWARE_TYPE_ETHERNET {
        return Err("address resolution hardware type is not Ethernet");
    }

    let protocol_type = u16::from_be_bytes([arp[2], arp[3]]);
    if protocol_type != ETHERNET_PROTOCOL_IPV4 {
        return Err("address resolution protocol type is not IPv4");
    }

    if arp[4] != 6 || arp[5] != 4 {
        return Err("address resolution address lengths are not Ethernet plus IPv4");
    }

    let opcode = u16::from_be_bytes([arp[6], arp[7]]);
    if opcode != ARP_OPERATION_REPLY {
        return Err("address resolution opcode is not a reply");
    }

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&arp[8..14]);
    let sender_ipv4 = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);

    Ok((sender_ipv4, sender_mac))
}

#[cfg(test)]
mod tests {
    use super::ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
    use super::ETHERNET_HEADER_LENGTH;
    use super::MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE;
    use super::build_address_resolution_request_ethernet_frame;
    use super::try_parse_address_resolution_reply_ipv4_over_ethernet;
    use std::net::Ipv4Addr;

    #[test]
    fn built_request_has_expected_ethernet_and_address_resolution_fields() {
        // Arrange
        let source_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        assert_eq!(&frame[0..6], &[0xFF; 6], "destination should be broadcast");
        assert_eq!(&frame[6..12], &source_mac, "source MAC should match");
        assert_eq!(&frame[12..14], &[0x08, 0x06], "EtherType should be ARP");
        let arp = &frame[ETHERNET_HEADER_LENGTH..];
        assert_eq!(
            u16::from_be_bytes([arp[0], arp[1]]),
            1,
            "hardware type should be Ethernet"
        );
        assert_eq!(
            u16::from_be_bytes([arp[6], arp[7]]),
            1,
            "opcode should be request"
        );
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            "frame should meet minimum Ethernet size"
        );
    }

    #[test]
    fn parses_valid_reply_with_trailing_padding() {
        // Arrange
        let source_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        let arp_start = ETHERNET_HEADER_LENGTH;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac);
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        let (ip, mac) = outcome.expect("valid reply should parse");
        assert_eq!(ip, source_ip, "sender IPv4 should match");
        assert_eq!(mac, source_mac, "sender MAC should match");
    }

    #[test]
    fn rejects_frame_that_is_too_short() {
        // Arrange
        let frame = [0u8; 20];

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert!(outcome.is_err(), "short frame should be rejected");
    }

    #[test]
    fn rejects_non_reply_opcode() {
        // Arrange
        let frame = build_address_resolution_request_ethernet_frame(
            [1, 2, 3, 4, 5, 6],
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 2),
        );

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert!(outcome.is_err(), "request opcode should not parse as reply");
    }

    fn reply_fixture(source_mac: [u8; 6], source_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        let arp_start = ETHERNET_HEADER_LENGTH;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac);
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);
        frame
    }

    #[test]
    fn built_request_places_target_ipv4_and_zero_target_hardware_in_payload() {
        // Arrange
        let source_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let source_ip = Ipv4Addr::new(10, 0, 0, 2);
        let target_ip = Ipv4Addr::new(10, 0, 0, 99);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        let arp = &frame[ETHERNET_HEADER_LENGTH..];
        assert_eq!(&arp[14..18], &source_ip.octets());
        assert_eq!(
            &arp[18..24],
            &[0u8; 6],
            "target hardware should be zero in requests"
        );
        assert_eq!(&arp[24..28], &target_ip.octets());
    }

    #[test]
    fn rejects_reply_when_ether_type_is_not_arp() {
        // Arrange
        let mut frame = reply_fixture([9; 6], Ipv4Addr::new(10, 0, 0, 2));
        frame[12] = 0x08;
        frame[13] = 0x00;

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("wrong EtherType should fail"),
            "EtherType is not address resolution protocol"
        );
    }

    #[test]
    fn rejects_reply_when_arp_hardware_type_is_not_ethernet() {
        // Arrange
        let mut frame = reply_fixture([9; 6], Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_HEADER_LENGTH;
        frame[arp_start..arp_start + 2].copy_from_slice(&2u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("non-Ethernet hardware type should fail"),
            "address resolution hardware type is not Ethernet"
        );
    }

    #[test]
    fn rejects_reply_when_arp_protocol_type_is_not_ipv4() {
        // Arrange
        let mut frame = reply_fixture([9; 6], Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_HEADER_LENGTH;
        frame[arp_start + 2..arp_start + 4].copy_from_slice(&0x86ddu16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("non-IPv4 protocol type should fail"),
            "address resolution protocol type is not IPv4"
        );
    }

    #[test]
    fn rejects_reply_when_arp_address_lengths_are_not_ethernet_ipv4() {
        // Arrange
        let mut frame = reply_fixture([9; 6], Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_HEADER_LENGTH;
        frame[arp_start + 4] = 5;

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("wrong hardware length should fail"),
            "address resolution address lengths are not Ethernet plus IPv4"
        );
    }
}
