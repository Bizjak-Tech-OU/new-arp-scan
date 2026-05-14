//! IPv4 address resolution protocol (ARP) over Ethernet serialization and reply parsing.
//!
//! Request frames are built with an explicit Ethernet II header, a 28-byte ARP payload, then
//! zero-filled padding to the minimum Ethernet length required on the wire for this tool.

use std::net::Ipv4Addr;

use crate::ethernet_frame::{
    ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IPV4, encode_ethernet_ii_frame,
    try_parse_ethernet_ii_frame,
};
use crate::linux_packet::{ARP_HARDWARE_TYPE_ETHERNET, ARP_OPERATION_REPLY, ARP_OPERATION_REQUEST};
use crate::mac_address::MacAddress;

/// Length of a minimal ARP packet for IPv4 over Ethernet (fixed field layout).
pub const ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH: usize = 28;

/// Minimum Ethernet frame length excluding the frame check sequence (IEEE 802.3).
pub const MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE: usize = 60;

/// Builds a minimum-length on-wire Ethernet frame carrying an IPv4 ARP request.
///
/// The Ethernet II header and 28-byte ARP payload are built first, then the buffer is zero-padded
/// to [`MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE`] octets for link-layer minimum
/// size.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_request_ethernet_frame(
    source_mac_address: MacAddress,
    source_ipv4_address: Ipv4Addr,
    target_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    let mut address_resolution_payload = [0u8; ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
    address_resolution_payload[0..2].copy_from_slice(&ARP_HARDWARE_TYPE_ETHERNET.to_be_bytes());
    address_resolution_payload[2..4].copy_from_slice(&ETHERNET_PROTOCOL_IPV4.to_be_bytes());
    address_resolution_payload[4] = 6;
    address_resolution_payload[5] = 4;
    address_resolution_payload[6..8].copy_from_slice(&ARP_OPERATION_REQUEST.to_be_bytes());
    address_resolution_payload[8..14].copy_from_slice(&source_mac_address.octets());
    address_resolution_payload[14..18].copy_from_slice(&source_ipv4_address.octets());
    address_resolution_payload[18..24].copy_from_slice(&MacAddress::ZERO.octets());
    address_resolution_payload[24..28].copy_from_slice(&target_ipv4_address.octets());

    let ethernet_body = encode_ethernet_ii_frame(
        MacAddress::BROADCAST,
        source_mac_address,
        ETHERNET_PROTOCOL_ARP,
        &address_resolution_payload,
    );

    let mut frame = [0u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE];
    let copy_length = ethernet_body.len();
    frame[..copy_length].copy_from_slice(&ethernet_body);

    frame
}

/// Parses an IPv4 ARP reply from a raw Ethernet frame buffer.
///
/// Trailing padding beyond the ARP payload is ignored once the fixed ARP fields are validated.
///
/// # Errors
///
/// Returns a static message when the Ethernet header, `EtherType`, or ARP fields are invalid, when
/// the opcode is not a reply, or when the buffer is too short.
///
/// # Panics
///
/// This function does not panic.
pub fn try_parse_address_resolution_reply_ipv4_over_ethernet(
    frame: &[u8],
) -> Result<(Ipv4Addr, MacAddress), &'static str> {
    let parsed = try_parse_ethernet_ii_frame(frame)?;
    if parsed.ether_type != ETHERNET_PROTOCOL_ARP {
        return Err("EtherType is not address resolution protocol");
    }

    if parsed.payload.len() < ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH {
        return Err("address resolution payload is shorter than IPv4 over Ethernet");
    }

    let arp = parsed.payload;
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
    match opcode {
        ARP_OPERATION_REPLY => {}
        ARP_OPERATION_REQUEST => {
            return Err("address resolution opcode is a request, not a reply");
        }
        _ => {
            return Err("address resolution opcode is not a recognized reply");
        }
    }

    let mut sender_mac_octets = [0u8; 6];
    sender_mac_octets.copy_from_slice(&arp[8..14]);
    let sender_ipv4 = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);

    Ok((sender_ipv4, MacAddress::from_octets(sender_mac_octets)))
}

#[cfg(test)]
mod tests {
    use super::ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
    use super::MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE;
    use super::build_address_resolution_request_ethernet_frame;
    use super::try_parse_address_resolution_reply_ipv4_over_ethernet;
    use crate::ethernet_frame::ETHERNET_II_HEADER_LENGTH;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;

    #[test]
    fn built_request_has_expected_ethernet_and_address_resolution_fields() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        assert_eq!(&frame[0..6], &MacAddress::BROADCAST.octets());
        assert_eq!(
            &frame[6..12],
            &source_mac.octets(),
            "source MAC should match"
        );
        assert_eq!(&frame[12..14], &[0x08, 0x06], "EtherType should be ARP");
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
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
        let source_mac = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12] = 0x08;
        frame[13] = 0x06;
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
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
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 2),
        );

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("request opcode should not parse as reply"),
            "address resolution opcode is a request, not a reply"
        );
    }

    fn reply_fixture(source_mac: MacAddress, source_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12] = 0x08;
        frame[13] = 0x06;
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);
        frame
    }

    #[test]
    fn built_request_places_target_ipv4_and_zero_target_hardware_in_payload() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 2);
        let target_ip = Ipv4Addr::new(10, 0, 0, 99);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
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
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
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
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
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
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
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
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 4] = 5;

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("wrong hardware length should fail"),
            "address resolution address lengths are not Ethernet plus IPv4"
        );
    }

    #[test]
    fn rejects_unknown_arp_opcode() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&99u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("unknown opcode should fail"),
            "address resolution opcode is not a recognized reply"
        );
    }

    #[test]
    fn rejects_vlan_tagged_frame_before_arp_parse() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[14..20].copy_from_slice(&[0u8; 6]);
        frame[20] = 0x08;
        frame[21] = 0x06;
        let arp_start = 22;
        let arp_end = arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        let arp = &mut frame[arp_start..arp_end];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert!(
            outcome
                .expect_err("VLAN-tagged frame should be rejected")
                .contains("802.1Q"),
            "expected VLAN rejection, got: {outcome:?}"
        );
    }
}
