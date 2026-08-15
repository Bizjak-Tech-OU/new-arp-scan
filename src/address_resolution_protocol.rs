//! IPv4 address resolution protocol (ARP) over Ethernet serialization and reply parsing.
//!
//! Request frames are built with an explicit Ethernet II header, a 28-byte ARP payload matching
//! RFC 826, then zero-filled padding to the IEEE 802.3 minimum frame length without the frame
//! check sequence. Parsers accept Ethernet II, a single IEEE 802.1Q tag, and RFC 1042 LLC/SNAP,
//! and they reject RFC 5494 reserved hardware-type and opcode values.

use std::net::Ipv4Addr;

use crate::ethernet_frame::{
    ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IPV4, encode_ethernet_ii_frame,
    try_parse_ethernet_frame,
};
use crate::mac_address::MacAddress;

/// ARP hardware type for Ethernet (`ARPHRD_ETHER` in `linux/if_arp.h`, RFC 826 `ar$hrd`).
pub(crate) const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;

/// ARP opcode for a request (`ARPOP_REQUEST`, RFC 826 `ares_op$REQUEST`).
pub(crate) const ARP_OPERATION_REQUEST: u16 = 1;

/// ARP opcode for a reply (`ARPOP_REPLY`, RFC 826 `ares_op$REPLY`).
pub(crate) const ARP_OPERATION_REPLY: u16 = 2;

/// RFC 5494 reserved `ar$hrd` / `ar$op` value 0.
const ARP_RESERVED_FIELD_ZERO: u16 = 0;

/// RFC 5494 reserved `ar$hrd` / `ar$op` value 65535.
const ARP_RESERVED_FIELD_ALL_ONES: u16 = 65535;

/// RFC 826 `ar$hrd` offset in an IPv4-over-Ethernet ARP payload.
const ARP_HARDWARE_TYPE_OFFSET: usize = 0;

/// RFC 826 `ar$pro` offset.
const ARP_PROTOCOL_TYPE_OFFSET: usize = 2;

/// RFC 826 `ar$hln` offset.
const ARP_HARDWARE_LENGTH_OFFSET: usize = 4;

/// RFC 826 `ar$pln` offset.
const ARP_PROTOCOL_LENGTH_OFFSET: usize = 5;

/// RFC 826 `ar$op` offset.
const ARP_OPCODE_OFFSET: usize = 6;

/// RFC 826 `ar$sha` offset for Ethernet (`ar$hln` = 6).
const ARP_SENDER_HARDWARE_OFFSET: usize = 8;

/// RFC 826 `ar$spa` offset for Ethernet plus IPv4.
const ARP_SENDER_PROTOCOL_OFFSET: usize = 14;

/// RFC 826 `ar$tha` offset for Ethernet plus IPv4.
const ARP_TARGET_HARDWARE_OFFSET: usize = 18;

/// RFC 826 `ar$tpa` offset for Ethernet plus IPv4.
const ARP_TARGET_PROTOCOL_OFFSET: usize = 24;

const _: () = {
    assert!(ARP_OPERATION_REQUEST == 1);
    assert!(ARP_OPERATION_REPLY == 2);
    assert!(ARP_HARDWARE_TYPE_ETHERNET == 1);
};

/// Length of a minimal ARP packet for IPv4 over Ethernet (fixed field layout).
pub const ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH: usize = 28;

/// Ethernet hardware address length (`ar$hln`) for IEEE 802 48-bit addresses.
pub const ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH: u8 = 6;

/// IPv4 protocol address length (`ar$pln`).
pub const ARP_IPV4_PROTOCOL_ADDRESS_LENGTH: u8 = 4;

/// Minimum Ethernet frame length excluding the frame check sequence (IEEE 802.3).
pub const MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE: usize = 60;

/// IEEE 802.3 MAC client data minimum (46 octets) that ARP's 28-byte payload must be padded to.
pub const MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH: usize = 46;

const _: () = {
    assert!(
        14 + MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
            == MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
    );
    assert!(
        ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH
            + (MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
                - ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH)
            == MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
    );
};

/// Builds a minimum-length on-wire Ethernet frame carrying an IPv4 ARP request.
///
/// The Ethernet II header and 28-byte ARP payload are built first, then the buffer is zero-padded
/// to [`MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE`] octets for link-layer minimum
/// size. Sender protocol address is `source_ipv4_address` (RFC 826 request, not an RFC 5227 Probe).
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use new_arp_scan::{MacAddress, build_address_resolution_request_ethernet_frame};
///
/// let frame = build_address_resolution_request_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     Ipv4Addr::new(192, 168, 1, 1),
///     Ipv4Addr::new(192, 168, 1, 50),
/// );
/// assert_eq!(&frame[12..14], &[0x08, 0x06]);
/// assert_eq!(frame.len(), 60);
/// ```
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
    build_address_resolution_ethernet_frame(
        source_mac_address,
        source_ipv4_address,
        MacAddress::ZERO,
        target_ipv4_address,
        ARP_OPERATION_REQUEST,
    )
}

/// Builds an RFC 5227 ARP Probe: an ARP request with an all-zero sender IPv4 address.
///
/// Sender hardware address is the scanning interface MAC. Target hardware address is all zeroes.
/// Target protocol address is the address being probed.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use new_arp_scan::{MacAddress, build_address_resolution_probe_ethernet_frame};
///
/// let frame = build_address_resolution_probe_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     Ipv4Addr::new(192, 168, 1, 50),
/// );
/// assert_eq!(&frame[28..32], &[0, 0, 0, 0]);
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_probe_ethernet_frame(
    source_mac_address: MacAddress,
    target_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    build_address_resolution_ethernet_frame(
        source_mac_address,
        Ipv4Addr::UNSPECIFIED,
        MacAddress::ZERO,
        target_ipv4_address,
        ARP_OPERATION_REQUEST,
    )
}

/// Builds an RFC 5227 ARP Announcement: an ARP request whose sender and target IPv4 addresses are
/// both the claimed address.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use new_arp_scan::{MacAddress, build_address_resolution_announcement_ethernet_frame};
///
/// let claimed = Ipv4Addr::new(192, 168, 1, 50);
/// let frame = build_address_resolution_announcement_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     claimed,
/// );
/// assert_eq!(&frame[28..32], &claimed.octets());
/// assert_eq!(&frame[38..42], &claimed.octets());
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_announcement_ethernet_frame(
    source_mac_address: MacAddress,
    claimed_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    build_address_resolution_ethernet_frame(
        source_mac_address,
        claimed_ipv4_address,
        MacAddress::ZERO,
        claimed_ipv4_address,
        ARP_OPERATION_REQUEST,
    )
}

fn build_address_resolution_ethernet_frame(
    source_mac_address: MacAddress,
    source_ipv4_address: Ipv4Addr,
    target_mac_address: MacAddress,
    target_ipv4_address: Ipv4Addr,
    opcode: u16,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    let mut address_resolution_payload = [0u8; ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
    address_resolution_payload[ARP_HARDWARE_TYPE_OFFSET..ARP_HARDWARE_TYPE_OFFSET + 2]
        .copy_from_slice(&ARP_HARDWARE_TYPE_ETHERNET.to_be_bytes());
    address_resolution_payload[ARP_PROTOCOL_TYPE_OFFSET..ARP_PROTOCOL_TYPE_OFFSET + 2]
        .copy_from_slice(&ETHERNET_PROTOCOL_IPV4.to_be_bytes());
    address_resolution_payload[ARP_HARDWARE_LENGTH_OFFSET] = ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH;
    address_resolution_payload[ARP_PROTOCOL_LENGTH_OFFSET] = ARP_IPV4_PROTOCOL_ADDRESS_LENGTH;
    address_resolution_payload[ARP_OPCODE_OFFSET..ARP_OPCODE_OFFSET + 2]
        .copy_from_slice(&opcode.to_be_bytes());
    address_resolution_payload[ARP_SENDER_HARDWARE_OFFSET..ARP_SENDER_HARDWARE_OFFSET + 6]
        .copy_from_slice(&source_mac_address.octets());
    address_resolution_payload[ARP_SENDER_PROTOCOL_OFFSET..ARP_SENDER_PROTOCOL_OFFSET + 4]
        .copy_from_slice(&source_ipv4_address.octets());
    address_resolution_payload[ARP_TARGET_HARDWARE_OFFSET..ARP_TARGET_HARDWARE_OFFSET + 6]
        .copy_from_slice(&target_mac_address.octets());
    address_resolution_payload[ARP_TARGET_PROTOCOL_OFFSET..ARP_TARGET_PROTOCOL_OFFSET + 4]
        .copy_from_slice(&target_ipv4_address.octets());

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
/// A single IEEE 802.1Q tag and RFC 1042 LLC/SNAP encapsulation are accepted. Sender hardware and
/// protocol addresses (`ar$sha`, `ar$spa`) are the values returned, matching RFC 826.
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
    let parsed = try_parse_ethernet_frame(frame)?;
    if parsed.ether_type != ETHERNET_PROTOCOL_ARP {
        return Err("EtherType is not address resolution protocol");
    }

    if parsed.payload.len() < ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH {
        return Err("address resolution payload is shorter than IPv4 over Ethernet");
    }

    let arp = parsed.payload;
    let hardware_type = u16::from_be_bytes([
        arp[ARP_HARDWARE_TYPE_OFFSET],
        arp[ARP_HARDWARE_TYPE_OFFSET + 1],
    ]);
    if hardware_type == ARP_RESERVED_FIELD_ZERO || hardware_type == ARP_RESERVED_FIELD_ALL_ONES {
        return Err("address resolution hardware type is reserved by RFC 5494");
    }
    if hardware_type != ARP_HARDWARE_TYPE_ETHERNET {
        return Err("address resolution hardware type is not Ethernet");
    }

    let protocol_type = u16::from_be_bytes([
        arp[ARP_PROTOCOL_TYPE_OFFSET],
        arp[ARP_PROTOCOL_TYPE_OFFSET + 1],
    ]);
    if protocol_type != ETHERNET_PROTOCOL_IPV4 {
        return Err("address resolution protocol type is not IPv4");
    }

    if arp[ARP_HARDWARE_LENGTH_OFFSET] != ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH
        || arp[ARP_PROTOCOL_LENGTH_OFFSET] != ARP_IPV4_PROTOCOL_ADDRESS_LENGTH
    {
        return Err("address resolution address lengths are not Ethernet plus IPv4");
    }

    let opcode = u16::from_be_bytes([arp[ARP_OPCODE_OFFSET], arp[ARP_OPCODE_OFFSET + 1]]);
    if opcode == ARP_RESERVED_FIELD_ZERO || opcode == ARP_RESERVED_FIELD_ALL_ONES {
        return Err("address resolution opcode is reserved by RFC 5494");
    }
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
    sender_mac_octets
        .copy_from_slice(&arp[ARP_SENDER_HARDWARE_OFFSET..ARP_SENDER_HARDWARE_OFFSET + 6]);
    let sender_ipv4 = Ipv4Addr::new(
        arp[ARP_SENDER_PROTOCOL_OFFSET],
        arp[ARP_SENDER_PROTOCOL_OFFSET + 1],
        arp[ARP_SENDER_PROTOCOL_OFFSET + 2],
        arp[ARP_SENDER_PROTOCOL_OFFSET + 3],
    );

    Ok((sender_ipv4, MacAddress::from_octets(sender_mac_octets)))
}

#[cfg(test)]
mod tests {
    use super::ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
    use super::MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE;
    use super::MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH;
    use super::build_address_resolution_announcement_ethernet_frame;
    use super::build_address_resolution_probe_ethernet_frame;
    use super::build_address_resolution_request_ethernet_frame;
    use super::try_parse_address_resolution_reply_ipv4_over_ethernet;
    use crate::ethernet_frame::ETHERNET_II_HEADER_LENGTH;
    use crate::ethernet_frame::ETHERNET_PROTOCOL_VLAN_TAG;
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
    fn built_request_zero_pads_to_ieee_8023_minimum_without_frame_check_sequence() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        let header_and_arp =
            ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        assert_eq!(
            header_and_arp + 18,
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            "28-byte ARP plus 18 pad octets is the 46-octet IEEE 802.3 minimum client data"
        );
        assert!(
            frame[header_and_arp..].iter().all(|octet| *octet == 0),
            "IEEE 802.3 padding must be zeroes"
        );
        assert_eq!(
            frame.len() - ETHERNET_II_HEADER_LENGTH,
            MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
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
    fn rfc_5227_probe_uses_unspecified_sender_ipv4_and_zero_target_hardware() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame = build_address_resolution_probe_ethernet_frame(source_mac, target_ip);

        // Assert
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), 1, "opcode is request");
        assert_eq!(&arp[8..14], &source_mac.octets());
        assert_eq!(
            &arp[14..18],
            &[0, 0, 0, 0],
            "RFC 5227 Probe SPA is all zeros"
        );
        assert_eq!(&arp[18..24], &[0u8; 6], "RFC 5227 Probe THA SHOULD be zero");
        assert_eq!(&arp[24..28], &target_ip.octets());
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
        );
    }

    #[test]
    fn rfc_5227_announcement_sets_sender_and_target_ipv4_to_the_claimed_address() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let claimed = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame = build_address_resolution_announcement_ethernet_frame(source_mac, claimed);

        // Assert
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), 1, "opcode is request");
        assert_eq!(&arp[14..18], &claimed.octets());
        assert_eq!(&arp[24..28], &claimed.octets());
        assert_eq!(&arp[18..24], &[0u8; 6]);
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
    fn rejects_rfc_5494_reserved_hardware_type_zero() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start..arp_start + 2].copy_from_slice(&0u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved hardware type 0 should fail"),
            "address resolution hardware type is reserved by RFC 5494"
        );
    }

    #[test]
    fn rejects_rfc_5494_reserved_hardware_type_all_ones() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start..arp_start + 2].copy_from_slice(&65535u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved hardware type 65535 should fail"),
            "address resolution hardware type is reserved by RFC 5494"
        );
    }

    #[test]
    fn rejects_rfc_5494_reserved_opcode_zero() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&0u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved opcode 0 should fail"),
            "address resolution opcode is reserved by RFC 5494"
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
    fn parses_ieee_8021q_tagged_arp_reply() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        frame[14..16].copy_from_slice(&0x0064u16.to_be_bytes());
        frame[16] = 0x08;
        frame[17] = 0x06;
        let arp_start = 18;
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
        let (ip, mac) = outcome.expect("802.1Q tagged ARP reply should parse");
        assert_eq!(ip, source_ip);
        assert_eq!(mac, source_mac);
    }

    #[test]
    fn uses_arp_sender_hardware_when_ethernet_source_differs() {
        // Arrange
        let ethernet_source = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let arp_sender = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = reply_fixture(arp_sender, source_ip);
        frame[6..12].copy_from_slice(&ethernet_source.octets());

        // Act
        let (ip, mac) = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame)
            .expect("reply should parse using ar$sha");

        // Assert
        assert_eq!(ip, source_ip);
        assert_eq!(
            mac, arp_sender,
            "RFC 826 sender hardware address is ar$sha, not the Ethernet source"
        );
        assert_ne!(mac, ethernet_source);
    }

    #[test]
    fn parses_rfc_1042_llc_snap_arp_reply() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&46u16.to_be_bytes());
        frame[14] = 0xAA;
        frame[15] = 0xAA;
        frame[16] = 0x03;
        frame[17..20].copy_from_slice(&[0, 0, 0]);
        frame[20] = 0x08;
        frame[21] = 0x06;
        let arp_start = 22;
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
        let (ip, mac) = outcome.expect("RFC 1042 SNAP ARP reply should parse");
        assert_eq!(ip, source_ip);
        assert_eq!(mac, source_mac);
    }
}
