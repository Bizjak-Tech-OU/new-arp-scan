//! Ethernet II frame encoding and defensive parsing.
//!
//! Encoders return exactly 14 octets of header plus the caller-supplied payload with no automatic
//! minimum-frame padding. Parsers reject undersized buffers and outer IEEE 802.1Q tags so ARP
//! handling does not mis-parse VLAN-shifted layouts.

use crate::mac_address::MacAddress;

/// Length of an Ethernet II header (destination, source, `EtherType`).
pub const ETHERNET_II_HEADER_LENGTH: usize = 14;

/// `EtherType` for IEEE 802.1Q VLAN tagging (`ETH_P_8021Q` in `linux/if_ether.h`).
pub const ETHERNET_PROTOCOL_VLAN_TAG: u16 = 0x8100;

/// `EtherType` for IPv4 (`ETH_P_IP`).
pub const ETHERNET_PROTOCOL_IPV4: u16 = 0x0800;

/// `EtherType` for address resolution protocol (`ETH_P_ARP`).
pub const ETHERNET_PROTOCOL_ARP: u16 = 0x0806;

/// A borrowed view of a parsed Ethernet II frame (no VLAN stacking interpretation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedEthernetIiFrame<'a> {
    /// Destination hardware address.
    pub destination: MacAddress,
    /// Source hardware address.
    pub source: MacAddress,
    /// `EtherType` in host byte order (big-endian on the wire).
    pub ether_type: u16,
    /// Payload following the 14-byte header (may be empty).
    pub payload: &'a [u8],
}

/// Builds an Ethernet II frame with exactly `ETHERNET_II_HEADER_LENGTH + payload.len()` bytes.
///
/// No minimum-frame padding is applied; callers that require IEEE 802.3 minimum size must pad.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn encode_ethernet_ii_frame(
    destination: MacAddress,
    source: MacAddress,
    ether_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETHERNET_II_HEADER_LENGTH + payload.len());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parses a leading Ethernet II header and returns the payload slice.
///
/// VLAN-tagged frames whose outer `EtherType` is [`ETHERNET_PROTOCOL_VLAN_TAG`] are rejected so higher layers
/// do not misinterpret the inner `EtherType` as the outer frame type.
///
/// # Errors
///
/// Returns a static message when `frame_slice` is too short or when VLAN tagging is present.
///
/// # Panics
///
/// This function does not panic.
pub fn try_parse_ethernet_ii_frame(
    frame_slice: &[u8],
) -> Result<ParsedEthernetIiFrame<'_>, &'static str> {
    if frame_slice.len() < ETHERNET_II_HEADER_LENGTH {
        return Err("frame is shorter than Ethernet II header");
    }

    let mut destination_octets = [0u8; 6];
    destination_octets.copy_from_slice(&frame_slice[0..6]);
    let mut source_octets = [0u8; 6];
    source_octets.copy_from_slice(&frame_slice[6..12]);
    let ether_type = u16::from_be_bytes([frame_slice[12], frame_slice[13]]);

    if ether_type == ETHERNET_PROTOCOL_VLAN_TAG {
        return Err(
            "Ethernet frame uses IEEE 802.1Q tagging; plain untagged Ethernet II is required here",
        );
    }

    Ok(ParsedEthernetIiFrame {
        destination: MacAddress::from_octets(destination_octets),
        source: MacAddress::from_octets(source_octets),
        ether_type,
        payload: &frame_slice[ETHERNET_II_HEADER_LENGTH..],
    })
}

#[cfg(test)]
mod tests {
    use super::ETHERNET_II_HEADER_LENGTH;
    use super::ETHERNET_PROTOCOL_ARP;
    use super::ETHERNET_PROTOCOL_IPV4;
    use super::ETHERNET_PROTOCOL_VLAN_TAG;
    use super::encode_ethernet_ii_frame;
    use super::try_parse_ethernet_ii_frame;
    use crate::mac_address::MacAddress;

    #[test]
    fn encode_produces_exact_header_plus_payload_length() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);
        let payload = [1u8, 2, 3];

        // Act
        let frame = encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_ARP, &payload);

        // Assert
        assert_eq!(
            frame.len(),
            ETHERNET_II_HEADER_LENGTH + payload.len(),
            "encoder must not add padding"
        );
    }

    #[test]
    fn encode_places_destination_source_and_ether_type_in_network_order() {
        // Arrange
        let destination = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let source = MacAddress::from_octets([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        let payload: [u8; 0] = [];

        // Act
        let frame = encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_IPV4, &payload);

        // Assert
        assert_eq!(&frame[0..6], &destination.octets());
        assert_eq!(&frame[6..12], &source.octets());
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert!(
            frame[14..].is_empty(),
            "empty payload should yield empty tail"
        );
    }

    #[test]
    fn parse_round_trips_encoded_frame() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([9, 8, 7, 6, 5, 4]);
        let payload = [0xDE, 0xAD];
        let wire = encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_ARP, &payload);

        // Act
        let parsed = try_parse_ethernet_ii_frame(&wire).expect("encoded frame should parse");

        // Assert
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.payload, payload.as_slice());
    }

    #[test]
    fn parse_rejects_undersized_frame() {
        // Arrange
        let frame = [0u8; 10];

        // Act
        let outcome = try_parse_ethernet_ii_frame(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("short frame should fail"),
            "frame is shorter than Ethernet II header"
        );
    }

    #[test]
    fn parse_rejects_vlan_tagged_outer_header() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let inner = [0x81, 0x00, 0x00, 0x01, 0x08, 0x06];
        let wire =
            encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_VLAN_TAG, &inner);

        // Act
        let outcome = try_parse_ethernet_ii_frame(&wire);

        // Assert
        assert!(
            outcome
                .expect_err("VLAN tag should be rejected")
                .contains("802.1Q"),
            "error should mention VLAN tagging, got: {outcome:?}"
        );
    }
}
