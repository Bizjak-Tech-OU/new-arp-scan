//! Ethernet II frame encoding and defensive parsing.
//!
//! Encoders return the header octets plus the caller-supplied payload with no automatic
//! minimum-frame padding. Parsers distinguish IEEE 802.3 length fields from Ethernet II `EtherType`
//! values, decode either a single IEEE 802.1Q customer tag (TPID `0x8100`) or one IEEE 802.1Q
//! service tag (TPID `0x88A8`) wrapping exactly one customer tag, accept RFC 1042 LLC/SNAP ARP
//! encapsulation, and reject every other tag arrangement so higher layers never misread a shifted
//! layout.
//!
//! The two-tag form is the IEEE 802.1ad Provider Bridge model later incorporated into IEEE 802.1Q:
//! an outer service tag (S-TAG) whose TPID is the IANA-registered `EtherType` 34984 (`0x88A8`,
//! "IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)"), then an inner customer tag (C-TAG)
//! with TPID `0x8100`, each carrying its own Tag Control Information. Deeper stacks, the reverse
//! order, and the unofficial vendor TPIDs `0x9100` / `0x9200` / `0x9300` are all rejected.

use crate::mac_address::MacAddress;

/// Length of an untagged Ethernet II header (destination, source, `EtherType`).
pub const ETHERNET_II_HEADER_LENGTH: usize = 14;

/// Extra octets added by a single IEEE 802.1Q tag (TPID + TCI).
pub const IEEE_8021Q_TAG_LENGTH: usize = 4;

/// Extra octets added by an IEEE 802.1Q service tag stacked on a customer tag (S-TAG + C-TAG).
pub const IEEE_8021AD_TAG_STACK_LENGTH: usize = IEEE_8021Q_TAG_LENGTH * 2;

/// Length of an IEEE 802.2 LLC header plus RFC 1042 SNAP header (DSAP, SSAP, control, OUI, type).
pub const IEEE_8023_LLC_SNAP_HEADER_LENGTH: usize = 8;

/// IEEE 802.3 maximum MAC client data length; values in `0..=1500` in the length/type field are
/// lengths, not `EtherType` values.
pub const IEEE_8023_MAXIMUM_LENGTH: u16 = 1500;

/// Smallest length/type value that is an Ethernet II `EtherType` (IEEE 802.3 / RFC 5342).
pub const MINIMUM_ETHERNET_II_ETHERTYPE: u16 = 1536;

/// `EtherType` for IEEE 802.1Q VLAN tagging (`ETH_P_8021Q` in `linux/if_ether.h`).
pub const ETHERNET_PROTOCOL_VLAN_TAG: u16 = 0x8100;

/// `EtherType` for IEEE 802.1Q service VLAN tagging / IEEE 802.1ad S-TAG (`ETH_P_8021AD`).
///
/// IANA IEEE 802 Numbers registers decimal 34984 as "IEEE Std 802.1Q - Service VLAN tag identifier
/// (S-Tag)". Linux `linux/if_ether.h` spells the same value `ETH_P_8021AD`.
pub const ETHERNET_PROTOCOL_VLAN_TAG_SERVICE: u16 = 0x88A8;

/// Unofficial stacked-VLAN TPID `0x9100` still seen on some switches.
const ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9100: u16 = 0x9100;

/// Unofficial stacked-VLAN TPID `0x9200` still seen on some switches.
const ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9200: u16 = 0x9200;

/// Unofficial stacked-VLAN TPID `0x9300` still seen on some switches.
const ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9300: u16 = 0x9300;

/// IEEE 802.1Q VLAN identifier mask (12 bits) applied to the TCI.
pub const IEEE_8021Q_VLAN_IDENTIFIER_MASK: u16 = 0x0FFF;

/// A 12-bit IEEE 802.1Q VLAN identifier (`0..=4095`).
///
/// Identifier `0` is the null VID (priority tagging). Identifier `4095` is reserved in IEEE 802.1Q
/// but is still a legal 12-bit TCI field; this type permits the full range so operators can match
/// original `arp-scan --vlan` / `-Q` behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ieee8021qVlanIdentifier(u16);

impl Ieee8021qVlanIdentifier {
    /// Inclusive maximum 12-bit VLAN identifier.
    pub const MAXIMUM: u16 = IEEE_8021Q_VLAN_IDENTIFIER_MASK;

    /// Returns a VLAN identifier when `vlan_identifier` fits in 12 bits.
    #[must_use]
    pub const fn new(vlan_identifier: u16) -> Option<Self> {
        if vlan_identifier <= Self::MAXIMUM {
            Some(Self(vlan_identifier))
        } else {
            None
        }
    }

    /// Masks `tag_control_information` down to the 12-bit VID.
    #[must_use]
    pub const fn from_tag_control_information(tag_control_information: u16) -> Self {
        Self(tag_control_information & IEEE_8021Q_VLAN_IDENTIFIER_MASK)
    }

    /// Returns the 12-bit identifier in host byte order.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// IEEE 802.1Q Priority Code Point bit shift within the Tag Control Information field.
pub const IEEE_8021Q_PRIORITY_CODE_POINT_SHIFT: u16 = 13;

/// IEEE 802.1Q Drop Eligible Indicator bit within the Tag Control Information field.
pub const IEEE_8021Q_DROP_ELIGIBLE_INDICATOR_BIT: u16 = 1 << 12;

/// A 3-bit IEEE 802.1Q Priority Code Point (`0..=7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ieee8021qPriorityCodePoint(u8);

impl Ieee8021qPriorityCodePoint {
    /// Best-effort / default priority (PCP 0).
    pub const ZERO: Self = Self(0);

    /// Inclusive maximum 3-bit Priority Code Point.
    pub const MAXIMUM: u8 = 7;

    /// Returns a Priority Code Point when `priority_code_point` fits in 3 bits.
    #[must_use]
    pub const fn new(priority_code_point: u8) -> Option<Self> {
        if priority_code_point <= Self::MAXIMUM {
            Some(Self(priority_code_point))
        } else {
            None
        }
    }

    /// Returns the 3-bit priority in host byte order.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Masks `tag_control_information` down to the 3-bit PCP.
    #[must_use]
    pub const fn from_tag_control_information(tag_control_information: u16) -> Self {
        Self(((tag_control_information >> IEEE_8021Q_PRIORITY_CODE_POINT_SHIFT) & 0b111) as u8)
    }
}

/// Full IEEE 802.1Q Tag Control Information: PCP (3 bits), DEI (1 bit), and VID (12 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ieee8021qTagControlInformation {
    /// IEEE 802.1Q Priority Code Point (`0..=7`).
    pub priority_code_point: Ieee8021qPriorityCodePoint,
    /// IEEE 802.1Q Drop Eligible Indicator (formerly CFI).
    pub drop_eligible_indicator: bool,
    /// IEEE 802.1Q VLAN identifier (`0..=4095`).
    pub vlan_identifier: Ieee8021qVlanIdentifier,
}

impl Ieee8021qTagControlInformation {
    /// Builds Tag Control Information from a VLAN identifier with PCP 0 and DEI 0.
    #[must_use]
    pub const fn from_vlan_identifier(vlan_identifier: Ieee8021qVlanIdentifier) -> Self {
        Self {
            priority_code_point: Ieee8021qPriorityCodePoint::ZERO,
            drop_eligible_indicator: false,
            vlan_identifier,
        }
    }

    /// Builds Tag Control Information from PCP, DEI, and VID.
    #[must_use]
    pub const fn new(
        priority_code_point: Ieee8021qPriorityCodePoint,
        drop_eligible_indicator: bool,
        vlan_identifier: Ieee8021qVlanIdentifier,
    ) -> Self {
        Self {
            priority_code_point,
            drop_eligible_indicator,
            vlan_identifier,
        }
    }

    /// Encodes PCP, DEI, and VID as a 16-bit TCI in host byte order.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        let priority =
            (self.priority_code_point.as_u8() as u16) << IEEE_8021Q_PRIORITY_CODE_POINT_SHIFT;
        let drop_eligible = if self.drop_eligible_indicator {
            IEEE_8021Q_DROP_ELIGIBLE_INDICATOR_BIT
        } else {
            0
        };
        priority | drop_eligible | self.vlan_identifier.as_u16()
    }

    /// Decodes a 16-bit TCI into PCP, DEI, and VID.
    #[must_use]
    pub const fn from_tag_control_information(tag_control_information: u16) -> Self {
        Self {
            priority_code_point: Ieee8021qPriorityCodePoint::from_tag_control_information(
                tag_control_information,
            ),
            drop_eligible_indicator: (tag_control_information
                & IEEE_8021Q_DROP_ELIGIBLE_INDICATOR_BIT)
                != 0,
            vlan_identifier: Ieee8021qVlanIdentifier::from_tag_control_information(
                tag_control_information,
            ),
        }
    }
}

impl From<Ieee8021qVlanIdentifier> for Ieee8021qTagControlInformation {
    fn from(vlan_identifier: Ieee8021qVlanIdentifier) -> Self {
        Self::from_vlan_identifier(vlan_identifier)
    }
}

/// The VLAN tags carried by one transmitted frame.
///
/// This models the only two arrangements the encoders and parser accept, so a service tag without
/// its customer tag cannot be constructed: a lone IEEE 802.1Q customer tag (TPID `0x8100`), or an
/// IEEE 802.1Q service tag (TPID `0x88A8`) wrapping exactly one customer tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ieee8021qTagStack {
    /// One customer tag (C-TAG), TPID `0x8100`.
    Customer(Ieee8021qTagControlInformation),
    /// One service tag (S-TAG, TPID `0x88A8`) followed by one customer tag (C-TAG, TPID `0x8100`).
    ServiceAndCustomer {
        /// Outer service Tag Control Information.
        service: Ieee8021qTagControlInformation,
        /// Inner customer Tag Control Information.
        customer: Ieee8021qTagControlInformation,
    },
}

impl Ieee8021qTagStack {
    /// Builds the stack from an optional service TCI and a required customer TCI.
    #[must_use]
    pub const fn new(
        service: Option<Ieee8021qTagControlInformation>,
        customer: Ieee8021qTagControlInformation,
    ) -> Self {
        match service {
            Some(service) => Self::ServiceAndCustomer { service, customer },
            None => Self::Customer(customer),
        }
    }

    /// Returns the outer service Tag Control Information, when the stack carries an S-TAG.
    #[must_use]
    pub const fn service_tag_control_information(self) -> Option<Ieee8021qTagControlInformation> {
        match self {
            Self::Customer(_) => None,
            Self::ServiceAndCustomer { service, .. } => Some(service),
        }
    }

    /// Returns the inner customer Tag Control Information, which is always present.
    #[must_use]
    pub const fn customer_tag_control_information(self) -> Ieee8021qTagControlInformation {
        match self {
            Self::Customer(customer) | Self::ServiceAndCustomer { customer, .. } => customer,
        }
    }

    /// Octets this stack adds to an Ethernet header.
    #[must_use]
    pub const fn encoded_octet_count(self) -> usize {
        match self {
            Self::Customer(_) => IEEE_8021Q_TAG_LENGTH,
            Self::ServiceAndCustomer { .. } => IEEE_8021AD_TAG_STACK_LENGTH,
        }
    }

    /// Returns the outermost TPID this stack puts in the length/type field at offset 12.
    #[must_use]
    pub const fn outer_tag_protocol_identifier(self) -> u16 {
        match self {
            Self::Customer(_) => ETHERNET_PROTOCOL_VLAN_TAG,
            Self::ServiceAndCustomer { .. } => ETHERNET_PROTOCOL_VLAN_TAG_SERVICE,
        }
    }
}

impl From<Ieee8021qTagControlInformation> for Ieee8021qTagStack {
    fn from(customer: Ieee8021qTagControlInformation) -> Self {
        Self::Customer(customer)
    }
}

/// `EtherType` for IPv4 (`ETH_P_IP`).
pub const ETHERNET_PROTOCOL_IPV4: u16 = 0x0800;

/// `EtherType` for address resolution protocol (`ETH_P_ARP`).
pub const ETHERNET_PROTOCOL_ARP: u16 = 0x0806;

/// RFC 1042 LLC DSAP/SSAP value identifying SNAP (`0xAA`).
const LLC_SNAP_ADDRESS: u8 = 0xAA;

/// IEEE 802.2 unnumbered-information control value used with SNAP (`0x03`).
const LLC_UNNUMBERED_INFORMATION: u8 = 0x03;

/// RFC 1042 SNAP organizationally unique identifier (encoded `EtherType` follows).
const RFC_1042_SNAP_ORGANIZATIONALLY_UNIQUE_IDENTIFIER: [u8; 3] = [0, 0, 0];

/// How the payload following the MAC addresses is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetFraming {
    /// Ethernet II: length/type field is an `EtherType` (`>= 1536`).
    EthernetIi,
    /// IEEE 802.3 length field plus RFC 1042 LLC/SNAP.
    Ieee8023LlcSnap,
}

/// A borrowed view of a parsed Ethernet frame after optional 802.1Q and LLC/SNAP decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedEthernetFrame<'a> {
    /// Destination hardware address.
    pub destination: MacAddress,
    /// Source hardware address.
    pub source: MacAddress,
    /// Inner `EtherType` in host byte order (after stripping one 802.1Q tag and/or SNAP).
    pub ether_type: u16,
    /// IEEE 802.1Q service Tag Control Information when an outer S-TAG (TPID `0x88A8`) was
    /// present. Always accompanied by [`Self::vlan_tag`]; an S-TAG alone does not parse.
    pub service_vlan_tag: Option<Ieee8021qTagControlInformation>,
    /// IEEE 802.1Q customer Tag Control Information when a customer tag (TPID `0x8100`) was
    /// present, whether alone or inside a service tag.
    pub vlan_tag: Option<Ieee8021qTagControlInformation>,
    /// Customer IEEE 802.1Q VLAN identifier when a customer tag was present (low 12 TCI bits).
    pub vlan_identifier: Option<u16>,
    /// Framing used to reach [`Self::ether_type`].
    pub framing: EthernetFraming,
    /// Payload following the decoded headers (may be empty).
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

/// Builds an Ethernet II frame, optionally inserting an IEEE 802.1Q tag stack after the source
/// address.
///
/// When `vlan_tag` is [`None`], this matches [`encode_ethernet_ii_frame`]. For
/// [`Ieee8021qTagStack::Customer`] the header is destination, source, TPID `0x8100`, the 16-bit
/// TCI, inner `EtherType`, then `payload`. For [`Ieee8021qTagStack::ServiceAndCustomer`] the
/// header is destination, source, TPID `0x88A8`, the service TCI, TPID `0x8100`, the customer TCI,
/// inner `EtherType`, then `payload`. No minimum-frame padding is applied.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
    destination: MacAddress,
    source: MacAddress,
    vlan_tag: Option<Ieee8021qTagStack>,
    ether_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let Some(vlan_tag) = vlan_tag else {
        return encode_ethernet_ii_frame(destination, source, ether_type, payload);
    };

    let tagged_header_length = ETHERNET_II_HEADER_LENGTH + vlan_tag.encoded_octet_count();
    let mut frame = Vec::with_capacity(tagged_header_length + payload.len());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&source.octets());
    append_ieee_8021q_tag_stack(&mut frame, vlan_tag);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Builds an IEEE 802.3 frame with RFC 1042 LLC/SNAP encapsulation and an optional IEEE 802.1Q tag
/// stack.
///
/// Layout is destination, source, the optional tag stack (one customer tag, or a service tag then
/// a customer tag), a length field equal to LLC + SNAP + `payload` (the MAC client data following
/// the length field), then `AA AA 03 00 00 00`, the inner `EtherType`, then `payload`. VLAN tags
/// sit before the length field and are therefore not counted in it. No minimum-frame padding is
/// applied.
///
/// # Panics
///
/// This function does not panic. If LLC/SNAP plus `payload` exceeds an IEEE 802.3 length field, the
/// length is clamped to [`IEEE_8023_MAXIMUM_LENGTH`].
#[must_use]
pub fn encode_ieee_8023_rfc_1042_llc_snap_frame(
    destination: MacAddress,
    source: MacAddress,
    vlan_tag: Option<Ieee8021qTagStack>,
    ether_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mac_client_data_length = IEEE_8023_LLC_SNAP_HEADER_LENGTH.saturating_add(payload.len());
    let length_field = u16::try_from(mac_client_data_length).unwrap_or(IEEE_8023_MAXIMUM_LENGTH);
    let tagged_header_length =
        ETHERNET_II_HEADER_LENGTH + vlan_tag.map_or(0, Ieee8021qTagStack::encoded_octet_count);
    let mut frame =
        Vec::with_capacity(tagged_header_length + IEEE_8023_LLC_SNAP_HEADER_LENGTH + payload.len());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&source.octets());
    if let Some(vlan_tag) = vlan_tag {
        append_ieee_8021q_tag_stack(&mut frame, vlan_tag);
    }
    frame.extend_from_slice(&length_field.to_be_bytes());
    frame.push(LLC_SNAP_ADDRESS);
    frame.push(LLC_SNAP_ADDRESS);
    frame.push(LLC_UNNUMBERED_INFORMATION);
    frame.extend_from_slice(&RFC_1042_SNAP_ORGANIZATIONALLY_UNIQUE_IDENTIFIER);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Appends the tag stack after the source address.
///
/// The first TPID written is [`Ieee8021qTagStack::outer_tag_protocol_identifier`], so the octets on
/// the wire and the `sockaddr_ll` send protocol Linux uses for the same frame cannot disagree.
fn append_ieee_8021q_tag_stack(frame: &mut Vec<u8>, vlan_tag: Ieee8021qTagStack) {
    frame.extend_from_slice(&vlan_tag.outer_tag_protocol_identifier().to_be_bytes());
    if let Some(service) = vlan_tag.service_tag_control_information() {
        frame.extend_from_slice(&service.as_u16().to_be_bytes());
        frame.extend_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
    }
    frame.extend_from_slice(
        &vlan_tag
            .customer_tag_control_information()
            .as_u16()
            .to_be_bytes(),
    );
}

/// Parses destination, source, and the payload after Ethernet II, an optional IEEE 802.1Q tag
/// stack, and optional RFC 1042 LLC/SNAP headers.
///
/// Exactly two tag arrangements are accepted: one customer tag (TPID `0x8100`), or one service tag
/// (TPID `0x88A8`) immediately followed by one customer tag. Every other arrangement — a lone
/// service tag, a customer tag outside a service tag, three or more tags, and the unofficial
/// vendor TPIDs `0x9100` / `0x9200` / `0x9300` — is rejected so the inner `EtherType` is never read
/// from the wrong offset. IEEE 802.3 length values that are not RFC 1042 SNAP are rejected.
///
/// # Errors
///
/// Returns a static message when `frame_slice` is too short, when a tag header is truncated, when
/// tagging uses an unsupported TPID or an unsupported arrangement, or when a length field does not
/// introduce RFC 1042 SNAP.
///
/// # Panics
///
/// This function does not panic.
pub fn try_parse_ethernet_frame(
    frame_slice: &[u8],
) -> Result<ParsedEthernetFrame<'_>, &'static str> {
    if frame_slice.len() < ETHERNET_II_HEADER_LENGTH {
        return Err("frame is shorter than Ethernet II header");
    }

    let mut destination_octets = [0u8; 6];
    destination_octets.copy_from_slice(&frame_slice[0..6]);
    let mut source_octets = [0u8; 6];
    source_octets.copy_from_slice(&frame_slice[6..12]);
    let type_or_length = u16::from_be_bytes([frame_slice[12], frame_slice[13]]);

    let (vlan_tag, inner_type_or_length, payload_start) =
        decode_optional_ieee_8021q_tag_stack(frame_slice, type_or_length)?;
    let (ether_type, payload_start, framing) =
        decode_ethertype_or_ieee_8023_snap(frame_slice, inner_type_or_length, payload_start)?;

    let customer_tag = vlan_tag.map(Ieee8021qTagStack::customer_tag_control_information);
    Ok(ParsedEthernetFrame {
        destination: MacAddress::from_octets(destination_octets),
        source: MacAddress::from_octets(source_octets),
        ether_type,
        service_vlan_tag: vlan_tag.and_then(Ieee8021qTagStack::service_tag_control_information),
        vlan_tag: customer_tag,
        vlan_identifier: customer_tag.map(|tag| tag.vlan_identifier.as_u16()),
        framing,
        payload: &frame_slice[payload_start..],
    })
}

/// Reads the 16-bit field at `offset`, or reports `truncation_message` when it is not fully present.
fn read_u16_at(
    frame_slice: &[u8],
    offset: usize,
    truncation_message: &'static str,
) -> Result<u16, &'static str> {
    let field = frame_slice
        .get(offset..offset.saturating_add(2))
        .ok_or(truncation_message)?;
    Ok(u16::from_be_bytes([field[0], field[1]]))
}

/// Decodes the optional IEEE 802.1Q tag stack that follows the source address.
///
/// Returns the decoded stack, the length/type field that follows it, and the offset at which that
/// field's payload begins.
fn decode_optional_ieee_8021q_tag_stack(
    frame_slice: &[u8],
    type_or_length: u16,
) -> Result<(Option<Ieee8021qTagStack>, u16, usize), &'static str> {
    if is_unsupported_vlan_tpid(type_or_length) {
        return Err(UNSUPPORTED_QINQ_TPID_MESSAGE);
    }

    if type_or_length == ETHERNET_PROTOCOL_VLAN_TAG_SERVICE {
        return decode_ieee_8021ad_service_and_customer_tags(frame_slice);
    }

    if type_or_length != ETHERNET_PROTOCOL_VLAN_TAG {
        return Ok((None, type_or_length, ETHERNET_II_HEADER_LENGTH));
    }

    let customer = Ieee8021qTagControlInformation::from_tag_control_information(read_u16_at(
        frame_slice,
        ETHERNET_II_HEADER_LENGTH,
        "IEEE 802.1Q tag is truncated",
    )?);
    let payload_start = ETHERNET_II_HEADER_LENGTH + IEEE_8021Q_TAG_LENGTH;
    let inner_type_or_length = read_u16_at(
        frame_slice,
        ETHERNET_II_HEADER_LENGTH + 2,
        "IEEE 802.1Q tag is truncated",
    )?;

    if inner_type_or_length == ETHERNET_PROTOCOL_VLAN_TAG
        || inner_type_or_length == ETHERNET_PROTOCOL_VLAN_TAG_SERVICE
        || is_unsupported_vlan_tpid(inner_type_or_length)
    {
        return Err(STACKED_CUSTOMER_TAG_MESSAGE);
    }

    Ok((
        Some(Ieee8021qTagStack::Customer(customer)),
        inner_type_or_length,
        payload_start,
    ))
}

/// Decodes an IEEE 802.1Q service tag (`0x88A8`) that must be followed by exactly one customer tag.
fn decode_ieee_8021ad_service_and_customer_tags(
    frame_slice: &[u8],
) -> Result<(Option<Ieee8021qTagStack>, u16, usize), &'static str> {
    let service = Ieee8021qTagControlInformation::from_tag_control_information(read_u16_at(
        frame_slice,
        ETHERNET_II_HEADER_LENGTH,
        SERVICE_TAG_TRUNCATED_MESSAGE,
    )?);
    let customer_tag_protocol_identifier = read_u16_at(
        frame_slice,
        ETHERNET_II_HEADER_LENGTH + 2,
        SERVICE_TAG_TRUNCATED_MESSAGE,
    )?;
    if customer_tag_protocol_identifier != ETHERNET_PROTOCOL_VLAN_TAG {
        return Err(SERVICE_TAG_WITHOUT_CUSTOMER_TAG_MESSAGE);
    }

    let customer_tag_offset = ETHERNET_II_HEADER_LENGTH + IEEE_8021Q_TAG_LENGTH;
    let customer = Ieee8021qTagControlInformation::from_tag_control_information(read_u16_at(
        frame_slice,
        customer_tag_offset,
        CUSTOMER_TAG_TRUNCATED_MESSAGE,
    )?);
    let payload_start = ETHERNET_II_HEADER_LENGTH + IEEE_8021AD_TAG_STACK_LENGTH;
    let inner_type_or_length = read_u16_at(
        frame_slice,
        customer_tag_offset + 2,
        CUSTOMER_TAG_TRUNCATED_MESSAGE,
    )?;

    if inner_type_or_length == ETHERNET_PROTOCOL_VLAN_TAG
        || inner_type_or_length == ETHERNET_PROTOCOL_VLAN_TAG_SERVICE
        || is_unsupported_vlan_tpid(inner_type_or_length)
    {
        return Err(TAG_STACK_TOO_DEEP_MESSAGE);
    }

    Ok((
        Some(Ieee8021qTagStack::ServiceAndCustomer { service, customer }),
        inner_type_or_length,
        payload_start,
    ))
}

/// Rejection message for the unofficial vendor `QinQ` TPIDs `0x9100` / `0x9200` / `0x9300`.
const UNSUPPORTED_QINQ_TPID_MESSAGE: &str = "Ethernet frame uses an unofficial QinQ TPID; only IEEE 802.1Q 0x8100 and 0x88A8 tagging is supported here";

/// Rejection message for a customer tag directly inside another customer tag.
const STACKED_CUSTOMER_TAG_MESSAGE: &str = "Ethernet frame stacks a VLAN tag inside an IEEE 802.1Q customer tag; only 0x88A8 may wrap 0x8100";

/// Rejection message for a service tag whose Tag Control Information or inner TPID is cut off.
const SERVICE_TAG_TRUNCATED_MESSAGE: &str = "IEEE 802.1Q service tag is truncated";

/// Rejection message for a customer tag inside a service tag whose fields are cut off.
const CUSTOMER_TAG_TRUNCATED_MESSAGE: &str =
    "IEEE 802.1Q customer tag inside a service tag is truncated";

/// Rejection message for `0x88A8` that is not followed by a `0x8100` customer tag.
const SERVICE_TAG_WITHOUT_CUSTOMER_TAG_MESSAGE: &str =
    "IEEE 802.1Q service tag is not followed by an IEEE 802.1Q customer tag";

/// Rejection message for a third tag after a legal service-plus-customer pair.
const TAG_STACK_TOO_DEEP_MESSAGE: &str =
    "Ethernet frame stacks more than one IEEE 802.1Q service tag and one customer tag";

fn is_unsupported_vlan_tpid(type_or_length: u16) -> bool {
    type_or_length == ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9100
        || type_or_length == ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9200
        || type_or_length == ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9300
}

fn decode_ethertype_or_ieee_8023_snap(
    frame_slice: &[u8],
    type_or_length: u16,
    payload_start: usize,
) -> Result<(u16, usize, EthernetFraming), &'static str> {
    if type_or_length >= MINIMUM_ETHERNET_II_ETHERTYPE {
        return Ok((type_or_length, payload_start, EthernetFraming::EthernetIi));
    }

    if type_or_length > IEEE_8023_MAXIMUM_LENGTH {
        return Err(
            "length/type field is neither an IEEE 802.3 length nor an Ethernet II EtherType",
        );
    }

    decode_rfc_1042_llc_snap(frame_slice, payload_start)
}

fn decode_rfc_1042_llc_snap(
    frame_slice: &[u8],
    payload_start: usize,
) -> Result<(u16, usize, EthernetFraming), &'static str> {
    let snap_end = payload_start.saturating_add(IEEE_8023_LLC_SNAP_HEADER_LENGTH);
    let header = frame_slice
        .get(payload_start..snap_end)
        .ok_or("IEEE 802.3 LLC/SNAP header is truncated")?;

    if header[0] != LLC_SNAP_ADDRESS
        || header[1] != LLC_SNAP_ADDRESS
        || header[2] != LLC_UNNUMBERED_INFORMATION
    {
        return Err("IEEE 802.3 frame is not RFC 1042 LLC/SNAP");
    }

    let organizationally_unique_identifier = [header[3], header[4], header[5]];
    if organizationally_unique_identifier != RFC_1042_SNAP_ORGANIZATIONALLY_UNIQUE_IDENTIFIER {
        return Err("SNAP organizationally unique identifier is not RFC 1042 Ethernet");
    }

    let ether_type = u16::from_be_bytes([header[6], header[7]]);
    Ok((ether_type, snap_end, EthernetFraming::Ieee8023LlcSnap))
}

#[cfg(test)]
mod tests {
    use super::ETHERNET_II_HEADER_LENGTH;
    use super::ETHERNET_PROTOCOL_ARP;
    use super::ETHERNET_PROTOCOL_IPV4;
    use super::ETHERNET_PROTOCOL_VLAN_TAG;
    use super::ETHERNET_PROTOCOL_VLAN_TAG_SERVICE;
    use super::EthernetFraming;
    use super::IEEE_8021Q_TAG_LENGTH;
    use super::IEEE_8023_LLC_SNAP_HEADER_LENGTH;
    use super::IEEE_8023_MAXIMUM_LENGTH;
    use super::Ieee8021qPriorityCodePoint;
    use super::Ieee8021qTagControlInformation;
    use super::Ieee8021qTagStack;
    use super::Ieee8021qVlanIdentifier;
    use super::MINIMUM_ETHERNET_II_ETHERTYPE;
    use super::encode_ethernet_ii_frame;
    use super::encode_ethernet_ii_frame_with_optional_ieee_8021q_tag;
    use super::encode_ieee_8023_rfc_1042_llc_snap_frame;
    use super::try_parse_ethernet_frame;
    use crate::mac_address::MacAddress;

    #[test]
    fn vlan_identifier_new_accepts_twelve_bit_range_and_rejects_4096() {
        // Arrange
        // Act
        let zero = Ieee8021qVlanIdentifier::new(0);
        let maximum = Ieee8021qVlanIdentifier::new(Ieee8021qVlanIdentifier::MAXIMUM);
        let too_large = Ieee8021qVlanIdentifier::new(4096);

        // Assert
        assert_eq!(zero.map(Ieee8021qVlanIdentifier::as_u16), Some(0));
        assert_eq!(
            maximum.map(Ieee8021qVlanIdentifier::as_u16),
            Some(0x0FFF),
            "4095 is a legal 12-bit VLAN identifier"
        );
        assert!(
            too_large.is_none(),
            "4096 is outside the IEEE 802.1Q 12-bit VID field"
        );
    }

    #[test]
    fn tag_control_information_encodes_pcp_dei_and_vid() {
        // Arrange
        let vlan_identifier = Ieee8021qVlanIdentifier::new(0x044).expect("VID fits in 12 bits");
        let priority = Ieee8021qPriorityCodePoint::new(7).expect("PCP 7 fits in 3 bits");
        let tag = Ieee8021qTagControlInformation::new(priority, true, vlan_identifier);

        // Act
        let tci = tag.as_u16();
        let vid_only =
            Ieee8021qTagControlInformation::from_vlan_identifier(vlan_identifier).as_u16();

        // Assert
        assert_eq!(
            tci, 0xF044,
            "PCP 7, DEI 1, VID 0x044 should encode as TCI 0xF044"
        );
        assert_eq!(
            vid_only, 0x0044,
            "VID-only TCI should leave PCP and DEI zero"
        );
        assert_eq!(
            Ieee8021qTagControlInformation::from_tag_control_information(tci),
            tag,
            "TCI 0xF044 should decode back to PCP 7, DEI 1, VID 0x044"
        );
        assert!(
            Ieee8021qPriorityCodePoint::new(8).is_none(),
            "PCP 8 is outside the 3-bit field"
        );
    }

    #[test]
    fn encode_with_vlan_inserts_tpid_tci_and_inner_ether_type() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits in 12 bits");
        let payload = [0xAAu8, 0xBB];

        // Act
        let frame = encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
            destination,
            source,
            Some(Ieee8021qTagStack::Customer(
                Ieee8021qTagControlInformation::from_vlan_identifier(vlan_identifier),
            )),
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );

        // Assert
        assert_eq!(
            frame.len(),
            ETHERNET_II_HEADER_LENGTH + IEEE_8021Q_TAG_LENGTH + payload.len(),
            "tagged encoder must not add padding"
        );
        assert_eq!(&frame[12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(&frame[14..16], &10u16.to_be_bytes());
        assert_eq!(&frame[16..18], &ETHERNET_PROTOCOL_ARP.to_be_bytes());
        assert_eq!(&frame[18..], payload.as_slice());
        let parsed = try_parse_ethernet_frame(&frame).expect("tagged encoding should parse");
        assert_eq!(parsed.vlan_identifier, Some(10));
        assert_eq!(
            parsed.vlan_tag.map(Ieee8021qTagControlInformation::as_u16),
            Some(10)
        );
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.payload, payload.as_slice());
    }

    #[test]
    fn encode_rfc_1042_llc_snap_uses_ieee_8023_length_and_round_trips() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);
        let payload = [0xAAu8, 0xBB];
        let expected_length =
            u16::try_from(IEEE_8023_LLC_SNAP_HEADER_LENGTH + payload.len()).expect("fits u16");

        // Act
        let frame = encode_ieee_8023_rfc_1042_llc_snap_frame(
            destination,
            source,
            None,
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );

        // Assert
        assert_eq!(&frame[12..14], &expected_length.to_be_bytes());
        assert_eq!(&frame[14..17], &[0xAA, 0xAA, 0x03]);
        assert_eq!(&frame[17..20], &[0, 0, 0]);
        assert_eq!(&frame[20..22], &ETHERNET_PROTOCOL_ARP.to_be_bytes());
        let parsed = try_parse_ethernet_frame(&frame).expect("RFC 1042 SNAP encoding should parse");
        assert_eq!(parsed.framing, EthernetFraming::Ieee8023LlcSnap);
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.vlan_identifier, None);
        assert_eq!(parsed.vlan_tag, None);
        assert_eq!(parsed.payload, payload.as_slice());
    }

    #[test]
    fn encode_rfc_1042_llc_snap_with_vlan_places_length_after_tci() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);
        let payload = [0xAAu8, 0xBB];
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits in 12 bits");
        let expected_length =
            u16::try_from(IEEE_8023_LLC_SNAP_HEADER_LENGTH + payload.len()).expect("fits u16");

        // Act
        let frame = encode_ieee_8023_rfc_1042_llc_snap_frame(
            destination,
            source,
            Some(Ieee8021qTagStack::Customer(
                Ieee8021qTagControlInformation::from_vlan_identifier(vlan_identifier),
            )),
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );

        // Assert
        assert_eq!(&frame[12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(&frame[14..16], &10u16.to_be_bytes());
        assert_eq!(&frame[16..18], &expected_length.to_be_bytes());
        assert_eq!(&frame[18..21], &[0xAA, 0xAA, 0x03]);
        let parsed = try_parse_ethernet_frame(&frame).expect("tagged SNAP encoding should parse");
        assert_eq!(parsed.framing, EthernetFraming::Ieee8023LlcSnap);
        assert_eq!(parsed.vlan_identifier, Some(10));
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.payload, payload.as_slice());
        let vlan_tag = parsed.vlan_tag.expect("tagged SNAP should expose TCI");
        assert_eq!(
            vlan_tag.priority_code_point,
            Ieee8021qPriorityCodePoint::ZERO
        );
        assert!(!vlan_tag.drop_eligible_indicator);
    }

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
        let parsed = try_parse_ethernet_frame(&wire).expect("encoded frame should parse");

        // Assert
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.vlan_identifier, None);
        assert_eq!(parsed.vlan_tag, None);
        assert_eq!(parsed.framing, EthernetFraming::EthernetIi);
        assert_eq!(parsed.payload, payload.as_slice());
    }

    #[test]
    fn parse_rejects_undersized_frame() {
        // Arrange
        let frame = [0u8; 10];

        // Act
        let outcome = try_parse_ethernet_frame(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("short frame should fail"),
            "frame is shorter than Ethernet II header"
        );
    }

    #[test]
    fn parse_decodes_ieee_8021q_tagged_ethernet_ii_arp() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let payload = [0x08, 0x06, 0xAA];
        let tagged = encode_ethernet_ii_frame(
            destination,
            source,
            ETHERNET_PROTOCOL_VLAN_TAG,
            &[0x20, 0x0A, payload[0], payload[1], payload[2]],
        );

        // Act
        let parsed = try_parse_ethernet_frame(&tagged).expect("single 802.1Q tag should parse");

        // Assert
        assert_eq!(parsed.vlan_identifier, Some(0x00A));
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.framing, EthernetFraming::EthernetIi);
        assert_eq!(parsed.payload, &[0xAA]);
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.source, source);
        let vlan_tag = parsed
            .vlan_tag
            .expect("single 802.1Q tag should expose TCI");
        assert_eq!(vlan_tag.priority_code_point.as_u8(), 1);
        assert!(!vlan_tag.drop_eligible_indicator);
        assert_eq!(vlan_tag.vlan_identifier.as_u16(), 0x00A);
    }

    #[test]
    fn parse_decodes_ieee_8021q_priority_code_point_and_drop_eligible_indicator() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let tci: u16 = 0xF044;
        let mut payload = Vec::from(tci.to_be_bytes());
        payload.extend_from_slice(&ETHERNET_PROTOCOL_ARP.to_be_bytes());
        payload.push(0x99);
        let frame =
            encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_VLAN_TAG, &payload);

        // Act
        let parsed = try_parse_ethernet_frame(&frame).expect("802.1Q frame should parse");

        // Assert
        assert_eq!(parsed.vlan_identifier, Some(0x044));
        let vlan_tag = parsed
            .vlan_tag
            .expect("tagged frame should expose Tag Control Information");
        assert_eq!(vlan_tag.priority_code_point.as_u8(), 7);
        assert!(vlan_tag.drop_eligible_indicator);
        assert_eq!(vlan_tag.vlan_identifier.as_u16(), 0x044);
        assert_eq!(vlan_tag.as_u16(), 0xF044);
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.payload, &[0x99]);
    }

    #[test]
    fn parse_rejects_service_tag_that_is_not_followed_by_a_customer_tag() {
        // Arrange: 0x88A8, a service TCI, then ARP directly instead of a 0x8100 customer tag.
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let inner = [0x00, 0x01, 0x08, 0x06];
        let wire = encode_ethernet_ii_frame(
            destination,
            source,
            ETHERNET_PROTOCOL_VLAN_TAG_SERVICE,
            &inner,
        );

        // Act
        let outcome = try_parse_ethernet_frame(&wire);

        // Assert
        assert_eq!(
            outcome.expect_err("a lone service tag should be rejected"),
            "IEEE 802.1Q service tag is not followed by an IEEE 802.1Q customer tag",
            "an S-TAG without its C-TAG must not be read as untagged ARP"
        );
    }

    #[test]
    fn parse_rejects_stacked_ieee_8021q_tags() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let inner = [0x00, 0x01, 0x81, 0x00, 0x00, 0x02, 0x08, 0x06];
        let wire =
            encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_VLAN_TAG, &inner);

        // Act
        let outcome = try_parse_ethernet_frame(&wire);

        // Assert
        assert_eq!(
            outcome.expect_err("two stacked customer tags should be rejected"),
            "Ethernet frame stacks a VLAN tag inside an IEEE 802.1Q customer tag; only 0x88A8 may wrap 0x8100",
            "0x8100 inside 0x8100 is vendor QinQ, not the IEEE S-TAG/C-TAG pair"
        );
    }

    #[test]
    fn parse_rejects_ieee_8023_length_that_is_not_llc_snap() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let payload = [0xE0, 0xE0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        let wire =
            encode_ethernet_ii_frame(destination, source, IEEE_8023_MAXIMUM_LENGTH, &payload);

        // Act
        let outcome = try_parse_ethernet_frame(&wire);

        // Assert
        assert_eq!(
            outcome.expect_err("non-SNAP 802.3 should fail"),
            "IEEE 802.3 frame is not RFC 1042 LLC/SNAP"
        );
    }

    #[test]
    fn parse_accepts_rfc_1042_llc_snap_arp() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let mut payload = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06];
        payload.extend_from_slice(&[0x11, 0x22]);
        let wire = encode_ethernet_ii_frame(destination, source, 46, &payload);

        // Act
        let parsed = try_parse_ethernet_frame(&wire).expect("RFC 1042 SNAP ARP should parse");

        // Assert
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
        assert_eq!(parsed.framing, EthernetFraming::Ieee8023LlcSnap);
        assert_eq!(parsed.vlan_identifier, None);
        assert_eq!(parsed.vlan_tag, None);
        assert_eq!(parsed.payload, &[0x11, 0x22]);
    }

    #[test]
    fn parse_rejects_length_type_gap_between_8023_and_ethertype() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let gap_value = IEEE_8023_MAXIMUM_LENGTH + 1;
        assert!(
            gap_value < MINIMUM_ETHERNET_II_ETHERTYPE,
            "fixture must sit in the undefined gap"
        );
        let wire = encode_ethernet_ii_frame(destination, source, gap_value, &[]);

        // Act
        let outcome = try_parse_ethernet_frame(&wire);

        // Assert
        assert_eq!(
            outcome.expect_err("undefined length/type gap should fail"),
            "length/type field is neither an IEEE 802.3 length nor an Ethernet II EtherType"
        );
    }

    #[test]
    fn parse_rejects_truncated_ieee_8021q_tag() {
        // Arrange
        let mut frame = encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            ETHERNET_PROTOCOL_VLAN_TAG,
            &[0x00],
        );
        frame.truncate(ETHERNET_II_HEADER_LENGTH + 1);

        // Act
        let outcome = try_parse_ethernet_frame(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("truncated 802.1Q should fail"),
            "IEEE 802.1Q tag is truncated"
        );
    }

    #[test]
    fn parse_rejects_unofficial_qinq_tpids() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let inner = [0x00, 0x01, 0x08, 0x06];
        let tpids = [
            super::ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9100,
            super::ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9200,
            super::ETHERNET_PROTOCOL_VLAN_TAG_QINQ_9300,
        ];
        let frames: Vec<Vec<u8>> = tpids
            .iter()
            .map(|tpid| encode_ethernet_ii_frame(destination, source, *tpid, &inner))
            .collect();

        // Act
        let outcomes: Vec<_> = frames
            .iter()
            .map(|frame| try_parse_ethernet_frame(frame))
            .collect();

        // Assert
        for (tpid, outcome) in tpids.iter().zip(outcomes) {
            assert_eq!(
                outcome.expect_err("unofficial QinQ TPID should be rejected"),
                "Ethernet frame uses an unofficial QinQ TPID; only IEEE 802.1Q 0x8100 and 0x88A8 tagging is supported here",
                "TPID {tpid:#06x} is not an officially registered EtherType and must stay rejected"
            );
        }
    }

    #[test]
    fn parse_rejects_ieee_8021ad_as_inner_type_after_customer_tag() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let mut inner = Vec::from(0x000Au16.to_be_bytes());
        inner.extend_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG_SERVICE.to_be_bytes());
        inner.extend_from_slice(&ETHERNET_PROTOCOL_ARP.to_be_bytes());
        let frame =
            encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_VLAN_TAG, &inner);

        // Act
        let outcome = try_parse_ethernet_frame(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("a service tag inside a customer tag should be rejected"),
            "Ethernet frame stacks a VLAN tag inside an IEEE 802.1Q customer tag; only 0x88A8 may wrap 0x8100",
            "IEEE 802.1ad orders the S-TAG outside the C-TAG; the reverse order is not accepted"
        );
    }

    #[test]
    fn parse_rejects_truncated_rfc_1042_llc_snap_header() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let frame = encode_ethernet_ii_frame(destination, source, 46, &[0xAA, 0xAA, 0x03]);

        // Act
        let outcome = try_parse_ethernet_frame(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("truncated SNAP should fail"),
            "IEEE 802.3 LLC/SNAP header is truncated"
        );
    }

    #[test]
    fn parse_rejects_snap_when_organizationally_unique_identifier_is_not_rfc_1042() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let payload = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x01, 0x08, 0x06];
        let frame = encode_ethernet_ii_frame(destination, source, 46, &payload);

        // Act
        let outcome = try_parse_ethernet_frame(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("non-zero SNAP OUI should fail"),
            "SNAP organizationally unique identifier is not RFC 1042 Ethernet"
        );
    }

    #[test]
    fn parse_decodes_null_vlan_identifier_with_priority_code_point_and_drop_eligible() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let tag = Ieee8021qTagControlInformation::new(
            Ieee8021qPriorityCodePoint::new(7).expect("PCP 7 fits"),
            true,
            Ieee8021qVlanIdentifier::new(0).expect("null VID is legal"),
        );
        let frame = encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
            destination,
            source,
            Some(Ieee8021qTagStack::Customer(tag)),
            ETHERNET_PROTOCOL_ARP,
            &[0x99],
        );

        // Act
        let parsed = try_parse_ethernet_frame(&frame).expect("priority-tagged frame should parse");

        // Assert
        assert_eq!(tag.as_u16(), 0xF000);
        assert_eq!(parsed.vlan_identifier, Some(0));
        let vlan_tag = parsed.vlan_tag.expect("priority tagging should expose TCI");
        assert_eq!(vlan_tag.priority_code_point.as_u8(), 7);
        assert!(vlan_tag.drop_eligible_indicator);
        assert_eq!(vlan_tag.vlan_identifier.as_u16(), 0);
        assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
    }

    #[test]
    fn encode_rfc_1042_llc_snap_uses_maximum_ieee_8023_length_when_mac_client_data_is_full() {
        // Arrange
        let destination = MacAddress::BROADCAST;
        let source = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);
        let payload =
            vec![0xAAu8; usize::from(IEEE_8023_MAXIMUM_LENGTH) - IEEE_8023_LLC_SNAP_HEADER_LENGTH];

        // Act
        let frame = encode_ieee_8023_rfc_1042_llc_snap_frame(
            destination,
            source,
            None,
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );

        // Assert
        assert_eq!(&frame[12..14], &IEEE_8023_MAXIMUM_LENGTH.to_be_bytes());
        let parsed = try_parse_ethernet_frame(&frame).expect("maximum-length SNAP should parse");
        assert_eq!(parsed.framing, EthernetFraming::Ieee8023LlcSnap);
        assert_eq!(parsed.payload, payload.as_slice());
    }
}
