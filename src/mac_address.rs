//! Ethernet media access control address parsing and formatting.
//!
//! [`MacAddress`] is a small newtype over six octets used by scan results and packet helpers.

use std::fmt;

/// A 48-bit Ethernet hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress([u8; 6]);

/// Describes why a string could not be parsed as a [`MacAddress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacAddressParseError {
    /// The string did not contain exactly six colon-separated components.
    WrongComponentCount {
        /// Number of components expected (always six for Ethernet).
        expected_component_count: usize,
        /// Number of components observed after splitting on `:`.
        actual_component_count: usize,
    },
    /// A single component was not exactly two hexadecimal digits.
    ComponentWrongLength {
        /// Zero-based index of the offending component.
        component_index: usize,
        /// Observed component length in characters.
        observed_length: usize,
    },
    /// A character in a component was not valid hexadecimal.
    InvalidHexadecimalDigit {
        /// Zero-based index of the component containing the bad character.
        component_index: usize,
        /// The offending character.
        character: char,
    },
}

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddressParseError::WrongComponentCount {
                expected_component_count,
                actual_component_count,
            } => write!(
                formatter,
                "expected {expected_component_count} colon-separated components, got {actual_component_count}"
            ),
            MacAddressParseError::ComponentWrongLength {
                component_index,
                observed_length,
            } => write!(
                formatter,
                "component at index {component_index} must be exactly two hexadecimal digits, got length {observed_length}"
            ),
            MacAddressParseError::InvalidHexadecimalDigit {
                component_index,
                character,
            } => write!(
                formatter,
                "invalid hexadecimal digit `{character}` in component at index {component_index}"
            ),
        }
    }
}

impl std::error::Error for MacAddressParseError {}

fn parse_hexadecimal_nibble_for_mac_address_text(
    character: u8,
    component_index: usize,
) -> Result<u8, MacAddressParseError> {
    match character {
        b'0'..=b'9' => Ok(character - b'0'),
        b'a'..=b'f' => Ok(character - b'a' + 10),
        b'A'..=b'F' => Ok(character - b'A' + 10),
        _ => Err(MacAddressParseError::InvalidHexadecimalDigit {
            component_index,
            character: char::from(character),
        }),
    }
}

impl MacAddress {
    /// Broadcast destination address (all ones).
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// assert!(MacAddress::BROADCAST.is_broadcast());
    /// ```
    pub const BROADCAST: Self = Self([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    /// All-zero hardware address (for example target hardware in address resolution requests).
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// assert!(MacAddress::ZERO.is_zero());
    /// ```
    pub const ZERO: Self = Self([0u8; 6]);

    /// Wraps a fixed six-octet value as a [`MacAddress`].
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// let address = MacAddress::from_octets([0, 0, 0, 0, 0, 1]);
    /// assert_eq!(address.octets()[5], 1);
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub const fn from_octets(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Returns the six octets of this address.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// let octets = [10u8, 0, 0, 0, 0, 1];
    /// assert_eq!(MacAddress::from_octets(octets).octets(), octets);
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Returns `true` when this address is the Ethernet broadcast address.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// assert!(MacAddress::BROADCAST.is_broadcast());
    /// assert!(!MacAddress::ZERO.is_broadcast());
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self.0 == Self::BROADCAST.0
    }

    /// Returns `true` when every octet is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// assert!(MacAddress::ZERO.is_zero());
    /// assert!(!MacAddress::BROADCAST.is_zero());
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 6]
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets = self.0;
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        )
    }
}

impl TryFrom<&str> for MacAddress {
    type Error = MacAddressParseError;

    /// Parses a colon-separated Ethernet address string (six pairs of hexadecimal digits).
    ///
    /// # Errors
    ///
    /// Returns [`MacAddressParseError`] when the string is not exactly six `:`-separated components
    /// of two hexadecimal digits each.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// let address = MacAddress::try_from("aa:bb:cc:dd:ee:ff").expect("fixture should parse");
    /// assert_eq!(address.octets(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    /// ```
    fn try_from(text: &str) -> Result<Self, Self::Error> {
        const EXPECTED_COMPONENT_COUNT: usize = 6;
        let components: Vec<&str> = text.split(':').collect();
        if components.len() != EXPECTED_COMPONENT_COUNT {
            return Err(MacAddressParseError::WrongComponentCount {
                expected_component_count: EXPECTED_COMPONENT_COUNT,
                actual_component_count: components.len(),
            });
        }

        let mut octets = [0u8; EXPECTED_COMPONENT_COUNT];
        for (component_index, component) in components.iter().enumerate() {
            let trimmed = component.trim();
            if trimmed.len() != 2 {
                return Err(MacAddressParseError::ComponentWrongLength {
                    component_index,
                    observed_length: trimmed.len(),
                });
            }
            let pair_bytes = trimmed.as_bytes();
            let high_nibble =
                parse_hexadecimal_nibble_for_mac_address_text(pair_bytes[0], component_index)?;
            let low_nibble =
                parse_hexadecimal_nibble_for_mac_address_text(pair_bytes[1], component_index)?;
            octets[component_index] = (high_nibble << 4) | low_nibble;
        }

        Ok(Self(octets))
    }
}

impl From<[u8; 6]> for MacAddress {
    /// Converts raw octets into a [`MacAddress`].
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::MacAddress;
    ///
    /// let address = MacAddress::from([1, 2, 3, 4, 5, 6]);
    /// assert_eq!(address.octets(), [1, 2, 3, 4, 5, 6]);
    /// ```
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

#[cfg(test)]
mod tests {
    use super::MacAddress;
    use super::MacAddressParseError;

    #[test]
    fn display_formats_lowercase_colon_separated() {
        // Arrange
        let address = MacAddress::from_octets([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);

        // Act
        let formatted = address.to_string();

        // Assert
        assert_eq!(
            formatted, "00:1a:2b:3c:4d:5e",
            "display should be stable lowercase colon-separated notation"
        );
    }

    #[test]
    fn try_from_accepts_uppercase_hex() {
        // Arrange
        let text = "AA:BB:CC:DD:EE:FF";

        // Act
        let outcome = MacAddress::try_from(text);

        // Assert
        assert_eq!(
            outcome.expect("uppercase hex should parse"),
            MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
    }

    #[test]
    fn try_from_accepts_mixed_case_hex() {
        // Arrange
        let text = "aA:Bb:01:02:03:04";

        // Act
        let outcome = MacAddress::try_from(text);

        // Assert
        assert_eq!(
            outcome.expect("mixed case should parse"),
            MacAddress::from_octets([0xAA, 0xBB, 1, 2, 3, 4])
        );
    }

    #[test]
    fn try_from_rejects_wrong_component_count() {
        // Arrange
        let text = "00:11:22:33:44";

        // Act
        let outcome = MacAddress::try_from(text);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(MacAddressParseError::WrongComponentCount {
                    actual_component_count: 5,
                    ..
                })
            ),
            "expected wrong count error, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_rejects_empty_component() {
        // Arrange
        let text = "00:11::33:44:55";

        // Act
        let outcome = MacAddress::try_from(text);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(MacAddressParseError::ComponentWrongLength { .. })
            ),
            "empty component should fail length check, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_rejects_invalid_hex_digit() {
        // Arrange
        let text = "00:11:22:33:44:GZ";

        // Act
        let outcome = MacAddress::try_from(text);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(MacAddressParseError::InvalidHexadecimalDigit { .. })
            ),
            "non-hex character should fail, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_rejects_component_too_long() {
        // Arrange
        let text = "00:11:22:334:55:66";

        // Act
        let outcome = MacAddress::try_from(text);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(MacAddressParseError::ComponentWrongLength { .. })
            ),
            "three-digit component should fail, got: {outcome:?}"
        );
    }

    #[test]
    fn broadcast_detection_matches_all_ones() {
        // Arrange
        let address = MacAddress::BROADCAST;

        // Act
        // Assert
        assert!(address.is_broadcast(), "all-ones should be broadcast");
        assert!(!address.is_zero(), "broadcast is not zero");
    }

    #[test]
    fn zero_detection_matches_all_zeroes() {
        // Arrange
        let address = MacAddress::ZERO;

        // Act
        // Assert
        assert!(address.is_zero(), "all-zero should be zero");
        assert!(!address.is_broadcast(), "zero is not broadcast");
    }

    #[test]
    fn from_array_round_trips_through_octets() {
        // Arrange
        let octets = [1u8, 2, 3, 4, 5, 6];

        // Act
        let address = MacAddress::from(octets);

        // Assert
        assert_eq!(address.octets(), octets, "octets should round-trip");
    }
}
