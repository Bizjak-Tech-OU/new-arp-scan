//! IEEE MA-L / MA-M / MA-S (and IAB) MAC prefix to vendor mapping.
//!
//! The file format matches `arp-scan`'s `ieee-oui.txt`: one mapping per line as
//! `<hex-prefix><TAB><vendor>`. Blank lines and `#` comments are ignored. Prefixes may be any even
//! or odd number of hexadecimal digits from 2 through 12 (one octet through a full 48-bit address).
//! IEEE MA-L assignments are 6 digits (24 bits), MA-M assignments are 7 digits (28 bits), and MA-S
//! (OUI-36) assignments are 9 digits (36 bits). Lookup uses longest-prefix match, so a MA-S row
//! wins over a overlapping MA-L row.

use std::collections::HashMap;
use std::path::Path;

use crate::mac_address::MacAddress;

/// Displayed when a registry is loaded but no prefix matches the address.
pub const UNKNOWN_MAC_VENDOR_NAME: &str = "(Unknown)";

/// Default mapping file name searched in the current directory, matching `arp-scan`.
pub const DEFAULT_MAC_VENDOR_FILE_NAME: &str = "ieee-oui.txt";

/// Longest-prefix IEEE MAC registry used to annotate scan results with a vendor name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacVendorRegistry {
    /// Uppercase hexadecimal prefix (2..=12 digits) to vendor name.
    prefixes: HashMap<String, String>,
}

/// Why a MAC vendor mapping file or text could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacVendorRegistryParseError {
    /// A non-comment line did not contain a tab-separated prefix and vendor.
    LineMissingTab {
        /// 1-based line number in the mapping text.
        line_number: usize,
    },
    /// The prefix was empty, longer than 12 hex digits, or contained a non-hexadecimal character.
    InvalidPrefix {
        /// 1-based line number in the mapping text.
        line_number: usize,
        /// Prefix text after stripping separators.
        prefix: String,
    },
}

impl std::fmt::Display for MacVendorRegistryParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacVendorRegistryParseError::LineMissingTab { line_number } => write!(
                formatter,
                "MAC vendor mapping line {line_number} is missing a tab separator"
            ),
            MacVendorRegistryParseError::InvalidPrefix {
                line_number,
                prefix,
            } => write!(
                formatter,
                "MAC vendor mapping line {line_number} has an invalid hexadecimal prefix `{prefix}`"
            ),
        }
    }
}

impl std::error::Error for MacVendorRegistryParseError {}

impl MacVendorRegistry {
    /// Parses `arp-scan` `ieee-oui.txt` text (IEEE MA-L / MA-M / MA-S prefixes).
    ///
    /// # Errors
    ///
    /// Returns [`MacVendorRegistryParseError`] when a non-comment line cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::{MacAddress, MacVendorRegistry};
    ///
    /// let registry = MacVendorRegistry::parse_ieee_oui_text("F4A475\tIntel Corporate\n")
    ///     .expect("fixture mapping should parse");
    /// let address = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x00, 0x00, 0x01]);
    /// assert_eq!(registry.vendor_name_for(address), Some("Intel Corporate"));
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn parse_ieee_oui_text(text: &str) -> Result<Self, MacVendorRegistryParseError> {
        let mut prefixes = HashMap::new();
        for (index, raw_line) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((prefix_field, vendor_field)) = line.split_once('\t') else {
                return Err(MacVendorRegistryParseError::LineMissingTab { line_number });
            };
            let prefix = normalize_hexadecimal_prefix(prefix_field);
            if prefix.len() < 2
                || prefix.len() > 12
                || !prefix.bytes().all(|octet| octet.is_ascii_hexdigit())
            {
                return Err(MacVendorRegistryParseError::InvalidPrefix {
                    line_number,
                    prefix,
                });
            }
            let vendor = vendor_field.trim();
            if vendor.is_empty() {
                return Err(MacVendorRegistryParseError::InvalidPrefix {
                    line_number,
                    prefix,
                });
            }
            prefixes.insert(prefix, vendor.to_string());
        }
        Ok(Self { prefixes })
    }

    /// Loads [`Self::parse_ieee_oui_text`] from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] when the file cannot be read, or an [`std::io::Error`] whose
    /// kind is [`std::io::ErrorKind::InvalidData`] when the text cannot be parsed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn load_from_path(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse_ieee_oui_text(&text).map_err(|parse_error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, parse_error)
        })
    }

    /// Loads [`DEFAULT_MAC_VENDOR_FILE_NAME`] from the current directory when that file exists.
    ///
    /// Missing files yield [`None`] so default scan output stays two-column. Parse errors are
    /// returned so operators can fix a present but invalid file.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] when the default file exists but cannot be read or parsed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn load_default_file_if_present() -> std::io::Result<Option<Self>> {
        let path = Path::new(DEFAULT_MAC_VENDOR_FILE_NAME);
        if !path.is_file() {
            return Ok(None);
        }
        Self::load_from_path(path).map(Some)
    }

    /// Returns the vendor name for the longest matching prefix, or [`None`] if nothing matches.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::{MacAddress, MacVendorRegistry};
    ///
    /// let text = "\
    /// F4A475\tMA-L vendor
    /// F4A4750\tMA-M vendor
    /// F4A475000\tMA-S vendor
    /// ";
    /// let registry = MacVendorRegistry::parse_ieee_oui_text(text).expect("fixture should parse");
    /// let address = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x00, 0x00, 0x01]);
    /// assert_eq!(registry.vendor_name_for(address), Some("MA-S vendor"));
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn vendor_name_for(&self, address: MacAddress) -> Option<&str> {
        let hex = format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            address.octets()[0],
            address.octets()[1],
            address.octets()[2],
            address.octets()[3],
            address.octets()[4],
            address.octets()[5],
        );
        for prefix_length in (2..=12).rev() {
            if let Some(vendor) = self.prefixes.get(&hex[..prefix_length]) {
                return Some(vendor.as_str());
            }
        }
        None
    }

    /// Returns how many prefix mappings are stored.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.prefixes.len()
    }
}

fn normalize_hexadecimal_prefix(prefix_field: &str) -> String {
    prefix_field
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|octet| char::from(octet).to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::MacVendorRegistry;
    use super::MacVendorRegistryParseError;
    use crate::mac_address::MacAddress;

    #[test]
    fn longest_prefix_prefers_ma_s_over_ma_m_over_ma_l() {
        // Arrange
        let text = "\
F4A475\tMA-L vendor
F4A4750\tMA-M vendor
F4A475000\tMA-S vendor
";
        let registry = MacVendorRegistry::parse_ieee_oui_text(text).expect("fixture should parse");
        let twenty_four_bit_prefix_address =
            MacAddress::from_octets([0xF4, 0xA4, 0x75, 0xF0, 0x00, 0x01]);
        let twenty_eight_bit_prefix_address =
            MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x0F, 0x00, 0x01]);
        let thirty_six_bit_prefix_address =
            MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x00, 0x00, 0x01]);

        // Act
        let thirty_six_bit_vendor = registry.vendor_name_for(thirty_six_bit_prefix_address);
        let twenty_eight_bit_vendor = registry.vendor_name_for(twenty_eight_bit_prefix_address);
        let twenty_four_bit_vendor = registry.vendor_name_for(twenty_four_bit_prefix_address);

        // Assert
        assert_eq!(thirty_six_bit_vendor, Some("MA-S vendor"));
        assert_eq!(twenty_eight_bit_vendor, Some("MA-M vendor"));
        assert_eq!(twenty_four_bit_vendor, Some("MA-L vendor"));
    }

    #[test]
    fn returns_none_when_no_prefix_matches() {
        // Arrange
        let registry = MacVendorRegistry::parse_ieee_oui_text("001122\tExample\n")
            .expect("fixture should parse");
        let address = MacAddress::from_octets([0xFF, 0xEE, 0xDD, 0, 0, 1]);

        // Act
        let outcome = registry.vendor_name_for(address);

        // Assert
        assert_eq!(outcome, None);
    }

    #[test]
    fn strips_colon_separators_from_prefix_field() {
        // Arrange
        let registry = MacVendorRegistry::parse_ieee_oui_text("00:11:22\tSeparated\n")
            .expect("colon-separated prefix should parse");
        let address = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Act
        let outcome = registry.vendor_name_for(address);

        // Assert
        assert_eq!(outcome, Some("Separated"));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        // Arrange
        let text = "\
# ieee-oui.txt
\n
AABBCC\tVendor
";
        let registry = MacVendorRegistry::parse_ieee_oui_text(text).expect("comments should skip");

        // Act
        // Assert
        assert_eq!(registry.mapping_count(), 1);
    }

    #[test]
    fn rejects_line_without_tab() {
        // Arrange
        let text = "AABBCC Vendor without tab\n";

        // Act
        let outcome = MacVendorRegistry::parse_ieee_oui_text(text);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(MacVendorRegistryParseError::LineMissingTab { line_number: 1 })
            ),
            "expected missing tab error, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_non_hexadecimal_prefix() {
        // Arrange
        let text = "GGHHII\tBad\n";

        // Act
        let outcome = MacVendorRegistry::parse_ieee_oui_text(text);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(MacVendorRegistryParseError::InvalidPrefix { line_number: 1, .. })
            ),
            "expected invalid prefix, got: {outcome:?}"
        );
    }

    #[test]
    fn last_duplicate_prefix_wins() {
        // Arrange
        let text = "\
001122\tFirst
001122\tSecond
";
        let registry =
            MacVendorRegistry::parse_ieee_oui_text(text).expect("duplicates should parse");
        let address = MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1]);

        // Act
        let outcome = registry.vendor_name_for(address);

        // Assert
        assert_eq!(outcome, Some("Second"));
    }
}
