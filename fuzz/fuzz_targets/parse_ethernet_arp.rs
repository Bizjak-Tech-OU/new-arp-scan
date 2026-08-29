//! Fuzz the Ethernet, IEEE 802.1Q tag stack, RFC 1042 LLC/SNAP, and RFC 826 ARP decode chain.
//!
//! Every octet the scanner parses arrives from the network, so this is the crate's untrusted-input
//! boundary (constitution section 9). `try_parse_address_resolution_reply_ipv4_over_ethernet` is
//! the public entry point that drives the whole chain: Ethernet header, then either one IEEE
//! 802.1Q customer tag or an IEEE 802.1ad service tag wrapping one customer tag, then either an
//! `EtherType` or an IEEE 802.3 length with RFC 1042 SNAP, then the ARP PDU.
//!
//! The parser is total: every input must yield `Ok` or a static `Err`, never a panic, an
//! out-of-bounds slice, or an arithmetic overflow.

#![no_main]

use libfuzzer_sys::fuzz_target;
use new_arp_scan::try_parse_address_resolution_reply_ipv4_over_ethernet;

fuzz_target!(|data: &[u8]| {
    if let Ok((sender_ipv4_address, sender_hardware_address)) =
        try_parse_address_resolution_reply_ipv4_over_ethernet(data)
    {
        // Force the decoded values to be materialized so the optimizer cannot elide the parse.
        std::hint::black_box((sender_ipv4_address, sender_hardware_address));
    }
});
