//! Linux entry points for address resolution scanning.
//!
//! These thin wrappers validate the interface and target, open a Linux `AF_PACKET`
//! [`crate::link_layer_backend::LinkLayerEndpoint`], and delegate the OS-agnostic scheduling and
//! reply collection to [`crate::scanner`].

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::application_outcome::ScanOutcome;
use crate::error::AppError;
use crate::ipv4_subnet::validate_strict_interior_scan_target_ipv4_address;
use crate::linux_interface_discovery::discover_interface_scan_addresses;
use crate::linux_socket::{
    open_linux_link_layer_endpoint, validated_interface_index_for_arp_scanning,
};
use crate::scanner::{self, ArpReplyAcceptance};

/// Performs a full-subnet IPv4 address resolution scan on `interface_name`.
///
/// `receive_timeout_after_last_request` bounds how long the scanner waits for replies after the
/// last request is sent. `pacing_between_scan_rounds` is the delay after each full round of
/// target sends except the final round. `scan_round_count` is how many such rounds run.
///
/// # Errors
///
/// Returns [`AppError`] when interface discovery, subnet validation, socket setup, or the receive
/// poll loop fails fatally.
///
/// # Panics
///
/// This function does not panic.
pub fn perform_arp_scan(
    interface_name: &str,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
) -> Result<ScanOutcome, AppError> {
    // Validate interface usability (loopback / down / NOARP rejection) and the subnet before
    // opening any socket; `open_linux_link_layer_endpoint` repeats the interface validation while
    // acquiring the descriptor.
    validated_interface_index_for_arp_scanning(interface_name)?;
    let addresses = discover_interface_scan_addresses(interface_name)?;
    let plan = scanner::full_subnet_scan_plan(&addresses)?;

    let mut endpoint = open_linux_link_layer_endpoint(interface_name)?;
    scanner::collect_scan_over_endpoint(
        &mut endpoint,
        &plan.targets,
        (addresses.source_mac_address, addresses.source_ipv4_address),
        &plan.acceptance,
        receive_timeout_after_last_request,
        pacing_between_scan_rounds,
        scan_round_count,
    )
}

/// Performs address resolution probing for a single strictly interior IPv4 target on
/// `interface_name`.
///
/// Semantics match [`perform_arp_scan`] for timing: `receive_timeout_after_last_request` is the
/// global receive window after the last request, `pacing_between_scan_rounds` sleeps between
/// full send rounds except the last, and `scan_round_count` is how many rounds run. Only replies
/// whose sender IPv4 equals `target_ipv4_address` are recorded.
///
/// # Errors
///
/// Returns [`AppError`] when the target is not strictly interior on the interface subnet, when
/// interface discovery or socket setup fails, or when the receive poll loop fails fatally.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use std::num::NonZeroU64;
/// use std::time::Duration;
///
/// # fn main() {
/// #[cfg(target_os = "linux")]
/// {
///     let _: fn(
///         &str,
///         Ipv4Addr,
///         Duration,
///         Duration,
///         NonZeroU64,
///     ) -> Result<new_arp_scan::application_outcome::ScanOutcome, new_arp_scan::AppError> =
///         new_arp_scan::perform_arp_probe;
/// }
/// # }
/// ```
///
/// # Panics
///
/// This function does not panic.
pub fn perform_arp_probe(
    interface_name: &str,
    target_ipv4_address: Ipv4Addr,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
) -> Result<ScanOutcome, AppError> {
    // Validate interface usability and the single target before opening any socket;
    // `open_linux_link_layer_endpoint` repeats the interface validation while acquiring the
    // descriptor.
    validated_interface_index_for_arp_scanning(interface_name)?;
    let addresses = discover_interface_scan_addresses(interface_name)?;
    validate_strict_interior_scan_target_ipv4_address(
        interface_name,
        target_ipv4_address,
        addresses.source_ipv4_address,
        addresses.ipv4_netmask,
    )?;

    let mut endpoint = open_linux_link_layer_endpoint(interface_name)?;
    let acceptance = ArpReplyAcceptance::ExactTarget {
        target_ipv4_address,
    };
    scanner::collect_scan_over_endpoint(
        &mut endpoint,
        &[target_ipv4_address],
        (addresses.source_mac_address, addresses.source_ipv4_address),
        &acceptance,
        receive_timeout_after_last_request,
        pacing_between_scan_rounds,
        scan_round_count,
    )
}
