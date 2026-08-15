//! Portable address resolution scan orchestration.
//!
//! Target expansion, send rounds with inter-round pacing, the bounded receive phase, duplicate
//! reply merging, and warning collection are all platform-neutral. They are parameterized over the
//! [`LinkLayerEndpoint`] backend, so Linux (`AF_PACKET`) and macOS (Berkeley Packet Filter) share
//! one scan engine and only differ in interface discovery and raw frame input/output.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::thread;
use std::time::{Duration, Instant};

use crate::address_resolution_protocol::{
    encode_address_resolution_request_from_layout,
    try_parse_address_resolution_reply_ipv4_over_ethernet,
};
use crate::application_command::ScanWireOptions;
use crate::application_outcome::{DiscoveredHost, ScanOutcome};
use crate::error::AppError;
use crate::ethernet_frame::{ETHERNET_PROTOCOL_ARP, try_parse_ethernet_frame};
use crate::ipv4_cidr::Ipv4HostAddressIterator;
use crate::ipv4_subnet::ipv4_address_is_strictly_inside_subnet;
use crate::link_layer_backend::{InterfaceScanAddresses, LinkLayerEndpoint};
use crate::mac_address::MacAddress;

/// Converts remaining receive time to a `poll(2)` timeout in whole milliseconds, clamped to
/// [`libc::c_int::MAX`] when the span does not fit the system call parameter type.
fn poll_timeout_milliseconds_for_receive_wait(remaining: Duration) -> libc::c_int {
    let milliseconds = remaining.as_millis();
    libc::c_int::try_from(milliseconds).unwrap_or(libc::c_int::MAX)
}

/// Builds the ordered list of IPv4 targets: interior hosts from the iterator, then the interface
/// address when it is not strictly inside the open `(network, broadcast)` interval.
fn ipv4_scan_target_address_sequence(
    interior_host_addresses: impl Iterator<Item = Ipv4Addr>,
    source_ipv4_address: Ipv4Addr,
    network_bits: u32,
    broadcast_bits: u32,
) -> Vec<Ipv4Addr> {
    let mut targets: Vec<Ipv4Addr> = interior_host_addresses.collect();
    if !ipv4_address_is_strictly_inside_subnet(source_ipv4_address, network_bits, broadcast_bits) {
        targets.push(source_ipv4_address);
    }
    targets
}

/// Returns whether inter-round pacing should run after the round at `round_index` (zero-based).
fn should_apply_pacing_after_scan_round(
    round_index: u64,
    total_rounds: u64,
    pacing_between_scan_rounds: Duration,
) -> bool {
    !pacing_between_scan_rounds.is_zero() && round_index.saturating_add(1) < total_rounds
}

/// Returns how many address resolution requests are sent for `target_count` targets over
/// `scan_round_count` full rounds, or [`None`] when the product does not fit [`u64`].
#[cfg(test)]
fn total_address_resolution_request_send_count(
    target_count: usize,
    scan_round_count: NonZeroU64,
) -> Option<u64> {
    let target_count_u64 = u64::try_from(target_count).ok()?;
    target_count_u64.checked_mul(scan_round_count.get())
}

/// Counts inter-round pacing sleeps implied by [`should_apply_pacing_after_scan_round`] for every
/// zero-based round index in a scan.
#[cfg(test)]
fn inter_round_sleep_count_for_scan_schedule(
    total_rounds: u64,
    pacing_between_scan_rounds: Duration,
) -> u64 {
    if pacing_between_scan_rounds.is_zero() || total_rounds <= 1 {
        return 0;
    }
    total_rounds - 1
}

/// Inserts or merges a sender IPv4 and Ethernet address from a parsed address resolution reply.
///
/// The first media access control address wins; later replies with a different address for the
/// same IPv4 produce a warning and are ignored.
fn merge_address_resolution_reply_sender_into_discovered_hosts(
    discovered_hosts: &mut BTreeMap<Ipv4Addr, MacAddress>,
    ipv4_address: Ipv4Addr,
    media_access_control_address: MacAddress,
    warnings: &mut Vec<String>,
) {
    match discovered_hosts.entry(ipv4_address) {
        Entry::Vacant(entry) => {
            entry.insert(media_access_control_address);
        }
        Entry::Occupied(entry) => {
            let stored = *entry.get();
            if stored != media_access_control_address {
                warnings.push(format!(
                    "conflicting address resolution reply for {ipv4_address}: keeping {stored}, ignoring {media_access_control_address}"
                ));
            }
        }
    }
}

fn ipv4_sender_is_probed_target(
    sender_ipv4_address: Ipv4Addr,
    source_ipv4_address: Ipv4Addr,
    network_bits: u32,
    broadcast_bits: u32,
) -> bool {
    sender_ipv4_address == source_ipv4_address
        || ipv4_address_is_strictly_inside_subnet(sender_ipv4_address, network_bits, broadcast_bits)
}

/// Selects which address resolution reply senders are recorded during a receive phase.
pub(crate) enum ArpReplyAcceptance {
    /// Accept the interface address and any strictly interior subnet senders (full-subnet scan).
    SubnetScope {
        source_ipv4_address: Ipv4Addr,
        network_bits: u32,
        broadcast_bits: u32,
    },
    /// Accept only replies whose sender IPv4 equals the probed target.
    ExactTarget { target_ipv4_address: Ipv4Addr },
}

impl ArpReplyAcceptance {
    fn accepts_sender_ipv4_address(&self, sender_ipv4_address: Ipv4Addr) -> bool {
        match self {
            ArpReplyAcceptance::SubnetScope {
                source_ipv4_address,
                network_bits,
                broadcast_bits,
            } => ipv4_sender_is_probed_target(
                sender_ipv4_address,
                *source_ipv4_address,
                *network_bits,
                *broadcast_bits,
            ),
            ArpReplyAcceptance::ExactTarget {
                target_ipv4_address,
            } => sender_ipv4_address == *target_ipv4_address,
        }
    }
}

/// MAC, interface IPv4, and on-wire options used when sending ARP requests.
#[derive(Clone)]
pub(crate) struct ScanTransmitContext {
    /// Scanning interface Ethernet address (`ar$sha`).
    pub source_mac_address: MacAddress,
    /// Scanning interface IPv4 address, used when [`ScanWireOptions::sender_protocol_address`] is
    /// [`crate::application_command::ArpSenderProtocolAddress::Interface`].
    pub interface_ipv4_address: Ipv4Addr,
    /// VLAN tag, `ar$spa` override, LLC/SNAP framing, and Ethernet/ARP field overrides.
    pub wire: ScanWireOptions,
}

fn run_address_resolution_request_rounds(
    endpoint: &impl LinkLayerEndpoint,
    target_ipv4_addresses: &[Ipv4Addr],
    transmit: ScanTransmitContext,
    scan_round_count: NonZeroU64,
    pacing_between_scan_rounds: Duration,
    warnings: &mut Vec<String>,
) {
    let total_rounds = scan_round_count.get();
    for round_index in 0..total_rounds {
        for target_ipv4_address in target_ipv4_addresses {
            send_one_address_resolution_request(
                endpoint,
                &transmit,
                *target_ipv4_address,
                warnings,
            );
        }
        if should_apply_pacing_after_scan_round(
            round_index,
            total_rounds,
            pacing_between_scan_rounds,
        ) {
            thread::sleep(pacing_between_scan_rounds);
        }
    }
}

fn send_one_address_resolution_request(
    endpoint: &impl LinkLayerEndpoint,
    transmit: &ScanTransmitContext,
    target_ipv4_address: Ipv4Addr,
    warnings: &mut Vec<String>,
) {
    let sender_protocol_address = transmit
        .wire
        .sender_protocol_address
        .ipv4_address_for_target(transmit.interface_ipv4_address, target_ipv4_address);
    let layout = transmit.wire.address_resolution_request_layout(
        transmit.source_mac_address,
        sender_protocol_address,
        target_ipv4_address,
    );
    let frame = encode_address_resolution_request_from_layout(layout);
    if let Err(source) = endpoint.send_ethernet_frame(&frame) {
        warnings.push(format!(
            "failed to send ARP request to {target_ipv4_address}: {source}"
        ));
    }
}

fn collect_address_resolution_replies_until_deadline(
    endpoint: &mut impl LinkLayerEndpoint,
    receive_buffer: &mut [u8],
    deadline: Instant,
    reply_acceptance: &ArpReplyAcceptance,
    warnings: &mut Vec<String>,
) -> Result<BTreeMap<Ipv4Addr, MacAddress>, AppError> {
    let mut discovered_hosts: BTreeMap<Ipv4Addr, MacAddress> = BTreeMap::new();
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_milliseconds = poll_timeout_milliseconds_for_receive_wait(remaining);

        if endpoint.wait_until_readable(timeout_milliseconds)? {
            drain_buffered_reply_frames(
                endpoint,
                receive_buffer,
                reply_acceptance,
                &mut discovered_hosts,
                warnings,
            )?;
        }
    }
    Ok(discovered_hosts)
}

fn drain_buffered_reply_frames(
    endpoint: &mut impl LinkLayerEndpoint,
    receive_buffer: &mut [u8],
    reply_acceptance: &ArpReplyAcceptance,
    discovered_hosts: &mut BTreeMap<Ipv4Addr, MacAddress>,
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    while let Some(bytes_received) = endpoint.try_receive_ethernet_frame(receive_buffer)? {
        let frame_slice = &receive_buffer[..bytes_received];
        if ethernet_frame_is_not_address_resolution_protocol(frame_slice) {
            continue;
        }
        match try_parse_address_resolution_reply_ipv4_over_ethernet(frame_slice) {
            Ok((sender_ipv4_address, sender_mac_address)) => {
                if reply_acceptance.accepts_sender_ipv4_address(sender_ipv4_address) {
                    merge_address_resolution_reply_sender_into_discovered_hosts(
                        discovered_hosts,
                        sender_ipv4_address,
                        sender_mac_address,
                        warnings,
                    );
                }
            }
            Err(reason) => {
                warnings.push(format!("received malformed Ethernet/ARP frame: {reason}"));
            }
        }
    }

    Ok(())
}

/// Returns whether `frame_slice` is Ethernet that is not IPv4 ARP (including frames that cannot be
/// parsed as Ethernet). Those arrivals are expected when the capture socket is bound to every
/// protocol, and they are not operator-facing malformation warnings.
fn ethernet_frame_is_not_address_resolution_protocol(frame_slice: &[u8]) -> bool {
    match try_parse_ethernet_frame(frame_slice) {
        Ok(parsed) => parsed.ether_type != ETHERNET_PROTOCOL_ARP,
        Err(_) => true,
    }
}

/// The ordered target list and reply-acceptance rule for a full-subnet scan.
pub(crate) struct SubnetScanPlan {
    /// Targets to probe, interior hosts first, then the interface address when it lies on an edge.
    pub targets: Vec<Ipv4Addr>,
    /// Reply acceptance scoped to the interface subnet.
    pub acceptance: ArpReplyAcceptance,
}

/// Validates the interface subnet and builds the full-subnet scan plan.
///
/// This is the portable, pre-socket step: callers run it before opening a link-layer endpoint so a
/// subnet that cannot be scanned (for example `/31` or `/32`) is rejected first.
///
/// # Errors
///
/// Returns [`AppError::Ipv4NetmaskInvalid`] or [`AppError::Ipv4SubnetUnsupported`] when the
/// interface subnet cannot be scanned.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn full_subnet_scan_plan(
    addresses: &InterfaceScanAddresses,
) -> Result<SubnetScanPlan, AppError> {
    let host_address_iterator = Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(
        addresses.source_ipv4_address,
        addresses.ipv4_netmask,
    )?;

    let mask_bits = addresses.ipv4_netmask.to_bits();
    let network_bits = addresses.source_ipv4_address.to_bits() & mask_bits;
    let broadcast_bits = network_bits | !mask_bits;

    let targets = ipv4_scan_target_address_sequence(
        host_address_iterator,
        addresses.source_ipv4_address,
        network_bits,
        broadcast_bits,
    );

    Ok(SubnetScanPlan {
        targets,
        acceptance: ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: addresses.source_ipv4_address,
            network_bits,
            broadcast_bits,
        },
    })
}

/// Sends the request rounds and collects replies on an already-open `endpoint`, returning the
/// discovered hosts and any warnings.
///
/// `transmit` is the scanning interface MAC/IPv4 plus on-wire options (VLAN, `ar$spa`, LLC/SNAP). `acceptance` decides which
/// reply senders are recorded (full subnet versus a single probed target). The timing parameters
/// match the public scan contract: `receive_timeout_after_last_request` bounds the receive phase
/// after the final round, `pacing_between_scan_rounds` sleeps after each round except the last, and
/// `scan_round_count` is the number of rounds.
///
/// # Errors
///
/// Returns [`AppError`] when the receive poll loop fails fatally.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn collect_scan_over_endpoint(
    endpoint: &mut impl LinkLayerEndpoint,
    target_ipv4_addresses: &[Ipv4Addr],
    transmit: ScanTransmitContext,
    acceptance: &ArpReplyAcceptance,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
) -> Result<ScanOutcome, AppError> {
    transmit.wire.validate_ieee_8023_mac_client_data()?;
    let mut warnings = Vec::new();

    run_address_resolution_request_rounds(
        endpoint,
        target_ipv4_addresses,
        transmit,
        scan_round_count,
        pacing_between_scan_rounds,
        &mut warnings,
    );

    let deadline = Instant::now() + receive_timeout_after_last_request;
    let mut receive_buffer = [0u8; 4096];
    let discovered_hosts = collect_address_resolution_replies_until_deadline(
        endpoint,
        &mut receive_buffer,
        deadline,
        acceptance,
        &mut warnings,
    )?;

    let hosts: Vec<DiscoveredHost> = discovered_hosts
        .into_iter()
        .map(
            |(ipv4_address, media_access_control_address)| DiscoveredHost {
                ipv4_address,
                media_access_control_address,
            },
        )
        .collect();

    Ok(ScanOutcome {
        discovered_hosts: hosts,
        warnings,
        timing_summary: None,
    })
}

#[cfg(test)]
mod poll_timeout_milliseconds_for_receive_wait_tests {
    use super::poll_timeout_milliseconds_for_receive_wait;
    use std::time::Duration;

    #[test]
    fn maps_zero_duration_to_zero_milliseconds() {
        // Arrange
        let remaining = Duration::ZERO;

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome, 0,
            "zero remaining time should map to immediate poll timeout"
        );
    }

    #[test]
    fn maps_small_duration_to_matching_milliseconds() {
        // Arrange
        let remaining = Duration::from_millis(1500);

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome, 1500,
            "poll timeout should match remaining milliseconds when it fits c_int"
        );
    }

    #[test]
    fn clamps_duration_when_milliseconds_exceed_c_int_maximum() {
        // Arrange
        let remaining = Duration::from_millis(u64::from(libc::c_int::MAX as u32).saturating_add(1));

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome,
            libc::c_int::MAX,
            "oversized millisecond span should clamp to c_int::MAX for poll(2)"
        );
    }

    #[test]
    fn maps_duration_when_milliseconds_equal_c_int_maximum_without_clamping() {
        // Arrange
        let remaining = Duration::from_millis(libc::c_int::MAX as u64);

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome,
            libc::c_int::MAX,
            "exactly representable maximum poll timeout should pass through unchanged"
        );
    }
}

#[cfg(test)]
mod ipv4_scan_target_address_sequence_tests {
    use super::ipv4_scan_target_address_sequence;
    use std::net::Ipv4Addr;

    fn network_and_broadcast_slash_24() -> (u32, u32) {
        let network = Ipv4Addr::new(192, 168, 1, 0);
        let broadcast = Ipv4Addr::new(192, 168, 1, 255);
        (network.to_bits(), broadcast.to_bits())
    }

    #[test]
    fn appends_source_when_source_is_not_strictly_inside_open_host_interval() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 0);
        let interior = [Ipv4Addr::new(192, 168, 1, 10)];

        // Act
        let targets = ipv4_scan_target_address_sequence(
            interior.into_iter(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 0),
            ],
            "interface address on the subnet boundary should be probed after interior hosts"
        );
    }

    #[test]
    fn does_not_append_source_when_source_is_strictly_inside_open_host_interval() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 50);
        let interior = [
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
        ];

        // Act
        let targets = ipv4_scan_target_address_sequence(
            interior.into_iter(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
            ],
            "strictly interior interface address should not duplicate as trailing self-probe"
        );
    }

    #[test]
    fn appends_broadcast_source_after_interior_hosts_when_broadcast_is_interface_address() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 255);
        let interior = [Ipv4Addr::new(192, 168, 1, 10)];

        // Act
        let targets = ipv4_scan_target_address_sequence(
            interior.into_iter(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 255),
            ],
            "broadcast interface address should still receive a trailing self-probe"
        );
    }

    #[test]
    fn yields_only_broadcast_source_when_interior_iterator_is_empty_and_source_is_broadcast() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 255);

        // Act
        let targets = ipv4_scan_target_address_sequence(
            core::iter::empty(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![Ipv4Addr::new(192, 168, 1, 255)],
            "empty interior range with broadcast source should still probe that address once"
        );
    }

    #[test]
    fn yields_empty_target_list_when_interior_iterator_is_empty_and_source_is_strictly_inside() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let targets = ipv4_scan_target_address_sequence(
            core::iter::empty(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert!(
            targets.is_empty(),
            "strictly interior source with no interior iterator should not add duplicate self row"
        );
    }
}

#[cfg(test)]
mod should_apply_pacing_after_scan_round_tests {
    use super::should_apply_pacing_after_scan_round;
    use std::time::Duration;

    #[test]
    fn returns_true_when_more_rounds_remain_and_pacing_is_nonzero() {
        // Arrange
        let pacing = Duration::from_millis(5);

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 3, pacing);

        // Assert
        assert!(
            outcome,
            "pacing should apply between first and second round when pacing is nonzero"
        );
    }

    #[test]
    fn returns_false_on_final_round_even_when_pacing_is_nonzero() {
        // Arrange
        let pacing = Duration::from_millis(5);

        // Act
        let outcome = should_apply_pacing_after_scan_round(2, 3, pacing);

        // Assert
        assert!(!outcome, "pacing must not run after the final round");
    }

    #[test]
    fn returns_false_when_only_one_round_is_planned() {
        // Arrange
        let pacing = Duration::from_millis(5);

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 1, pacing);

        // Assert
        assert!(
            !outcome,
            "single-round scan should not sleep after the only round"
        );
    }

    #[test]
    fn returns_false_when_pacing_duration_is_zero() {
        // Arrange
        let pacing = Duration::ZERO;

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 5, pacing);

        // Assert
        assert!(
            !outcome,
            "zero pacing should never schedule sleeps between rounds"
        );
    }

    #[test]
    fn returns_false_when_total_rounds_is_zero_even_with_nonzero_pacing() {
        // Arrange
        let pacing = Duration::from_millis(1);

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 0, pacing);

        // Assert
        assert!(!outcome, "empty round plan must not schedule pacing sleeps");
    }

    #[test]
    fn returns_true_for_middle_round_when_more_than_two_rounds_remain() {
        // Arrange
        let pacing = Duration::from_millis(1);

        // Act
        let outcome = should_apply_pacing_after_scan_round(1, 4, pacing);

        // Assert
        assert!(
            outcome,
            "middle rounds should still schedule pacing when more rounds follow"
        );
    }
}

#[cfg(test)]
mod scan_round_schedule_tests {
    use super::{
        inter_round_sleep_count_for_scan_schedule, should_apply_pacing_after_scan_round,
        total_address_resolution_request_send_count,
    };
    use std::num::NonZeroU64;
    use std::time::Duration;

    #[test]
    fn total_send_count_is_zero_when_target_count_is_zero() {
        // Arrange
        let rounds = NonZeroU64::new(5).expect("five is non-zero");

        // Act
        let outcome = total_address_resolution_request_send_count(0, rounds);

        // Assert
        assert_eq!(
            outcome,
            Some(0),
            "empty target list should yield zero sends regardless of rounds"
        );
    }

    #[test]
    fn total_send_count_multiplies_targets_by_rounds() {
        // Arrange
        let rounds = NonZeroU64::new(4).expect("four is non-zero");

        // Act
        let outcome = total_address_resolution_request_send_count(7, rounds);

        // Assert
        assert_eq!(
            outcome,
            Some(28),
            "seven targets across four rounds should schedule twenty-eight sends"
        );
    }

    #[test]
    fn total_send_count_returns_none_when_product_overflows_u64() {
        // Arrange
        let rounds = NonZeroU64::new(u64::MAX).expect("maximum is non-zero");

        // Act
        let outcome = total_address_resolution_request_send_count(2, rounds);

        // Assert
        assert_eq!(
            outcome, None,
            "overflowing send count should surface as None instead of wrapping"
        );
    }

    #[test]
    fn inter_round_sleep_count_matches_sum_of_pacing_gates_for_each_round_index() {
        // Arrange
        let pacing = Duration::from_nanos(1);

        for total_rounds in 0_u64..=6_u64 {
            // Act
            let expected = inter_round_sleep_count_for_scan_schedule(total_rounds, pacing);
            let summed = (0..total_rounds)
                .filter(|&round_index| {
                    should_apply_pacing_after_scan_round(round_index, total_rounds, pacing)
                })
                .count() as u64;

            // Assert
            assert_eq!(
                summed, expected,
                "aggregated pacing gates should match closed-form count for total_rounds={total_rounds}"
            );
        }
    }

    #[test]
    fn inter_round_sleep_count_is_zero_when_pacing_is_zero_even_with_many_rounds() {
        // Arrange
        let pacing = Duration::ZERO;

        // Act
        let outcome = inter_round_sleep_count_for_scan_schedule(50, pacing);

        // Assert
        assert_eq!(
            outcome, 0,
            "zero pacing should never schedule sleeps between rounds"
        );
    }
}

#[cfg(test)]
mod merge_address_resolution_reply_sender_into_discovered_hosts_tests {
    use super::merge_address_resolution_reply_sender_into_discovered_hosts;
    use crate::mac_address::MacAddress;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    #[test]
    fn inserts_first_reply_for_each_ipv4_address() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let first_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            first_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(
            map.get(&ip).copied(),
            Some(first_mac),
            "first reply should populate the table"
        );
        assert!(
            warnings.is_empty(),
            "first insert should not warn, got: {warnings:?}"
        );
    }

    #[test]
    fn ignores_identical_duplicate_replies_without_warning() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(map.get(&ip).copied(), Some(mac));
        assert!(
            warnings.is_empty(),
            "same media access control should not warn, got: {warnings:?}"
        );
    }

    #[test]
    fn keeps_first_mac_and_emits_warning_for_each_conflicting_duplicate() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let first_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let second_mac = MacAddress::from_octets([9, 8, 7, 6, 5, 4]);
        let third_mac = MacAddress::from_octets([0xAA; 6]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            first_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            second_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            third_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(map.get(&ip).copied(), Some(first_mac));
        assert_eq!(
            warnings.len(),
            2,
            "each conflicting duplicate should warn once, got: {warnings:?}"
        );
        assert!(
            warnings[0].contains("conflicting") && warnings[0].contains("ignoring"),
            "warning should describe conflict, got: {}",
            warnings[0]
        );
    }

    #[test]
    fn tracks_independent_ipv4_addresses_without_cross_talk() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let first_ip = Ipv4Addr::new(10, 0, 0, 2);
        let second_ip = Ipv4Addr::new(10, 0, 0, 3);
        let first_mac = MacAddress::from_octets([1, 1, 1, 1, 1, 1]);
        let second_mac = MacAddress::from_octets([2, 2, 2, 2, 2, 2]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            first_ip,
            first_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            second_ip,
            second_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(
            map.len(),
            2,
            "two distinct IPv4 addresses should both be stored"
        );
        assert_eq!(map.get(&first_ip).copied(), Some(first_mac));
        assert_eq!(map.get(&second_ip).copied(), Some(second_mac));
        assert!(
            warnings.is_empty(),
            "independent first inserts should not warn, got: {warnings:?}"
        );
    }

    #[test]
    fn emits_separate_warning_each_time_the_same_conflicting_media_access_control_address_returns()
    {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let first_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let conflicting_mac = MacAddress::from_octets([9, 9, 9, 9, 9, 9]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            first_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            conflicting_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            conflicting_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(map.get(&ip).copied(), Some(first_mac));
        assert_eq!(
            warnings.len(),
            2,
            "repeated identical conflicting sender should still warn each time, got: {warnings:?}"
        );
        for (index, warning) in warnings.iter().enumerate() {
            assert!(
                warning.contains("10.0.0.5")
                    && warning.contains("01:02:03:04:05:06")
                    && warning.contains("09:09:09:09:09:09"),
                "warning {index} should name the IPv4 and both media access control addresses, got: {warning}"
            );
        }
    }
}

#[cfg(test)]
mod ipv4_sender_is_probed_target_tests {
    use super::ipv4_sender_is_probed_target;
    use std::net::Ipv4Addr;

    fn network_broadcast_slash_24() -> (u32, u32) {
        let net = Ipv4Addr::new(192, 168, 1, 0);
        let bcast = Ipv4Addr::new(192, 168, 1, 255);
        (net.to_bits(), bcast.to_bits())
    }

    #[test]
    fn treats_interface_source_address_as_in_scope_even_when_not_strictly_inside_open_interval() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 1);

        // Act
        let outcome = ipv4_sender_is_probed_target(source, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            outcome,
            "gateway-style interface address on the subnet edge should still count as in-scope"
        );
    }

    #[test]
    fn interior_subnet_address_is_in_scope() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let sender = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let outcome = ipv4_sender_is_probed_target(sender, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            outcome,
            "strictly interior host addresses should be accepted"
        );
    }

    #[test]
    fn network_and_broadcast_addresses_are_out_of_scope_when_not_source() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let network = Ipv4Addr::new(192, 168, 1, 0);
        let broadcast = Ipv4Addr::new(192, 168, 1, 255);

        // Act
        let network_outcome =
            ipv4_sender_is_probed_target(network, source, network_bits, broadcast_bits);
        let broadcast_outcome =
            ipv4_sender_is_probed_target(broadcast, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            !network_outcome,
            "network address should not match strict interior rule"
        );
        assert!(
            !broadcast_outcome,
            "broadcast address should not match strict interior rule"
        );
    }

    #[test]
    fn address_outside_subnet_is_rejected_when_distinct_from_source() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let outsider = Ipv4Addr::new(10, 0, 0, 1);

        // Act
        let outcome = ipv4_sender_is_probed_target(outsider, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            !outcome,
            "off-subnet senders should be ignored unless they equal the interface address"
        );
    }
}

#[cfg(test)]
mod arp_reply_acceptance_tests {
    use super::ArpReplyAcceptance;
    use std::net::Ipv4Addr;

    #[test]
    fn exact_target_accepts_only_matching_sender() {
        // Arrange
        let target = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target,
        };

        // Act
        let match_outcome = acceptance.accepts_sender_ipv4_address(target);
        let other_interior = acceptance.accepts_sender_ipv4_address(Ipv4Addr::new(192, 168, 1, 51));

        // Assert
        assert!(match_outcome, "exact target should accept matching sender");
        assert!(
            !other_interior,
            "different interior sender should be ignored in exact-target mode"
        );
    }

    #[test]
    fn subnet_scope_matches_ipv4_sender_is_probed_target_rules() {
        // Arrange
        let network = Ipv4Addr::new(192, 168, 1, 0).to_bits();
        let broadcast = Ipv4Addr::new(192, 168, 1, 255).to_bits();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let acceptance = ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: source,
            network_bits: network,
            broadcast_bits: broadcast,
        };

        // Act
        let interior = acceptance.accepts_sender_ipv4_address(Ipv4Addr::new(192, 168, 1, 20));

        // Assert
        assert!(
            interior,
            "subnet scope should accept interior senders like full scan"
        );
    }

    #[test]
    fn subnet_scope_rejects_sender_outside_local_subnet_when_not_equal_to_source() {
        // Arrange
        let network = Ipv4Addr::new(192, 168, 1, 0).to_bits();
        let broadcast = Ipv4Addr::new(192, 168, 1, 255).to_bits();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let acceptance = ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: source,
            network_bits: network,
            broadcast_bits: broadcast,
        };

        // Act
        let outsider = Ipv4Addr::new(10, 0, 0, 1);
        let outcome = acceptance.accepts_sender_ipv4_address(outsider);

        // Assert
        assert!(
            !outcome,
            "off-subnet sender should be rejected in subnet scope unless it equals the interface address"
        );
    }
}

#[cfg(test)]
mod collect_scan_over_endpoint_vlan_and_capture_noise_tests {
    use super::ArpReplyAcceptance;
    use super::ScanTransmitContext;
    use super::collect_scan_over_endpoint;
    use crate::application_command::{ArpSenderProtocolAddress, ScanWireOptions};
    use crate::error::AppError;
    use crate::ethernet_frame::{
        ETHERNET_PROTOCOL_IPV4, ETHERNET_PROTOCOL_VLAN_TAG, Ieee8021qPriorityCodePoint,
        Ieee8021qVlanIdentifier, encode_ethernet_ii_frame,
    };
    use crate::link_layer_backend::LinkLayerEndpoint;
    use crate::mac_address::MacAddress;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::time::Duration;

    struct ScriptedEndpoint {
        sent: RefCell<Vec<Vec<u8>>>,
        inbound: Vec<Vec<u8>>,
    }

    impl LinkLayerEndpoint for ScriptedEndpoint {
        fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
            self.sent.borrow_mut().push(frame.to_vec());
            Ok(())
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Ok(!self.inbound.is_empty())
        }

        fn try_receive_ethernet_frame(
            &mut self,
            buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            if self.inbound.is_empty() {
                return Ok(None);
            }
            let frame = self.inbound.remove(0);
            buffer[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }
    }

    #[test]
    fn sends_ieee_8021q_tagged_request_when_vlan_identifier_is_set() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits in 12 bits");
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    vlan_identifier: Some(vlan_identifier),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(sent.len(), 1, "one target and one round should send once");
        assert_eq!(&sent[0][12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(&sent[0][14..16], &10u16.to_be_bytes());
        assert_eq!(&sent[0][16..18], &[0x08, 0x06]);
        assert!(
            outcome.warnings.is_empty(),
            "successful tagged send should not warn, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn sends_ieee_8021q_priority_code_point_and_drop_eligible_indicator() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits in 12 bits");
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    vlan_identifier: Some(vlan_identifier),
                    vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(5)
                        .expect("PCP 5 fits"),
                    vlan_drop_eligible_indicator: true,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(&sent[0][12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(
            &sent[0][14..16],
            &0xB00Au16.to_be_bytes(),
            "PCP 5, DEI 1, VID 10 should encode as TCI 0xB00A"
        );
    }

    #[test]
    fn sends_custom_padding_after_arp_payload() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };
        let padding = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    padding: padding.clone(),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        let payload_start = 14 + 28;
        assert_eq!(
            &sent[0][payload_start..payload_start + 4],
            padding.as_slice()
        );
        assert_eq!(sent[0].len(), 60);
    }

    #[test]
    fn collect_rejects_padding_that_exceeds_ieee_8023_mac_client_data() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    llc_snap: true,
                    padding: vec![0; 1465],
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::Ieee8023MacClientDataExceedsMaximum { .. })
            ),
            "SNAP padding of 1465 octets must exceed the 1500-octet MAC client data maximum, got: {outcome:?}"
        );
        assert!(
            endpoint.sent.borrow().is_empty(),
            "oversize padding must not transmit a frame"
        );
    }

    #[test]
    fn ignores_non_arp_ethernet_frames_without_malformed_warning() {
        // Arrange
        let ipv4_frame = encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            ETHERNET_PROTOCOL_IPV4,
            &[0x45, 0x00],
        );
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![ipv4_frame],
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions::default(),
            },
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(
            outcome.discovered_hosts.is_empty(),
            "IPv4 frames must not be recorded as ARP replies"
        );
        assert!(
            outcome.warnings.is_empty(),
            "non-ARP capture noise should not produce malformed-frame warnings, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn sends_rfc_5227_probe_when_sender_protocol_address_is_unspecified() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    sender_protocol_address: ArpSenderProtocolAddress::Explicit(
                        Ipv4Addr::UNSPECIFIED,
                    ),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(
            &sent[0][28..32],
            &[0, 0, 0, 0],
            "RFC 5227 Probe SPA is 0.0.0.0"
        );
        assert_eq!(&sent[0][38..42], &target_ip.octets());
    }

    #[test]
    fn sends_rfc_5227_announcement_when_sender_protocol_address_is_destination_target() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    sender_protocol_address: ArpSenderProtocolAddress::DestinationTarget,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(
            &sent[0][28..32],
            &target_ip.octets(),
            "RFC 5227 Announcement sets ar$spa to the target"
        );
        assert_eq!(&sent[0][38..42], &target_ip.octets());
    }

    #[test]
    fn sends_rfc_1042_llc_snap_when_llc_snap_is_set() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    llc_snap: true,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(
            &sent[0][14..17],
            &[0xAA, 0xAA, 0x03],
            "RFC 1042 LLC header should precede SNAP"
        );
        assert_eq!(
            &sent[0][20..22],
            &[0x08, 0x06],
            "SNAP EtherType should be ARP"
        );
        assert_eq!(
            &sent[0][12..14],
            &36u16.to_be_bytes(),
            "IEEE 802.3 length is LLC/SNAP plus ARP (36), not an Ethernet-header-inclusive size"
        );
    }

    #[test]
    fn sends_unicast_ethernet_destination_and_independent_arp_sender_hardware() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let destination = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ethernet_source = MacAddress::from_octets([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        let sender_hardware = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    ethernet_destination: Some(destination),
                    ethernet_source: Some(ethernet_source),
                    arp_sender_hardware: Some(sender_hardware),
                    arp_hardware_type: 6,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(&sent[0][0..6], &destination.octets());
        assert_eq!(&sent[0][6..12], &ethernet_source.octets());
        assert_eq!(&sent[0][22..28], &sender_hardware.octets());
        assert_eq!(&sent[0][14..16], &6u16.to_be_bytes());
    }
}
