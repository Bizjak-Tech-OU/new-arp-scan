//! Linux address resolution scanning orchestration.

use std::collections::BTreeMap;
use std::mem::zeroed;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::address_resolution_protocol::{
    build_address_resolution_request_ethernet_frame,
    try_parse_address_resolution_reply_ipv4_over_ethernet,
};
use crate::application_outcome::{DiscoveredHost, ScanOutcome};
use crate::error::AppError;
use crate::ipv4_cidr::Ipv4HostAddressIterator;
use crate::ipv4_subnet::ipv4_address_is_strictly_inside_subnet;
use crate::linux_interface_discovery::discover_interface_scan_addresses;
use crate::linux_packet::{
    ARP_HARDWARE_TYPE_ETHERNET, ETHERNET_PROTOCOL_ARP, SOCKET_ADDRESS_FAMILY_PACKET,
    SockAddressLinkLayer, ethernet_protocol_host_to_network_order,
};
use crate::linux_socket::{
    open_bound_raw_arp_packet_socket, validated_interface_index_for_arp_scanning,
};
use crate::linux_system_call;
use crate::mac_address::MacAddress;

/// Duration after the last request transmission during which replies are collected.
const RECEIVE_WINDOW_AFTER_LAST_REQUEST: Duration = Duration::from_secs(3);

/// Performs a full-subnet IPv4 address resolution scan on `interface_name`.
///
/// # Errors
///
/// Returns [`AppError`] when interface discovery, socket setup, or the receive poll loop fails
/// fatally.
///
/// # Panics
///
/// This function does not panic.
pub fn perform_arp_scan(interface_name: &str) -> Result<ScanOutcome, AppError> {
    let interface_index = validated_interface_index_for_arp_scanning(interface_name)?;
    let addresses = discover_interface_scan_addresses(interface_name)?;
    let host_address_iterator = Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(
        addresses.source_ipv4_address,
        addresses.ipv4_netmask,
    )?;

    let mask_bits = addresses.ipv4_netmask.to_bits();
    let network_bits = addresses.source_ipv4_address.to_bits() & mask_bits;
    let broadcast_bits = network_bits | !mask_bits;

    let packet_socket = open_bound_raw_arp_packet_socket(interface_name)?;

    let mut link_layer_destination: SockAddressLinkLayer = unsafe { zeroed() };
    link_layer_destination.socket_address_family = SOCKET_ADDRESS_FAMILY_PACKET;
    link_layer_destination.link_layer_protocol =
        ethernet_protocol_host_to_network_order(ETHERNET_PROTOCOL_ARP);
    link_layer_destination.interface_index =
        libc::c_int::try_from(interface_index).map_err(|_| AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("interface index {interface_index} does not fit sockaddr_ll"),
            ),
        })?;
    link_layer_destination.hardware_type = ARP_HARDWARE_TYPE_ETHERNET;
    link_layer_destination.hardware_address_length = 6;
    link_layer_destination.hardware_address[0..6].fill(0xFF);

    let mut warnings = Vec::new();

    for target_ipv4_address in host_address_iterator {
        send_one_address_resolution_request(
            &packet_socket,
            &link_layer_destination,
            addresses.source_mac_address,
            addresses.source_ipv4_address,
            target_ipv4_address,
            &mut warnings,
        );
    }

    if !ipv4_address_is_strictly_inside_subnet(
        addresses.source_ipv4_address,
        network_bits,
        broadcast_bits,
    ) {
        send_one_address_resolution_request(
            &packet_socket,
            &link_layer_destination,
            addresses.source_mac_address,
            addresses.source_ipv4_address,
            addresses.source_ipv4_address,
            &mut warnings,
        );
    }

    let deadline = Instant::now() + RECEIVE_WINDOW_AFTER_LAST_REQUEST;
    let mut discovered_hosts: BTreeMap<Ipv4Addr, MacAddress> = BTreeMap::new();
    let mut receive_buffer = [0u8; 4096];

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_milliseconds =
            libc::c_int::try_from(remaining.as_millis()).unwrap_or(libc::c_int::MAX);

        match linux_system_call::poll_socket_readiness(
            &packet_socket,
            libc::POLLIN,
            timeout_milliseconds,
        ) {
            Ok(0) => {}
            Ok(_) => {
                drain_readable_packet_socket(
                    &packet_socket,
                    &mut receive_buffer,
                    addresses.source_ipv4_address,
                    network_bits,
                    broadcast_bits,
                    &mut discovered_hosts,
                    &mut warnings,
                )?;
            }
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(AppError::PollWaitFailed { source });
            }
        }
    }

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
    })
}

fn send_one_address_resolution_request(
    packet_socket: &std::os::fd::OwnedFd,
    link_layer_destination: &SockAddressLinkLayer,
    source_mac_address: MacAddress,
    source_ipv4_address: Ipv4Addr,
    target_ipv4_address: Ipv4Addr,
    warnings: &mut Vec<String>,
) {
    let frame = build_address_resolution_request_ethernet_frame(
        source_mac_address,
        source_ipv4_address,
        target_ipv4_address,
    );
    match linux_system_call::send_to_link_layer(
        packet_socket,
        frame.as_ref(),
        link_layer_destination.as_libc_sockaddr_link_layer(),
    ) {
        Ok(_) => {}
        Err(source) => {
            warnings.push(format!(
                "failed to send ARP request to {target_ipv4_address}: {source}"
            ));
        }
    }
}

fn drain_readable_packet_socket(
    packet_socket: &std::os::fd::OwnedFd,
    receive_buffer: &mut [u8],
    source_ipv4_address: Ipv4Addr,
    network_bits: u32,
    broadcast_bits: u32,
    discovered_hosts: &mut BTreeMap<Ipv4Addr, MacAddress>,
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    loop {
        match linux_system_call::receive_from_link_layer(
            packet_socket,
            receive_buffer,
            libc::MSG_DONTWAIT,
            None,
        ) {
            Ok(0) => {
                break;
            }
            Ok(bytes_received) => {
                let frame_slice = &receive_buffer[..bytes_received];
                match try_parse_address_resolution_reply_ipv4_over_ethernet(frame_slice) {
                    Ok((sender_ipv4_address, sender_mac_address)) => {
                        if ipv4_sender_is_probed_target(
                            sender_ipv4_address,
                            source_ipv4_address,
                            network_bits,
                            broadcast_bits,
                        ) {
                            discovered_hosts
                                .entry(sender_ipv4_address)
                                .or_insert(sender_mac_address);
                        }
                    }
                    Err(reason) => {
                        warnings.push(format!("received malformed Ethernet/ARP frame: {reason}"));
                    }
                }
            }
            Err(source)
                if source.raw_os_error() == Some(libc::EAGAIN)
                    || source.raw_os_error() == Some(libc::EWOULDBLOCK) =>
            {
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(AppError::RawPacketReceiveFailed { source });
            }
        }
    }

    Ok(())
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
