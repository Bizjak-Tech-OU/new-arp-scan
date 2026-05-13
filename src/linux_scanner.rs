//! Linux address resolution scanning orchestration.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem::zeroed;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::application_outcome::{DiscoveredHost, ScanOutcome};
use crate::error::AppError;
use crate::ethernet_arp::build_address_resolution_request_ethernet_frame;
use crate::ethernet_arp::try_parse_address_resolution_reply_ipv4_over_ethernet;
use crate::ipv4_subnet::{
    inclusive_host_address_range_excluding_edges, ipv4_address_is_strictly_inside_subnet,
};
use crate::linux_interface_discovery::discover_interface_scan_addresses;
use crate::linux_packet::{
    ARP_HARDWARE_TYPE_ETHERNET, ETHERNET_PROTOCOL_ARP, SockAddressLinkLayer,
};
use crate::linux_socket::open_bound_raw_arp_packet_socket;
use crate::linux_system_call;

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
    let addresses = discover_interface_scan_addresses(interface_name)?;
    let (first_host_bits, last_host_bits) = inclusive_host_address_range_excluding_edges(
        addresses.source_ipv4_address,
        addresses.ipv4_netmask,
    )?;

    let mask_bits = addresses.ipv4_netmask.to_bits();
    let network_bits = addresses.source_ipv4_address.to_bits() & mask_bits;
    let broadcast_bits = network_bits | !mask_bits;

    let terminated = CString::new(interface_name).map_err(|_| AppError::InvalidInterfaceName {
        message: "interface name contains an interior NUL byte".to_string(),
    })?;
    let interface_index =
        linux_system_call::interface_index_from_name(&terminated).map_err(|source| {
            AppError::InterfaceLookupFailed {
                interface_name: interface_name.to_string(),
                source,
            }
        })?;

    let packet_socket = open_bound_raw_arp_packet_socket(interface_name)?;

    let mut link_layer_destination: SockAddressLinkLayer = unsafe { zeroed() };
    link_layer_destination.socket_address_family = libc::AF_PACKET as libc::c_ushort;
    link_layer_destination.link_layer_protocol =
        u32::from(ETHERNET_PROTOCOL_ARP).to_be() as libc::c_ushort;
    link_layer_destination.interface_index = interface_index as libc::c_int;
    link_layer_destination.hardware_type = ARP_HARDWARE_TYPE_ETHERNET as libc::c_ushort;
    link_layer_destination.hardware_address_length = 6;
    link_layer_destination.hardware_address[0..6].fill(0xFF);

    let mut warnings = Vec::new();

    for host_bits in first_host_bits..=last_host_bits {
        let target_ipv4_address = Ipv4Addr::from_bits(host_bits);
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
    let mut discovered_hosts: BTreeMap<Ipv4Addr, [u8; 6]> = BTreeMap::new();
    let mut receive_buffer = [0u8; 4096];

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_milliseconds: libc::c_int = remaining
            .as_millis()
            .min(u128::from(libc::c_int::MAX as u32))
            as libc::c_int;

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
        .map(|(ipv4_address, mac_address)| DiscoveredHost {
            ipv4_address,
            mac_address,
        })
        .collect();

    Ok(ScanOutcome {
        discovered_hosts: hosts,
        warnings,
    })
}

fn send_one_address_resolution_request(
    packet_socket: &std::os::fd::OwnedFd,
    link_layer_destination: &SockAddressLinkLayer,
    source_mac_address: [u8; 6],
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
    discovered_hosts: &mut BTreeMap<Ipv4Addr, [u8; 6]>,
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
