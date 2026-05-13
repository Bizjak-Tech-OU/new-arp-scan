//! Linux raw `AF_PACKET` socket initialization for ARP scanning.

use std::ffi::CString;
use std::mem::zeroed;
use std::os::fd::OwnedFd;

use crate::error::AppError;
use crate::interface_validation;
use crate::linux_packet::{
    ARP_HARDWARE_TYPE_ETHERNET, ETHERNET_PROTOCOL_ARP, INTERFACE_FLAG_LOOPBACK,
    INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP, SockAddressLinkLayer,
};
use crate::linux_system_call;

/// Opens a raw `AF_PACKET` socket, binds it to `interface_name`, and returns the socket for ARP
/// scanning.
///
/// # Errors
///
/// Returns [`AppError::InvalidInterfaceName`] when the interface name is not usable.
///
/// Returns [`AppError::InterfaceLookupFailed`] when the interface cannot be resolved.
///
/// Returns [`AppError::InterfaceFlagsQueryFailed`] when interface flags cannot be read.
///
/// Returns [`AppError::InterfaceRejectedForScanning`] when the interface is loopback,
/// administratively down, or has `NOARP` set.
///
/// Returns [`AppError::RawSocketOpenFailed`], [`AppError::RawSocketCapabilityRequired`], or
/// [`AppError::SocketBindFailed`] when the underlying syscalls fail (for example missing
/// `CAP_NET_RAW`).
///
/// # Panics
///
/// This function does not panic.
pub fn open_bound_raw_arp_packet_socket(interface_name: &str) -> Result<OwnedFd, AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    let interface_index = interface_index_from_name(interface_name)?;
    let flags = read_interface_flags(interface_name)?;
    validate_interface_flags_for_arp_scanning(interface_name, flags)?;
    let packet_socket = open_raw_packet_socket()?;
    bind_packet_socket_to_interface(&packet_socket, interface_index)?;
    Ok(packet_socket)
}

fn interface_index_from_name(interface_name: &str) -> Result<libc::c_uint, AppError> {
    let terminated = CString::new(interface_name).map_err(|_| AppError::InvalidInterfaceName {
        message: "interface name contains an interior NUL byte".to_string(),
    })?;

    linux_system_call::interface_index_from_name(&terminated).map_err(|source| {
        AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source,
        }
    })
}

fn copy_interface_name_to_ifreq(
    interface_name: &str,
    request: &mut libc::ifreq,
) -> Result<(), AppError> {
    let bytes = interface_name.as_bytes();
    if bytes.len() >= interface_validation::INTERFACE_NAME_BUFFER_SIZE {
        return Err(AppError::InvalidInterfaceName {
            message: format!(
                "interface name must be shorter than {} bytes",
                interface_validation::INTERFACE_NAME_BUFFER_SIZE
            ),
        });
    }

    for (index, byte) in bytes.iter().enumerate() {
        request.ifr_name[index] = *byte as libc::c_char;
    }

    Ok(())
}

fn read_interface_flags(interface_name: &str) -> Result<i32, AppError> {
    let control_socket = linux_system_call::open_inet_datagram_socket().map_err(AppError::Io)?;
    let mut request: libc::ifreq = unsafe { zeroed() };
    copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        &control_socket,
        linux_system_call::SIOCGIFFLAGS_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceFlagsQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    let flags = i32::from(unsafe { request.ifr_ifru.ifru_flags });
    Ok(flags)
}

fn validate_interface_flags_for_arp_scanning(
    interface_name: &str,
    flags: i32,
) -> Result<(), AppError> {
    if (flags & INTERFACE_FLAG_LOOPBACK) != 0 {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "loopback interface".to_string(),
        });
    }

    if (flags & INTERFACE_FLAG_NO_ARP) != 0 {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "interface has NOARP set".to_string(),
        });
    }

    if (flags & INTERFACE_FLAG_UP) == 0 {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "interface is not UP".to_string(),
        });
    }

    Ok(())
}

fn open_raw_packet_socket() -> Result<OwnedFd, AppError> {
    match linux_system_call::open_packet_raw_socket(ETHERNET_PROTOCOL_ARP) {
        Ok(socket) => Ok(socket),
        Err(source) => {
            if source.kind() == std::io::ErrorKind::PermissionDenied {
                Err(AppError::RawSocketCapabilityRequired { source })
            } else {
                Err(AppError::RawSocketOpenFailed { source })
            }
        }
    }
}

fn bind_packet_socket_to_interface(
    packet_socket: &OwnedFd,
    interface_index: libc::c_uint,
) -> Result<(), AppError> {
    let mut address: SockAddressLinkLayer = unsafe { zeroed() };
    address.socket_address_family = libc::AF_PACKET as libc::c_ushort;
    address.link_layer_protocol = u32::from(ETHERNET_PROTOCOL_ARP).to_be() as libc::c_ushort;
    address.interface_index = interface_index as libc::c_int;
    address.hardware_type = ARP_HARDWARE_TYPE_ETHERNET as libc::c_ushort;

    linux_system_call::bind_sockaddr_link_layer(
        packet_socket,
        address.as_libc_sockaddr_link_layer(),
    )
    .map_err(|source| AppError::SocketBindFailed { source })
}

#[cfg(test)]
mod tests {
    use super::validate_interface_flags_for_arp_scanning;
    use crate::error::AppError;
    use crate::linux_packet::{INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP};

    #[test]
    fn returns_error_when_interface_flags_indicate_loopback() {
        // Arrange
        let interface_name = "lo";
        let flags = INTERFACE_FLAG_UP | INTERFACE_FLAG_LOOPBACK;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_flags_indicate_no_arp() {
        // Arrange
        let interface_name = "eth0";
        let flags = INTERFACE_FLAG_UP | INTERFACE_FLAG_NO_ARP;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "NOARP should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_flags_indicate_administratively_down() {
        // Arrange
        let interface_name = "eth0";
        let flags = 0;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "not UP should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn accepts_interface_flags_when_interface_is_up_and_not_loopback_and_arp_enabled() {
        // Arrange
        let interface_name = "eth0";
        let flags = INTERFACE_FLAG_UP;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "UP non-loopback without NOARP should be accepted, got: {outcome:?}"
        );
    }
}
