//! Linux raw `AF_PACKET` socket initialization for ARP scanning.

use std::ffi::CString;
use std::mem::zeroed;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use crate::error::AppError;
use crate::interface_validation;
use crate::linux_packet::{
    ARP_HARDWARE_TYPE_ETHERNET, ETHERNET_PROTOCOL_ARP, INTERFACE_FLAG_LOOPBACK,
    INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP, SockAddressLinkLayer,
};

/// `ioctl(2)` request for reading interface flags (`SIOCGIFFLAGS`).
///
/// This matches the value used by the Linux kernel user-space application binary interface on
/// common architectures (see `linux/sockios.h`).
const SIOCGIFFLAGS_REQUEST: libc::Ioctl = 0x8913;

/// Opens a raw `AF_PACKET` socket, binds it to `interface_name`, and prepares for future ARP
/// scanning work.
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
/// Returns [`AppError::RawSocketOpenFailed`] or [`AppError::SocketBindFailed`] when the
/// underlying syscalls fail (for example missing `CAP_NET_RAW`).
///
/// # Panics
///
/// This function does not panic.
pub fn initialize_raw_arp_socket_for_scanning(interface_name: &str) -> Result<(), AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    let interface_index = interface_index_from_name(interface_name)?;
    let flags = read_interface_flags(interface_name)?;
    validate_interface_flags_for_arp_scanning(interface_name, flags)?;
    let packet_socket = open_raw_packet_socket()?;
    bind_packet_socket_to_interface(&packet_socket, interface_index)?;
    Ok(())
}

fn interface_index_from_name(interface_name: &str) -> Result<libc::c_uint, AppError> {
    let terminated = CString::new(interface_name).map_err(|_| AppError::InvalidInterfaceName {
        message: "interface name contains an interior NUL byte".to_string(),
    })?;

    // SAFETY: `terminated` is a valid NUL-terminated C string pointer accepted by `if_nametoindex`.
    let index = unsafe { libc::if_nametoindex(terminated.as_ptr()) };
    if index == 0 {
        return Err(AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(index)
}

fn open_inet_datagram_control_socket() -> Result<OwnedFd, AppError> {
    // SAFETY: `socket(2)` with `AF_INET`/`SOCK_DGRAM` is the standard portable approach for
    // issuing interface `ioctl`s.
    let file_descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };

    if file_descriptor < 0 {
        return Err(AppError::Io(std::io::Error::last_os_error()));
    }

    // SAFETY: `file_descriptor` is a freshly created valid socket file descriptor returned by
    // `socket(2)`.
    Ok(unsafe { OwnedFd::from_raw_fd(file_descriptor) })
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
    let control_socket = open_inet_datagram_control_socket()?;
    let mut request: libc::ifreq = unsafe { zeroed() };
    copy_interface_name_to_ifreq(interface_name, &mut request)?;

    // SAFETY: `control_socket` is a valid socket file descriptor and `request` is a valid
    // `ifreq` pointer for `SIOCGIFFLAGS`.
    let ioctl_result = unsafe {
        libc::ioctl(
            control_socket.as_raw_fd(),
            SIOCGIFFLAGS_REQUEST,
            std::ptr::addr_of_mut!(request),
        )
    };

    if ioctl_result < 0 {
        return Err(AppError::InterfaceFlagsQueryFailed {
            interface_name: interface_name.to_string(),
            source: std::io::Error::last_os_error(),
        });
    }

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
    let protocol = u32::from(ETHERNET_PROTOCOL_ARP).to_be() as libc::c_int;

    // SAFETY: `socket(2)` with `AF_PACKET`/`SOCK_RAW` is the documented Linux mechanism for raw
    // link-layer access (see `packet(7)`).
    let file_descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };

    if file_descriptor < 0 {
        return Err(AppError::RawSocketOpenFailed {
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: `file_descriptor` is a freshly created valid socket file descriptor returned by
    // `socket(2)`.
    Ok(unsafe { OwnedFd::from_raw_fd(file_descriptor) })
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

    // SAFETY: `address` matches `struct sockaddr_ll` layout and `bind(2)` expects a `sockaddr`
    // pointer with the correct length for this address family.
    let bind_result = unsafe {
        libc::bind(
            packet_socket.as_raw_fd(),
            std::ptr::addr_of!(address).cast::<libc::sockaddr>(),
            std::mem::size_of::<SockAddressLinkLayer>() as libc::socklen_t,
        )
    };

    if bind_result < 0 {
        return Err(AppError::SocketBindFailed {
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(())
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
