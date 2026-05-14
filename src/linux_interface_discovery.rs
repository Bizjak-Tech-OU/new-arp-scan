//! Discovers IPv4 addresses, netmasks, and hardware addresses for a named Linux interface.

use std::mem::zeroed;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

use crate::error::AppError;
use crate::interface_validation;
use crate::linux_system_call;

/// IPv4 configuration and Ethernet hardware address discovered for scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceScanAddresses {
    /// Primary IPv4 address selected for scanning (first address returned by the kernel).
    pub source_ipv4_address: Ipv4Addr,
    /// IPv4 netmask associated with [`Self::source_ipv4_address`].
    pub ipv4_netmask: Ipv4Addr,
    /// Source Ethernet hardware address used in outgoing frames.
    pub source_mac_address: [u8; 6],
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
        // `libc` may expose `ifr_name` as either `c_char` (`i8`) or `u8` depending on the target
        // and crate version; `as _` assigns the correct representation in both cases.
        request.ifr_name[index] = *byte as _;
    }

    Ok(())
}

fn read_ipv4_from_sockaddr(
    sockaddr: &libc::sockaddr,
    wrong_family_error: impl FnOnce(libc::sa_family_t) -> AppError,
) -> Result<Ipv4Addr, AppError> {
    if libc::c_int::from(sockaddr.sa_family) != libc::AF_INET {
        return Err(wrong_family_error(sockaddr.sa_family));
    }

    // SAFETY: `sockaddr` was validated as `AF_INET` and can be reinterpreted as `sockaddr_in`.
    let socket_address_internet = unsafe {
        std::ptr::from_ref(sockaddr)
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };

    let octets = socket_address_internet.sin_addr.s_addr.to_be_bytes();
    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

fn read_hardware_address_from_sockaddr(
    interface_name: &str,
    sockaddr: &libc::sockaddr,
) -> Result<[u8; 6], AppError> {
    if sockaddr.sa_family != libc::ARPHRD_ETHER {
        return Err(AppError::InterfaceHardwareAddressUnsupported {
            interface_name: interface_name.to_string(),
            reason: format!(
                "hardware address family is not Ethernet (expected {}, got {})",
                libc::ARPHRD_ETHER,
                sockaddr.sa_family
            ),
        });
    }

    let mut mac_address = [0u8; 6];
    for (index, octet) in mac_address.iter_mut().enumerate() {
        // `libc` may use `c_char` (`i8`) or `u8` for `sa_data`; cast is a no-op on `u8` targets.
        #[allow(clippy::unnecessary_cast)]
        {
            *octet = sockaddr.sa_data[index] as u8;
        }
    }
    Ok(mac_address)
}

/// Reads [`InterfaceScanAddresses`] for `interface_name` using `ioctl(2)` on an `AF_INET` datagram
/// control socket.
///
/// # Errors
///
/// Returns [`AppError`] when the interface name is invalid, when any `ioctl` fails, when the
/// address family is unexpected, or when the hardware address is not Ethernet.
///
/// # Panics
///
/// This function does not panic.
pub fn discover_interface_scan_addresses(
    interface_name: &str,
) -> Result<InterfaceScanAddresses, AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    let control_socket = linux_system_call::open_inet_datagram_socket().map_err(AppError::Io)?;

    let source_ipv4_address = read_interface_ipv4_address(&control_socket, interface_name)?;
    let ipv4_netmask = read_interface_ipv4_netmask(&control_socket, interface_name)?;
    let source_mac_address = read_interface_hardware_address(&control_socket, interface_name)?;

    Ok(InterfaceScanAddresses {
        source_ipv4_address,
        ipv4_netmask,
        source_mac_address,
    })
}

fn read_interface_ipv4_address(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<Ipv4Addr, AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFADDR_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceIpv4AddressQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    // SAFETY: `ioctl` populated `ifr_addr` for this interface name.
    let sockaddr = unsafe { request.ifr_ifru.ifru_addr };
    read_ipv4_from_sockaddr(&sockaddr, |address_family| {
        AppError::InterfaceIpv4AddressInvalidFamily { address_family }
    })
}

fn read_interface_ipv4_netmask(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<Ipv4Addr, AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFNETMASK_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceIpv4NetmaskQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    // SAFETY: `ioctl` populated `ifr_netmask` for this interface name.
    let sockaddr = unsafe { request.ifr_ifru.ifru_netmask };
    read_ipv4_from_sockaddr(&sockaddr, |address_family| {
        AppError::InterfaceIpv4NetmaskInvalidFamily {
            interface_name: interface_name.to_string(),
            address_family,
        }
    })
}

fn read_interface_hardware_address(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<[u8; 6], AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFHWADDR_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceHardwareAddressQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    // SAFETY: `ioctl` populated `ifr_hwaddr` for this interface name.
    let sockaddr = unsafe { request.ifr_ifru.ifru_hwaddr };
    read_hardware_address_from_sockaddr(interface_name, &sockaddr)
}

#[cfg(test)]
mod tests {
    use super::read_ipv4_from_sockaddr;
    use crate::error::AppError;
    use std::mem::zeroed;
    use std::net::Ipv4Addr;

    #[test]
    fn reads_ipv4_from_sockaddr_in_fixture() {
        // Arrange
        let expected = Ipv4Addr::new(198, 51, 100, 7);
        let mut socket_address_internet: libc::sockaddr_in = unsafe { zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET should fit sa_family_t");
        socket_address_internet.sin_addr.s_addr = u32::from_be_bytes(expected.octets());

        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_in` for the lifetime of this test.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = read_ipv4_from_sockaddr(sockaddr_ref, |family| {
            AppError::InterfaceIpv4AddressInvalidFamily {
                address_family: family,
            }
        });

        // Assert
        assert_eq!(
            outcome.expect("fixture sockaddr_in should parse"),
            expected,
            "parsed IPv4 should match fixture"
        );
    }
}
