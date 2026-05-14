//! Thin `libc` wrappers for Linux system calls used by raw packet scanning.
//!
//! All foreign-function-interface calls are concentrated here. Callers translate operating
//! system errors into [`crate::error::AppError`] at higher layers.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::linux_packet::ethernet_protocol_host_to_network_order;

/// `ioctl(2)` request for reading interface flags (`SIOCGIFFLAGS`).
pub const SIOCGIFFLAGS_REQUEST: libc::Ioctl = 0x8913;

/// `ioctl(2)` request for reading an interface IPv4 address (`SIOCGIFADDR`).
pub const SIOCGIFADDR_REQUEST: libc::Ioctl = 0x8915;

/// `ioctl(2)` request for reading an interface IPv4 netmask (`SIOCGIFNETMASK`).
pub const SIOCGIFNETMASK_REQUEST: libc::Ioctl = 0x891b;

/// `ioctl(2)` request for reading an interface hardware address (`SIOCGIFHWADDR`).
pub const SIOCGIFHWADDR_REQUEST: libc::Ioctl = 0x8927;

fn sockaddr_link_layer_length() -> std::io::Result<libc::socklen_t> {
    libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sockaddr_ll length does not fit socklen_t",
        )
    })
}

/// Opens an `AF_INET` datagram socket for interface `ioctl` operations.
///
/// # Errors
///
/// Returns the last operating system error when `socket(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn open_inet_datagram_socket() -> std::io::Result<OwnedFd> {
    // SAFETY: `socket(2)` with `AF_INET`/`SOCK_DGRAM` is the standard approach for issuing
    // interface `ioctl`s (see `netdevice(7)`).
    let file_descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };

    if file_descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `file_descriptor` is a freshly created valid socket file descriptor returned by
    // `socket(2)`.
    Ok(unsafe { OwnedFd::from_raw_fd(file_descriptor) })
}

/// Invokes `ioctl(2)` with a mutable [`libc::ifreq`] buffer.
///
/// # Errors
///
/// Returns the last operating system error when `ioctl(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn ioctl_ifreq(
    socket: &OwnedFd,
    request_code: libc::Ioctl,
    request: &mut libc::ifreq,
) -> std::io::Result<()> {
    // SAFETY: `socket` is a valid datagram socket file descriptor and `request` is a valid
    // `ifreq` pointer for the given `request_code` (see `ioctl(2)` and `netdevice(7)`).
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            request_code,
            std::ptr::from_mut(request).cast::<libc::c_void>(),
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Resolves `interface_name` to an interface index via `if_nametoindex(3)`.
///
/// # Errors
///
/// Returns the last operating system error when the name is not found or resolution fails.
///
/// # Panics
///
/// This function does not panic.
pub fn interface_index_from_name(interface_name: &std::ffi::CStr) -> std::io::Result<libc::c_uint> {
    // SAFETY: `interface_name` is a valid NUL-terminated C string pointer accepted by
    // `if_nametoindex(3)`.
    let index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(index)
}

/// Opens a raw `AF_PACKET` / `SOCK_RAW` socket for the given Ethernet protocol (for example
/// [`crate::linux_packet::ETHERNET_PROTOCOL_ARP`] in host byte order; the kernel expects
/// `protocol` in network byte order per `packet(7)`).
///
/// # Errors
///
/// Returns the last operating system error when `socket(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn open_packet_raw_socket(ethernet_protocol_host_order: u16) -> std::io::Result<OwnedFd> {
    let protocol = libc::c_int::from(ethernet_protocol_host_to_network_order(
        ethernet_protocol_host_order,
    ));

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
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `file_descriptor` is a freshly created valid socket file descriptor returned by
    // `socket(2)`.
    Ok(unsafe { OwnedFd::from_raw_fd(file_descriptor) })
}

/// Binds a packet socket to a [`libc::sockaddr_ll`] address.
///
/// # Errors
///
/// Returns the last operating system error when `bind(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn bind_sockaddr_link_layer(
    socket: &OwnedFd,
    address: &libc::sockaddr_ll,
) -> std::io::Result<()> {
    let address_length = sockaddr_link_layer_length()?;

    // SAFETY: `address` matches `struct sockaddr_ll` and `bind(2)` expects a `sockaddr` pointer
    // with the correct length for this address family (see `packet(7)`).
    let bind_result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::from_ref::<libc::sockaddr_ll>(address).cast::<libc::sockaddr>(),
            address_length,
        )
    };

    if bind_result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Sends a datagram on a packet socket using `sendto(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `sendto(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn send_to_link_layer(
    socket: &OwnedFd,
    message: &[u8],
    destination: &libc::sockaddr_ll,
) -> std::io::Result<usize> {
    let destination_length = sockaddr_link_layer_length()?;

    // SAFETY: `message` is a valid byte slice and `destination` points to a valid `sockaddr_ll`
    // for the packet socket (see `sendto(2)` and `packet(7)`).
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr().cast::<libc::c_void>(),
            message.len(),
            0,
            std::ptr::from_ref::<libc::sockaddr_ll>(destination).cast::<libc::sockaddr>(),
            destination_length,
        )
    };

    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }

    usize::try_from(sent)
        .map_err(|_| std::io::Error::other("sendto returned a negative byte count"))
}

/// Receives a datagram from a packet socket using `recvfrom(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `recvfrom(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn receive_from_link_layer(
    socket: &OwnedFd,
    buffer: &mut [u8],
    flags: libc::c_int,
    source_out: Option<&mut libc::sockaddr_ll>,
) -> std::io::Result<usize> {
    let mut address_length = sockaddr_link_layer_length()?;
    let (source_pointer, source_length_pointer) = match source_out {
        Some(out) => (
            std::ptr::from_mut(out).cast::<libc::sockaddr>(),
            std::ptr::from_mut(&mut address_length),
        ),
        None => (std::ptr::null_mut(), std::ptr::null_mut()),
    };

    // SAFETY: `buffer` is a valid writable slice; when `source_out` is `Some`, `out` is large
    // enough for `sockaddr_ll` and `address_length` is initialized to that size (see
    // `recvfrom(2)`).
    let received = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            flags,
            source_pointer,
            source_length_pointer,
        )
    };

    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }

    usize::try_from(received)
        .map_err(|_| std::io::Error::other("recvfrom returned a negative byte count"))
}

/// Waits for readiness on `socket` using `poll(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `poll(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn poll_socket_readiness(
    socket: &OwnedFd,
    events: i16,
    timeout_milliseconds: libc::c_int,
) -> std::io::Result<libc::c_int> {
    let mut poll_file_descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };

    // SAFETY: `poll_file_descriptor` points to one element for the duration of the call.
    let ready = unsafe {
        libc::poll(
            std::ptr::addr_of_mut!(poll_file_descriptor),
            1,
            timeout_milliseconds,
        )
    };

    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::interface_index_from_name;
    use super::open_inet_datagram_socket;
    use super::poll_socket_readiness;
    use std::ffi::CString;

    #[test]
    fn opens_inet_datagram_socket_successfully_on_linux() {
        // Arrange
        // Act
        let outcome = open_inet_datagram_socket();

        // Assert
        assert!(
            outcome.is_ok(),
            "opening an inet datagram socket should succeed on Linux, got: {outcome:?}"
        );
    }

    #[test]
    fn resolves_loopback_interface_index_on_linux() {
        // Arrange
        let name = CString::new("lo").expect("loopback interface name should be valid C string");

        // Act
        let outcome = interface_index_from_name(&name);

        // Assert
        assert!(
            outcome.is_ok(),
            "loopback interface index should resolve on Linux, got: {outcome:?}"
        );
        assert_ne!(
            outcome.expect("index resolution should succeed"),
            0,
            "loopback index should be non-zero"
        );
    }

    #[test]
    fn interface_index_from_name_fails_for_nonexistent_interface() {
        // Arrange
        let name = CString::new("narp___nonexistent_iface___").expect("fixture name");

        // Act
        let outcome = interface_index_from_name(&name);

        // Assert
        assert!(
            outcome.is_err(),
            "bogus interface names should fail resolution, got: {outcome:?}"
        );
    }

    #[test]
    fn poll_on_inet_datagram_socket_reports_pollout_without_blocking_forever() {
        // Arrange
        let socket = open_inet_datagram_socket().expect("inet datagram socket should open");
        let timeout_milliseconds: libc::c_int = 100;

        // Act
        let outcome = poll_socket_readiness(&socket, libc::POLLOUT, timeout_milliseconds);

        // Assert
        let ready = outcome.expect("poll on open socket should succeed");
        assert_ne!(
            ready, 0,
            "POLLOUT should become ready quickly on an open datagram socket, got ready={ready}"
        );
    }
}
