//! Portable link-layer backend boundary shared by platform-specific scanners.
//!
//! Scan scheduling and Ethernet/ARP framing are platform-neutral; only interface discovery and
//! raw frame input/output differ between Linux `AF_PACKET` sockets and macOS Berkeley Packet
//! Filter devices. This module defines the narrow surface those platforms implement: the value
//! types produced by interface discovery and the [`LinkLayerEndpoint`] trait for sending and
//! receiving complete Ethernet II frames. See the 2026-06-03 `DECISIONS.md` entry.

use std::net::Ipv4Addr;

use crate::error::AppError;
use crate::mac_address::MacAddress;

/// IPv4 configuration and Ethernet hardware address discovered for scanning one interface.
// Consumed by the scan path of each backend; the macOS scan path lands in #56.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "consumed by the macOS scan path in #56")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceScanAddresses {
    /// Primary IPv4 address selected for scanning (first address returned by the kernel).
    pub source_ipv4_address: Ipv4Addr,
    /// IPv4 netmask associated with [`Self::source_ipv4_address`].
    pub ipv4_netmask: Ipv4Addr,
    /// Source Ethernet hardware address used in outgoing frames.
    pub source_mac_address: MacAddress,
}

/// One local interface that satisfies the ARP scan filtering rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpScanInterfaceCandidate {
    /// Operating system interface name (for example `eth0` or `en0`).
    pub interface_name: String,
    /// Operating system interface index (`ifindex`).
    pub interface_index: u32,
    /// Primary IPv4 address on this interface.
    pub source_ipv4_address: Ipv4Addr,
    /// IPv4 netmask associated with [`Self::source_ipv4_address`].
    pub ipv4_netmask: Ipv4Addr,
    /// Ethernet hardware address for this interface.
    pub source_mac_address: MacAddress,
}

/// A link-layer endpoint bound to one interface for Ethernet II ARP frames.
///
/// Implementations own the underlying operating system descriptor and close it on drop. The
/// destination of an outgoing frame is the broadcast address already encoded in the frame, so the
/// platform address structure (Linux `sockaddr_ll`, macOS none) stays inside the implementation.
// On Linux the shared scanner calls these methods; on macOS the generic scan caller is wired in
// #56, so off Linux the methods have no caller yet (the macOS BPF impl exists but is not driven).
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "the macOS scan path that calls these is wired in #56"
    )
)]
pub trait LinkLayerEndpoint {
    /// Sends one complete Ethernet II frame on the bound interface.
    ///
    /// # Errors
    ///
    /// Returns the underlying operating system error when the send fails. Callers treat a failed
    /// send as a non-fatal, per-target warning rather than aborting the scan.
    fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()>;

    /// Waits for the endpoint to become readable, up to `timeout_milliseconds`.
    ///
    /// Returns `Ok(true)` when at least one frame is ready, `Ok(false)` on timeout or a benign
    /// interruption (the caller re-evaluates its own deadline).
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the readiness wait fails fatally.
    fn wait_until_readable(&self, timeout_milliseconds: libc::c_int) -> Result<bool, AppError>;

    /// Receives the next currently buffered Ethernet II frame into `buffer` without blocking.
    ///
    /// Returns `Ok(Some(length))` for a frame written to `buffer[..length]`, or `Ok(None)` when no
    /// frame is currently available (the endpoint is drained or the read would block). Benign
    /// interruptions are retried internally.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when receiving fails fatally.
    fn try_receive_ethernet_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, AppError>;
}
