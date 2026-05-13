//! IPv4 subnet helpers for address resolution scanning.

use std::net::Ipv4Addr;

use crate::error::AppError;

/// Returns the prefix length for `netmask` when it is a contiguous classless inter-domain
/// routing netmask.
///
/// # Errors
///
/// Returns [`AppError::Ipv4NetmaskInvalid`] when `netmask` is not a valid contiguous netmask.
///
/// # Panics
///
/// This function does not panic.
pub fn prefix_length_from_contiguous_netmask(netmask: Ipv4Addr) -> Result<u8, AppError> {
    let mask_bits = netmask.to_bits();
    let inverted = !mask_bits;

    if inverted == 0 {
        return Ok(32);
    }

    let power_of_two_host_space = inverted.wrapping_add(1);
    if (inverted & power_of_two_host_space) != 0 {
        return Err(AppError::Ipv4NetmaskInvalid {
            netmask: netmask.to_string(),
        });
    }

    let prefix_bits = inverted.trailing_zeros();
    u8::try_from(prefix_bits).map_err(|_| AppError::Ipv4NetmaskInvalid {
        netmask: netmask.to_string(),
    })
}

/// Computes the first and last **host** IPv4 addresses (excluding network and broadcast) for a
/// subnet described by `interface_address` and `netmask`.
///
/// # Errors
///
/// Returns [`AppError::Ipv4SubnetUnsupported`] when the prefix is `/31`, `/32`, or when there are
/// no usable host addresses between network and broadcast.
///
/// # Panics
///
/// This function does not panic.
pub fn inclusive_host_address_range_excluding_edges(
    interface_address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<(u32, u32), AppError> {
    let prefix_length = prefix_length_from_contiguous_netmask(netmask)?;

    if prefix_length >= 31 {
        return Err(AppError::Ipv4SubnetUnsupported {
            message: format!(
                "IPv4 subnets with prefix length {prefix_length} are not supported for scanning"
            ),
        });
    }

    let mask_bits = netmask.to_bits();
    let network_bits = interface_address.to_bits() & mask_bits;
    let broadcast_bits = network_bits | !mask_bits;
    let first_host_bits =
        network_bits
            .checked_add(1)
            .ok_or_else(|| AppError::Ipv4SubnetUnsupported {
                message: "subnet arithmetic overflow when computing first host address".to_string(),
            })?;
    let last_host_bits =
        broadcast_bits
            .checked_sub(1)
            .ok_or_else(|| AppError::Ipv4SubnetUnsupported {
                message: "subnet arithmetic overflow when computing last host address".to_string(),
            })?;

    if first_host_bits > last_host_bits {
        return Err(AppError::Ipv4SubnetUnsupported {
            message: "no usable host addresses exist between network and broadcast addresses"
                .to_string(),
        });
    }

    Ok((first_host_bits, last_host_bits))
}

/// Returns `true` when `candidate` lies strictly between `network_bits` and `broadcast_bits`.
///
/// # Panics
///
/// This function does not panic.
pub fn ipv4_address_is_strictly_inside_subnet(
    candidate: Ipv4Addr,
    network_bits: u32,
    broadcast_bits: u32,
) -> bool {
    let candidate_bits = candidate.to_bits();
    candidate_bits > network_bits && candidate_bits < broadcast_bits
}

#[cfg(test)]
mod tests {
    use super::inclusive_host_address_range_excluding_edges;
    use super::ipv4_address_is_strictly_inside_subnet;
    use super::prefix_length_from_contiguous_netmask;
    use crate::error::AppError;
    use std::net::Ipv4Addr;

    #[test]
    fn computes_prefix_length_for_slash_24_netmask() {
        // Arrange
        let netmask = Ipv4Addr::new(255, 255, 255, 0);

        // Act
        let outcome = prefix_length_from_contiguous_netmask(netmask);

        // Assert
        assert_eq!(
            outcome.expect("valid contiguous netmask should parse"),
            24,
            "expected /24 prefix length"
        );
    }

    #[test]
    fn returns_error_when_netmask_is_not_contiguous() {
        // Arrange
        let netmask = Ipv4Addr::new(255, 0, 255, 0);

        // Act
        let outcome = prefix_length_from_contiguous_netmask(netmask);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4NetmaskInvalid { .. })),
            "non-contiguous netmask should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_for_slash_31_prefix() {
        // Arrange
        let address = Ipv4Addr::new(192, 0, 2, 0);
        let netmask = Ipv4Addr::new(255, 255, 255, 254);

        // Act
        let outcome = inclusive_host_address_range_excluding_edges(address, netmask);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4SubnetUnsupported { .. })),
            "/31 subnets should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_for_slash_32_prefix() {
        // Arrange
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let netmask = Ipv4Addr::BROADCAST;

        // Act
        let outcome = inclusive_host_address_range_excluding_edges(address, netmask);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4SubnetUnsupported { .. })),
            "/32 subnets should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn computes_host_range_for_slash_24() {
        // Arrange
        let address = Ipv4Addr::new(192, 168, 1, 10);
        let netmask = Ipv4Addr::new(255, 255, 255, 0);

        // Act
        let outcome = inclusive_host_address_range_excluding_edges(address, netmask);

        // Assert
        let (first, last) = outcome.expect("valid /24 subnet should yield a host range");
        assert_eq!(
            Ipv4Addr::from_bits(first),
            Ipv4Addr::new(192, 168, 1, 1),
            "first host should be .1"
        );
        assert_eq!(
            Ipv4Addr::from_bits(last),
            Ipv4Addr::new(192, 168, 1, 254),
            "last host should be .254"
        );
    }

    #[test]
    fn detects_address_inside_open_subnet_interval() {
        // Arrange
        let network = Ipv4Addr::new(10, 0, 0, 0).to_bits();
        let broadcast = Ipv4Addr::new(10, 0, 0, 255).to_bits();
        let inside = Ipv4Addr::new(10, 0, 0, 50);

        // Act
        let inside_outcome = ipv4_address_is_strictly_inside_subnet(inside, network, broadcast);
        let network_outcome =
            ipv4_address_is_strictly_inside_subnet(Ipv4Addr::new(10, 0, 0, 0), network, broadcast);
        let broadcast_outcome = ipv4_address_is_strictly_inside_subnet(
            Ipv4Addr::new(10, 0, 0, 255),
            network,
            broadcast,
        );

        // Assert
        assert!(inside_outcome, "interior address should be inside subnet");
        assert!(
            !network_outcome,
            "network address should not be strictly inside subnet"
        );
        assert!(
            !broadcast_outcome,
            "broadcast address should not be strictly inside subnet"
        );
    }
}
