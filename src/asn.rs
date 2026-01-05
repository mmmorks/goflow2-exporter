use ipnet::IpNet;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use strum_macros::{Display, EnumString};
use tracing::warn;

pub struct AsnLookup {
    reader: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, PartialEq, Clone, Copy, Display, EnumString)]
pub enum AddressType {
    #[strum(serialize = "IPv4")]
    IPv4,
    #[strum(serialize = "IPv6")]
    IPv6,
}

#[derive(Debug, PartialEq)]
pub struct AsnInfo {
    pub number: u32,
    pub organization: String,
}

#[derive(Debug, PartialEq)]
pub struct SubnetInfo {
    pub cidr: String,
    pub address_type: AddressType,
}

#[derive(Debug, PartialEq)]
pub struct IpInfo {
    pub asn: AsnInfo,
    pub subnet: SubnetInfo,
}

/// Classifies an IPv6 address as "own" based on next_hop patterns.
///
/// For 6rd tunnels and similar IPv6 deployments:
/// - next_hop "::300:0:0:0" indicates outbound traffic
/// - next_hop "::4000:0:0:0" indicates inbound traffic
///
/// Returns synthetic IpInfo with ASN 64516 if either magic next_hop value is present.
fn classify_own_ipv6(ip: IpAddr, next_hop: Option<&str>) -> Option<IpInfo> {
    if !matches!(ip, IpAddr::V6(_)) {
        return None;
    }

    // Check for either magic next_hop value
    let is_own = matches!(next_hop, Some("::300:0:0:0") | Some("::4000:0:0:0"));

    if is_own {
        // Extract /64 prefix from the full IPv6 address for subnet tracking
        if let IpAddr::V6(v6) = ip {
            let segments = v6.segments();
            let prefix = format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            );

            return Some(IpInfo {
                asn: AsnInfo {
                    number: 64516,
                    organization: "Own (Public IPv6)".to_string(),
                },
                subnet: SubnetInfo {
                    cidr: prefix,
                    address_type: AddressType::IPv6,
                },
            });
        }
    }

    None
}

/// Classifies a private IP address and returns synthetic IpInfo.
/// Handles RFC 1918 private IPv4 ranges and IPv6 ULA addresses.
fn classify_private_ip(ip: IpAddr) -> Option<IpInfo> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            // 10.0.0.0/8 - RFC 1918
            if octets[0] == 10 {
                return Some(IpInfo {
                    asn: AsnInfo {
                        number: 64512,
                        organization: "Private (Class A)".to_string(),
                    },
                    subnet: SubnetInfo {
                        cidr: "10.0.0.0/8".to_string(),
                        address_type: AddressType::IPv4,
                    },
                });
            }

            // 172.16.0.0/12 - RFC 1918 (172.16.0.0 to 172.31.255.255)
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return Some(IpInfo {
                    asn: AsnInfo {
                        number: 64513,
                        organization: "Private (Class B)".to_string(),
                    },
                    subnet: SubnetInfo {
                        cidr: "172.16.0.0/12".to_string(),
                        address_type: AddressType::IPv4,
                    },
                });
            }

            // 192.168.0.0/16 - RFC 1918
            if octets[0] == 192 && octets[1] == 168 {
                return Some(IpInfo {
                    asn: AsnInfo {
                        number: 64514,
                        organization: "Private (Class C)".to_string(),
                    },
                    subnet: SubnetInfo {
                        cidr: "192.168.0.0/16".to_string(),
                        address_type: AddressType::IPv4,
                    },
                });
            }

            None
        }
        IpAddr::V6(v6) => {
            // fc00::/7 - IPv6 Unique Local Addresses (ULA)
            // First byte should be 0xfc or 0xfd
            let octets = v6.octets();
            if octets[0] == 0xfc || octets[0] == 0xfd {
                return Some(IpInfo {
                    asn: AsnInfo {
                        number: 64515,
                        organization: "Private (ULA)".to_string(),
                    },
                    subnet: SubnetInfo {
                        cidr: "fc00::/7".to_string(),
                        address_type: AddressType::IPv6,
                    },
                });
            }

            None
        }
    }
}

impl AsnLookup {
    pub fn new(db_path: Option<&str>) -> Self {
        let reader = db_path.and_then(|path| match Reader::open_readfile(path) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!("Failed to load ASN database from {}: {}", path, e);
                None
            }
        });

        Self { reader }
    }

    /// Lookup both ASN and subnet information for an IP address with next_hop context.
    ///
    /// Checks in order:
    /// 1. Own IPv6 addresses (based on next_hop magic values for 6rd/tunnels)
    /// 2. Private IP addresses (RFC 1918, IPv6 ULA)
    /// 3. MaxMind ASN database
    /// 4. Falls back to "Unknown" (ASN 0)
    ///
    /// The next_hop parameter enables automatic detection of own public IPv6 addresses
    /// in 6rd deployments. If next_hop is "::300:0:0:0" or "::4000:0:0:0", IPv6 addresses
    /// are classified as "own".
    pub fn lookup_with_context(&self, ip: IpAddr, next_hop: Option<&str>) -> Option<IpInfo> {
        // First check if this is own public IPv6 (6rd or similar)
        if let Some(own_info) = classify_own_ipv6(ip, next_hop) {
            return Some(own_info);
        }

        // Fall back to standard lookup (private IPs, database, unknown)
        self.lookup(ip)
    }

    /// Lookup both ASN and subnet information for an IP address with a single database query.
    /// Returns synthetic IpInfo for private IP addresses (RFC 1918 and IPv6 ULA).
    /// Returns "Unknown" (ASN 0, subnet 0.0.0.0/0 or ::/0) for IPs not found in database
    /// to ensure all traffic is tracked even without ASN data.
    pub fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        // First check if this is a private IP address
        if let Some(private_info) = classify_private_ip(ip) {
            return Some(private_info);
        }

        // For public IPs, query the MaxMind database
        if let Some(reader) = self.reader.as_ref() {
            if let Ok((asn_record, prefix_len)) = reader.lookup_prefix::<geoip2::Asn>(ip) {
                if let Some(number) = asn_record.autonomous_system_number {
                    let organization = asn_record
                        .autonomous_system_organization
                        .unwrap_or("Unknown")
                        .to_string();

                    // Calculate subnet CIDR notation using ipnet
                    if let Ok(network) = IpNet::new(ip, prefix_len as u8) {
                        let cidr = network.trunc().to_string();
                        let address_type = match ip {
                            IpAddr::V4(_) => AddressType::IPv4,
                            IpAddr::V6(_) => AddressType::IPv6,
                        };

                        return Some(IpInfo {
                            asn: AsnInfo {
                                number,
                                organization,
                            },
                            subnet: SubnetInfo { cidr, address_type },
                        });
                    }
                }
            }
        }

        // If we get here, either no database, IP not found, or lookup failed
        // Return synthetic "Unknown" data to ensure traffic is tracked
        let (cidr, address_type) = match ip {
            IpAddr::V4(_) => ("0.0.0.0/0".to_string(), AddressType::IPv4),
            IpAddr::V6(_) => ("::/0".to_string(), AddressType::IPv6),
        };

        Some(IpInfo {
            asn: AsnInfo {
                number: 0,
                organization: "Unknown".to_string(),
            },
            subnet: SubnetInfo { cidr, address_type },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_lookup_without_database() {
        let lookup = AsnLookup::new(None);
        assert!(lookup.reader.is_none());

        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let info = lookup.lookup(ip).unwrap();

        // Without database, should return "Unknown" ASN 0
        assert_eq!(info.asn.number, 0);
        assert_eq!(info.asn.organization, "Unknown");
        assert_eq!(info.subnet.cidr, "0.0.0.0/0");
        assert_eq!(info.subnet.address_type, AddressType::IPv4);
    }

    #[test]
    fn test_lookup_with_invalid_path() {
        let lookup = AsnLookup::new(Some("/nonexistent/path.mmdb"));
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let info = lookup.lookup(ip).unwrap();

        // Invalid database path should return "Unknown" ASN 0
        assert_eq!(info.asn.number, 0);
        assert_eq!(info.asn.organization, "Unknown");
        assert_eq!(info.subnet.cidr, "0.0.0.0/0");
    }

    #[test]
    fn test_ipv4_lookup_with_database() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));
        assert!(lookup.reader.is_some());

        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let info = lookup.lookup(ip).unwrap();

        // Verify ASN information
        assert_eq!(info.asn.number, 15169);
        assert!(info.asn.organization.contains("Google") || !info.asn.organization.is_empty());

        // Verify subnet information
        assert_eq!(info.subnet.cidr, "8.8.8.0/24");
        assert_eq!(info.subnet.address_type, AddressType::IPv4);
        assert_eq!(info.subnet.address_type.to_string(), "IPv4");
    }

    #[test]
    fn test_ipv6_lookup_with_database() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));

        let ip = IpAddr::from_str("2001:4860:4860::8888").unwrap();
        let info = lookup.lookup(ip).unwrap();

        // Verify ASN information
        assert_eq!(info.asn.number, 15169);

        // Verify subnet information
        assert_eq!(info.subnet.cidr, "2001:4860:4860::/48");
        assert_eq!(info.subnet.address_type, AddressType::IPv6);
        assert_eq!(info.subnet.address_type.to_string(), "IPv6");
    }

    #[test]
    fn test_subnet_masking() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));

        // Test that different IPs in the same /24 subnet return the same CIDR
        let ip1 = IpAddr::from_str("8.8.8.8").unwrap();
        let ip2 = IpAddr::from_str("8.8.8.9").unwrap();

        let info1 = lookup.lookup(ip1).unwrap();
        let info2 = lookup.lookup(ip2).unwrap();

        // Both IPs are in Google's 8.8.8.0/24 subnet, should return the same CIDR
        assert_eq!(info1.subnet.cidr, "8.8.8.0/24");
        assert_eq!(info2.subnet.cidr, "8.8.8.0/24");
        assert_eq!(info1.subnet.cidr, info2.subnet.cidr);

        // Both should also have the same ASN
        assert_eq!(info1.asn.number, info2.asn.number);
    }

    #[test]
    fn test_private_ipv4_10_network() {
        let lookup = AsnLookup::new(None);

        // Test boundary cases for 10.0.0.0/8
        let test_cases = vec![
            "10.0.0.0",       // First IP
            "10.0.0.1",       // Second IP
            "10.128.0.1",     // Middle of range
            "10.255.255.254", // Near last IP
            "10.255.255.255", // Last IP
        ];

        for ip_str in test_cases {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            assert_eq!(info.asn.number, 64512);
            assert_eq!(info.asn.organization, "Private (Class A)");
            assert_eq!(info.subnet.cidr, "10.0.0.0/8");
            assert_eq!(info.subnet.address_type, AddressType::IPv4);
        }
    }

    #[test]
    fn test_private_ipv4_172_network() {
        let lookup = AsnLookup::new(None);

        // Test boundary cases for 172.16.0.0/12
        let test_cases = vec![
            "172.16.0.0",     // First IP
            "172.16.0.1",     // Second IP
            "172.20.0.1",     // Middle of range
            "172.31.255.254", // Near last IP
            "172.31.255.255", // Last IP
        ];

        for ip_str in test_cases {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            assert_eq!(info.asn.number, 64513);
            assert_eq!(info.asn.organization, "Private (Class B)");
            assert_eq!(info.subnet.cidr, "172.16.0.0/12");
            assert_eq!(info.subnet.address_type, AddressType::IPv4);
        }
    }

    #[test]
    fn test_non_private_172_network() {
        let lookup = AsnLookup::new(None);

        // Test IPs outside the private 172.16.0.0/12 range
        let non_private_ips = vec![
            "172.15.255.255",  // Just before private range
            "172.32.0.0",      // Just after private range
            "172.0.0.1",       // Far below private range
            "172.255.255.255", // Far above private range
        ];

        for ip_str in non_private_ips {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            // These are not private, and with no database should return "Unknown"
            assert_eq!(info.asn.number, 0, "IP {} should be Unknown ASN", ip_str);
            assert_eq!(
                info.asn.organization, "Unknown",
                "IP {} should be Unknown",
                ip_str
            );
            assert_eq!(
                info.subnet.cidr, "0.0.0.0/0",
                "IP {} should have 0.0.0.0/0 subnet",
                ip_str
            );
        }
    }

    #[test]
    fn test_private_ipv4_192_network() {
        let lookup = AsnLookup::new(None);

        // Test boundary cases for 192.168.0.0/16
        let test_cases = vec![
            "192.168.0.0",     // First IP
            "192.168.0.1",     // Second IP
            "192.168.1.1",     // Common home router
            "192.168.255.254", // Near last IP
            "192.168.255.255", // Last IP (broadcast)
        ];

        for ip_str in test_cases {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            assert_eq!(info.asn.number, 64514);
            assert_eq!(info.asn.organization, "Private (Class C)");
            assert_eq!(info.subnet.cidr, "192.168.0.0/16");
            assert_eq!(info.subnet.address_type, AddressType::IPv4);
        }
    }

    #[test]
    fn test_private_ipv6_ula() {
        let lookup = AsnLookup::new(None);

        // Test IPv6 Unique Local Addresses (fc00::/7)
        let test_cases = vec![
            "fc00::1",                                 // First usable in fc00::/8
            "fc00:1234:5678:9abc:def0:1234:5678:9abc", // Middle of fc00::/8
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // Last in fd00::/8
            "fd00::1",                                 // First usable in fd00::/8
        ];

        for ip_str in test_cases {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            assert_eq!(info.asn.number, 64515);
            assert_eq!(info.asn.organization, "Private (ULA)");
            assert_eq!(info.subnet.cidr, "fc00::/7");
            assert_eq!(info.subnet.address_type, AddressType::IPv6);
        }
    }

    #[test]
    fn test_public_ipv4_not_classified_as_private() {
        let lookup = AsnLookup::new(None);

        // Test various public IP ranges
        let public_ips = vec![
            "8.8.8.8",       // Google DNS
            "1.1.1.1",       // Cloudflare DNS
            "9.255.255.255", // Just before 10.0.0.0
            "11.0.0.0",      // Just after 10.0.0.0/8
            "192.167.1.1",   // Just before 192.168.0.0
            "192.169.1.1",   // Just after 192.168.0.0/16
        ];

        for ip_str in public_ips {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            // Without database, public IPs should return "Unknown" ASN 0
            assert_eq!(
                info.asn.number, 0,
                "IP {} should be Unknown ASN without database",
                ip_str
            );
            assert_eq!(
                info.asn.organization, "Unknown",
                "IP {} should be Unknown",
                ip_str
            );
            assert_eq!(
                info.subnet.cidr, "0.0.0.0/0",
                "IP {} should have 0.0.0.0/0 subnet",
                ip_str
            );
        }
    }

    #[test]
    fn test_public_ipv6_not_classified_as_private() {
        let lookup = AsnLookup::new(None);

        // Test public IPv6 addresses
        let public_ips = vec![
            "2001:4860:4860::8888", // Google DNS
            "2606:4700:4700::1111", // Cloudflare DNS
            "fe00::1",              // Just before fc00::/7
            "fe80::1",              // Link-local (different from ULA)
        ];

        for ip_str in public_ips {
            let ip = IpAddr::from_str(ip_str).unwrap();
            let info = lookup.lookup(ip).unwrap();

            // Without database, public IPv6 should return "Unknown" ASN 0
            assert_eq!(
                info.asn.number, 0,
                "IPv6 {} should be Unknown ASN without database",
                ip_str
            );
            assert_eq!(
                info.asn.organization, "Unknown",
                "IPv6 {} should be Unknown",
                ip_str
            );
            assert_eq!(
                info.subnet.cidr, "::/0",
                "IPv6 {} should have ::/0 subnet",
                ip_str
            );
        }
    }

    #[test]
    fn test_private_ip_overrides_database() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));

        // Even with database loaded, private IPs should use synthetic data
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let info = lookup.lookup(ip).unwrap();

        // Should get synthetic private IP data, not database data
        assert_eq!(info.asn.number, 64514);
        assert_eq!(info.asn.organization, "Private (Class C)");
        assert_eq!(info.subnet.cidr, "192.168.0.0/16");
    }

    #[test]
    fn test_public_ip_uses_database() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));

        // Public IPs should still use database when available
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let info = lookup.lookup(ip).unwrap();

        // Should get database data for Google
        assert_eq!(info.asn.number, 15169);
        assert_eq!(info.subnet.cidr, "8.8.8.0/24");
    }

    #[test]
    fn test_own_ipv6_outbound_detection() {
        let lookup = AsnLookup::new(None);

        // Outbound traffic (::300:0:0:0) - should be classified as own
        let ip = IpAddr::from_str("2602:47:d4ad:f901:aa23:feff:fe20:946b").unwrap();
        let info = lookup.lookup_with_context(ip, Some("::300:0:0:0")).unwrap();

        assert_eq!(info.asn.number, 64516);
        assert_eq!(info.asn.organization, "Own (Public IPv6)");
        assert_eq!(info.subnet.cidr, "2602:47:d4ad:f901::/64");
        assert_eq!(info.subnet.address_type, AddressType::IPv6);
    }

    #[test]
    fn test_own_ipv6_inbound_detection() {
        let lookup = AsnLookup::new(None);

        // Inbound traffic (::4000:0:0:0) - should be classified as own
        let ip = IpAddr::from_str("2602:47:d4ad:f901:3152:860d:d317:16d7").unwrap();
        let info = lookup
            .lookup_with_context(ip, Some("::4000:0:0:0"))
            .unwrap();

        assert_eq!(info.asn.number, 64516);
        assert_eq!(info.asn.organization, "Own (Public IPv6)");
        assert_eq!(info.subnet.cidr, "2602:47:d4ad:f901::/64");
        assert_eq!(info.subnet.address_type, AddressType::IPv6);
    }

    #[test]
    fn test_own_ipv6_no_next_hop_not_classified() {
        let lookup = AsnLookup::new(None);

        // No next_hop provided - should NOT be classified as own
        let ip = IpAddr::from_str("2602:47:d4ad:f901:aa23:feff:fe20:946b").unwrap();
        let info = lookup.lookup_with_context(ip, None).unwrap();

        // Should fall back to "Unknown" (ASN 0) since no database
        assert_eq!(info.asn.number, 0);
        assert_eq!(info.asn.organization, "Unknown");
    }

    #[test]
    fn test_own_ipv6_different_next_hop_not_classified() {
        let lookup = AsnLookup::new(None);

        // Different next_hop value - should NOT be classified as own
        let ip = IpAddr::from_str("2602:47:d4ad:f901:aa23:feff:fe20:946b").unwrap();
        let info = lookup
            .lookup_with_context(ip, Some("aa23:feff:fe20:946b:8000::"))
            .unwrap();

        // Should fall back to "Unknown" (ASN 0) since no database
        assert_eq!(info.asn.number, 0);
        assert_eq!(info.asn.organization, "Unknown");
    }

    #[test]
    fn test_own_ipv6_ipv4_not_affected() {
        let lookup = AsnLookup::new(None);

        // IPv4 address should not be affected by next_hop detection
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let info = lookup.lookup_with_context(ip, Some("::300:0:0:0")).unwrap();

        // Should still be classified as private IPv4
        assert_eq!(info.asn.number, 64514);
        assert_eq!(info.asn.organization, "Private (Class C)");
    }

    #[test]
    fn test_own_ipv6_overrides_database() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));

        // Even with database, own IPv6 detection should take precedence
        let ip = IpAddr::from_str("2602:47:d4ad:f901:aa23:feff:fe20:946b").unwrap();
        let info = lookup.lookup_with_context(ip, Some("::300:0:0:0")).unwrap();

        assert_eq!(info.asn.number, 64516);
        assert_eq!(info.asn.organization, "Own (Public IPv6)");
        assert_eq!(info.subnet.cidr, "2602:47:d4ad:f901::/64");
    }

    #[test]
    fn test_own_ipv6_multiple_hosts_same_prefix() {
        let lookup = AsnLookup::new(None);

        // Different hosts on the same /64 should all get the same subnet
        let hosts = vec![
            "2602:47:d4ad:f901:aa23:feff:fe20:946b",
            "2602:47:d4ad:f901:3152:860d:d317:16d7",
            "2602:47:d4ad:f901:bc14:668f:1c4:d89a",
            "2602:47:d4ad:f901:e150:d20a:204c:c4b0",
        ];

        for host_str in hosts {
            let ip = IpAddr::from_str(host_str).unwrap();
            let info = lookup.lookup_with_context(ip, Some("::300:0:0:0")).unwrap();

            assert_eq!(info.asn.number, 64516);
            assert_eq!(info.asn.organization, "Own (Public IPv6)");
            assert_eq!(
                info.subnet.cidr, "2602:47:d4ad:f901::/64",
                "All hosts should map to same /64 prefix"
            );
        }
    }
}
