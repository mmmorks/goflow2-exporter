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

    /// Lookup both ASN and subnet information for an IP address with a single database query.
    /// Returns synthetic IpInfo for private IP addresses (RFC 1918 and IPv6 ULA).
    pub fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        // First check if this is a private IP address
        if let Some(private_info) = classify_private_ip(ip) {
            return Some(private_info);
        }

        // For public IPs, query the MaxMind database
        let (asn_record, prefix_len) = self
            .reader
            .as_ref()?
            .lookup_prefix::<geoip2::Asn>(ip)
            .ok()?;

        // Extract ASN information
        let number = asn_record.autonomous_system_number?;
        let organization = asn_record
            .autonomous_system_organization
            .unwrap_or("Unknown")
            .to_string();

        // Calculate subnet CIDR notation using ipnet
        let network = IpNet::new(ip, prefix_len as u8).ok()?.trunc();
        let cidr = network.to_string();

        // Determine address type
        let address_type = match ip {
            IpAddr::V4(_) => AddressType::IPv4,
            IpAddr::V6(_) => AddressType::IPv6,
        };

        Some(IpInfo {
            asn: AsnInfo {
                number,
                organization,
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
        assert!(lookup.lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_with_invalid_path() {
        let lookup = AsnLookup::new(Some("/nonexistent/path.mmdb"));
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert!(lookup.lookup(ip).is_none());
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
            let info = lookup.lookup(ip);

            // These should return None since they're not private and we have no database
            assert!(
                info.is_none(),
                "IP {} should not be classified as private",
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
            let info = lookup.lookup(ip);

            // Should return None since no database is loaded
            assert!(
                info.is_none(),
                "IP {} should not be classified as private",
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
            let info = lookup.lookup(ip);

            // Should return None since no database is loaded
            assert!(
                info.is_none(),
                "IPv6 {} should not be classified as private",
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
}
