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

    /// Lookup both ASN and subnet information for an IP address with a single database query
    pub fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        let (asn_record, prefix_len) = self.reader.as_ref()?.lookup_prefix::<geoip2::Asn>(ip).ok()?;

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
            asn: AsnInfo { number, organization },
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
}
