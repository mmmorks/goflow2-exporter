use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use tracing::warn;

pub struct AsnLookup {
    reader: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, PartialEq)]
pub struct AsnInfo {
    pub number: u32,
    pub organization: String,
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

    pub fn lookup_asn_info(&self, ip: IpAddr) -> Option<AsnInfo> {
        let asn_record = self.reader.as_ref()?.lookup::<geoip2::Asn>(ip).ok()?;

        let number = asn_record.autonomous_system_number?;
        let organization = asn_record
            .autonomous_system_organization
            .unwrap_or("Unknown")
            .to_string();

        Some(AsnInfo {
            number,
            organization,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_asn_lookup_no_database() {
        let lookup = AsnLookup::new(None);
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert!(lookup.lookup_asn_info(ip).is_none());
    }

    #[test]
    fn test_asn_lookup_invalid_path() {
        let lookup = AsnLookup::new(Some("/nonexistent/path.mmdb"));
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert!(lookup.lookup_asn_info(ip).is_none());
    }

    #[test]
    fn test_asn_lookup_new_with_none() {
        let lookup = AsnLookup::new(None);
        assert!(lookup.reader.is_none());
    }

    #[test]
    fn test_asn_lookup_with_real_database() {
        // Test with our minimal test database
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));
        assert!(lookup.reader.is_some());

        // Test IPv4 lookup - Google's ASN is 15169
        let ipv4 = IpAddr::from_str("8.8.8.8").unwrap();
        let asn_info = lookup.lookup_asn_info(ipv4);
        assert!(asn_info.is_some());
        assert_eq!(asn_info.unwrap().number, 15169);

        // Test IPv6 lookup - Google's ASN is 15169
        let ipv6 = IpAddr::from_str("2001:4860:4860::8888").unwrap();
        let asn_info = lookup.lookup_asn_info(ipv6);
        assert!(asn_info.is_some());
        assert_eq!(asn_info.unwrap().number, 15169);
    }

    #[test]
    fn test_asn_lookup_info_with_real_database() {
        let lookup = AsnLookup::new(Some("./test_data/test-asn.mmdb"));
        assert!(lookup.reader.is_some());

        // Test IPv4 lookup with organization info
        let ipv4 = IpAddr::from_str("8.8.8.8").unwrap();
        let asn_info = lookup.lookup_asn_info(ipv4);
        assert!(asn_info.is_some());

        let info = asn_info.unwrap();
        assert_eq!(info.number, 15169);
        assert!(info.organization.contains("Google") || !info.organization.is_empty());
    }

    #[test]
    fn test_asn_lookup_info_no_database() {
        let lookup = AsnLookup::new(None);
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert!(lookup.lookup_asn_info(ip).is_none());
    }
}
