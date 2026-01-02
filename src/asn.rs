use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use tracing::warn;

pub struct AsnLookup {
    reader: Option<Reader<Vec<u8>>>,
}

impl AsnLookup {
    pub fn new(db_path: Option<&str>) -> Self {
        let reader = db_path.and_then(|path| {
            match Reader::open_readfile(path) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!("Failed to load ASN database from {}: {}", path, e);
                    None
                }
            }
        });
        
        Self { reader }
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        self.reader.as_ref()?.lookup::<geoip2::Asn>(ip)
            .ok()?
            .autonomous_system_number
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
        assert_eq!(lookup.lookup_asn(ip), None);
    }

    #[test]
    fn test_asn_lookup_invalid_path() {
        let lookup = AsnLookup::new(Some("/nonexistent/path.mmdb"));
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert_eq!(lookup.lookup_asn(ip), None);
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
        let asn_v4 = lookup.lookup_asn(ipv4);
        assert_eq!(asn_v4, Some(15169));
        
        // Test IPv6 lookup - Google's ASN is 15169
        let ipv6 = IpAddr::from_str("2001:4860:4860::8888").unwrap();
        let asn_v6 = lookup.lookup_asn(ipv6);
        assert_eq!(asn_v6, Some(15169));
    }
}
