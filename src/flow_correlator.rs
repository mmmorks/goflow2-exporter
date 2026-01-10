use crate::flow::FlowMessage;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;

/// Correlates inbound and outbound NAT flows to determine true destination IPs
pub struct FlowCorrelator {
    /// Cache of outbound flows keyed by (external_ip, client_port, server_port, proto)
    /// Maps to the internal IP that initiated the connection
    outbound_flows: RwLock<HashMap<FlowKey, InternalIpInfo>>,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FlowKey {
    external_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    proto: String,
}

#[derive(Clone, Debug)]
struct InternalIpInfo {
    ip: IpAddr,
    timestamp: u64,
}

impl Default for FlowCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowCorrelator {
    pub fn new() -> Self {
        Self {
            outbound_flows: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the true destination IP for a flow.
    ///
    /// For outbound NAT flows (private src → public dst):
    /// - Caches the internal IP for future matching
    /// - Returns the destination as-is (already correct)
    ///
    /// For inbound NAT flows (public src → any dst):
    /// - Looks up the matching outbound flow
    /// - Returns the real internal destination IP if found
    /// - Falls back to original destination if no match
    ///
    /// For other flows:
    /// - Returns destination as-is
    pub fn get_true_destination(&self, flow: &FlowMessage) -> IpAddr {
        // Parse src and dst IPs
        let src_ip = flow
            .src_addr
            .as_ref()
            .and_then(|s| s.parse::<IpAddr>().ok());
        let dst_ip = flow
            .dst_addr
            .as_ref()
            .and_then(|s| s.parse::<IpAddr>().ok());

        // Outbound NAT flow: private src → public dst
        if flow.etype.as_deref() == Some("IPv4")
            && src_ip.map(|ip| Self::is_private_ip(&ip)).unwrap_or(false)
            && dst_ip.map(|ip| !Self::is_private_ip(&ip)).unwrap_or(false)
        {
            if let (
                Some(external_ip),
                Some(client_port),
                Some(server_port),
                Some(proto),
                Some(timestamp),
            ) = (
                dst_ip,
                flow.src_port,
                flow.dst_port,
                flow.proto.as_ref(),
                flow.time_flow_start_ns,
            ) {
                let key = FlowKey {
                    external_ip,
                    client_port,
                    server_port,
                    proto: proto.clone(),
                };

                // Cache this mapping for matching inbound flows
                if let Some(internal_ip) = src_ip {
                    self.outbound_flows.write().insert(
                        key,
                        InternalIpInfo {
                            ip: internal_ip,
                            timestamp,
                        },
                    );
                }
            }

            // Destination is already correct
            dst_ip.unwrap_or_else(|| "0.0.0.0".parse().unwrap())
        }
        // Inbound flow: public src → try to find real internal destination
        else if flow.etype.as_deref() == Some("IPv4")
            && src_ip.map(|ip| !Self::is_private_ip(&ip)).unwrap_or(false)
        {
            if let (Some(external_ip), Some(client_port), Some(server_port), Some(proto)) = (
                src_ip,
                flow.dst_port, // Reversed: dst_port is client port
                flow.src_port, // Reversed: src_port is server port
                flow.proto.as_ref(),
            ) {
                let key = FlowKey {
                    external_ip,
                    client_port,
                    server_port,
                    proto: proto.clone(),
                };

                // Look up the matching outbound flow to find real internal IP
                return self
                    .outbound_flows
                    .read()
                    .get(&key)
                    .map(|info| info.ip)
                    .unwrap_or_else(|| dst_ip.unwrap_or_else(|| "0.0.0.0".parse().unwrap()));
            }

            dst_ip.unwrap_or_else(|| "0.0.0.0".parse().unwrap())
        }
        // Other flows (IPv6, internal traffic, etc.)
        else {
            dst_ip.unwrap_or_else(|| "0.0.0.0".parse().unwrap())
        }
    }

    /// Remove expired entries from the cache
    pub fn cleanup_expired(&self, ttl_ns: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut cache = self.outbound_flows.write();
        let initial_size = cache.len();
        cache.retain(|_, info| now - info.timestamp < ttl_ns);
        let removed = initial_size - cache.len();

        if removed > 0 {
            tracing::debug!("Flow correlator: cleaned up {} expired entries", removed);
        }
    }

    /// Check if an IP address is in private (RFC 1918) space
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_flow(
        src_addr: &str,
        dst_addr: &str,
        src_port: u16,
        dst_port: u16,
        proto: &str,
        etype: &str,
    ) -> FlowMessage {
        FlowMessage {
            flow_type: Some("IPFIX".to_string()),
            time_received_ns: Some(0),
            sequence_num: Some(1),
            sampling_rate: Some(0),
            sampler_address: Some("192.168.88.1".to_string()),
            time_flow_start_ns: Some(1_000_000_000),
            time_flow_end_ns: Some(1_000_000_000),
            bytes: Some(100),
            packets: Some(1),
            src_addr: Some(src_addr.to_string()),
            dst_addr: Some(dst_addr.to_string()),
            etype: Some(etype.to_string()),
            proto: Some(proto.to_string()),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            in_if: Some(0),
            out_if: Some(0),
            src_mac: Some("".to_string()),
            dst_mac: Some("".to_string()),
            tcp_flags: Some(0),
            next_hop: Some("0.0.0.0".to_string()),
        }
    }

    #[test]
    fn test_outbound_nat_flow_cached() {
        let correlator = FlowCorrelator::new();

        // Outbound: internal client → external server
        let outbound = make_test_flow("192.168.88.42", "40.112.143.140", 46912, 443, "TCP", "IPv4");

        let result = correlator.get_true_destination(&outbound);

        // Destination should be unchanged
        assert_eq!(result, "40.112.143.140".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_inbound_nat_flow_matched() {
        let correlator = FlowCorrelator::new();

        // First, outbound flow
        let outbound = make_test_flow("192.168.88.42", "40.112.143.140", 46912, 443, "TCP", "IPv4");
        correlator.get_true_destination(&outbound);

        // Then, matching inbound flow (with NAT IP)
        let inbound = make_test_flow(
            "40.112.143.140",
            "71.212.173.249", // NAT public IP
            443,
            46912,
            "TCP",
            "IPv4",
        );

        let result = correlator.get_true_destination(&inbound);

        // Should return the real internal IP, not the NAT IP
        assert_eq!(result, "192.168.88.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_inbound_without_matching_outbound() {
        let correlator = FlowCorrelator::new();

        // Inbound flow with no matching outbound
        let inbound = make_test_flow("1.2.3.4", "71.212.173.249", 443, 12345, "TCP", "IPv4");

        let result = correlator.get_true_destination(&inbound);

        // Should fall back to original destination
        assert_eq!(result, "71.212.173.249".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_internal_flow_passthrough() {
        let correlator = FlowCorrelator::new();

        // Internal flow: private → private
        let internal = make_test_flow("192.168.88.1", "192.168.88.2", 1234, 5678, "TCP", "IPv4");

        let result = correlator.get_true_destination(&internal);

        // Should pass through unchanged
        assert_eq!(result, "192.168.88.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_ipv6_flow_passthrough() {
        let correlator = FlowCorrelator::new();

        // IPv6 flow
        let ipv6 = make_test_flow(
            "2602:47:d4ad:f901::1",
            "2600:9000:26cc:a800::1",
            1234,
            443,
            "TCP",
            "IPv6",
        );

        let result = correlator.get_true_destination(&ipv6);

        // Should pass through unchanged
        assert_eq!(result, "2600:9000:26cc:a800::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_cleanup_expired() {
        let correlator = FlowCorrelator::new();

        // Add an outbound flow with old timestamp
        let mut outbound =
            make_test_flow("192.168.88.42", "40.112.143.140", 46912, 443, "TCP", "IPv4");
        outbound.time_flow_start_ns = Some(1_000_000_000); // Very old

        correlator.get_true_destination(&outbound);

        // Clean up with TTL of 1 second (1B nanoseconds)
        correlator.cleanup_expired(1_000_000_000);

        // Verify cleanup by checking that matching inbound flow no longer finds the cached entry
        let inbound = make_test_flow(
            "40.112.143.140",
            "71.212.173.249",
            443,
            46912,
            "TCP",
            "IPv4",
        );
        let result = correlator.get_true_destination(&inbound);

        // Should fall back to original destination since cache was cleaned up
        assert_eq!(result, "71.212.173.249".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_multiple_connections() {
        let correlator = FlowCorrelator::new();

        // Multiple outbound flows to different servers
        let out1 = make_test_flow("192.168.88.1", "8.8.8.8", 1000, 443, "TCP", "IPv4");
        let out2 = make_test_flow("192.168.88.2", "1.1.1.1", 2000, 443, "TCP", "IPv4");

        correlator.get_true_destination(&out1);
        correlator.get_true_destination(&out2);

        // Inbound for first connection
        let in1 = make_test_flow("8.8.8.8", "71.212.173.249", 443, 1000, "TCP", "IPv4");
        let result1 = correlator.get_true_destination(&in1);
        assert_eq!(result1, "192.168.88.1".parse::<IpAddr>().unwrap());

        // Inbound for second connection
        let in2 = make_test_flow("1.1.1.1", "71.212.173.249", 443, 2000, "TCP", "IPv4");
        let result2 = correlator.get_true_destination(&in2);
        assert_eq!(result2, "192.168.88.2".parse::<IpAddr>().unwrap());
    }
}
