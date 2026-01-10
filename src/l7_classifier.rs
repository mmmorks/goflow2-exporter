/// Checks if a port is in the ephemeral port range.
///
/// Ephemeral ports are temporary ports used by clients for outbound connections.
/// This function uses 2^15 (32768) as the threshold.
///
/// # Arguments
/// * `port` - The port number to check
///
/// # Returns
/// * `true` if the port is ephemeral (≥32768)
/// * `false` otherwise
pub fn is_ephemeral_port(port: u16) -> bool {
    port >= 32768 // 2^15
}

/// Classifies L7 application protocol based on L4 protocol and port number.
///
/// Returns `Some(protocol_name)` for well-known ports (e.g., "HTTPS", "DNS-UDP").
/// Returns `None` for unknown ports to avoid metric cardinality explosion.
///
/// # Arguments
/// * `l4_protocol` - The Layer 4 protocol (e.g., "TCP", "UDP", "IPv6-TCP")
/// * `port` - The port number to classify
///
/// # Examples
/// ```
/// use goflow2_exporter::l7_classifier::classify_l7_protocol;
///
/// assert_eq!(classify_l7_protocol("TCP", 80), Some("HTTP".to_string()));
/// assert_eq!(classify_l7_protocol("TCP", 443), Some("HTTPS".to_string()));
/// assert_eq!(classify_l7_protocol("UDP", 53), Some("DNS-UDP".to_string()));
/// assert_eq!(classify_l7_protocol("TCP", 9999), None); // Unknown port
/// ```
pub fn classify_l7_protocol(l4_protocol: &str, port: u16) -> Option<String> {
    // Normalize protocol (handle "IPv6-TCP" -> "TCP", etc.)
    let proto = l4_protocol.strip_prefix("IPv6-").unwrap_or(l4_protocol);

    match (proto, port) {
        // Web
        ("TCP", 80) => Some("HTTP".to_string()),
        ("TCP", 8080) => Some("HTTP-Alt".to_string()),
        ("TCP", 443) => Some("HTTPS".to_string()),
        ("TCP", 8443) => Some("HTTPS-Alt".to_string()),
        ("UDP", 443) => Some("QUIC".to_string()),

        // DNS
        ("UDP", 53) => Some("DNS-UDP".to_string()),
        ("TCP", 53) => Some("DNS-TCP".to_string()),

        // Email
        ("TCP", 25) => Some("SMTP".to_string()),
        ("TCP", 587) => Some("SMTP-Submission".to_string()),
        ("TCP", 143) => Some("IMAP".to_string()),
        ("TCP", 993) => Some("IMAPS".to_string()),
        ("TCP", 110) => Some("POP3".to_string()),
        ("TCP", 995) => Some("POP3S".to_string()),

        // Databases
        ("TCP", 3306) => Some("MySQL".to_string()),
        ("TCP", 5432) => Some("PostgreSQL".to_string()),
        ("TCP", 27017) => Some("MongoDB".to_string()),
        ("TCP", 27018) => Some("MongoDB-Secondary".to_string()),
        ("TCP", 6379) => Some("Redis".to_string()),
        ("TCP", 7000) => Some("Cassandra".to_string()),

        // Messaging & Push Notifications
        ("TCP", 1883) => Some("MQTT".to_string()),
        ("TCP", 8883) => Some("MQTT-TLS".to_string()),
        ("TCP", 5222) => Some("XMPP".to_string()),
        ("TCP", 5223) => Some("APNS".to_string()),

        // VoIP & Real-time Communication
        ("TCP", 5061) => Some("SIP-TLS".to_string()),
        ("UDP", 3478) => Some("STUN".to_string()),
        ("UDP", 4500) => Some("IPsec-NAT-T".to_string()),

        // Network Management & Monitoring
        ("UDP", 161) => Some("SNMP".to_string()),
        ("UDP", 2055) => Some("NetFlow".to_string()),
        ("TCP", 8089) => Some("Splunk".to_string()),

        // IoT & Device Management
        ("TCP", 5683) => Some("CoAP".to_string()),
        ("TCP", 8728) => Some("MikroTik-API".to_string()),

        // File Transfer & Remote Access
        ("TCP", 22) => Some("SSH".to_string()),
        ("TCP", 21) => Some("FTP".to_string()),
        ("TCP", 20) => Some("FTP-Data".to_string()),
        ("TCP", 3389) => Some("RDP".to_string()),
        ("TCP", 5900) => Some("VNC".to_string()),

        // Directory Services
        ("TCP", 389) => Some("LDAP".to_string()),
        ("TCP", 636) => Some("LDAPS".to_string()),

        // Time & Network Services
        ("UDP", 123) => Some("NTP".to_string()),
        ("UDP", 67) | ("UDP", 68) => Some("DHCP".to_string()),
        ("TCP", 7) => Some("Echo".to_string()),

        // Gaming
        ("TCP", 25565) => Some("Minecraft".to_string()),

        // Unknown ports - return None to skip classification
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_https_classification() {
        assert_eq!(classify_l7_protocol("TCP", 80), Some("HTTP".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 443), Some("HTTPS".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 8080),
            Some("HTTP-Alt".to_string())
        );
        assert_eq!(
            classify_l7_protocol("TCP", 8443),
            Some("HTTPS-Alt".to_string())
        );
    }

    #[test]
    fn test_dns_transport_specific() {
        assert_eq!(classify_l7_protocol("UDP", 53), Some("DNS-UDP".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 53), Some("DNS-TCP".to_string()));
    }

    #[test]
    fn test_ipv6_protocol_normalization() {
        assert_eq!(
            classify_l7_protocol("IPv6-TCP", 80),
            Some("HTTP".to_string())
        );
        assert_eq!(
            classify_l7_protocol("IPv6-TCP", 443),
            Some("HTTPS".to_string())
        );
        assert_eq!(
            classify_l7_protocol("IPv6-UDP", 53),
            Some("DNS-UDP".to_string())
        );
    }

    #[test]
    fn test_unknown_ports() {
        assert_eq!(classify_l7_protocol("TCP", 9999), None);
        assert_eq!(classify_l7_protocol("UDP", 8888), None);
        assert_eq!(classify_l7_protocol("IPv6-TCP", 12345), None);
    }

    #[test]
    fn test_common_services() {
        assert_eq!(classify_l7_protocol("TCP", 22), Some("SSH".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 3306), Some("MySQL".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 25565),
            Some("Minecraft".to_string())
        );
        assert_eq!(classify_l7_protocol("UDP", 123), Some("NTP".to_string()));
    }

    #[test]
    fn test_email_protocols() {
        assert_eq!(classify_l7_protocol("TCP", 25), Some("SMTP".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 587),
            Some("SMTP-Submission".to_string())
        );
        assert_eq!(classify_l7_protocol("TCP", 143), Some("IMAP".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 993), Some("IMAPS".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 110), Some("POP3".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 995), Some("POP3S".to_string()));
    }

    #[test]
    fn test_database_protocols() {
        assert_eq!(classify_l7_protocol("TCP", 3306), Some("MySQL".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 5432),
            Some("PostgreSQL".to_string())
        );
        assert_eq!(
            classify_l7_protocol("TCP", 27017),
            Some("MongoDB".to_string())
        );
        assert_eq!(classify_l7_protocol("TCP", 6379), Some("Redis".to_string()));
    }

    #[test]
    fn test_ftp_protocols() {
        assert_eq!(classify_l7_protocol("TCP", 21), Some("FTP".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 20),
            Some("FTP-Data".to_string())
        );
    }

    #[test]
    fn test_dhcp_ports() {
        assert_eq!(classify_l7_protocol("UDP", 67), Some("DHCP".to_string()));
        assert_eq!(classify_l7_protocol("UDP", 68), Some("DHCP".to_string()));
    }

    #[test]
    fn test_other_common_services() {
        assert_eq!(classify_l7_protocol("TCP", 3389), Some("RDP".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 5900), Some("VNC".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 389), Some("LDAP".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 636), Some("LDAPS".to_string()));
    }

    #[test]
    fn test_is_ephemeral_port() {
        assert!(is_ephemeral_port(32768)); // 2^15
        assert!(is_ephemeral_port(49152));
        assert!(is_ephemeral_port(52341));
        assert!(is_ephemeral_port(60000));
        assert!(is_ephemeral_port(65535));
    }

    #[test]
    fn test_is_not_ephemeral_port() {
        assert!(!is_ephemeral_port(80));
        assert!(!is_ephemeral_port(443));
        assert!(!is_ephemeral_port(8080));
        assert!(!is_ephemeral_port(8888));
        assert!(!is_ephemeral_port(32767)); // 2^15 - 1
    }

    #[test]
    fn test_new_protocol_classifications() {
        assert_eq!(classify_l7_protocol("UDP", 443), Some("QUIC".to_string()));
        assert_eq!(
            classify_l7_protocol("UDP", 2055),
            Some("NetFlow".to_string())
        );
        assert_eq!(classify_l7_protocol("TCP", 1883), Some("MQTT".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 8883),
            Some("MQTT-TLS".to_string())
        );
        assert_eq!(classify_l7_protocol("TCP", 5222), Some("XMPP".to_string()));
        assert_eq!(classify_l7_protocol("TCP", 5223), Some("APNS".to_string()));
        assert_eq!(classify_l7_protocol("UDP", 161), Some("SNMP".to_string()));
        assert_eq!(classify_l7_protocol("UDP", 3478), Some("STUN".to_string()));
        assert_eq!(
            classify_l7_protocol("TCP", 27018),
            Some("MongoDB-Secondary".to_string())
        );
        assert_eq!(
            classify_l7_protocol("TCP", 8728),
            Some("MikroTik-API".to_string())
        );
        assert_eq!(
            classify_l7_protocol("TCP", 7000),
            Some("Cassandra".to_string())
        );
        assert_eq!(
            classify_l7_protocol("TCP", 8089),
            Some("Splunk".to_string())
        );
        assert_eq!(
            classify_l7_protocol("UDP", 4500),
            Some("IPsec-NAT-T".to_string())
        );
    }
}
