/// Checks if a port is in the ephemeral port range.
///
/// Ephemeral ports are temporary ports used by clients for outbound connections.
/// IANA defines the range as 49152-65535, but many systems (including Linux) use 32768-60999.
/// This function uses 2^15 (32768) as the threshold for broader coverage.
///
/// # Arguments
/// * `port` - The port number to check
///
/// # Returns
/// * `true` if the port is in the ephemeral range (≥32768)
/// * `false` otherwise
pub fn is_ephemeral_port(port: u16) -> bool {
    port >= 32768 // 2^15
}

/// Classifies L7 application protocol based on L4 protocol and port number.
///
/// Returns transport-specific names (e.g., "HTTPS", "DNS-UDP") for well-known ports.
/// For unknown ports, returns formatted string like "TCP/8888" or "UDP/9999".
///
/// # Arguments
/// * `l4_protocol` - The Layer 4 protocol (e.g., "TCP", "UDP", "IPv6-TCP")
/// * `port` - The port number to classify
///
/// # Examples
/// ```
/// use goflow2_exporter::l7_classifier::classify_l7_protocol;
///
/// assert_eq!(classify_l7_protocol("TCP", 80), "HTTP");
/// assert_eq!(classify_l7_protocol("TCP", 443), "HTTPS");
/// assert_eq!(classify_l7_protocol("UDP", 53), "DNS-UDP");
/// assert_eq!(classify_l7_protocol("TCP", 9999), "TCP/9999");
/// ```
pub fn classify_l7_protocol(l4_protocol: &str, port: u16) -> String {
    // Normalize protocol (handle "IPv6-TCP" -> "TCP", etc.)
    let proto = l4_protocol.strip_prefix("IPv6-").unwrap_or(l4_protocol);

    match (proto, port) {
        // Web
        ("TCP", 80) => "HTTP".to_string(),
        ("TCP", 8080) => "HTTP-Alt".to_string(),
        ("TCP", 443) => "HTTPS".to_string(),
        ("TCP", 8443) => "HTTPS-Alt".to_string(),
        ("UDP", 443) => "QUIC".to_string(),

        // DNS
        ("UDP", 53) => "DNS-UDP".to_string(),
        ("TCP", 53) => "DNS-TCP".to_string(),

        // Email
        ("TCP", 25) => "SMTP".to_string(),
        ("TCP", 587) => "SMTP-Submission".to_string(),
        ("TCP", 143) => "IMAP".to_string(),
        ("TCP", 993) => "IMAPS".to_string(),
        ("TCP", 110) => "POP3".to_string(),
        ("TCP", 995) => "POP3S".to_string(),

        // Databases
        ("TCP", 3306) => "MySQL".to_string(),
        ("TCP", 5432) => "PostgreSQL".to_string(),
        ("TCP", 27017) => "MongoDB".to_string(),
        ("TCP", 27018) => "MongoDB-Secondary".to_string(),
        ("TCP", 6379) => "Redis".to_string(),

        // Messaging & Push Notifications
        ("TCP", 1883) => "MQTT".to_string(),
        ("TCP", 8883) => "MQTT-TLS".to_string(),
        ("TCP", 5222) => "XMPP".to_string(),
        ("TCP", 5223) => "APNS".to_string(),

        // VoIP & Real-time Communication
        ("TCP", 5061) => "SIP-TLS".to_string(),
        ("UDP", 3478) => "STUN".to_string(),

        // Network Management & Monitoring
        ("UDP", 161) => "SNMP".to_string(),
        ("UDP", 2055) => "NetFlow".to_string(),

        // IoT & Device Management
        ("TCP", 5683) => "CoAP".to_string(),
        ("TCP", 8728) => "MikroTik-API".to_string(),

        // File Transfer & Remote Access
        ("TCP", 22) => "SSH".to_string(),
        ("TCP", 21) => "FTP".to_string(),
        ("TCP", 20) => "FTP-Data".to_string(),
        ("TCP", 3389) => "RDP".to_string(),
        ("TCP", 5900) => "VNC".to_string(),

        // Directory Services
        ("TCP", 389) => "LDAP".to_string(),
        ("TCP", 636) => "LDAPS".to_string(),

        // Time & Network Services
        ("UDP", 123) => "NTP".to_string(),
        ("UDP", 67) | ("UDP", 68) => "DHCP".to_string(),
        ("TCP", 7) => "Echo".to_string(),

        // Gaming & Custom Services
        ("TCP", 25565) => "Minecraft".to_string(),
        ("TCP", 1337) => "Gaming".to_string(),

        // Custom/Unidentified Services (ports you're seeing traffic on)
        ("TCP", 1200) => "Custom-1200".to_string(),
        ("TCP", 4070) => "Custom-4070".to_string(),
        ("TCP", 4431) => "Custom-4431".to_string(),
        ("UDP", 7551) => "Custom-7551".to_string(),
        ("UDP", 8099) => "Custom-8099".to_string(),

        // Unknown ports - label with protocol and port number
        _ => format!("{}/{}", proto, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_https_classification() {
        assert_eq!(classify_l7_protocol("TCP", 80), "HTTP");
        assert_eq!(classify_l7_protocol("TCP", 443), "HTTPS");
        assert_eq!(classify_l7_protocol("TCP", 8080), "HTTP-Alt");
        assert_eq!(classify_l7_protocol("TCP", 8443), "HTTPS-Alt");
    }

    #[test]
    fn test_dns_transport_specific() {
        assert_eq!(classify_l7_protocol("UDP", 53), "DNS-UDP");
        assert_eq!(classify_l7_protocol("TCP", 53), "DNS-TCP");
    }

    #[test]
    fn test_ipv6_protocol_normalization() {
        assert_eq!(classify_l7_protocol("IPv6-TCP", 80), "HTTP");
        assert_eq!(classify_l7_protocol("IPv6-TCP", 443), "HTTPS");
        assert_eq!(classify_l7_protocol("IPv6-UDP", 53), "DNS-UDP");
    }

    #[test]
    fn test_unknown_ports() {
        assert_eq!(classify_l7_protocol("TCP", 9999), "TCP/9999");
        assert_eq!(classify_l7_protocol("UDP", 8888), "UDP/8888");
        assert_eq!(classify_l7_protocol("IPv6-TCP", 12345), "TCP/12345");
    }

    #[test]
    fn test_common_services() {
        assert_eq!(classify_l7_protocol("TCP", 22), "SSH");
        assert_eq!(classify_l7_protocol("TCP", 3306), "MySQL");
        assert_eq!(classify_l7_protocol("TCP", 25565), "Minecraft");
        assert_eq!(classify_l7_protocol("UDP", 123), "NTP");
    }

    #[test]
    fn test_email_protocols() {
        assert_eq!(classify_l7_protocol("TCP", 25), "SMTP");
        assert_eq!(classify_l7_protocol("TCP", 587), "SMTP-Submission");
        assert_eq!(classify_l7_protocol("TCP", 143), "IMAP");
        assert_eq!(classify_l7_protocol("TCP", 993), "IMAPS");
        assert_eq!(classify_l7_protocol("TCP", 110), "POP3");
        assert_eq!(classify_l7_protocol("TCP", 995), "POP3S");
    }

    #[test]
    fn test_database_protocols() {
        assert_eq!(classify_l7_protocol("TCP", 3306), "MySQL");
        assert_eq!(classify_l7_protocol("TCP", 5432), "PostgreSQL");
        assert_eq!(classify_l7_protocol("TCP", 27017), "MongoDB");
        assert_eq!(classify_l7_protocol("TCP", 6379), "Redis");
    }

    #[test]
    fn test_ftp_protocols() {
        assert_eq!(classify_l7_protocol("TCP", 21), "FTP");
        assert_eq!(classify_l7_protocol("TCP", 20), "FTP-Data");
    }

    #[test]
    fn test_dhcp_ports() {
        assert_eq!(classify_l7_protocol("UDP", 67), "DHCP");
        assert_eq!(classify_l7_protocol("UDP", 68), "DHCP");
    }

    #[test]
    fn test_other_common_services() {
        assert_eq!(classify_l7_protocol("TCP", 3389), "RDP");
        assert_eq!(classify_l7_protocol("TCP", 5900), "VNC");
        assert_eq!(classify_l7_protocol("TCP", 389), "LDAP");
        assert_eq!(classify_l7_protocol("TCP", 636), "LDAPS");
    }

    #[test]
    fn test_is_ephemeral_port() {
        // Ephemeral range starts at 32768 (2^15)
        assert!(is_ephemeral_port(32768));
        assert!(is_ephemeral_port(49152));
        assert!(is_ephemeral_port(52341));
        assert!(is_ephemeral_port(65000));
        assert!(is_ephemeral_port(65535));
    }

    #[test]
    fn test_is_not_ephemeral_port() {
        // Well-known and registered ports are not ephemeral
        assert!(!is_ephemeral_port(80));
        assert!(!is_ephemeral_port(443));
        assert!(!is_ephemeral_port(8080));
        assert!(!is_ephemeral_port(22));
        assert!(!is_ephemeral_port(3306));
        assert!(!is_ephemeral_port(32767)); // 2^15 - 1 (one below ephemeral range)
    }

    #[test]
    fn test_new_protocol_classifications() {
        assert_eq!(classify_l7_protocol("UDP", 443), "QUIC");
        assert_eq!(classify_l7_protocol("UDP", 2055), "NetFlow");
        assert_eq!(classify_l7_protocol("TCP", 1883), "MQTT");
        assert_eq!(classify_l7_protocol("TCP", 8883), "MQTT-TLS");
        assert_eq!(classify_l7_protocol("TCP", 5222), "XMPP");
        assert_eq!(classify_l7_protocol("TCP", 5223), "APNS");
        assert_eq!(classify_l7_protocol("UDP", 161), "SNMP");
        assert_eq!(classify_l7_protocol("UDP", 3478), "STUN");
        assert_eq!(classify_l7_protocol("TCP", 27018), "MongoDB-Secondary");
        assert_eq!(classify_l7_protocol("TCP", 8728), "MikroTik-API");
    }
}
