/// TCP flag constants based on RFC 793 and RFC 3168
const FIN: u16 = 0b0000_0001; // Finish - No more data from sender
const SYN: u16 = 0b0000_0010; // Synchronize - Synchronize sequence numbers
const RST: u16 = 0b0000_0100; // Reset - Reset the connection
const PSH: u16 = 0b0000_1000; // Push - Push function
const ACK: u16 = 0b0001_0000; // Acknowledgment - Acknowledgment field significant
const URG: u16 = 0b0010_0000; // Urgent - Urgent pointer field significant
const ECE: u16 = 0b0100_0000; // ECN-Echo - ECN-capable transport
const CWR: u16 = 0b1000_0000; // Congestion Window Reduced

/// Decode TCP flags bitmask into a human-readable string representation
///
/// Returns a comma-separated list of flag names that are set.
/// If no flags are set, returns "NONE".
///
/// # Examples
///
/// ```
/// use goflow2_exporter::tcp_flags::decode_tcp_flags;
/// assert_eq!(decode_tcp_flags(2), "SYN");
/// assert_eq!(decode_tcp_flags(18), "SYN,ACK");
/// assert_eq!(decode_tcp_flags(0), "NONE");
/// ```
pub fn decode_tcp_flags(flags: u16) -> String {
    if flags == 0 {
        return "NONE".to_string();
    }

    let mut parts = Vec::new();

    if flags & FIN != 0 {
        parts.push("FIN");
    }
    if flags & SYN != 0 {
        parts.push("SYN");
    }
    if flags & RST != 0 {
        parts.push("RST");
    }
    if flags & PSH != 0 {
        parts.push("PSH");
    }
    if flags & ACK != 0 {
        parts.push("ACK");
    }
    if flags & URG != 0 {
        parts.push("URG");
    }
    if flags & ECE != 0 {
        parts.push("ECE");
    }
    if flags & CWR != 0 {
        parts.push("CWR");
    }

    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_flags() {
        assert_eq!(decode_tcp_flags(0), "NONE");
    }

    #[test]
    fn test_single_flags() {
        assert_eq!(decode_tcp_flags(FIN), "FIN");
        assert_eq!(decode_tcp_flags(SYN), "SYN");
        assert_eq!(decode_tcp_flags(RST), "RST");
        assert_eq!(decode_tcp_flags(PSH), "PSH");
        assert_eq!(decode_tcp_flags(ACK), "ACK");
        assert_eq!(decode_tcp_flags(URG), "URG");
        assert_eq!(decode_tcp_flags(ECE), "ECE");
        assert_eq!(decode_tcp_flags(CWR), "CWR");
    }

    #[test]
    fn test_syn_ack() {
        // Common three-way handshake flag combination
        assert_eq!(decode_tcp_flags(SYN | ACK), "SYN,ACK");
        assert_eq!(decode_tcp_flags(0b0001_0010), "SYN,ACK");
        assert_eq!(decode_tcp_flags(18), "SYN,ACK");
    }

    #[test]
    fn test_fin_ack() {
        // Common connection termination flag combination
        assert_eq!(decode_tcp_flags(FIN | ACK), "FIN,ACK");
        assert_eq!(decode_tcp_flags(0b0001_0001), "FIN,ACK");
        assert_eq!(decode_tcp_flags(17), "FIN,ACK");
    }

    #[test]
    fn test_psh_ack() {
        // Common data transfer flag combination
        assert_eq!(decode_tcp_flags(PSH | ACK), "PSH,ACK");
        assert_eq!(decode_tcp_flags(0b0001_1000), "PSH,ACK");
        assert_eq!(decode_tcp_flags(24), "PSH,ACK");
    }

    #[test]
    fn test_rst_ack() {
        // Connection reset with acknowledgment
        assert_eq!(decode_tcp_flags(RST | ACK), "RST,ACK");
        assert_eq!(decode_tcp_flags(0b0001_0100), "RST,ACK");
        assert_eq!(decode_tcp_flags(20), "RST,ACK");
    }

    #[test]
    fn test_just_ack() {
        assert_eq!(decode_tcp_flags(ACK), "ACK");
        assert_eq!(decode_tcp_flags(16), "ACK");
    }

    #[test]
    fn test_sample_data_values() {
        // Values observed in examples/sample.json
        assert_eq!(decode_tcp_flags(0), "NONE");
        assert_eq!(decode_tcp_flags(2), "SYN");
        assert_eq!(decode_tcp_flags(16), "ACK");
        assert_eq!(decode_tcp_flags(17), "FIN,ACK");
        assert_eq!(decode_tcp_flags(18), "SYN,ACK");
        assert_eq!(decode_tcp_flags(24), "PSH,ACK");
        assert_eq!(decode_tcp_flags(82), "SYN,ACK,ECE"); // 0b01010010
        assert_eq!(decode_tcp_flags(194), "SYN,ECE,CWR"); // 0b11000010
    }

    #[test]
    fn test_all_flags() {
        assert_eq!(
            decode_tcp_flags(0b1111_1111),
            "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR"
        );
    }

    #[test]
    fn test_ecn_flags() {
        assert_eq!(decode_tcp_flags(ECE), "ECE");
        assert_eq!(decode_tcp_flags(CWR), "CWR");
        assert_eq!(decode_tcp_flags(ECE | CWR), "ECE,CWR");
    }
}
