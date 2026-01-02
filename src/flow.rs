use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowMessage {
    #[serde(rename = "type")]
    pub flow_type: Option<String>,

    #[serde(rename = "time_received_ns")]
    pub time_received_ns: Option<u64>,

    #[serde(rename = "sequence_num")]
    pub sequence_num: Option<u64>,

    #[serde(rename = "sampling_rate")]
    pub sampling_rate: Option<u64>,

    #[serde(rename = "sampler_address")]
    pub sampler_address: Option<String>,

    #[serde(rename = "time_flow_start_ns")]
    pub time_flow_start_ns: Option<u64>,

    #[serde(rename = "time_flow_end_ns")]
    pub time_flow_end_ns: Option<u64>,

    pub bytes: Option<u64>,
    pub packets: Option<u64>,

    #[serde(rename = "src_addr")]
    pub src_addr: Option<String>,

    #[serde(rename = "dst_addr")]
    pub dst_addr: Option<String>,

    #[serde(rename = "src_port")]
    pub src_port: Option<u16>,

    #[serde(rename = "dst_port")]
    pub dst_port: Option<u16>,

    pub etype: Option<String>,
    pub proto: Option<String>,

    #[serde(rename = "src_mac")]
    pub src_mac: Option<String>,

    #[serde(rename = "dst_mac")]
    pub dst_mac: Option<String>,

    #[serde(rename = "in_if")]
    pub in_if: Option<u32>,

    #[serde(rename = "out_if")]
    pub out_if: Option<u32>,
}

impl FlowMessage {
    pub fn scaled_bytes(&self) -> u64 {
        let bytes = self.bytes.unwrap_or(0);
        let sampling_rate = self.sampling_rate.unwrap_or(1);
        bytes * sampling_rate
    }

    pub fn scaled_packets(&self) -> u64 {
        let packets = self.packets.unwrap_or(0);
        let sampling_rate = self.sampling_rate.unwrap_or(1);
        packets * sampling_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_sample_flow() {
        let json = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":143,"packets":1,"src_addr":"192.168.89.2","dst_addr":"192.168.88.30","etype":"IPv4","proto":"UDP","src_port":53,"dst_port":55743,"in_if":11,"out_if":12,"src_mac":"42:61:64:55:53:42","dst_mac":"48:6f:73:74:50:43"}"#;
        
        let flow: FlowMessage = serde_json::from_str(json).unwrap();
        
        assert_eq!(flow.flow_type, Some("IPFIX".to_string()));
        assert_eq!(flow.bytes, Some(143));
        assert_eq!(flow.packets, Some(1));
        assert_eq!(flow.src_addr, Some("192.168.89.2".to_string()));
        assert_eq!(flow.dst_addr, Some("192.168.88.30".to_string()));
        assert_eq!(flow.proto, Some("UDP".to_string()));
        assert_eq!(flow.src_port, Some(53));
        assert_eq!(flow.dst_port, Some(55743));
    }

    #[test]
    fn test_scaled_bytes_with_sampling() {
        let flow = FlowMessage {
            bytes: Some(100),
            sampling_rate: Some(10),
            ..Default::default()
        };
        assert_eq!(flow.scaled_bytes(), 1000);
    }

    #[test]
    fn test_scaled_bytes_no_sampling() {
        let flow = FlowMessage {
            bytes: Some(100),
            sampling_rate: Some(1),
            ..Default::default()
        };
        assert_eq!(flow.scaled_bytes(), 100);
    }

    #[test]
    fn test_scaled_packets_with_sampling() {
        let flow = FlowMessage {
            packets: Some(5),
            sampling_rate: Some(20),
            ..Default::default()
        };
        assert_eq!(flow.scaled_packets(), 100);
    }
}
