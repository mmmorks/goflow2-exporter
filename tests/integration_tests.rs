use std::fs;
use std::sync::Arc;
use goflow2_exporter::flow::FlowMessage;
use goflow2_exporter::metrics::Metrics;

#[test]
fn test_parse_sample_data() {
    let sample_data = fs::read_to_string("examples/sample.json")
        .expect("Failed to read sample.json");
    
    let mut flow_count = 0;
    let mut udp_count = 0;
    let mut tcp_count = 0;
    
    for line in sample_data.lines().take(10) {
        let flow: FlowMessage = serde_json::from_str(line)
            .expect("Failed to parse flow message");
        
        flow_count += 1;
        
        match flow.proto.as_deref() {
            Some("UDP") => udp_count += 1,
            Some("TCP") => tcp_count += 1,
            _ => {}
        }
        
        // Validate required fields are present
        assert!(flow.flow_type.is_some());
        assert!(flow.time_received_ns.is_some());
        assert!(flow.bytes.is_some());
        assert!(flow.packets.is_some());
    }
    
    assert_eq!(flow_count, 10);
    assert!(udp_count > 0);
    assert!(tcp_count > 0);
}

#[test]
fn test_dns_traffic_parsing() {
    let dns_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":143,"packets":1,"src_addr":"192.168.89.2","dst_addr":"192.168.88.30","etype":"IPv4","proto":"UDP","src_port":53,"dst_port":55743,"in_if":11,"out_if":12,"src_mac":"42:61:64:55:53:42","dst_mac":"48:6f:73:74:50:43","src_vlan":0,"dst_vlan":0,"vlan_id":0,"ip_tos":0,"forwarding_status":0,"ip_ttl":0,"ip_flags":0,"tcp_flags":0,"icmp_type":0,"icmp_code":0,"ipv6_flow_label":0,"fragment_id":0,"fragment_offset":0,"src_as":0,"dst_as":0,"next_hop":"0.0.0.0","next_hop_as":0,"src_net":"0.0.0.0/0","dst_net":"0.0.0.0/0","bgp_next_hop":"","bgp_communities":[],"as_path":[],"mpls_ttl":[],"mpls_label":[],"mpls_ip":[],"observation_domain_id":0,"observation_point_id":0,"layer_stack":[],"layer_size":[],"ipv6_routing_header_addresses":[],"ipv6_routing_header_seg_left":0}"#;
    
    let flow: FlowMessage = serde_json::from_str(dns_flow).unwrap();
    
    assert_eq!(flow.src_port, Some(53)); // DNS port
    assert_eq!(flow.proto, Some("UDP".to_string()));
    assert_eq!(flow.etype, Some("IPv4".to_string()));
    assert_eq!(flow.bytes, Some(143));
    assert_eq!(flow.packets, Some(1));
}

#[test]
fn test_https_traffic_parsing() {
    let https_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787471565,"sequence_num":65372,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":272,"packets":5,"src_addr":"192.168.88.30","dst_addr":"54.68.150.54","etype":"IPv4","proto":"TCP","src_port":61269,"dst_port":4172,"in_if":12,"out_if":15,"src_mac":"9a:f9:87:2d:f5:96","dst_mac":"04:f4:1c:40:a3:fb","src_vlan":0,"dst_vlan":0,"vlan_id":0,"ip_tos":0,"forwarding_status":0,"ip_ttl":0,"ip_flags":0,"tcp_flags":194,"icmp_type":0,"icmp_code":0,"ipv6_flow_label":0,"fragment_id":0,"fragment_offset":0,"src_as":0,"dst_as":0,"next_hop":"0.0.0.0","next_hop_as":0,"src_net":"0.0.0.0/0","dst_net":"0.0.0.0/0","bgp_next_hop":"","bgp_communities":[],"as_path":[],"mpls_ttl":[],"mpls_label":[],"mpls_ip":[],"observation_domain_id":0,"observation_point_id":0,"layer_stack":[],"layer_size":[],"ipv6_routing_header_addresses":[],"ipv6_routing_header_seg_left":0}"#;
    
    let flow: FlowMessage = serde_json::from_str(https_flow).unwrap();
    
    assert_eq!(flow.proto, Some("TCP".to_string()));
    assert_eq!(flow.bytes, Some(272));
    assert_eq!(flow.packets, Some(5));
    assert_eq!(flow.src_addr, Some("192.168.88.30".to_string()));
    assert_eq!(flow.dst_addr, Some("54.68.150.54".to_string()));
}

#[test]
fn test_ipv6_traffic_parsing() {
    let ipv6_flow = r#"{"type":"IPFIX","time_received_ns":1767324722856857092,"sequence_num":65403,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324722000000000,"time_flow_end_ns":1767324722000000000,"bytes":72,"packets":1,"src_addr":"fe80::6f4:1cff:fe40:a3fb","dst_addr":"2602:47:d4ad:f901:aa23:feff:fe20:946b","etype":"IPv6","proto":"IPv6-ICMP","src_port":0,"dst_port":0,"in_if":12,"out_if":12,"src_mac":"00:00:00:00:00:00","dst_mac":"04:f4:1c:40:a3:fb","src_vlan":0,"dst_vlan":0,"vlan_id":0,"ip_tos":0,"forwarding_status":0,"ip_ttl":0,"ip_flags":0,"tcp_flags":0,"icmp_type":0,"icmp_code":0,"ipv6_flow_label":0,"fragment_id":0,"fragment_offset":0,"src_as":0,"dst_as":0,"next_hop":"aa23:feff:fe20:946b:8000::","next_hop_as":0,"src_net":"::/0","dst_net":"::/0","bgp_next_hop":"","bgp_communities":[],"as_path":[],"mpls_ttl":[],"mpls_label":[],"mpls_ip":[],"observation_domain_id":0,"observation_point_id":0,"layer_stack":[],"layer_size":[],"ipv6_routing_header_addresses":[],"ipv6_routing_header_seg_left":0}"#;
    
    let flow: FlowMessage = serde_json::from_str(ipv6_flow).unwrap();
    
    assert_eq!(flow.etype, Some("IPv6".to_string()));
    assert_eq!(flow.proto, Some("IPv6-ICMP".to_string()));
    assert_eq!(flow.src_addr, Some("fe80::6f4:1cff:fe40:a3fb".to_string()));
    assert_eq!(flow.dst_addr, Some("2602:47:d4ad:f901:aa23:feff:fe20:946b".to_string()));
    assert_eq!(flow.src_port, Some(0));
    assert_eq!(flow.dst_port, Some(0));
}

#[test]
fn test_icmp_traffic_parsing() {
    let icmp_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787475232,"sequence_num":65383,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":504,"packets":6,"src_addr":"192.168.88.40","dst_addr":"192.168.88.1","etype":"IPv4","proto":"ICMP","src_port":0,"dst_port":0,"in_if":12,"out_if":0,"src_mac":"6c:ae:f6:b6:3b:d2","dst_mac":"04:f4:1c:40:a3:fb","src_vlan":0,"dst_vlan":0,"vlan_id":0,"ip_tos":0,"forwarding_status":0,"ip_ttl":0,"ip_flags":0,"tcp_flags":0,"icmp_type":8,"icmp_code":0,"ipv6_flow_label":0,"fragment_id":0,"fragment_offset":0,"src_as":0,"dst_as":0,"next_hop":"0.0.0.0","next_hop_as":0,"src_net":"0.0.0.0/0","dst_net":"0.0.0.0/0","bgp_next_hop":"","bgp_communities":[],"as_path":[],"mpls_ttl":[],"mpls_label":[],"mpls_ip":[],"observation_domain_id":0,"observation_point_id":0,"layer_stack":[],"layer_size":[],"ipv6_routing_header_addresses":[],"ipv6_routing_header_seg_left":0}"#;
    
    let flow: FlowMessage = serde_json::from_str(icmp_flow).unwrap();
    
    assert_eq!(flow.proto, Some("ICMP".to_string()));
    assert_eq!(flow.etype, Some("IPv4".to_string()));
    assert_eq!(flow.bytes, Some(504));
    assert_eq!(flow.packets, Some(6));
    assert_eq!(flow.src_port, Some(0));
    assert_eq!(flow.dst_port, Some(0));
}

#[test]
fn test_asn_mapping_integration() {
    // Create test flow with Google DNS IP (known ASN 15169)
    let test_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":100,"packets":1,"src_addr":"192.168.1.1","dst_addr":"8.8.8.8","etype":"IPv4","proto":"UDP","src_port":12345,"dst_port":53,"in_if":11,"out_if":12,"src_mac":"00:00:00:00:00:00","dst_mac":"00:00:00:00:00:00","src_vlan":0,"dst_vlan":0,"vlan_id":0,"ip_tos":0,"forwarding_status":0,"ip_ttl":0,"ip_flags":0,"tcp_flags":0,"icmp_type":0,"icmp_code":0,"ipv6_flow_label":0,"fragment_id":0,"fragment_offset":0,"src_as":0,"dst_as":0,"next_hop":"0.0.0.0","next_hop_as":0,"src_net":"0.0.0.0/0","dst_net":"0.0.0.0/0","bgp_next_hop":"","bgp_communities":[],"as_path":[],"mpls_ttl":[],"mpls_label":[],"mpls_ip":[],"observation_domain_id":0,"observation_point_id":0,"layer_stack":[],"layer_size":[],"ipv6_routing_header_addresses":[],"ipv6_routing_header_seg_left":0}"#;

    let flow: FlowMessage = serde_json::from_str(test_flow).unwrap();

    // Test with our minimal test database
    let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));
    metrics.record_flow(&flow);

    let registry_output = String::from_utf8(metrics.gather()).unwrap();

    // Verify ASN metrics are recorded for Google (ASN 15169)
    assert!(registry_output.contains("flows_by_dst_asn"));
    assert!(registry_output.contains("15169"));
    assert!(registry_output.contains("bytes_by_dst_asn"));
}

#[test]
fn test_source_asn_mapping() {
    // Create test flow with Google DNS as SOURCE IP (ASN 15169)
    let test_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":200,"packets":2,"src_addr":"8.8.8.8","dst_addr":"192.168.1.1","etype":"IPv4","proto":"UDP","src_port":53,"dst_port":12345,"in_if":11,"out_if":12,"src_mac":"00:00:00:00:00:00","dst_mac":"00:00:00:00:00:00","src_vlan":0,"dst_vlan":0,"vlan_id":0,"ip_tos":0,"forwarding_status":0,"ip_ttl":0,"ip_flags":0,"tcp_flags":0,"icmp_type":0,"icmp_code":0,"ipv6_flow_label":0,"fragment_id":0,"fragment_offset":0,"src_as":0,"dst_as":0,"next_hop":"0.0.0.0","next_hop_as":0,"src_net":"0.0.0.0/0","dst_net":"0.0.0.0/0","bgp_next_hop":"","bgp_communities":[],"as_path":[],"mpls_ttl":[],"mpls_label":[],"mpls_ip":[],"observation_domain_id":0,"observation_point_id":0,"layer_stack":[],"layer_size":[],"ipv6_routing_header_addresses":[],"ipv6_routing_header_seg_left":0}"#;

    let flow: FlowMessage = serde_json::from_str(test_flow).unwrap();

    // Test with our minimal test database
    let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));
    metrics.record_flow(&flow);

    let registry_output = String::from_utf8(metrics.gather()).unwrap();

    // Verify source ASN metrics are recorded for Google (ASN 15169)
    assert!(registry_output.contains("flows_by_src_asn"));
    assert!(registry_output.contains("15169"));
    assert!(registry_output.contains("bytes_by_src_asn"));
    assert!(registry_output.contains("packets_by_src_asn"));
}

#[tokio::test]
async fn test_application_components() {
    use std::io::Cursor;
    use goflow2_exporter::stdin_reader;
    
    let metrics = Arc::new(Metrics::new(None));
    
    // Test JSON parsing first
    let test_json = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":1,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":1000,"packets":10,"src_addr":"10.0.0.1","dst_addr":"10.0.0.2","etype":"IPv4","proto":"TCP","src_port":80,"dst_port":443}"#;
    
    // Test direct parsing
    let flow: FlowMessage = serde_json::from_str(test_json).unwrap();
    assert_eq!(flow.bytes, Some(1000));
    
    // Test with newline (as stdin_reader expects)
    let test_data = format!("{}\n", test_json);
    let reader = Cursor::new(test_data);
    stdin_reader::process_reader(reader, metrics.clone()).await.unwrap();
    
    let output = String::from_utf8(metrics.gather()).unwrap();
    assert!(output.contains("goflow_flows_total"));
    assert!(output.contains("192.168.88.1"));
}
