use crate::flow::FlowMessage;
use crate::metrics::Metrics;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, warn};

pub async fn process_stdin(metrics: Arc<Metrics>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    process_lines(reader, metrics).await
}

#[allow(dead_code)]
pub async fn process_reader<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let buf_reader = BufReader::new(reader);
    process_lines(buf_reader, metrics).await
}

async fn process_lines<R: tokio::io::AsyncRead + Unpin>(
    reader: BufReader<R>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<FlowMessage>(&line) {
            Ok(flow) => {
                debug!("Parsed flow: {:?}", flow);
                metrics.record_flow(&flow);
            }
            Err(e) => {
                warn!("Failed to parse flow message: {} - Line: {}", e, line);
                metrics.increment_parse_errors();
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn test_process_valid_flow() {
        let metrics = Arc::new(Metrics::new(None));
        let valid_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":143,"packets":1,"src_addr":"192.168.89.2","dst_addr":"192.168.88.30","etype":"IPv4","proto":"UDP","src_port":53,"dst_port":55743}"#;

        let input = valid_flow.as_bytes();
        let reader = BufReader::new(input);

        let result = process_lines(reader, metrics.clone()).await;
        assert!(result.is_ok());

        // Verify metrics were recorded
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(output.contains("goflow_flows_all_total"));
    }

    #[tokio::test]
    async fn test_process_invalid_json() {
        let metrics = Arc::new(Metrics::new(None));
        let invalid_json = "this is not valid json";

        let input = invalid_json.as_bytes();
        let reader = BufReader::new(input);

        let result = process_lines(reader, metrics.clone()).await;
        assert!(result.is_ok());

        // Verify parse error was recorded
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(output.contains("goflow_parse_errors_total"));
        assert!(output.contains(r#"error_type="json""#));
    }

    #[tokio::test]
    async fn test_process_empty_lines() {
        let metrics = Arc::new(Metrics::new(None));
        let input = "\n\n\n".as_bytes();
        let reader = BufReader::new(input);

        let result = process_lines(reader, metrics.clone()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_mixed_valid_invalid() {
        let metrics = Arc::new(Metrics::new(None));
        let valid_flow = r#"{"type":"IPFIX","time_received_ns":1767324720787460121,"sequence_num":65361,"sampling_rate":0,"sampler_address":"192.168.88.1","time_flow_start_ns":1767324720000000000,"time_flow_end_ns":1767324720000000000,"bytes":143,"packets":1,"src_addr":"192.168.89.2","dst_addr":"192.168.88.30","etype":"IPv4","proto":"UDP","src_port":53,"dst_port":55743}"#;
        let invalid_json = "invalid json";
        let mixed_input = format!("{}\n{}\n{}", valid_flow, invalid_json, valid_flow);

        let input = mixed_input.as_bytes();
        let reader = BufReader::new(input);

        let result = process_lines(reader, metrics.clone()).await;
        assert!(result.is_ok());

        let output = String::from_utf8(metrics.gather()).unwrap();
        // Should have both valid flows and parse errors
        assert!(output.contains("goflow_flows_all_total"));
        assert!(output.contains("goflow_parse_errors_total"));
    }
}
