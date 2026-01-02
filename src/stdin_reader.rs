use crate::flow::FlowMessage;
use crate::metrics::Metrics;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, warn};

pub async fn process_stdin(metrics: Arc<Metrics>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
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
