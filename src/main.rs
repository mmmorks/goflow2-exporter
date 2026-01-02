mod asn;
mod flow;
mod metrics;
mod stdin_reader;

use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting goflow2-aggregator");

    let asn_db_path = std::env::var("ASN_DB_PATH")
        .unwrap_or_else(|_| "./data/GeoLite2-ASN.mmdb".to_string());
    
    let metrics = Arc::new(metrics::Metrics::new(Some(&asn_db_path)));

    let metrics_clone = metrics.clone();
    let metrics_server = tokio::spawn(async move {
        if let Err(e) = metrics::serve_metrics(metrics_clone).await {
            error!("Metrics server error: {}", e);
        }
    });

    let stdin_processor = tokio::spawn(async move {
        if let Err(e) = stdin_reader::process_stdin(metrics).await {
            error!("Stdin processing error: {}", e);
        }
    });

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        _ = metrics_server => {
            error!("Metrics server stopped unexpectedly");
        }
        _ = stdin_processor => {
            error!("Stdin processor stopped unexpectedly");
        }
    }

    info!("Shutting down");
    Ok(())
}
