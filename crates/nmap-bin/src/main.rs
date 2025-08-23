use anyhow::Result;
use nmap_cli::Cli;
use nmap_core::NmapEngine;
use std::env;
use tracing::{info, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let args: Vec<String> = env::args().collect();
    
    // Handle NMAP_ARGS environment variable (like original C++ version)
    let final_args = if let Ok(nmap_args) = env::var("NMAP_ARGS") {
        let mut combined_args = vec![args[0].clone()];
        combined_args.extend(nmap_args.split_whitespace().map(String::from));
        combined_args.extend(args.into_iter().skip(1));
        combined_args
    } else {
        args
    };
    
    // Handle --resume option
    if final_args.len() == 3 && final_args[1] == "--resume" {
        info!("Resuming scan from log file: {}", final_args[2]);
        return resume_scan(&final_args[2]).await;
    }
    
    // Parse command line arguments
    let cli = Cli::parse(&final_args)?;
    
    // Create and run the Nmap engine
    let mut engine = NmapEngine::new(cli.options)?;
    engine.run().await
}

async fn resume_scan(log_file: &str) -> Result<()> {
    // TODO: Implement scan resumption from log file
    error!("Scan resumption not yet implemented");
    anyhow::bail!("Cannot resume from log file {}", log_file);
}