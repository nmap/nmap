#!/usr/bin/env cargo

//! R-Map MCP Server - Network Reconnaissance via Model Context Protocol
//!
//! This server exposes R-Map's network scanning capabilities through the MCP protocol,
//! enabling AI assistants and automation tools to perform comprehensive network reconnaissance.
//!
//! Features:
//! - Port scanning (TCP/UDP, multiple scan types)
//! - Service detection (411+ signatures)
//! - OS fingerprinting (139+ signatures)
//! - Persistent storage with redb
//! - Multiple output formats

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod database;
mod scanner;
mod tools;

use database::ScanDatabase;
use scanner::ScanEngine;

/// MCP JSON-RPC request
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

/// MCP JSON-RPC response
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// MCP JSON-RPC error
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// MCP Server state
struct McpServer {
    database: ScanDatabase,
    scanner: ScanEngine,
}

impl McpServer {
    /// Create new MCP server
    fn new(db_path: PathBuf) -> Result<Self> {
        Ok(Self {
            database: ScanDatabase::new(db_path)?,
            scanner: ScanEngine::new(),
        })
    }

    /// Handle MCP protocol requests
    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();

        match request.method.as_str() {
            "initialize" => self.handle_initialize(id, request.params).await,
            "tools/list" => self.handle_list_tools(id).await,
            "tools/call" => self.handle_call_tool(id, request.params).await,
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", request.method),
                    data: None,
                }),
            },
        }
    }

    /// Handle initialize request
    async fn handle_initialize(&self, id: Option<Value>, _params: Option<Value>) -> JsonRpcResponse {
        info!("MCP server initializing");

        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "rmap-mcp-server",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        }
    }

    /// Handle list tools request
    async fn handle_list_tools(&self, id: Option<Value>) -> JsonRpcResponse {
        debug!("Listing available tools");

        let tools = tools::get_tool_definitions();

        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "tools": tools
            })),
            error: None,
        }
    }

    /// Handle call tool request
    async fn handle_call_tool(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Invalid params".to_string(),
                        data: None,
                    }),
                }
            }
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Tool name required".to_string(),
                        data: None,
                    }),
                }
            }
        };

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        info!("Calling tool: {}", tool_name);

        // Execute the tool
        let result = match tool_name {
            "rmap_scan" => self.execute_scan(arguments).await,
            "rmap_service_detect" => self.execute_service_detect(arguments).await,
            "rmap_os_detect" => self.execute_os_detect(arguments).await,
            "rmap_comprehensive_scan" => self.execute_comprehensive_scan(arguments).await,
            "rmap_export" => self.execute_export(arguments).await,
            "rmap_history" => self.execute_history(arguments).await,
            _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
        };

        match result {
            Ok(content) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(json!({
                    "content": [
                        {
                            "type": "text",
                            "text": content
                        }
                    ]
                })),
                error: None,
            },
            Err(e) => {
                error!("Tool execution error: {}", e);
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message: format!("Tool execution failed: {}", e),
                        data: None,
                    }),
                }
            }
        }
    }

    /// Execute port scan
    async fn execute_scan(&self, args: Value) -> Result<String> {
        let scan_id = Uuid::new_v4();
        let target = args.get("target")
            .and_then(|v| v.as_str())
            .context("target parameter required")?;

        info!("Starting port scan: {} (ID: {})", target, scan_id);

        let result = self.scanner.port_scan(target, &args).await?;

        // Store in database
        self.database.store_scan_result(scan_id, "port_scan", target, &result)?;

        Ok(format!("Port scan completed successfully (ID: {})\n\n{}", scan_id, result))
    }

    /// Execute service detection
    async fn execute_service_detect(&self, args: Value) -> Result<String> {
        let scan_id = Uuid::new_v4();
        let target = args.get("target")
            .and_then(|v| v.as_str())
            .context("target parameter required")?;

        info!("Starting service detection: {} (ID: {})", target, scan_id);

        let result = self.scanner.service_detect(target, &args).await?;

        self.database.store_scan_result(scan_id, "service_detect", target, &result)?;

        Ok(format!("Service detection completed (411+ signatures) (ID: {})\n\n{}", scan_id, result))
    }

    /// Execute OS detection
    async fn execute_os_detect(&self, args: Value) -> Result<String> {
        let scan_id = Uuid::new_v4();
        let target = args.get("target")
            .and_then(|v| v.as_str())
            .context("target parameter required")?;

        info!("Starting OS detection: {} (ID: {})", target, scan_id);

        let result = self.scanner.os_detect(target, &args).await?;

        self.database.store_scan_result(scan_id, "os_detect", target, &result)?;

        Ok(format!("OS detection completed (139+ signatures) (ID: {})\n\n{}", scan_id, result))
    }

    /// Execute comprehensive scan
    async fn execute_comprehensive_scan(&self, args: Value) -> Result<String> {
        let scan_id = Uuid::new_v4();
        let target = args.get("target")
            .and_then(|v| v.as_str())
            .context("target parameter required")?;

        info!("Starting comprehensive scan: {} (ID: {})", target, scan_id);

        let result = self.scanner.comprehensive_scan(target, &args).await?;

        self.database.store_scan_result(scan_id, "comprehensive", target, &result)?;

        Ok(format!("Comprehensive scan completed (ID: {})\n\n{}", scan_id, result))
    }

    /// Execute export
    async fn execute_export(&self, args: Value) -> Result<String> {
        let format = args.get("format")
            .and_then(|v| v.as_str())
            .context("format parameter required")?;

        let scan_id = args.get("scan_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .context("valid scan_id parameter required")?;

        info!("Exporting scan {} to format: {}", scan_id, format);

        let scan_data = self.database.get_scan_result(scan_id)?;
        let exported = self.scanner.export(&scan_data, format)?;

        Ok(format!("Export successful!\n\nFormat: {}\n\n{}", format, exported))
    }

    /// Get scan history
    async fn execute_history(&self, args: Value) -> Result<String> {
        let limit = args.get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        info!("Retrieving scan history (limit: {})", limit);

        let history = self.database.get_scan_history(limit)?;

        Ok(format!("Scan History (last {} scans)\n\n{}", limit, history))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_writer(std::io::stderr)
        .init();

    info!("🔥 Starting R-Map MCP Server (Rust)");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Database path
    let db_path = std::env::var("RMAP_DB_PATH")
        .unwrap_or_else(|_| {
            let mut path = std::env::current_dir().unwrap();
            path.push("rmap_scans.db");
            path.to_string_lossy().to_string()
        });

    info!("Database: {}", db_path);

    // Create server
    let server = McpServer::new(PathBuf::from(db_path))?;

    info!("MCP server ready - listening on stdin");

    // Read from stdin and write to stdout (MCP protocol)
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                debug!("EOF received, shutting down");
                break;
            }
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                debug!("Received request: {}", line);

                // Parse JSON-RPC request
                match serde_json::from_str::<JsonRpcRequest>(line) {
                    Ok(request) => {
                        // Handle request
                        let response = server.handle_request(request).await;

                        // Send response
                        let response_json = serde_json::to_string(&response)?;
                        writeln!(stdout, "{}", response_json)?;
                        stdout.flush()?;

                        debug!("Sent response");
                    }
                    Err(e) => {
                        error!("Failed to parse request: {}", e);

                        let error_response = JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: None,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32700,
                                message: format!("Parse error: {}", e),
                                data: None,
                            }),
                        };

                        let response_json = serde_json::to_string(&error_response)?;
                        writeln!(stdout, "{}", response_json)?;
                        stdout.flush()?;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from stdin: {}", e);
                break;
            }
        }
    }

    info!("MCP server shutting down");
    Ok(())
}
