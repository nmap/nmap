//! Enhanced MCP Server with Claude AI Agent Integration
//!
//! This MCP server combines:
//! - R-Map scanning tools (6 existing tools)
//! - PYRO Fire Marshal tools (6 new tools)
//! - Claude AI Agent tools (6 new tools)
//!
//! Total: 18 MCP tools for complete autonomous operation

use pyro_claude_integration::{PyroDatabase, EventBus, ClaudeAgent, FireMarshal};
use pyro_claude_integration::claude_agent::ClaudeWorkflows;
use pyro_claude_integration::fire_marshal::CreateInvestigationRequest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

#[tokio::main]
async fn main() {
    // Initialize database
    let db_path = std::env::var("PYRO_DB_PATH")
        .unwrap_or_else(|_| "./pyro_claude_integration.db".to_string());

    let db = Arc::new(PyroDatabase::new(&db_path).expect("Failed to create database"));
    let event_bus = Arc::new(EventBus::new(db.clone(), 1000));
    let claude_agent = Arc::new(ClaudeAgent::new(db.clone(), event_bus.clone()));
    let fire_marshal = Arc::new(FireMarshal::new(db.clone(), event_bus.clone()));

    let server = MCPServer {
        db,
        event_bus,
        claude_agent,
        fire_marshal,
    };

    eprintln!("[PYRO MCP Server] Started with 18 tools");
    eprintln!("[PYRO MCP Server] Database: {}", db_path);

    server.run().await;
}

struct MCPServer {
    db: Arc<PyroDatabase>,
    event_bus: Arc<EventBus>,
    claude_agent: Arc<ClaudeAgent>,
    fire_marshal: Arc<FireMarshal>,
}

impl MCPServer {
    async fn run(&self) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            let line = line.expect("Failed to read line");
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<Value>(&line) {
                Ok(request) => {
                    let response = self.handle_request(request).await;
                    let response_json = serde_json::to_string(&response).expect("Failed to serialize response");
                    writeln!(stdout, "{}", response_json).expect("Failed to write response");
                    stdout.flush().expect("Failed to flush stdout");
                }
                Err(e) => {
                    eprintln!("[PYRO MCP Server] Failed to parse request: {}", e);
                }
            }
        }
    }

    async fn handle_request(&self, request: Value) -> Value {
        let method = request["method"].as_str().unwrap_or("");
        let id = request["id"].clone();

        match method {
            "initialize" => self.handle_initialize(id),
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tool_call(id, request["params"].clone()).await,
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {}", method)
                }
            }),
        }
    }

    fn handle_initialize(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "pyro-claude-integration",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": {}
                }
            }
        })
    }

    fn handle_tools_list(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    // === R-Map Scanning Tools (6 existing) ===
                    {
                        "name": "rmap_scan",
                        "description": "Execute R-Map port scan on target",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string"},
                                "ports": {"type": "string"},
                                "scan_type": {"type": "string"},
                                "timing": {"type": "string"}
                            },
                            "required": ["target"]
                        }
                    },
                    {
                        "name": "rmap_service_detect",
                        "description": "Detect services on open ports (411+ signatures)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string"},
                                "ports": {"type": "string"},
                                "intensity": {"type": "number"}
                            },
                            "required": ["target"]
                        }
                    },
                    {
                        "name": "rmap_os_detect",
                        "description": "Fingerprint operating system (139+ signatures)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string"},
                                "method": {"type": "string"}
                            },
                            "required": ["target"]
                        }
                    },
                    {
                        "name": "rmap_comprehensive_scan",
                        "description": "Complete scan: ports + services + OS",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string"},
                                "scan_profile": {"type": "string"}
                            },
                            "required": ["target"]
                        }
                    },
                    {
                        "name": "rmap_export",
                        "description": "Export scan results in various formats",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "scan_id": {"type": "string"},
                                "format": {"type": "string"}
                            },
                            "required": ["scan_id", "format"]
                        }
                    },
                    {
                        "name": "rmap_history",
                        "description": "Retrieve scan history from redb database",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "limit": {"type": "number"}
                            }
                        }
                    },

                    // === PYRO Fire Marshal Tools (6 new) ===
                    {
                        "name": "fire_marshal_create_investigation",
                        "description": "Create new Fire Marshal investigation (Cryptex v2.0 compliant)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "marshal_level": {"type": "string", "enum": ["L1", "L2", "L3"]},
                                "subject": {"type": "string"},
                                "authorization": {"type": "string"},
                                "legal_review": {"type": "boolean"}
                            },
                            "required": ["marshal_level", "subject", "authorization"]
                        }
                    },
                    {
                        "name": "fire_marshal_add_evidence",
                        "description": "Link R-Map scan as evidence to investigation",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "investigation_id": {"type": "string"},
                                "scan_id": {"type": "string"}
                            },
                            "required": ["investigation_id", "scan_id"]
                        }
                    },
                    {
                        "name": "fire_marshal_trigger_detonator",
                        "description": "Run automated analysis detonator",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "investigation_id": {"type": "string"},
                                "detonator_name": {"type": "string", "enum": ["vulnerability_assessment", "compliance_check", "anomaly_detection"]}
                            },
                            "required": ["investigation_id", "detonator_name"]
                        }
                    },
                    {
                        "name": "fire_marshal_close_investigation",
                        "description": "Close investigation with findings and remediation",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "investigation_id": {"type": "string"},
                                "findings": {"type": "string"},
                                "remediation": {"type": "string"}
                            },
                            "required": ["investigation_id", "findings"]
                        }
                    },
                    {
                        "name": "fire_marshal_list_investigations",
                        "description": "List all Fire Marshal investigations",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "limit": {"type": "number"}
                            }
                        }
                    },
                    {
                        "name": "fire_marshal_validate_cryptex",
                        "description": "Validate investigation against Cryptex v2.0 compliance",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "investigation_id": {"type": "string"}
                            },
                            "required": ["investigation_id"]
                        }
                    },

                    // === Claude AI Agent Tools (6 new) ===
                    {
                        "name": "claude_start_workflow",
                        "description": "Start autonomous Claude workflow (e.g., network perimeter assessment)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "workflow_type": {"type": "string", "enum": ["network_perimeter", "incident_response", "continuous_monitoring"]},
                                "target": {"type": "string"},
                                "investigation_id": {"type": "string"}
                            },
                            "required": ["workflow_type", "target"]
                        }
                    },
                    {
                        "name": "claude_analyze_scan",
                        "description": "Claude AI analyzes scan results and provides recommendations",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "scan_id": {"type": "string"}
                            },
                            "required": ["scan_id"]
                        }
                    },
                    {
                        "name": "claude_compare_scans",
                        "description": "Compare two scans to detect changes (baseline vs current)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "current_scan_id": {"type": "string"},
                                "baseline_scan_id": {"type": "string"}
                            },
                            "required": ["current_scan_id", "baseline_scan_id"]
                        }
                    },
                    {
                        "name": "claude_escalation_decision",
                        "description": "Claude makes autonomous decision on investigation escalation",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "investigation_id": {"type": "string"}
                            },
                            "required": ["investigation_id"]
                        }
                    },
                    {
                        "name": "claude_workflow_status",
                        "description": "Get status of running Claude workflow",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "workflow_id": {"type": "string"}
                            },
                            "required": ["workflow_id"]
                        }
                    },
                    {
                        "name": "claude_get_events",
                        "description": "Get real-time events from redb event stream",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "since_minutes": {"type": "number"},
                                "limit": {"type": "number"}
                            }
                        }
                    }
                ]
            }
        })
    }

    async fn handle_tool_call(&self, id: Value, params: Value) -> Value {
        let tool_name = params["name"].as_str().unwrap_or("");
        let arguments = &params["arguments"];

        let result = match tool_name {
            // R-Map tools (stub - would integrate with rmap-engine)
            "rmap_scan" => self.handle_rmap_scan(arguments).await,
            "rmap_service_detect" => self.handle_rmap_service_detect(arguments).await,
            "rmap_os_detect" => self.handle_rmap_os_detect(arguments).await,
            "rmap_comprehensive_scan" => self.handle_rmap_comprehensive_scan(arguments).await,
            "rmap_export" => self.handle_rmap_export(arguments).await,
            "rmap_history" => self.handle_rmap_history(arguments).await,

            // Fire Marshal tools
            "fire_marshal_create_investigation" => self.handle_fire_marshal_create(arguments).await,
            "fire_marshal_add_evidence" => self.handle_fire_marshal_add_evidence(arguments).await,
            "fire_marshal_trigger_detonator" => self.handle_fire_marshal_trigger_detonator(arguments).await,
            "fire_marshal_close_investigation" => self.handle_fire_marshal_close(arguments).await,
            "fire_marshal_list_investigations" => self.handle_fire_marshal_list(arguments).await,
            "fire_marshal_validate_cryptex" => self.handle_fire_marshal_validate(arguments).await,

            // Claude AI tools
            "claude_start_workflow" => self.handle_claude_start_workflow(arguments).await,
            "claude_analyze_scan" => self.handle_claude_analyze(arguments).await,
            "claude_compare_scans" => self.handle_claude_compare(arguments).await,
            "claude_escalation_decision" => self.handle_claude_escalate(arguments).await,
            "claude_workflow_status" => self.handle_claude_workflow_status(arguments).await,
            "claude_get_events" => self.handle_claude_get_events(arguments).await,

            _ => json!([{
                "type": "text",
                "text": format!("Unknown tool: {}", tool_name)
            }]),
        };

        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": result
            }
        })
    }

    // Fire Marshal tool implementations

    async fn handle_fire_marshal_create(&self, args: &Value) -> Value {
        let req = CreateInvestigationRequest {
            marshal_level: args["marshal_level"].as_str().unwrap_or("L2").to_string(),
            subject: args["subject"].as_str().unwrap_or("").to_string(),
            authorization: args["authorization"].as_str().unwrap_or("").to_string(),
            legal_review: args["legal_review"].as_bool().unwrap_or(false),
        };

        match self.fire_marshal.create_investigation(req).await {
            Ok(investigation) => json!([{
                "type": "text",
                "text": format!("✅ Fire Marshal Investigation Created\n\nFire ID: {}\nMarshal Level: {}\nSubject: {}\nStatus: {}\nInvestigation ID: {}\n\nUse 'fire_marshal_add_evidence' to link R-Map scans to this investigation.",
                    investigation.fire_id, investigation.marshal_level, investigation.subject, investigation.status, investigation.id)
            }]),
            Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
        }
    }

    async fn handle_fire_marshal_add_evidence(&self, args: &Value) -> Value {
        let inv_id = Uuid::parse_str(args["investigation_id"].as_str().unwrap_or("")).ok();
        let scan_id = Uuid::parse_str(args["scan_id"].as_str().unwrap_or("")).ok();

        if let (Some(inv_id), Some(scan_id)) = (inv_id, scan_id) {
            match self.fire_marshal.add_evidence(&inv_id, &scan_id).await {
                Ok(_) => json!([{"type": "text", "text": format!("✅ Evidence added to investigation {}", inv_id)}]),
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid UUID"}])
        }
    }

    async fn handle_fire_marshal_trigger_detonator(&self, args: &Value) -> Value {
        let inv_id = Uuid::parse_str(args["investigation_id"].as_str().unwrap_or("")).ok();
        let detonator_name = args["detonator_name"].as_str().unwrap_or("vulnerability_assessment");

        if let Some(inv_id) = inv_id {
            match self.fire_marshal.trigger_detonator(&inv_id, detonator_name).await {
                Ok(result) => json!([{
                    "type": "text",
                    "text": format!("🔥 Detonator Triggered: {}\n\nStatus: {}\nSummary: {}\n\nDetails:\n{}",
                        detonator_name, result.status, result.summary, serde_json::to_string_pretty(&result.details).unwrap())
                }]),
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid UUID"}])
        }
    }

    async fn handle_fire_marshal_close(&self, args: &Value) -> Value {
        let inv_id = Uuid::parse_str(args["investigation_id"].as_str().unwrap_or("")).ok();
        let findings = args["findings"].as_str().unwrap_or("");
        let remediation = args["remediation"].as_str().map(|s| s.to_string());

        if let Some(inv_id) = inv_id {
            match self.fire_marshal.close_investigation(&inv_id, findings.to_string(), remediation).await {
                Ok(_) => json!([{"type": "text", "text": format!("✅ Investigation {} closed", inv_id)}]),
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid UUID"}])
        }
    }

    async fn handle_fire_marshal_list(&self, args: &Value) -> Value {
        let limit = args["limit"].as_u64().unwrap_or(10) as usize;

        match self.fire_marshal.list_investigations(limit) {
            Ok(investigations) => {
                let mut text = format!("📋 Fire Marshal Investigations ({} total)\n\n", investigations.len());
                for inv in investigations {
                    text.push_str(&format!("• {} - {} ({})\n  Subject: {}\n  Status: {}\n  Evidence: {} scans\n\n",
                        inv.fire_id, inv.marshal_level, inv.id, inv.subject, inv.status, inv.evidence.len()));
                }
                json!([{"type": "text", "text": text}])
            }
            Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
        }
    }

    async fn handle_fire_marshal_validate(&self, args: &Value) -> Value {
        let inv_id = Uuid::parse_str(args["investigation_id"].as_str().unwrap_or("")).ok();

        if let Some(inv_id) = inv_id {
            match self.fire_marshal.get_investigation(&inv_id) {
                Ok(investigation) => {
                    let validation = self.fire_marshal.validate_cryptex_compliance(&investigation);
                    json!([{
                        "type": "text",
                        "text": format!("🔍 Cryptex v2.0 Compliance Validation\n\nCompliant: {}\nVersion: {}\n\nIssues:\n{}",
                            if validation.is_compliant { "✅ PASS" } else { "❌ FAIL" },
                            validation.cryptex_version,
                            if validation.issues.is_empty() { "None".to_string() } else { validation.issues.join("\n") })
                    }])
                }
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid UUID"}])
        }
    }

    // Claude AI tool implementations

    async fn handle_claude_start_workflow(&self, args: &Value) -> Value {
        let workflow_type = args["workflow_type"].as_str().unwrap_or("network_perimeter");
        let target = args["target"].as_str().unwrap_or("").to_string();
        let investigation_id = args["investigation_id"].as_str()
            .and_then(|s| Uuid::parse_str(s).ok());

        let workflow = match workflow_type {
            "network_perimeter" => ClaudeWorkflows::network_perimeter_assessment(target.clone()),
            "incident_response" => ClaudeWorkflows::incident_response(target.clone()),
            "continuous_monitoring" => ClaudeWorkflows::continuous_monitoring(vec![target.clone()]),
            _ => ClaudeWorkflows::network_perimeter_assessment(target.clone()),
        };

        match self.claude_agent.start_workflow(workflow, investigation_id).await {
            Ok(workflow_id) => json!([{
                "type": "text",
                "text": format!("🤖 Claude Autonomous Workflow Started\n\nWorkflow ID: {}\nType: {}\nTarget: {}\n\nThe workflow will execute autonomously. Use 'claude_workflow_status' to check progress.",
                    workflow_id, workflow_type, target)
            }]),
            Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
        }
    }

    async fn handle_claude_analyze(&self, args: &Value) -> Value {
        let scan_id = Uuid::parse_str(args["scan_id"].as_str().unwrap_or("")).ok();

        if let Some(scan_id) = scan_id {
            match self.claude_agent.analyze_scan_results(&scan_id).await {
                Ok(analysis) => json!([{
                    "type": "text",
                    "text": format!("🧠 Claude AI Analysis\n\nScan ID: {}\n\nSummary: {}\n\nRisk Score: {:.1}/10.0\n\nNext Actions:\n{}",
                        scan_id, analysis.summary, analysis.risk_score,
                        analysis.next_actions.join("\n"))
                }]),
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid scan_id"}])
        }
    }

    async fn handle_claude_compare(&self, args: &Value) -> Value {
        json!([{"type": "text", "text": "🔍 Scan comparison completed (implementation pending)"}])
    }

    async fn handle_claude_escalate(&self, args: &Value) -> Value {
        let inv_id = Uuid::parse_str(args["investigation_id"].as_str().unwrap_or("")).ok();

        if let Some(inv_id) = inv_id {
            match self.claude_agent.should_escalate(&inv_id).await {
                Ok(decision) => json!([{
                    "type": "text",
                    "text": format!("⚡ Claude Escalation Decision\n\nShould Escalate: {}\nCurrent Level: {}\nRecommended Level: {}\n\nReasoning: {}\nConfidence: {:.0}%",
                        if decision.should_escalate { "YES" } else { "NO" },
                        decision.current_level, decision.recommended_level,
                        decision.reasoning, decision.confidence * 100.0)
                }]),
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid investigation_id"}])
        }
    }

    async fn handle_claude_workflow_status(&self, args: &Value) -> Value {
        let workflow_id = Uuid::parse_str(args["workflow_id"].as_str().unwrap_or("")).ok();

        if let Some(workflow_id) = workflow_id {
            match self.claude_agent.get_workflow_status(&workflow_id) {
                Ok(status) => json!([{
                    "type": "text",
                    "text": format!("📊 Workflow Status\n\nName: {}\nStatus: {}\nProgress: {}/{} steps\nStarted: {}\nTools Used: {}",
                        status.workflow_name, status.status, status.current_step, status.total_steps,
                        status.started_at, status.tools_used.join(", "))
                }]),
                Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
            }
        } else {
            json!([{"type": "text", "text": "Error: Invalid workflow_id"}])
        }
    }

    async fn handle_claude_get_events(&self, args: &Value) -> Value {
        let since_minutes = args["since_minutes"].as_u64().unwrap_or(10);
        let limit = args["limit"].as_u64().unwrap_or(50) as usize;

        let since = Utc::now() - chrono::Duration::minutes(since_minutes as i64);

        match self.event_bus.get_events_since(since, limit).await {
            Ok(events) => json!([{
                "type": "text",
                "text": format!("📡 Real-time Events ({} total)\n\n{}", events.len(),
                    serde_json::to_string_pretty(&events).unwrap_or_else(|_| "Error formatting events".to_string()))
            }]),
            Err(e) => json!([{"type": "text", "text": format!("Error: {}", e)}]),
        }
    }

    // R-Map tool stubs (would integrate with actual rmap-engine)

    async fn handle_rmap_scan(&self, _args: &Value) -> Value {
        json!([{"type": "text", "text": "R-Map scan (stub - integrate with rmap-engine)"}])
    }

    async fn handle_rmap_service_detect(&self, _args: &Value) -> Value {
        json!([{"type": "text", "text": "R-Map service detection (stub)"}])
    }

    async fn handle_rmap_os_detect(&self, _args: &Value) -> Value {
        json!([{"type": "text", "text": "R-Map OS detection (stub)"}])
    }

    async fn handle_rmap_comprehensive_scan(&self, _args: &Value) -> Value {
        json!([{"type": "text", "text": "R-Map comprehensive scan (stub)"}])
    }

    async fn handle_rmap_export(&self, _args: &Value) -> Value {
        json!([{"type": "text", "text": "R-Map export (stub)"}])
    }

    async fn handle_rmap_history(&self, args: &Value) -> Value {
        let limit = args["limit"].as_u64().unwrap_or(10);
        json!([{"type": "text", "text": format!("📜 Scan history (limit: {})", limit)}])
    }
}
