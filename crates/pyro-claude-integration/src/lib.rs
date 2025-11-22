//! PYRO Fire Marshal + R-Map + Claude AI Agent Integration
//!
//! This crate provides a unified integration layer that connects:
//! - R-Map network scanning engine
//! - PYRO Fire Marshal investigation framework
//! - Claude AI agent orchestration via MCP
//!
//! Uses redb (embedded database) instead of Redis/RethinkDB for:
//! - Event streaming (replaces Redis pub/sub)
//! - Persistent storage (replaces RethinkDB)
//! - Real-time updates
//! - Cross-component state management

pub mod database;
pub mod events;
pub mod claude_agent;
pub mod fire_marshal;
pub mod api;
pub mod workflows;

pub use database::PyroDatabase;
pub use events::{Event, EventBus, EventStream};
pub use claude_agent::ClaudeAgent;
pub use fire_marshal::FireMarshal;
