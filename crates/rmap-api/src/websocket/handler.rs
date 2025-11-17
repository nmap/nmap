use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::{
    models::{ClientMessage, ScanEvent, ServerMessage},
    services::EventBus,
};

/// Handle WebSocket upgrade request
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(event_bus): State<Arc<EventBus>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, event_bus))
}

/// Handle individual WebSocket connection
async fn handle_socket(socket: WebSocket, event_bus: Arc<EventBus>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = event_bus.subscribe();

    info!("WebSocket client connected");

    // Spawn task to send events to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let message = ServerMessage::Event(event);
            let json = match serde_json::to_string(&message) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize event: {}", e);
                    continue;
                }
            };

            if sender.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages from client
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(client_msg) => {
                            info!("Received client message: {:?}", client_msg);
                            handle_client_message(client_msg, &event_bus).await;
                        }
                        Err(e) => {
                            warn!("Failed to parse client message: {}", e);
                        }
                    }
                }
                Message::Close(_) => {
                    info!("WebSocket client disconnected");
                    break;
                }
                Message::Ping(_) => {
                    // Axum handles pong automatically
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    info!("WebSocket connection closed");
}

/// Handle messages from WebSocket clients
async fn handle_client_message(msg: ClientMessage, _event_bus: &EventBus) {
    match msg {
        ClientMessage::Subscribe { scan_id } => {
            info!("Client subscribed to scan: {}", scan_id);
            // In a full implementation, track subscriptions
        }
        ClientMessage::Unsubscribe { scan_id } => {
            info!("Client unsubscribed from scan: {}", scan_id);
        }
        ClientMessage::SubscribeAll => {
            info!("Client subscribed to all scans");
        }
        ClientMessage::PauseScan { scan_id } => {
            info!("Client requested pause for scan: {}", scan_id);
            // Implement scan pause logic
        }
        ClientMessage::ResumeScan { scan_id } => {
            info!("Client requested resume for scan: {}", scan_id);
            // Implement scan resume logic
        }
        ClientMessage::CancelScan { scan_id } => {
            info!("Client requested cancel for scan: {}", scan_id);
            // Implement scan cancel logic
        }
        ClientMessage::Ping => {
            // Ping handled by framework
        }
    }
}
