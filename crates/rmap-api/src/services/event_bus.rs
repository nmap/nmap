use tokio::sync::broadcast;
use crate::models::ScanEvent;

/// Event bus for broadcasting scan events to WebSocket clients
pub struct EventBus {
    tx: broadcast::Sender<ScanEvent>,
}

impl EventBus {
    /// Create a new event bus with capacity for 1000 events
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { tx }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: ScanEvent) {
        let _ = self.tx.send(event); // Ignore if no subscribers
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.tx.subscribe()
    }

    /// Get number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
