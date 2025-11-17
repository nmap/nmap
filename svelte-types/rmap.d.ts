/**
 * R-Map TypeScript Type Definitions for Svelte Frontend
 * Auto-generated types matching the R-Map API server models
 */

// ============================================================================
// SCAN TYPES
// ============================================================================

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export type ScanType = 'stealth' | 'connect' | 'udp' | 'ack' | 'fin' | 'null' | 'xmas' | 'comprehensive';

export interface Scan {
    id: string;
    status: ScanStatus;
    targets: string[];
    options: ScanOptions;
    progress: number; // 0-100
    stats: ScanStats;
    created_at: string; // ISO 8601 datetime
    updated_at: string;
    started_at?: string;
    completed_at?: string;
    error?: string;
}

export interface ScanOptions {
    scan_type: ScanType;
    ports: string; // "1-65535", "80,443,8080"
    timing: 0 | 1 | 2 | 3 | 4 | 5; // T0-T5
    scripts: string[];
    service_detection: boolean;
    os_detection: boolean;
    skip_ping: boolean;
    max_retries?: number;
    timeout?: number; // seconds
}

export interface ScanStats {
    hosts_total: number;
    hosts_up: number;
    hosts_down: number;
    ports_scanned: number;
    ports_open: number;
    ports_filtered: number;
    vulnerabilities: number;
    duration: number; // seconds
}

export interface CreateScanRequest {
    targets: string[];
    options?: ScanOptions;
}

export interface CreateScanResponse {
    scan_id: string;
    status: ScanStatus;
    created_at: string;
}

// ============================================================================
// HOST TYPES
// ============================================================================

export type HostState = 'up' | 'down' | 'unknown';
export type PortState = 'open' | 'closed' | 'filtered' | 'open|filtered' | 'closed|filtered';
export type Protocol = 'tcp' | 'udp';

export interface Host {
    id: string;
    scan_id: string;
    ip: string;
    hostname?: string;
    mac?: string;
    vendor?: string;
    os?: OSInfo;
    ports: Port[];
    state: HostState;
    first_seen: string;
    last_seen: string;
}

export interface Port {
    number: number;
    protocol: Protocol;
    state: PortState;
    service?: string;
    version?: string;
    banner?: string;
    product?: string;
    extra_info?: string;
}

export interface OSInfo {
    name: string;
    version?: string;
    confidence: number; // 0-100
    cpe?: string; // Common Platform Enumeration
    family?: string;
}

// ============================================================================
// VULNERABILITY TYPES
// ============================================================================

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Vulnerability {
    id: string;
    scan_id: string;
    host_id: string;
    host_ip: string;
    port: number;
    service: string;
    name: string;
    description: string;
    severity: Severity;
    cvss?: number; // 0.0-10.0
    cve?: string; // CVE identifier
    cwe?: string; // CWE identifier
    evidence: string[];
    remediation: string;
    references: string[];
    discovered_at: string;
}

export interface SeverityCounts {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
}

// ============================================================================
// EVENT TYPES (WebSocket)
// ============================================================================

export type ScanEvent =
    | ScanStartedEvent
    | ScanProgressEvent
    | HostDiscoveredEvent
    | PortOpenEvent
    | ServiceIdentifiedEvent
    | VulnerabilityFoundEvent
    | ScanCompletedEvent
    | ScanFailedEvent
    | ScanCancelledEvent
    | StatusUpdateEvent;

export interface ScanStartedEvent {
    type: 'scan_started';
    scan_id: string;
    targets: string[];
}

export interface ScanProgressEvent {
    type: 'scan_progress';
    scan_id: string;
    progress: number;
    stats: ScanStats;
}

export interface HostDiscoveredEvent {
    type: 'host_discovered';
    scan_id: string;
    host: Host;
}

export interface PortOpenEvent {
    type: 'port_open';
    scan_id: string;
    host: string;
    port: Port;
}

export interface ServiceIdentifiedEvent {
    type: 'service_identified';
    scan_id: string;
    host: string;
    port: number;
    service: string;
    version?: string;
}

export interface VulnerabilityFoundEvent {
    type: 'vulnerability_found';
    scan_id: string;
    vulnerability: Vulnerability;
}

export interface ScanCompletedEvent {
    type: 'scan_completed';
    scan_id: string;
    stats: ScanStats;
    duration: number;
}

export interface ScanFailedEvent {
    type: 'scan_failed';
    scan_id: string;
    error: string;
}

export interface ScanCancelledEvent {
    type: 'scan_cancelled';
    scan_id: string;
}

export interface StatusUpdateEvent {
    type: 'status_update';
    scan_id: string;
    status: ScanStatus;
    message: string;
}

// ============================================================================
// API RESPONSE TYPES
// ============================================================================

export interface ListScansResponse {
    scans: ScanSummary[];
    total: number;
}

export interface ScanSummary {
    id: string;
    status: ScanStatus;
    targets: string[];
    progress: number;
    created_at: string;
    duration?: number;
}

export interface ListHostsResponse {
    hosts: Host[];
    total: number;
}

export interface ListVulnerabilitiesResponse {
    vulnerabilities: Vulnerability[];
    total: number;
    by_severity: SeverityCounts;
}

// ============================================================================
// CLIENT MESSAGE TYPES (WebSocket Commands)
// ============================================================================

export type ClientMessage =
    | { type: 'subscribe'; scan_id: string }
    | { type: 'unsubscribe'; scan_id: string }
    | { type: 'subscribe_all' }
    | { type: 'pause_scan'; scan_id: string }
    | { type: 'resume_scan'; scan_id: string }
    | { type: 'cancel_scan'; scan_id: string }
    | { type: 'ping' };

export type ServerMessage =
    | { type: 'event'; payload: ScanEvent }
    | { type: 'subscribed'; scan_id?: string }
    | { type: 'unsubscribed'; scan_id: string }
    | { type: 'pong' }
    | { type: 'error'; message: string };

// ============================================================================
// UTILITY TYPES
// ============================================================================

export interface APIError {
    error: string;
    status: number;
    timestamp: string;
}

export interface HealthCheckResponse {
    status: 'ok' | 'degraded' | 'down';
    version: string;
    uptime: number;
}
