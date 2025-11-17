/**
 * R-Map API Client Library
 * Provides methods to interact with the R-Map REST API
 */

const axios = require('axios');
const WebSocket = require('ws');

class RMapClient {
    constructor(baseUrl = 'http://localhost:8080') {
        this.baseUrl = baseUrl;
        this.wsUrl = baseUrl.replace('http', 'ws');
        this.client = axios.create({
            baseURL: this.baseUrl,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }

    /**
     * Create a new scan
     * @param {Array<string>} targets - Target IPs, CIDRs, or hostnames
     * @param {Object} options - Scan options
     * @returns {Promise<Object>} Scan creation response
     */
    async createScan(targets, options = {}) {
        const response = await this.client.post('/api/v1/scans', {
            targets,
            options: {
                scan_type: options.scanType || 'stealth',
                ports: options.ports || '1-1000',
                timing: options.timing || 3,
                scripts: options.scripts || [],
                service_detection: options.serviceDetection || false,
                os_detection: options.osDetection || false,
                skip_ping: options.skipPing || false,
                max_retries: options.maxRetries || 2,
                timeout: options.timeout || 300
            }
        });
        return response.data;
    }

    /**
     * Get scan status
     * @param {string} scanId - Scan UUID
     * @returns {Promise<Object>} Scan details
     */
    async getScan(scanId) {
        const response = await this.client.get(`/api/v1/scans/${scanId}`);
        return response.data;
    }

    /**
     * List all scans
     * @returns {Promise<Object>} List of scans
     */
    async listScans() {
        const response = await this.client.get('/api/v1/scans');
        return response.data;
    }

    /**
     * Cancel a running scan
     * @param {string} scanId - Scan UUID
     * @returns {Promise<void>}
     */
    async cancelScan(scanId) {
        await this.client.delete(`/api/v1/scans/${scanId}`);
    }

    /**
     * Start a pending scan
     * @param {string} scanId - Scan UUID
     * @returns {Promise<void>}
     */
    async startScan(scanId) {
        await this.client.post(`/api/v1/scans/${scanId}/start`);
    }

    /**
     * Get hosts discovered in a scan
     * @param {string} scanId - Scan UUID
     * @returns {Promise<Object>} List of hosts
     */
    async getScanHosts(scanId) {
        const response = await this.client.get(`/api/v1/scans/${scanId}/hosts`);
        return response.data;
    }

    /**
     * Get vulnerabilities found in a scan
     * @param {string} scanId - Scan UUID
     * @returns {Promise<Object>} List of vulnerabilities
     */
    async getScanVulnerabilities(scanId) {
        const response = await this.client.get(`/api/v1/scans/${scanId}/vulnerabilities`);
        return response.data;
    }

    /**
     * Connect to WebSocket for real-time events
     * @param {Function} onEvent - Callback for events
     * @param {Function} onError - Callback for errors
     * @returns {WebSocket} WebSocket connection
     */
    connectWebSocket(onEvent, onError) {
        const ws = new WebSocket(`${this.wsUrl}/ws`);

        ws.on('open', () => {
            console.log('WebSocket connected to R-Map API');
        });

        ws.on('message', (data) => {
            try {
                const event = JSON.parse(data);
                if (onEvent) onEvent(event);
            } catch (error) {
                if (onError) onError(error);
            }
        });

        ws.on('error', (error) => {
            if (onError) onError(error);
        });

        ws.on('close', () => {
            console.log('WebSocket disconnected from R-Map API');
        });

        return ws;
    }

    /**
     * Subscribe to scan events via WebSocket
     * @param {WebSocket} ws - WebSocket connection
     * @param {string} scanId - Scan UUID (optional, subscribes to all if not provided)
     */
    subscribeToScan(ws, scanId = null) {
        const message = scanId
            ? { type: 'subscribe', scan_id: scanId }
            : { type: 'subscribe_all' };

        ws.send(JSON.stringify(message));
    }
}

module.exports = RMapClient;
