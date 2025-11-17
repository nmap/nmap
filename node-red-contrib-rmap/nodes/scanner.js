/**
 * R-Map Scanner Node for Node-RED
 * Executes network scans on specified targets
 */

const RMapClient = require('../lib/rmap-client');

module.exports = function(RED) {
    function ScannerNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        // Get R-Map API URL from settings or use default
        const apiUrl = RED.settings.rmapApiUrl || 'http://localhost:8080';
        const client = new RMapClient(apiUrl);

        node.on('input', async function(msg) {
            try {
                // Extract scan parameters from msg or config
                const targets = msg.targets || [config.target];
                const options = {
                    scanType: msg.scanType || config.scanType || 'stealth',
                    ports: msg.ports || config.ports || '1-1000',
                    timing: msg.timing !== undefined ? msg.timing : (config.timing || 3),
                    scripts: msg.scripts || config.scripts || [],
                    serviceDetection: msg.serviceDetection !== undefined ? msg.serviceDetection : (config.serviceDetection || false),
                    osDetection: msg.osDetection !== undefined ? msg.osDetection : (config.osDetection || false),
                    skipPing: msg.skipPing !== undefined ? msg.skipPing : (config.skipPing || false)
                };

                node.status({ fill: 'blue', shape: 'dot', text: 'creating scan...' });

                // Create the scan
                const scanResponse = await client.createScan(targets, options);
                const scanId = scanResponse.scan_id;

                node.log(`Created scan: ${scanId}`);
                node.status({ fill: 'yellow', shape: 'ring', text: 'starting scan...' });

                // Start the scan
                await client.startScan(scanId);

                // Poll for completion or use WebSocket for real-time updates
                if (config.useWebSocket) {
                    // WebSocket mode - real-time updates
                    const ws = client.connectWebSocket(
                        (event) => {
                            handleScanEvent(node, event, scanId);
                        },
                        (error) => {
                            node.error(`WebSocket error: ${error.message}`);
                        }
                    );

                    // Subscribe to this scan's events
                    client.subscribeToScan(ws, scanId);

                    // Store WebSocket for cleanup
                    node.ws = ws;
                } else {
                    // Polling mode - check status periodically
                    const pollInterval = setInterval(async () => {
                        try {
                            const scan = await client.getScan(scanId);

                            node.status({
                                fill: 'yellow',
                                shape: 'dot',
                                text: `scanning... ${scan.progress.toFixed(1)}%`
                            });

                            if (scan.status === 'completed') {
                                clearInterval(pollInterval);
                                await handleScanComplete(node, client, scanId);
                            } else if (scan.status === 'failed') {
                                clearInterval(pollInterval);
                                node.status({ fill: 'red', shape: 'ring', text: 'scan failed' });
                                node.send([null, { payload: scan.error, scanId }]);
                            }
                        } catch (error) {
                            clearInterval(pollInterval);
                            node.error(`Polling error: ${error.message}`);
                            node.send([null, { payload: error.message, scanId }]);
                        }
                    }, 2000); // Poll every 2 seconds

                    // Store interval for cleanup
                    node.pollInterval = pollInterval;
                }

            } catch (error) {
                node.status({ fill: 'red', shape: 'ring', text: 'error' });
                node.error(`Scanner error: ${error.message}`, msg);
                node.send([null, { payload: error.message }]);
            }
        });

        node.on('close', function() {
            // Cleanup
            if (node.ws) {
                node.ws.close();
            }
            if (node.pollInterval) {
                clearInterval(node.pollInterval);
            }
        });
    }

    /**
     * Handle scan events from WebSocket
     */
    function handleScanEvent(node, event, scanId) {
        if (!event.Event) return;

        const scanEvent = event.Event;
        const eventScanId = scanEvent.scan_id;

        // Only process events for our scan
        if (eventScanId !== scanId) return;

        switch (scanEvent.type) {
            case 'scan_progress':
                node.status({
                    fill: 'yellow',
                    shape: 'dot',
                    text: `scanning... ${scanEvent.progress.toFixed(1)}%`
                });
                break;

            case 'scan_completed':
                node.status({ fill: 'green', shape: 'dot', text: 'completed' });
                handleScanComplete(node, new RMapClient(), scanId);
                if (node.ws) node.ws.close();
                break;

            case 'scan_failed':
                node.status({ fill: 'red', shape: 'ring', text: 'failed' });
                node.send([null, { payload: scanEvent.error, scanId }]);
                if (node.ws) node.ws.close();
                break;

            case 'vulnerability_found':
                // Optionally emit vulnerabilities as they're found
                if (node.config.emitRealtime) {
                    node.send([{ payload: scanEvent.vulnerability, scanId }, null]);
                }
                break;
        }
    }

    /**
     * Handle scan completion - fetch results and send
     */
    async function handleScanComplete(node, client, scanId) {
        try {
            const [scan, hosts, vulnerabilities] = await Promise.all([
                client.getScan(scanId),
                client.getScanHosts(scanId),
                client.getScanVulnerabilities(scanId)
            ]);

            node.status({ fill: 'green', shape: 'dot', text: 'completed' });

            // Send results to first output
            node.send([{
                payload: {
                    scan,
                    hosts: hosts.hosts,
                    vulnerabilities: vulnerabilities.vulnerabilities,
                    stats: scan.stats
                },
                scanId
            }, null]);

        } catch (error) {
            node.error(`Failed to fetch results: ${error.message}`);
            node.send([null, { payload: error.message, scanId }]);
        }
    }

    RED.nodes.registerType('rmap-scanner', ScannerNode);
};
