# R-Map Svelte TypeScript Definitions

Type definitions for building Svelte frontends that consume the R-Map API.

## Installation

```bash
npm install --save-dev file:../R-map/svelte-types
```

## Usage

### In SvelteKit

```typescript
// src/lib/types.ts
export * from 'rmap';

// src/routes/+page.svelte
<script lang="ts">
    import type { Scan, Host, Vulnerability } from '$lib/types';

    let scans: Scan[] = [];
    let selectedScan: Scan | null = null;
</script>
```

### API Client Example

```typescript
// src/lib/api/rmap.ts
import type {
    CreateScanRequest,
    CreateScanResponse,
    Scan,
    ListScansResponse,
    ListHostsResponse,
    ListVulnerabilitiesResponse,
    ScanEvent
} from 'rmap';

const API_BASE = 'http://localhost:8080/api/v1';
const WS_BASE = 'ws://localhost:8080';

export class RMapAPI {
    async createScan(request: CreateScanRequest): Promise<CreateScanResponse> {
        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request)
        });
        return response.json();
    }

    async getScan(scanId: string): Promise<Scan> {
        const response = await fetch(`${API_BASE}/scans/${scanId}`);
        return response.json();
    }

    async listScans(): Promise<ListScansResponse> {
        const response = await fetch(`${API_BASE}/scans`);
        return response.json();
    }

    connectWebSocket(onEvent: (event: ScanEvent) => void): WebSocket {
        const ws = new WebSocket(`${WS_BASE}/ws`);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'event') {
                onEvent(data.payload);
            }
        };

        return ws;
    }
}
```

### Svelte Store Integration

```typescript
// src/lib/stores/scans.ts
import { writable, derived } from 'svelte/store';
import type { Scan, ScanEvent } from 'rmap';
import { RMapAPI } from '$lib/api/rmap';

export const scans = writable<Map<string, Scan>>(new Map());

export const activeScans = derived(scans, $scans =>
    Array.from($scans.values()).filter(s => s.status === 'running')
);

export const completedScans = derived(scans, $scans =>
    Array.from($scans.values()).filter(s => s.status === 'completed')
);

const api = new RMapAPI();
const ws = api.connectWebSocket((event: ScanEvent) => {
    switch (event.type) {
        case 'scan_progress':
            scans.update(map => {
                const scan = map.get(event.scan_id);
                if (scan) {
                    scan.progress = event.progress;
                    scan.stats = event.stats;
                    map.set(event.scan_id, scan);
                }
                return map;
            });
            break;

        case 'host_discovered':
            // Handle host discovery
            break;

        case 'vulnerability_found':
            // Handle vulnerability
            break;
    }
});
```

### Component Example

```svelte
<!-- src/routes/scans/[id]/+page.svelte -->
<script lang="ts">
    import { onMount } from 'svelte';
    import type { Scan, Host, Vulnerability } from 'rmap';
    import { RMapAPI } from '$lib/api/rmap';

    export let data;
    const api = new RMapAPI();

    let scan: Scan;
    let hosts: Host[] = [];
    let vulnerabilities: Vulnerability[] = [];

    onMount(async () => {
        scan = await api.getScan(data.scanId);
        const hostsResponse = await api.getScanHosts(data.scanId);
        const vulnsResponse = await api.getScanVulnerabilities(data.scanId);

        hosts = hostsResponse.hosts;
        vulnerabilities = vulnsResponse.vulnerabilities;
    });
</script>

<div class="scan-details">
    {#if scan}
        <h1>Scan: {scan.targets.join(', ')}</h1>
        <p>Status: {scan.status}</p>
        <p>Progress: {scan.progress.toFixed(1)}%</p>

        <div class="stats">
            <span>Hosts Up: {scan.stats.hosts_up}</span>
            <span>Ports Open: {scan.stats.ports_open}</span>
            <span>Vulnerabilities: {scan.stats.vulnerabilities}</span>
        </div>

        <h2>Hosts</h2>
        {#each hosts as host}
            <div class="host-card">
                <h3>{host.ip} {#if host.hostname}({host.hostname}){/if}</h3>
                <p>State: {host.state}</p>
                <p>Open Ports: {host.ports.filter(p => p.state === 'open').length}</p>
            </div>
        {/each}

        <h2>Vulnerabilities</h2>
        {#each vulnerabilities as vuln}
            <div class="vuln-card severity-{vuln.severity}">
                <h3>{vuln.name}</h3>
                <p>{vuln.description}</p>
                <p>Severity: {vuln.severity}</p>
                {#if vuln.cve}<p>CVE: {vuln.cve}</p>{/if}
            </div>
        {/each}
    {/if}
</div>
```

## Type Reference

See `rmap.d.ts` for complete type definitions including:

- `Scan`, `ScanOptions`, `ScanStats`
- `Host`, `Port`, `OSInfo`
- `Vulnerability`, `Severity`
- `ScanEvent` (WebSocket events)
- API request/response types

## License

MIT
