<script>
	import { Download, CheckCircle, AlertCircle } from 'lucide-svelte';

	export let data;

	let exportFormat = 'json';
	let exporting = false;

	async function handleExport() {
		if (!data?.id) return;

		exporting = true;
		try {
			const response = await fetch(`/api/scans/export`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					scan_id: data.id,
					format: exportFormat
				})
			});

			if (!response.ok) throw new Error('Export failed');

			const blob = await response.blob();
			const url = window.URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `scan_${data.id}.${exportFormat}`;
			a.click();
			window.URL.revokeObjectURL(url);
		} catch (error) {
			console.error('Export failed:', error);
		} finally {
			exporting = false;
		}
	}
</script>

<div class="scan-results">
	<div class="results-header">
		<div>
			<h2>Scan Results</h2>
			{#if data?.status === 'completed'}
				<div class="status-badge success">
					<CheckCircle size={16} />
					Completed
				</div>
			{:else}
				<div class="status-badge warning">
					<AlertCircle size={16} />
					{data?.status || 'Unknown'}
				</div>
			{/if}
		</div>

		<div class="export-controls">
			<select bind:value={exportFormat} disabled={exporting}>
				<option value="json">JSON</option>
				<option value="xml">XML</option>
				<option value="html">HTML</option>
				<option value="markdown">Markdown</option>
			</select>
			<button on:click={handleExport} disabled={exporting}>
				<Download size={18} />
				{exporting ? 'Exporting...' : 'Export'}
			</button>
		</div>
	</div>

	<div class="metadata">
		<div class="meta-item">
			<strong>Scan ID:</strong>
			<code>{data?.id || 'N/A'}</code>
		</div>
		<div class="meta-item">
			<strong>Target:</strong>
			<span>{data?.target || 'N/A'}</span>
		</div>
		<div class="meta-item">
			<strong>Type:</strong>
			<span>{data?.scan_type || 'N/A'}</span>
		</div>
		<div class="meta-item">
			<strong>Timestamp:</strong>
			<span>{data?.timestamp ? new Date(data.timestamp).toLocaleString() : 'N/A'}</span>
		</div>
	</div>

	<div class="results-content">
		<h3>Scan Output</h3>
		<div class="results-data">
			<pre>{JSON.stringify(data?.results || data, null, 2)}</pre>
		</div>
	</div>

	{#if data?.results?.open_ports && data.results.open_ports.length > 0}
		<div class="ports-section">
			<h3>Open Ports ({data.results.open_ports.length})</h3>
			<div class="ports-grid">
				{#each data.results.open_ports as port}
					<div class="port-card">
						<div class="port-number">{port.port}</div>
						<div class="port-protocol">{port.protocol || 'TCP'}</div>
						{#if port.service}
							<div class="port-service">{port.service}</div>
						{/if}
					</div>
				{/each}
			</div>
		</div>
	{/if}

	{#if data?.performance}
		<div class="performance-section">
			<h3>Performance Metrics</h3>
			<div class="perf-grid">
				{#each Object.entries(data.performance) as [key, value]}
					<div class="perf-item">
						<span class="perf-label">{key.replace(/_/g, ' ')}:</span>
						<span class="perf-value">{value}</span>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</div>

<style>
	.scan-results {
		background: white;
		border-radius: 12px;
		padding: 2rem;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
	}

	.results-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
		flex-wrap: wrap;
		gap: 1rem;
	}

	.results-header h2 {
		margin: 0 0 0.5rem 0;
		color: #2d3748;
		font-size: 1.5rem;
	}

	.status-badge {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		border-radius: 20px;
		font-size: 0.9rem;
		font-weight: 600;
	}

	.status-badge.success {
		background: #c6f6d5;
		color: #22543d;
	}

	.status-badge.warning {
		background: #fed7aa;
		color: #7c2d12;
	}

	.export-controls {
		display: flex;
		gap: 0.5rem;
	}

	.export-controls select {
		padding: 0.5rem 1rem;
		border: 2px solid #e2e8f0;
		border-radius: 8px;
		font-size: 0.9rem;
	}

	.export-controls button {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		background: #667eea;
		color: white;
		border: none;
		border-radius: 8px;
		cursor: pointer;
		font-weight: 600;
		transition: background 0.2s;
	}

	.export-controls button:hover:not(:disabled) {
		background: #5a67d8;
	}

	.export-controls button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.metadata {
		background: #f7fafc;
		padding: 1.5rem;
		border-radius: 8px;
		margin-bottom: 2rem;
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
		gap: 1rem;
	}

	.meta-item {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.meta-item strong {
		color: #718096;
		font-size: 0.85rem;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.meta-item code {
		background: #edf2f7;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.85rem;
		font-family: 'Courier New', monospace;
		color: #667eea;
	}

	.results-content,
	.ports-section,
	.performance-section {
		margin-bottom: 2rem;
	}

	.results-content h3,
	.ports-section h3,
	.performance-section h3 {
		margin: 0 0 1rem 0;
		color: #2d3748;
		font-size: 1.2rem;
	}

	.results-data {
		background: #2d3748;
		color: #e2e8f0;
		padding: 1.5rem;
		border-radius: 8px;
		overflow-x: auto;
	}

	.results-data pre {
		margin: 0;
		font-family: 'Courier New', monospace;
		font-size: 0.85rem;
		line-height: 1.5;
	}

	.ports-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
		gap: 1rem;
	}

	.port-card {
		background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
		color: white;
		padding: 1rem;
		border-radius: 8px;
		text-align: center;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
	}

	.port-number {
		font-size: 1.5rem;
		font-weight: 700;
		margin-bottom: 0.25rem;
	}

	.port-protocol {
		font-size: 0.8rem;
		opacity: 0.9;
	}

	.port-service {
		margin-top: 0.5rem;
		font-size: 0.75rem;
		opacity: 0.8;
	}

	.perf-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
	}

	.perf-item {
		background: #f7fafc;
		padding: 1rem;
		border-radius: 8px;
		border-left: 4px solid #667eea;
	}

	.perf-label {
		display: block;
		color: #718096;
		font-size: 0.85rem;
		text-transform: capitalize;
		margin-bottom: 0.25rem;
	}

	.perf-value {
		display: block;
		color: #2d3748;
		font-size: 1.1rem;
		font-weight: 600;
	}
</style>
