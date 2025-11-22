<script>
	import { createEventDispatcher } from 'svelte';
	import { Clock, RefreshCw, Eye, Trash2 } from 'lucide-svelte';

	export let scans = [];

	const dispatch = createEventDispatcher();

	let loading = false;

	async function handleRefresh() {
		loading = true;
		dispatch('refresh');
		setTimeout(() => (loading = false), 500);
	}

	async function viewScan(scanId) {
		// Future: emit event to view scan details
		console.log('View scan:', scanId);
	}

	async function deleteScan(scanId) {
		if (!confirm('Delete this scan?')) return;

		try {
			await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
			handleRefresh();
		} catch (error) {
			console.error('Delete failed:', error);
		}
	}

	function getScanTypeColor(type) {
		const colors = {
			port_scan: '#667eea',
			service_detect: '#764ba2',
			os_detect: '#f093fb',
			comprehensive: '#4facfe'
		};
		return colors[type] || '#718096';
	}
</script>

<div class="scan-history">
	<div class="history-header">
		<div>
			<h2>Scan History</h2>
			<p>{scans.length} recent scans from redb database</p>
		</div>
		<button on:click={handleRefresh} disabled={loading} class="refresh-btn">
			<RefreshCw size={18} class:spinning={loading} />
			Refresh
		</button>
	</div>

	{#if scans.length === 0}
		<div class="empty-state">
			<Clock size={48} />
			<h3>No scans yet</h3>
			<p>Launch a scan to see results here</p>
		</div>
	{:else}
		<div class="scans-list">
			{#each scans as scan}
				<div class="scan-card">
					<div class="scan-header">
						<div
							class="scan-type"
							style="background-color: {getScanTypeColor(scan.scan_type)}"
						>
							{scan.scan_type.replace('_', ' ')}
						</div>
						<div class="scan-actions">
							<button on:click={() => viewScan(scan.id)} title="View details">
								<Eye size={16} />
							</button>
							<button on:click={() => deleteScan(scan.id)} title="Delete scan">
								<Trash2 size={16} />
							</button>
						</div>
					</div>

					<div class="scan-info">
						<div class="info-row">
							<strong>Target:</strong>
							<span>{scan.target}</span>
						</div>
						<div class="info-row">
							<strong>Scan ID:</strong>
							<code>{scan.id}</code>
						</div>
						<div class="info-row">
							<strong>Timestamp:</strong>
							<span>{new Date(scan.timestamp).toLocaleString()}</span>
						</div>
					</div>

					{#if scan.summary}
						<div class="scan-summary">
							<h4>Summary</h4>
							<div class="summary-grid">
								{#each Object.entries(scan.summary) as [key, value]}
									<div class="summary-item">
										<span class="summary-label">{key}:</span>
										<span class="summary-value">{value}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.scan-history {
		background: white;
		border-radius: 12px;
		padding: 2rem;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
	}

	.history-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
	}

	.history-header h2 {
		margin: 0 0 0.5rem 0;
		color: #2d3748;
		font-size: 1.5rem;
	}

	.history-header p {
		margin: 0;
		color: #718096;
		font-size: 0.9rem;
	}

	.refresh-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1.5rem;
		background: #667eea;
		color: white;
		border: none;
		border-radius: 8px;
		cursor: pointer;
		font-weight: 600;
		transition: background 0.2s;
	}

	.refresh-btn:hover:not(:disabled) {
		background: #5a67d8;
	}

	.refresh-btn:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}

	:global(.spinning) {
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		from {
			transform: rotate(0deg);
		}
		to {
			transform: rotate(360deg);
		}
	}

	.empty-state {
		text-align: center;
		padding: 4rem 2rem;
		color: #a0aec0;
	}

	.empty-state h3 {
		margin: 1rem 0 0.5rem 0;
		color: #4a5568;
	}

	.empty-state p {
		margin: 0;
	}

	.scans-list {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.scan-card {
		background: #f7fafc;
		border: 1px solid #e2e8f0;
		border-radius: 8px;
		padding: 1.5rem;
		transition: transform 0.2s, box-shadow 0.2s;
	}

	.scan-card:hover {
		transform: translateY(-2px);
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
	}

	.scan-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.scan-type {
		display: inline-block;
		padding: 0.5rem 1rem;
		border-radius: 20px;
		color: white;
		font-size: 0.85rem;
		font-weight: 600;
		text-transform: capitalize;
	}

	.scan-actions {
		display: flex;
		gap: 0.5rem;
	}

	.scan-actions button {
		padding: 0.5rem;
		background: white;
		border: 1px solid #e2e8f0;
		border-radius: 6px;
		cursor: pointer;
		color: #718096;
		transition: all 0.2s;
	}

	.scan-actions button:hover {
		background: #edf2f7;
		color: #2d3748;
	}

	.scan-info {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.info-row {
		display: flex;
		gap: 0.5rem;
		align-items: baseline;
	}

	.info-row strong {
		color: #4a5568;
		font-size: 0.9rem;
		min-width: 100px;
	}

	.info-row span {
		color: #2d3748;
	}

	.info-row code {
		background: #edf2f7;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.8rem;
		font-family: 'Courier New', monospace;
		color: #667eea;
	}

	.scan-summary {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px solid #e2e8f0;
	}

	.scan-summary h4 {
		margin: 0 0 0.75rem 0;
		color: #2d3748;
		font-size: 1rem;
	}

	.summary-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
		gap: 0.75rem;
	}

	.summary-item {
		background: white;
		padding: 0.75rem;
		border-radius: 6px;
	}

	.summary-label {
		display: block;
		color: #718096;
		font-size: 0.8rem;
		margin-bottom: 0.25rem;
		text-transform: capitalize;
	}

	.summary-value {
		display: block;
		color: #2d3748;
		font-weight: 600;
	}
</style>
