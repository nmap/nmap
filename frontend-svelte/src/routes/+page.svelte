<script>
	import { onMount } from 'svelte';
	import ScanForm from '$lib/components/ScanForm.svelte';
	import ScanResults from '$lib/components/ScanResults.svelte';
	import ScanHistory from '$lib/components/ScanHistory.svelte';
	import { Activity, Database, Network, Shield, Zap } from 'lucide-svelte';

	let activeTab = 'scan';
	let scanResults = null;
	let scanHistory = [];
	let stats = {
		totalScans: 0,
		signatures: {
			services: 411,
			os: 139
		},
		performance: '10,000-15,000 ports/sec'
	};

	onMount(async () => {
		// Load initial stats and history
		await loadStats();
		await loadHistory();
	});

	async function loadStats() {
		try {
			const response = await fetch('/api/stats');
			if (response.ok) {
				const data = await response.json();
				stats = { ...stats, ...data };
			}
		} catch (error) {
			console.error('Failed to load stats:', error);
		}
	}

	async function loadHistory() {
		try {
			const response = await fetch('/api/scans/history?limit=10');
			if (response.ok) {
				scanHistory = await response.json();
			}
		} catch (error) {
			console.error('Failed to load history:', error);
		}
	}

	function handleScanComplete(event) {
		scanResults = event.detail;
		activeTab = 'results';
		loadHistory(); // Refresh history
	}
</script>

<svelte:head>
	<title>R-Map - Network Reconnaissance</title>
</svelte:head>

<div class="app">
	<header>
		<div class="header-content">
			<div class="logo">
				<Shield size={32} />
				<h1>R-Map</h1>
				<span class="version">v1.0</span>
			</div>
			<div class="stats">
				<div class="stat">
					<Database size={18} />
					<span>{stats.totalScans} scans</span>
				</div>
				<div class="stat">
					<Activity size={18} />
					<span>{stats.signatures.services}+ services</span>
				</div>
				<div class="stat">
					<Network size={18} />
					<span>{stats.signatures.os}+ OS</span>
				</div>
				<div class="stat">
					<Zap size={18} />
					<span>{stats.performance}</span>
				</div>
			</div>
		</div>
	</header>

	<nav>
		<button class:active={activeTab === 'scan'} on:click={() => (activeTab = 'scan')}>
			<Zap size={20} />
			New Scan
		</button>
		<button class:active={activeTab === 'results'} on:click={() => (activeTab = 'results')} disabled={!scanResults}>
			<Activity size={20} />
			Results
		</button>
		<button class:active={activeTab === 'history'} on:click={() => (activeTab = 'history')}>
			<Database size={20} />
			History
		</button>
	</nav>

	<main>
		{#if activeTab === 'scan'}
			<ScanForm on:scanComplete={handleScanComplete} />
		{:else if activeTab === 'results' && scanResults}
			<ScanResults data={scanResults} />
		{:else if activeTab === 'history'}
			<ScanHistory scans={scanHistory} on:refresh={loadHistory} />
		{/if}
	</main>

	<footer>
		<p>
			R-Map v1.0 - Network Reconnaissance
			<span class="separator">|</span>
			Rust + redb + Svelte
			<span class="separator">|</span>
			<a href="https://github.com/Ununp3ntium115/R-map" target="_blank">GitHub</a>
		</p>
	</footer>
</div>

<style>
	:global(body) {
		margin: 0;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell,
			sans-serif;
		background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
		min-height: 100vh;
	}

	.app {
		display: flex;
		flex-direction: column;
		min-height: 100vh;
	}

	header {
		background: rgba(255, 255, 255, 0.95);
		backdrop-filter: blur(10px);
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
		padding: 1.5rem 2rem;
	}

	.header-content {
		max-width: 1400px;
		margin: 0 auto;
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.logo {
		display: flex;
		align-items: center;
		gap: 1rem;
		color: #667eea;
	}

	.logo h1 {
		margin: 0;
		font-size: 1.8rem;
		font-weight: 700;
	}

	.version {
		background: #667eea;
		color: white;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 600;
	}

	.stats {
		display: flex;
		gap: 2rem;
	}

	.stat {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		color: #4a5568;
		font-size: 0.9rem;
	}

	nav {
		background: rgba(255, 255, 255, 0.9);
		padding: 1rem 2rem;
		display: flex;
		gap: 1rem;
		max-width: 1400px;
		margin: 1rem auto;
		border-radius: 12px;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
	}

	nav button {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1.5rem;
		border: none;
		background: transparent;
		color: #4a5568;
		cursor: pointer;
		border-radius: 8px;
		font-size: 1rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	nav button:hover:not(:disabled) {
		background: rgba(102, 126, 234, 0.1);
		color: #667eea;
	}

	nav button.active {
		background: #667eea;
		color: white;
	}

	nav button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	main {
		flex: 1;
		padding: 0 2rem 2rem;
		max-width: 1400px;
		width: 100%;
		margin: 0 auto;
	}

	footer {
		background: rgba(255, 255, 255, 0.9);
		padding: 1.5rem 2rem;
		text-align: center;
		color: #4a5568;
		font-size: 0.9rem;
	}

	footer p {
		margin: 0;
	}

	.separator {
		margin: 0 1rem;
		color: #cbd5e0;
	}

	footer a {
		color: #667eea;
		text-decoration: none;
		font-weight: 600;
	}

	footer a:hover {
		text-decoration: underline;
	}
</style>
