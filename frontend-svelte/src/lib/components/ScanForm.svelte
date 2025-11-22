<script>
	import { createEventDispatcher } from 'svelte';
	import { PlayCircle, Loader2 } from 'lucide-svelte';

	const dispatch = createEventDispatcher();

	let scanType = 'port_scan';
	let target = '';
	let ports = 'top-100';
	let scanMethod = 'syn';
	let timing = 'normal';
	let scanProfile = 'standard';
	let loading = false;
	let error = null;

	async function handleSubmit() {
		if (!target.trim()) {
			error = 'Target is required';
			return;
		}

		loading = true;
		error = null;

		try {
			const endpoint = `/api/scans/${scanType}`;
			const body = {
				target: target.trim(),
				...(scanType === 'port_scan' && { ports, scan_type: scanMethod, timing }),
				...(scanType === 'service_detect' && { ports, intensity: 7 }),
				...(scanType === 'os_detect' && { method: 'all', intensity: 7 }),
				...(scanType === 'comprehensive' && { scan_profile: scanProfile, timing })
			};

			const response = await fetch(endpoint, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});

			if (!response.ok) {
				throw new Error(await response.text());
			}

			const result = await response.json();
			dispatch('scanComplete', result);
		} catch (err) {
			error = err.message || 'Scan failed';
		} finally {
			loading = false;
		}
	}
</script>

<div class="scan-form">
	<div class="form-header">
		<h2>Launch Network Scan</h2>
		<p>Configure and execute network reconnaissance scans</p>
	</div>

	<form on:submit|preventDefault={handleSubmit}>
		<div class="form-group">
			<label for="scanType">Scan Type</label>
			<select id="scanType" bind:value={scanType} disabled={loading}>
				<option value="port_scan">Port Scan</option>
				<option value="service_detect">Service Detection</option>
				<option value="os_detect">OS Fingerprinting</option>
				<option value="comprehensive">Comprehensive Scan</option>
			</select>
		</div>

		<div class="form-group">
			<label for="target">Target *</label>
			<input
				id="target"
				type="text"
				bind:value={target}
				placeholder="192.168.1.1, example.com, or 10.0.0.0/24"
				disabled={loading}
				required
			/>
			<span class="help-text">IP address, hostname, or CIDR range</span>
		</div>

		{#if scanType === 'port_scan'}
			<div class="form-row">
				<div class="form-group">
					<label for="ports">Ports</label>
					<input id="ports" type="text" bind:value={ports} disabled={loading} />
					<span class="help-text">e.g., "80,443", "1-1000", "top-100"</span>
				</div>

				<div class="form-group">
					<label for="scanMethod">Method</label>
					<select id="scanMethod" bind:value={scanMethod} disabled={loading}>
						<option value="syn">SYN (stealth)</option>
						<option value="connect">Connect</option>
						<option value="udp">UDP</option>
						<option value="ack">ACK</option>
						<option value="fin">FIN</option>
					</select>
				</div>

				<div class="form-group">
					<label for="timing">Timing</label>
					<select id="timing" bind:value={timing} disabled={loading}>
						<option value="paranoid">Paranoid</option>
						<option value="sneaky">Sneaky</option>
						<option value="polite">Polite</option>
						<option value="normal">Normal</option>
						<option value="aggressive">Aggressive</option>
						<option value="insane">Insane</option>
					</select>
				</div>
			</div>
		{:else if scanType === 'service_detect'}
			<div class="form-group">
				<label for="servicePorts">Ports to Probe</label>
				<input id="servicePorts" type="text" bind:value={ports} disabled={loading} />
				<span class="help-text">411+ service signatures available</span>
			</div>
		{:else if scanType === 'os_detect'}
			<div class="info-box">
				<p><strong>OS Detection Methods:</strong></p>
				<ul>
					<li>Active fingerprinting (TCP/IP stack)</li>
					<li>Passive fingerprinting (traffic analysis)</li>
					<li>Application-layer detection</li>
					<li>Bayesian fusion (139+ signatures)</li>
				</ul>
			</div>
		{:else if scanType === 'comprehensive'}
			<div class="form-group">
				<label for="scanProfile">Scan Profile</label>
				<select id="scanProfile" bind:value={scanProfile} disabled={loading}>
					<option value="quick">Quick (top 100 ports)</option>
					<option value="standard">Standard (top 1000 ports)</option>
					<option value="thorough">Thorough (all 65535 ports)</option>
				</select>
			</div>

			<div class="form-group">
				<label for="timing">Timing</label>
				<select id="timing" bind:value={timing} disabled={loading}>
					<option value="normal">Normal</option>
					<option value="aggressive">Aggressive</option>
					<option value="insane">Insane</option>
				</select>
			</div>
		{/if}

		{#if error}
			<div class="error-box">
				<strong>Error:</strong> {error}
			</div>
		{/if}

		<button type="submit" class="submit-btn" disabled={loading}>
			{#if loading}
				<Loader2 class="spinner" size={20} />
				Scanning...
			{:else}
				<PlayCircle size={20} />
				Launch Scan
			{/if}
		</button>
	</form>
</div>

<style>
	.scan-form {
		background: white;
		border-radius: 12px;
		padding: 2rem;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
	}

	.form-header {
		margin-bottom: 2rem;
	}

	.form-header h2 {
		margin: 0 0 0.5rem 0;
		color: #2d3748;
		font-size: 1.5rem;
	}

	.form-header p {
		margin: 0;
		color: #718096;
		font-size: 0.9rem;
	}

	form {
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}

	.form-row {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	label {
		font-weight: 600;
		color: #4a5568;
		font-size: 0.9rem;
	}

	input,
	select {
		padding: 0.75rem;
		border: 2px solid #e2e8f0;
		border-radius: 8px;
		font-size: 1rem;
		transition: border-color 0.2s;
	}

	input:focus,
	select:focus {
		outline: none;
		border-color: #667eea;
	}

	input:disabled,
	select:disabled {
		background: #f7fafc;
		cursor: not-allowed;
	}

	.help-text {
		font-size: 0.8rem;
		color: #a0aec0;
	}

	.info-box {
		background: #edf2f7;
		border-left: 4px solid #667eea;
		padding: 1rem;
		border-radius: 4px;
	}

	.info-box p {
		margin: 0 0 0.5rem 0;
		color: #4a5568;
	}

	.info-box ul {
		margin: 0;
		padding-left: 1.5rem;
		color: #718096;
	}

	.error-box {
		background: #fed7d7;
		border: 1px solid #fc8181;
		color: #742a2a;
		padding: 1rem;
		border-radius: 8px;
	}

	.submit-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		padding: 1rem 2rem;
		background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
		color: white;
		border: none;
		border-radius: 8px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: transform 0.2s, box-shadow 0.2s;
	}

	.submit-btn:hover:not(:disabled) {
		transform: translateY(-2px);
		box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
	}

	.submit-btn:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}

	:global(.spinner) {
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
</style>
