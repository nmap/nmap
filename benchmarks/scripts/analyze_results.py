#!/usr/bin/env python3
"""
R-Map Benchmark Results Analyzer
Performs statistical analysis and generates comparison reports
"""

import json
import sys
import statistics
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class BenchmarkStats:
    """Statistical summary of benchmark results"""
    median: float
    mean: float
    std_dev: float
    min: float
    max: float
    p95: float
    p99: float

def calculate_stats(values: List[float]) -> BenchmarkStats:
    """Calculate statistical measures from a list of values"""
    if not values:
        return BenchmarkStats(0, 0, 0, 0, 0, 0, 0)
    
    sorted_values = sorted(values)
    n = len(sorted_values)
    
    return BenchmarkStats(
        median=statistics.median(sorted_values),
        mean=statistics.mean(sorted_values),
        std_dev=statistics.stdev(sorted_values) if n > 1 else 0,
        min=min(sorted_values),
        max=max(sorted_values),
        p95=sorted_values[int(n * 0.95)] if n > 1 else sorted_values[0],
        p99=sorted_values[int(n * 0.99)] if n > 1 else sorted_values[0]
    )

def parse_time(time_str: str) -> float:
    """Parse time string (MM:SS.ss or SS.ss) to seconds"""
    try:
        if ':' in time_str:
            parts = time_str.split(':')
            return float(parts[0]) * 60 + float(parts[1])
        else:
            return float(time_str)
    except:
        return 0.0

def analyze_scenario(scenario: Dict) -> Dict:
    """Analyze a single benchmark scenario"""
    # Parse times
    nmap_times = [parse_time(str(t)) for t in scenario['nmap_times'] if t]
    rmap_times = [parse_time(str(t)) for t in scenario['rmap_times'] if t]
    
    # Calculate stats
    nmap_stats = calculate_stats(nmap_times)
    rmap_stats = calculate_stats(rmap_times)
    
    # Memory stats
    nmap_mem = calculate_stats([float(m) for m in scenario['nmap_memory_kb'] if m])
    rmap_mem = calculate_stats([float(m) for m in scenario['rmap_memory_kb'] if m])
    
    # CPU stats
    nmap_cpu = calculate_stats([float(c) for c in scenario['nmap_cpu_percent'] if c])
    rmap_cpu = calculate_stats([float(c) for c in scenario['rmap_cpu_percent'] if c])
    
    # Calculate differences
    time_diff_pct = ((rmap_stats.median - nmap_stats.median) / nmap_stats.median * 100) if nmap_stats.median > 0 else 0
    mem_diff_pct = ((rmap_mem.median - nmap_mem.median) / nmap_mem.median * 100) if nmap_mem.median > 0 else 0
    cpu_diff_pct = ((rmap_cpu.median - nmap_cpu.median) / nmap_cpu.median * 100) if nmap_cpu.median > 0 else 0
    
    # Determine pass/fail (within 20% for time and memory)
    time_pass = abs(time_diff_pct) <= 20
    mem_pass = abs(mem_diff_pct) <= 20
    
    return {
        'scenario_id': scenario['scenario_id'],
        'scenario_name': scenario['scenario_name'],
        'nmap': {
            'time': nmap_stats,
            'memory_kb': nmap_mem,
            'cpu_percent': nmap_cpu
        },
        'rmap': {
            'time': rmap_stats,
            'memory_kb': rmap_mem,
            'cpu_percent': rmap_cpu
        },
        'differences': {
            'time_pct': time_diff_pct,
            'memory_pct': mem_diff_pct,
            'cpu_pct': cpu_diff_pct
        },
        'pass': time_pass and mem_pass,
        'time_pass': time_pass,
        'mem_pass': mem_pass
    }

def generate_markdown_report(results: Dict, analyses: List[Dict], output_path: Path):
    """Generate a Markdown report"""
    
    report = []
    report.append("# R-Map vs nmap Performance Benchmark Report\n")
    report.append(f"**Generated:** {results['benchmark_metadata']['timestamp']}\n")
    report.append(f"**R-Map Version:** {results['benchmark_metadata']['rmap_version']}\n")
    report.append(f"**nmap Version:** {results['benchmark_metadata']['nmap_version']}\n")
    report.append(f"**System:** {results['benchmark_metadata']['hostname']} ({results['benchmark_metadata']['cpu_count']} CPUs)\n")
    report.append("\n---\n\n")
    
    # Executive Summary
    total_scenarios = len(analyses)
    passed_scenarios = sum(1 for a in analyses if a['pass'])
    pass_rate = (passed_scenarios / total_scenarios * 100) if total_scenarios > 0 else 0
    
    report.append("## Executive Summary\n\n")
    report.append(f"- **Total Scenarios:** {total_scenarios}\n")
    report.append(f"- **Passed:** {passed_scenarios}/{total_scenarios} ({pass_rate:.1f}%)\n")
    report.append(f"- **Overall Status:** {'✅ PASS' if pass_rate >= 80 else '❌ FAIL'}\n\n")
    
    # Calculate average performance difference
    avg_time_diff = statistics.mean([a['differences']['time_pct'] for a in analyses])
    avg_mem_diff = statistics.mean([a['differences']['memory_pct'] for a in analyses])
    
    report.append("### Key Findings\n\n")
    report.append(f"- **Average Speed Difference:** {avg_time_diff:+.1f}% (negative is better)\n")
    report.append(f"- **Average Memory Difference:** {avg_mem_diff:+.1f}% (negative is better)\n")
    report.append("\n---\n\n")
    
    # Detailed Results
    report.append("## Detailed Results\n\n")
    
    for analysis in analyses:
        report.append(f"### {analysis['scenario_id']}: {analysis['scenario_name']}\n\n")
        
        status = "✅ PASS" if analysis['pass'] else "❌ FAIL"
        report.append(f"**Status:** {status}\n\n")
        
        # Performance Table
        report.append("| Metric | R-Map | nmap | Difference | Status |\n")
        report.append("|--------|-------|------|------------|--------|\n")
        
        # Time
        time_status = "✅" if analysis['time_pass'] else "❌"
        report.append(f"| **Median Time** | {analysis['rmap']['time'].median:.2f}s | "
                     f"{analysis['nmap']['time'].median:.2f}s | "
                     f"{analysis['differences']['time_pct']:+.1f}% | {time_status} |\n")
        
        # P95 Time
        report.append(f"| **P95 Time** | {analysis['rmap']['time'].p95:.2f}s | "
                     f"{analysis['nmap']['time'].p95:.2f}s | "
                     f"- | - |\n")
        
        # Memory
        mem_status = "✅" if analysis['mem_pass'] else "❌"
        rmap_mem_mb = analysis['rmap']['memory_kb'].median / 1024
        nmap_mem_mb = analysis['nmap']['memory_kb'].median / 1024
        report.append(f"| **Peak Memory** | {rmap_mem_mb:.1f} MB | "
                     f"{nmap_mem_mb:.1f} MB | "
                     f"{analysis['differences']['memory_pct']:+.1f}% | {mem_status} |\n")
        
        # CPU
        report.append(f"| **CPU Usage** | {analysis['rmap']['cpu_percent'].median:.1f}% | "
                     f"{analysis['nmap']['cpu_percent'].median:.1f}% | "
                     f"{analysis['differences']['cpu_pct']:+.1f}% | - |\n")
        
        report.append("\n")
    
    # Recommendations
    report.append("---\n\n")
    report.append("## Recommendations\n\n")
    
    failed_scenarios = [a for a in analyses if not a['pass']]
    if failed_scenarios:
        report.append("### Performance Issues Detected\n\n")
        for scenario in failed_scenarios:
            report.append(f"- **{scenario['scenario_id']}**: ")
            if not scenario['time_pass']:
                report.append(f"Speed regression ({scenario['differences']['time_pct']:+.1f}%) ")
            if not scenario['mem_pass']:
                report.append(f"Memory regression ({scenario['differences']['memory_pct']:+.1f}%) ")
            report.append("\n")
        report.append("\n")
    else:
        report.append("✅ All scenarios passed! R-Map performance is competitive with nmap.\n\n")
    
    # Write report
    with open(output_path, 'w') as f:
        f.write(''.join(report))
    
    print(f"\n✅ Markdown report generated: {output_path}")

def generate_console_summary(analyses: List[Dict]):
    """Print a summary to the console"""
    print("\n" + "="*70)
    print(" BENCHMARK SUMMARY")
    print("="*70 + "\n")
    
    for analysis in analyses:
        status_icon = "✅" if analysis['pass'] else "❌"
        print(f"{status_icon} {analysis['scenario_id']}: {analysis['scenario_name']}")
        print(f"   Time:   nmap={analysis['nmap']['time'].median:.2f}s, "
              f"rmap={analysis['rmap']['time'].median:.2f}s "
              f"({analysis['differences']['time_pct']:+.1f}%)")
        print(f"   Memory: nmap={analysis['nmap']['memory_kb'].median/1024:.1f}MB, "
              f"rmap={analysis['rmap']['memory_kb'].median/1024:.1f}MB "
              f"({analysis['differences']['memory_pct']:+.1f}%)")
        print()
    
    # Overall summary
    total = len(analyses)
    passed = sum(1 for a in analyses if a['pass'])
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    print("="*70)
    print(f" OVERALL: {passed}/{total} scenarios passed ({pass_rate:.1f}%)")
    print("="*70 + "\n")

def main():
    """Main analysis function"""
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_results.py <benchmark_results.json>")
        sys.exit(1)
    
    results_file = Path(sys.argv[1])
    
    if not results_file.exists():
        print(f"Error: Results file not found: {results_file}")
        sys.exit(1)
    
    # Load results
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    # Analyze each scenario
    analyses = []
    for scenario in results['scenarios']:
        analysis = analyze_scenario(scenario)
        analyses.append(analysis)
    
    # Generate reports
    output_dir = results_file.parent
    
    # Console summary
    generate_console_summary(analyses)
    
    # Markdown report
    markdown_path = output_dir / f"SUMMARY_{results_file.stem}.md"
    generate_markdown_report(results, analyses, markdown_path)
    
    # Save detailed analysis as JSON
    analysis_json = {
        'metadata': results['benchmark_metadata'],
        'analyses': analyses
    }
    json_path = output_dir / f"analysis_{results_file.stem}.json"
    with open(json_path, 'w') as f:
        json.dump(analysis_json, f, indent=2, default=str)
    print(f"✅ JSON analysis saved: {json_path}")
    
    # Exit with error code if any scenario failed
    if not all(a['pass'] for a in analyses):
        print("\n❌ Some benchmarks failed!")
        sys.exit(1)
    else:
        print("\n✅ All benchmarks passed!")
        sys.exit(0)

if __name__ == '__main__':
    main()
