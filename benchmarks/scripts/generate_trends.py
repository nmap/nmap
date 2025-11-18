#!/usr/bin/env python3
"""
Generate performance trend analysis from historical benchmark results
"""

import json
import sys
from pathlib import Path
from typing import List, Dict
from datetime import datetime

def load_benchmark_files(file_paths: List[Path]) -> List[Dict]:
    """Load all benchmark JSON files and sort by timestamp"""
    results = []
    
    for file_path in file_paths:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                results.append(data)
        except Exception as e:
            print(f"Warning: Failed to load {file_path}: {e}", file=sys.stderr)
    
    # Sort by timestamp
    results.sort(key=lambda x: x['benchmark_metadata']['timestamp'])
    
    return results

def parse_time(time_str: str) -> float:
    """Parse time string to seconds"""
    try:
        if ':' in time_str:
            parts = time_str.split(':')
            return float(parts[0]) * 60 + float(parts[1])
        return float(time_str)
    except:
        return 0.0

def generate_trend_report(benchmarks: List[Dict]):
    """Generate markdown trend report"""
    
    if len(benchmarks) < 2:
        print("# Performance Trends\n")
        print("Not enough historical data for trend analysis.")
        print(f"\nOnly {len(benchmarks)} benchmark run(s) available. Need at least 2.")
        return
    
    print("# R-Map Performance Trends\n")
    print(f"**Analysis Period:** {benchmarks[0]['benchmark_metadata']['timestamp']} to {benchmarks[-1]['benchmark_metadata']['timestamp']}\n")
    print(f"**Total Runs:** {len(benchmarks)}\n")
    print("---\n")
    
    # Analyze each scenario across all runs
    scenario_ids = [s['scenario_id'] for s in benchmarks[0]['scenarios']]
    
    for scenario_id in scenario_ids:
        scenario_name = benchmarks[0]['scenarios'][0]['scenario_name']
        
        # Find scenario in first benchmark
        for s in benchmarks[0]['scenarios']:
            if s['scenario_id'] == scenario_id:
                scenario_name = s['scenario_name']
                break
        
        print(f"## {scenario_id}: {scenario_name}\n")
        
        # Collect data points
        timestamps = []
        rmap_medians = []
        nmap_medians = []
        
        for benchmark in benchmarks:
            for scenario in benchmark['scenarios']:
                if scenario['scenario_id'] == scenario_id:
                    import statistics
                    
                    rmap_times = [parse_time(str(t)) for t in scenario['rmap_times'] if t]
                    nmap_times = [parse_time(str(t)) for t in scenario['nmap_times'] if t]
                    
                    if rmap_times and nmap_times:
                        timestamps.append(benchmark['benchmark_metadata']['timestamp'])
                        rmap_medians.append(statistics.median(rmap_times))
                        nmap_medians.append(statistics.median(nmap_times))
                    
                    break
        
        if not rmap_medians:
            print("*No data available*\n")
            continue
        
        # Calculate trend
        if len(rmap_medians) >= 2:
            first_rmap = rmap_medians[0]
            last_rmap = rmap_medians[-1]
            trend_pct = ((last_rmap - first_rmap) / first_rmap * 100) if first_rmap > 0 else 0
            
            trend_icon = "📈" if trend_pct > 5 else "📉" if trend_pct < -5 else "➡️"
            trend_text = "improving" if trend_pct < 0 else "degrading" if trend_pct > 0 else "stable"
            
            print(f"**Trend:** {trend_icon} {trend_text} ({trend_pct:+.1f}% over period)\n")
        
        # Table
        print("| Date | R-Map (median) | nmap (median) | Difference |\n")
        print("|------|----------------|---------------|------------|\n")
        
        for i in range(len(timestamps)):
            diff_pct = ((rmap_medians[i] - nmap_medians[i]) / nmap_medians[i] * 100) if nmap_medians[i] > 0 else 0
            
            # Format timestamp
            try:
                ts = datetime.strptime(timestamps[i], "%Y%m%d_%H%M%S")
                date_str = ts.strftime("%Y-%m-%d")
            except:
                date_str = timestamps[i][:8]
            
            print(f"| {date_str} | {rmap_medians[i]:.2f}s | {nmap_medians[i]:.2f}s | {diff_pct:+.1f}% |\n")
        
        print()
    
    # Overall summary
    print("---\n")
    print("## Summary\n")
    
    # Compare first and last runs
    first_run = benchmarks[0]
    last_run = benchmarks[-1]
    
    improvements = 0
    regressions = 0
    stable = 0
    
    for scenario_id in scenario_ids:
        first_scenario = next((s for s in first_run['scenarios'] if s['scenario_id'] == scenario_id), None)
        last_scenario = next((s for s in last_run['scenarios'] if s['scenario_id'] == scenario_id), None)
        
        if not first_scenario or not last_scenario:
            continue
        
        import statistics
        
        first_rmap = [parse_time(str(t)) for t in first_scenario['rmap_times'] if t]
        last_rmap = [parse_time(str(t)) for t in last_scenario['rmap_times'] if t]
        
        if first_rmap and last_rmap:
            first_median = statistics.median(first_rmap)
            last_median = statistics.median(last_rmap)
            
            change_pct = ((last_median - first_median) / first_median * 100) if first_median > 0 else 0
            
            if change_pct < -5:
                improvements += 1
            elif change_pct > 5:
                regressions += 1
            else:
                stable += 1
    
    print(f"- **Improvements:** {improvements} scenario(s) got faster\n")
    print(f"- **Regressions:** {regressions} scenario(s) got slower\n")
    print(f"- **Stable:** {stable} scenario(s) remained stable\n")
    
    if regressions > improvements:
        print("\n⚠️ **Warning:** More regressions than improvements detected over time.\n")
    elif improvements > regressions:
        print("\n✅ **Good:** Performance is improving over time!\n")
    else:
        print("\n➡️ **Stable:** Performance has remained consistent.\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_trends.py <benchmark1.json> <benchmark2.json> ...")
        sys.exit(1)
    
    file_paths = [Path(arg) for arg in sys.argv[1:]]
    
    # Filter to existing files
    existing_files = [f for f in file_paths if f.exists()]
    
    if not existing_files:
        print("Error: No valid benchmark files found")
        sys.exit(1)
    
    benchmarks = load_benchmark_files(existing_files)
    generate_trend_report(benchmarks)

if __name__ == '__main__':
    main()
