#!/usr/bin/env python3
"""
Compare current benchmark results with baseline
Detects performance regressions
"""

import json
import sys
from pathlib import Path
from typing import Dict

def load_json(file_path: Path) -> Dict:
    """Load JSON file"""
    with open(file_path, 'r') as f:
        return json.load(f)

def parse_time(time_str: str) -> float:
    """Parse time string to seconds"""
    try:
        if ':' in time_str:
            parts = time_str.split(':')
            return float(parts[0]) * 60 + float(parts[1])
        return float(time_str)
    except:
        return 0.0

def compare_results(current_file: Path, baseline_file: Path) -> bool:
    """
    Compare current results with baseline
    Returns True if no regression, False if regression detected
    """
    current = load_json(current_file)
    baseline = load_json(baseline_file)
    
    # Create scenario lookup for baseline
    baseline_scenarios = {s['scenario_id']: s for s in baseline['scenarios']}
    
    regressions = []
    
    print("\n" + "="*70)
    print(" BASELINE COMPARISON")
    print("="*70 + "\n")
    
    for current_scenario in current['scenarios']:
        scenario_id = current_scenario['scenario_id']
        scenario_name = current_scenario['scenario_name']
        
        if scenario_id not in baseline_scenarios:
            print(f"⚠️  {scenario_id}: No baseline data (new scenario)")
            continue
        
        baseline_scenario = baseline_scenarios[scenario_id]
        
        # Compare median times
        current_times = [parse_time(str(t)) for t in current_scenario['rmap_times'] if t]
        baseline_times = [parse_time(str(t)) for t in baseline_scenario['rmap_times'] if t]
        
        if not current_times or not baseline_times:
            continue
        
        import statistics
        current_median = statistics.median(current_times)
        baseline_median = statistics.median(baseline_times)
        
        time_change_pct = ((current_median - baseline_median) / baseline_median * 100)
        
        # Compare memory
        current_mem = [float(m) for m in current_scenario['rmap_memory_kb'] if m]
        baseline_mem = [float(m) for m in baseline_scenario['rmap_memory_kb'] if m]
        
        current_mem_median = statistics.median(current_mem) if current_mem else 0
        baseline_mem_median = statistics.median(baseline_mem) if baseline_mem else 0
        
        mem_change_pct = ((current_mem_median - baseline_mem_median) / baseline_mem_median * 100) if baseline_mem_median > 0 else 0
        
        # Check for regressions
        time_regressed = time_change_pct > 10  # >10% slower
        mem_regressed = mem_change_pct > 15    # >15% more memory
        
        if time_regressed or mem_regressed:
            regressions.append({
                'scenario_id': scenario_id,
                'scenario_name': scenario_name,
                'time_change_pct': time_change_pct,
                'mem_change_pct': mem_change_pct,
                'time_regressed': time_regressed,
                'mem_regressed': mem_regressed
            })
            
            status = "❌ REGRESSION"
        elif time_change_pct < -5 or mem_change_pct < -5:
            status = "✨ IMPROVEMENT"
        else:
            status = "✅ OK"
        
        print(f"{status} {scenario_id}: {scenario_name}")
        print(f"   Time:   {current_median:.2f}s vs {baseline_median:.2f}s ({time_change_pct:+.1f}%)")
        print(f"   Memory: {current_mem_median/1024:.1f}MB vs {baseline_mem_median/1024:.1f}MB ({mem_change_pct:+.1f}%)")
        print()
    
    # Summary
    print("="*70)
    if regressions:
        print(f" ❌ REGRESSION DETECTED: {len(regressions)} scenario(s) regressed")
        print("="*70 + "\n")
        
        print("Regressions:")
        for reg in regressions:
            print(f"  - {reg['scenario_id']}: ", end="")
            if reg['time_regressed']:
                print(f"Time +{reg['time_change_pct']:.1f}% ", end="")
            if reg['mem_regressed']:
                print(f"Memory +{reg['mem_change_pct']:.1f}%", end="")
            print()
        
        # Create regression flag file
        results_dir = current_file.parent
        (results_dir / "regression_detected.flag").touch()
        
        return False
    else:
        print(" ✅ NO REGRESSIONS DETECTED")
        print("="*70 + "\n")
        return True

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 compare_baseline.py <current_results.json> <baseline.json>")
        sys.exit(1)
    
    current_file = Path(sys.argv[1])
    baseline_file = Path(sys.argv[2])
    
    if not current_file.exists():
        print(f"Error: Current results file not found: {current_file}")
        sys.exit(1)
    
    if not baseline_file.exists():
        print(f"Warning: Baseline file not found: {baseline_file}")
        print("Skipping baseline comparison (no regression check)")
        sys.exit(0)
    
    no_regression = compare_results(current_file, baseline_file)
    
    sys.exit(0 if no_regression else 1)

if __name__ == '__main__':
    main()
