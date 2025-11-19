# Performance Baseline Directory

This directory stores the performance baseline for R-Map benchmarks.

## Purpose

The baseline serves as a reference point for detecting performance regressions:
- Compare current benchmark results against baseline
- Detect degradations (>10% slower, >15% more memory)
- Track improvements over time
- Gate CI/CD pipeline on regressions

## Files

### baseline.json
The current performance baseline. This file contains:
- Benchmark metadata (version, timestamp, system info)
- Results for all 10 test scenarios
- Raw timing data (10 iterations per scenario)
- Memory and CPU measurements

**Format:** Same JSON structure as benchmark results

## Establishing a Baseline

### Initial Baseline (v1.0)

```bash
# 1. Ensure clean build
cd /home/user/R-map
cargo build --release

# 2. Run benchmarks (3 times for consistency)
cd benchmarks/scripts
./run_benchmarks.sh
sleep 300  # Cool down
./run_benchmarks.sh
sleep 300
./run_benchmarks.sh

# 3. Review results
ls -lth ../results/benchmark_*.json
python3 analyze_results.py ../results/benchmark_*.json

# 4. Choose the best run (lowest median time, consistent results)
cp ../results/benchmark_20241118_153045.json ../baseline/baseline.json

# 5. Commit to repository
git add ../baseline/baseline.json
git commit -m "chore: Establish v1.0 performance baseline"
git push
```

### Updating Baseline

Update baseline when:
- ✅ Verified performance improvements merged
- ✅ Major version releases
- ✅ System/infrastructure upgrades
- ❌ NOT after regressions
- ❌ NOT on temporary improvements

```bash
# After verifying improvement
cp benchmarks/results/benchmark_latest.json \
   benchmarks/baseline/baseline.json

git add benchmarks/baseline/baseline.json
git commit -m "chore: Update baseline - 15% performance improvement"
```

## Using the Baseline

### Compare Against Baseline

```bash
# Run benchmarks
cd /home/user/R-map/benchmarks/scripts
./run_benchmarks.sh

# Compare with baseline
python3 compare_baseline.py \
  ../results/benchmark_$(date +%Y%m%d)*.json \
  ../baseline/baseline.json

# Exit code:
# 0 = No regression
# 1 = Regression detected
```

### CI/CD Integration

GitHub Actions automatically:
1. Runs benchmarks on every PR
2. Compares against baseline
3. Comments results on PR
4. Blocks merge if regression detected
5. Auto-updates baseline on successful merges to main

## Baseline History

Track baseline changes over time:

```bash
# View baseline commit history
git log --follow benchmarks/baseline/baseline.json

# Compare two baselines
python3 scripts/compare_baseline.py \
  baseline/baseline.json \
  baseline/baseline_old.json
```

## Regression Thresholds

**Time Regression:**
- Threshold: >10% slower
- Example: 2.0s → 2.2s = FAIL

**Memory Regression:**
- Threshold: >15% more memory
- Example: 10MB → 11.6MB = FAIL

**CPU Regression:**
- Not gated, but monitored
- Informational only

## Sample Baseline Structure

```json
{
  "benchmark_metadata": {
    "timestamp": "20241118_140530",
    "rmap_version": "v1.0.0",
    "nmap_version": "7.96",
    "hostname": "benchmark-runner",
    "kernel": "5.15.0",
    "cpu_count": "8"
  },
  "scenarios": [
    {
      "scenario_id": "TC-001",
      "scenario_name": "Single Host, Top 100 Ports",
      "iterations": 10,
      "rmap_times": [2.34, 2.31, 2.35, ...],
      "rmap_memory_kb": [14523, 14612, ...],
      "rmap_cpu_percent": [95, 96, ...],
      ...
    },
    ...
  ]
}
```

## Baseline Validation

Before committing a baseline, verify:
- ✅ All 10 scenarios completed successfully
- ✅ Consistent results (low standard deviation)
- ✅ No outliers or anomalies
- ✅ System was idle during benchmark
- ✅ Same hardware as production CI
- ✅ Clean build from release mode

## Troubleshooting

### Baseline file missing
```bash
# First run - no baseline yet
# This is expected on first setup
# Run benchmarks to create baseline
./run_benchmarks.sh
cp ../results/benchmark_*.json ../baseline/baseline.json
```

### Baseline incompatible
```bash
# If scenario IDs changed, create new baseline
# Old baseline is no longer valid
rm ../baseline/baseline.json
./run_benchmarks.sh
cp ../results/benchmark_*.json ../baseline/baseline.json
```

### False regressions
```bash
# If getting false positives:
# 1. Ensure CPU governor is in performance mode
# 2. Close all background applications
# 3. Run benchmarks multiple times
# 4. Use median values, not single runs
```

## Best Practices

1. **Consistency:** Always run on same hardware
2. **Environment:** Idle system, no background processes
3. **Multiple runs:** Average of 3+ benchmark runs
4. **Documentation:** Note changes in commit messages
5. **Verification:** Review results before committing baseline
6. **History:** Keep old baselines for reference (git tags)
7. **Communication:** Announce baseline updates to team

## Notes

- Baseline should be committed to git
- Do NOT gitignore baseline.json
- Keep baseline.json in repository for team access
- CI uses baseline from repository
- Local and CI baselines must match

## Support

For questions about baseline management:
- See [USAGE_GUIDE.md](/home/user/R-map/benchmarks/USAGE_GUIDE.md)
- Review [BENCHMARKING_PLAN.md](/home/user/R-map/benchmarks/BENCHMARKING_PLAN.md)
- Check CI workflow: `.github/workflows/benchmark.yml`
