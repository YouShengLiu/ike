#!/bin/bash

# CPU Profiling Script for DH Computation Bottleneck Analysis
# This script runs benchmarks with CPU profiling to identify the exact bottleneck

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROFILE_DIR="${SCRIPT_DIR}/profile_results"

# Create output directory
mkdir -p "${PROFILE_DIR}"

echo "=========================================="
echo "DH Computation CPU Profiling"
echo "=========================================="
echo ""

# Test 1: Sequential DH operations (baseline)
echo "[1/5] Running Sequential Benchmark (single-threaded baseline)..."
cd "${SCRIPT_DIR}/security/dh"
go test -bench=BenchmarkDH_2048_Combined -benchtime=5s -count=3 \
    -cpuprofile="${PROFILE_DIR}/cpu_sequential.prof" 2>&1 | tee "${PROFILE_DIR}/sequential_benchmark.txt"

echo ""
echo "[2/5] Running Concurrent Benchmark (simulates 8 workers)..."
go test -bench=BenchmarkDH_2048_Concurrent -benchtime=5s -count=3 \
    -cpuprofile="${PROFILE_DIR}/cpu_concurrent.prof" 2>&1 | tee "${PROFILE_DIR}/concurrent_benchmark.txt"

echo ""
echo "[3/5] Running Individual Operation Benchmarks..."
go test -bench=BenchmarkDH_2048_GetPublicValue -benchtime=5s \
    -cpuprofile="${PROFILE_DIR}/cpu_publicvalue.prof" 2>&1 | tee "${PROFILE_DIR}/publicvalue_benchmark.txt"

go test -bench=BenchmarkDH_2048_GetSharedKey -benchtime=5s \
    -cpuprofile="${PROFILE_DIR}/cpu_sharedkey.prof" 2>&1 | tee "${PROFILE_DIR}/sharedkey_benchmark.txt"

echo ""
echo "[4/5] Generating CPU Profiles (top functions)..."

# Function to generate profile summary
generate_profile_summary() {
    local prof_file=$1
    local output_file=$2
    local title=$3

    if [ -f "${prof_file}" ]; then
        echo "=== ${title} ===" > "${output_file}"
        echo "" >> "${output_file}"
        echo "Top 20 CPU-consuming functions:" >> "${output_file}"
        go tool pprof -top -nodecount=20 "${prof_file}" >> "${output_file}" 2>&1
        echo "" >> "${output_file}"
        echo "Call graph (top 30):" >> "${output_file}"
        go tool pprof -list=Exp "${prof_file}" >> "${output_file}" 2>&1 || true
    fi
}

generate_profile_summary "${PROFILE_DIR}/cpu_sequential.prof" "${PROFILE_DIR}/profile_sequential.txt" "Sequential DH"
generate_profile_summary "${PROFILE_DIR}/cpu_concurrent.prof" "${PROFILE_DIR}/profile_concurrent.txt" "Concurrent DH"
generate_profile_summary "${PROFILE_DIR}/cpu_publicvalue.prof" "${PROFILE_DIR}/profile_publicvalue.txt" "Public Value Computation"
generate_profile_summary "${PROFILE_DIR}/cpu_sharedkey.prof" "${PROFILE_DIR}/profile_sharedkey.txt" "Shared Key Computation"

echo ""
echo "[5/5] Generating Analysis Report..."

# Create comprehensive analysis report
cat > "${PROFILE_DIR}/PROFILING_ANALYSIS.md" << 'EOF'
# DH Computation CPU Profiling Analysis Report

## Test Setup

- **Test Date**: $(date)
- **Benchmark Duration**: 5 seconds per benchmark
- **Iteration Count**: 3 runs
- **DH Group**: 2048-bit MODP (Group 14)
- **Operation**: Full DH exchange (GetPublicValue + GetSharedKey)

## Benchmarks Run

### 1. Sequential Benchmark
- **Purpose**: Single-threaded baseline performance
- **File**: `sequential_benchmark.txt`
- **Profile**: `cpu_sequential.prof`

### 2. Concurrent Benchmark
- **Purpose**: Simulates 8 concurrent workers
- **File**: `concurrent_benchmark.txt`
- **Profile**: `cpu_concurrent.prof`
- **Expected Result**: Should show performance degradation if serialization occurs

### 3. Individual Operations
- **Public Value**: GetPublicValue computation (g^secret mod p)
- **Shared Key**: GetSharedKey computation (peer^secret mod p)
- **Purpose**: Identify which operation is the bottleneck

## Key Metrics to Compare

### From Benchmark Output

Look for these metrics in the output files:

```
BenchmarkDH_2048_Combined
    Sequential: X ns/op (baseline)
    Concurrent: Y ns/op (with concurrent load)

Performance Ratio: Y/X =
    - If close to 1.0: No serialization
    - If > 2.0: Significant serialization
    - If > 4.0: Severe serialization
```

### From CPU Profile

```
Top function (should be math/big.Exp):
    - Percentage of total CPU time
    - Number of calls
    - Average time per call
```

## Expected Results

Based on previous analysis:

| Scenario | Expected Time | Expected Ratio |
|----------|---------------|----------------|
| Sequential (1 op) | ~27.8ms | 1.0x |
| Concurrent (8 ops) | ~123.5ms | 4.4x slower |
| Ideally (if parallelized) | ~3.5ms | 8x faster |

## How to Interpret Results

### If Ratio is Close to 1.0
- Concurrent DH is as fast as sequential
- **Interpretation**: NO serialization at this level
- **Action**: Problem is elsewhere (check N3IWF dispatcher)

### If Ratio is 4-5x Slower
- Matches our observed behavior
- **Interpretation**: math/big.Exp() is serializing
- **Action**: Confirms ECDH is the only viable solution

### If Ratio is 2-3x Slower
- Partial serialization
- **Interpretation**: Some parallelism, but still bottlenecked
- **Action**: Investigate Go runtime scheduler, consider ECDH

## CPU Profile Analysis

### math/big.Exp() Characteristics

The top functions in the CPU profile should show:

1. **math/big.(*Int).Exp()** - Most CPU time (should be 80-90%)
2. **math/big.(*Int).modMul()** - Internal multiplication (20-30%)
3. **runtime.mallocgc** - Memory allocation (5-10%)
4. **sync.(*Mutex).Lock()** (if present) - Indicates lock contention

## Visualization

To view profiles graphically (requires Graphviz):

```bash
# Interactive flamegraph
go tool pprof -http=:8080 cpu_concurrent.prof

# Or text-based tree
go tool pprof -tree cpu_concurrent.prof
```

## Next Steps

1. **Review the benchmark results**
   - Compare sequential vs concurrent timings
   - Check the ratio (should be ~4.4x based on field data)

2. **Analyze CPU profile**
   - Identify which functions consume most CPU
   - Look for evidence of lock contention (sync primitives)

3. **Make decision**
   - If ratio confirms serialization → proceed with ECDH evaluation
   - If ratio is low → investigate N3IWF code instead

---

**Generated**: $(date)
EOF

echo "Analysis report created: ${PROFILE_DIR}/PROFILING_ANALYSIS.md"

echo ""
echo "=========================================="
echo "Profiling Complete!"
echo "=========================================="
echo ""
echo "Results saved to: ${PROFILE_DIR}/"
echo ""
echo "Key files:"
echo "  - sequential_benchmark.txt    : Sequential DH times"
echo "  - concurrent_benchmark.txt    : Concurrent DH times (8 workers)"
echo "  - profile_concurrent.txt      : CPU profile analysis"
echo "  - PROFILING_ANALYSIS.md       : Detailed analysis guide"
echo ""
echo "To view interactive profile:"
echo "  go tool pprof -http=:8080 ${PROFILE_DIR}/cpu_concurrent.prof"
echo ""
