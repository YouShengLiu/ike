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
