# GroveSTARK Production Benchmarking Guide

## Overview

GroveSTARK now has a comprehensive, production-grade benchmarking suite that provides complete performance coverage organized into logical categories. Benchmarks use proper EdDSA witness creation.

## Benchmark Organization

### Files

- `benches/quick_benchmarks.rs` — fast subset for CI/dev (< ~2–3 minutes depending on machine)
- `benches/comprehensive_benchmarks.rs` — full coverage (can take tens of minutes)

**Old files removed:**
- ❌ `stark_benchmarks.rs` (outdated APIs)  
- ❌ `eddsa_benchmarks.rs` (duplicated scope)

### Five Logical Categories

The benchmarks are organized into 5 logical groups for production monitoring:

#### 1. **End-to-End Performance** (`end_to_end_benches`)
- `bench_end_to_end_proof_generation` - Complete proof generation across document sizes (64B to 16KB)
- `bench_end_to_end_verification` - Proof verification performance
- `bench_end_to_end_batch_proving` - Batch processing performance (1, 2, 4, 8 proofs)

#### 2. **Core Cryptographic Operations** (`crypto_benches`)
- `bench_crypto_eddsa_operations` - EdDSA scalar multiplication, window decomposition, verification
- `bench_crypto_blake3_hashing` - BLAKE3 performance across data sizes (32B to 4KB)
- `bench_crypto_merkle_operations` - Merkle tree construction, proof generation/verification
- `bench_crypto_field_arithmetic` - Goldilocks field operations (add, multiply, divide, exponentiation)

#### 3. **Component Performance** (`component_benches`)
- `bench_components_stark_operations` - STARK proof generation via winterfell
- `bench_components_trace_generation` - Trace generation across witness sizes

#### 4. **Integration Performance** (`integration_benches`)
- `bench_integration_ed25519_conversion` - Point decompression, witness population, hash_h computation
- `bench_integration_grovedb_parsing` - GroveDB proof parsing performance
- `bench_integration_serialization` - Proof serialization and deserialization

#### 5. **Scalability Testing** (`scalability_benches`)
- `bench_scalability_merkle_depth` - Impact of Merkle path length (5 to 30 nodes)
- `bench_scalability_memory_usage` - Memory scaling with large documents (1KB to 256KB)

## Running Benchmarks

### Run All Benchmarks
```bash
cargo bench --features bench
```

### Run Specific Categories
```bash
# End-to-end performance only
cargo bench --features bench end_to_end_benches

# Cryptographic operations only  
cargo bench --features bench crypto_benches

# Component performance only
cargo bench --features bench component_benches

# Integration performance only
cargo bench --features bench integration_benches

# Scalability testing only
cargo bench --features bench scalability_benches
```

### Run Individual Benchmarks
```bash
# Specific benchmark function
cargo bench --features bench bench_crypto_eddsa_operations

# Specific test within a benchmark
cargo bench --features bench "eddsa_operations/scalar_multiplication"
```

### Quick Suite Only
```bash
cargo bench --features bench --bench quick_benchmarks
```

## Key Improvements from Old Benchmarks

### ✅ **Proper EdDSA Integration**
- **Before**: Used incomplete witness creation
- **After**: Full EdDSA witness creation with proper hash_h computation and extended coordinates

### ✅ **Production-Grade Witness Creation**
- **Before**: Placeholder values, incomplete initialization
- **After**: Complete witness with proper Ed25519 point conversion, window decompositions, varying Merkle paths

### ✅ **Comprehensive Coverage**
- **Before**: Scattered, incomplete benchmark coverage
- **After**: 5 logical categories covering all performance aspects

### ✅ **Eliminates Degeneracy Issues**  
- **Before**: Used uniform test data that could cause constraint degeneracy
- **After**: Varies critical witness fields to ensure realistic constraint evaluation

### ✅ **Realistic Test Scenarios**
- **Before**: Artificial test cases
- **After**: Production-realistic document sizes, Merkle path lengths, batch sizes

## Expected Performance Metrics

Based on current implementation:

### End-to-End Performance (indicative)
- **Proof Generation**: ~4–10 seconds for documents up to 16KB (machine‑dependent)
- **Verification**: ~50–200 ms (config/machine dependent)
- **Batch Processing**: Near-linear scaling

### Cryptographic Operations
- **EdDSA Scalar Multiplication**: 100-500 microseconds
- **BLAKE3 Hashing**: <1ms for documents up to 4KB
- **Field Arithmetic**: Nanosecond-level operations

### Integration Operations
- **Ed25519 Point Conversion**: <1ms per point
- **GroveDB Parsing**: <10ms for typical proofs
- **Serialization**: <10ms for typical proofs

### Scalability
- **Document Size**: Minimal impact on proving time (STARK-dominated)
- **Merkle Depth**: Linear increase with path length
- **Memory Usage**: Predictable scaling

## Production Monitoring

### Key Metrics to Track

1. **Proof Generation Time** - Primary SLA metric
2. **Verification Time** - Critical for blockchain integration  
3. **Memory Usage** - Resource planning
4. **Batch Throughput** - Scalability planning
5. **Ed25519 Conversion** - Integration bottleneck monitoring

### Performance Regression Detection

Run benchmarks on each PR/release to detect:
- Proof generation time increases >10%
- Memory usage increases >20%  
- Verification time increases >5%
- Cryptographic operation slowdowns

## Guardrails & Dev Flags

- Release/bench profiles enforce production minimums by default:
  - expansion_factor ≥ 16, num_queries ≥ 48, folding_factor ≥ 4.
- Some scalability benchmarks explore small parameters; those groups set `GS_ALLOW_WEAK_PARAMS=1` internally to bypass guardrails purely for measurement. Do not use reduced params in production.

### Benchmark Results Storage

Consider storing benchmark results for trend analysis:
```bash
cargo bench --features bench -- --save-baseline main
cargo bench --features bench -- --baseline main
```

## Development Workflow

### Adding New Benchmarks

1. **Identify Category** - Place in appropriate group (end_to_end, crypto, component, integration, scalability)
2. **Use Production Witnesses** - Always use `create_production_witness()` or variants
3. **Follow Naming Convention** - `bench_<category>_<operation>`
4. **Add to Appropriate Group** - Update `criterion_group!` macro

### Benchmark Best Practices

1. **Realistic Test Data** - Use production-like witness data
2. **Proper Timing** - Set appropriate `measurement_time` for expensive operations
3. **Sample Sizes** - Adjust `sample_size` for statistical significance vs. runtime
4. **Black Box** - Use `black_box()` to prevent compiler optimizations
5. **Resource Management** - Clean up resources between iterations

## Integration with CI/CD

### Automated Benchmarking
```yaml
# Example GitHub Actions
- name: Run Benchmarks
  run: cargo bench --features bench -- --output-format json
  
- name: Compare Performance  
  run: cargo bench --features bench -- --baseline baseline
```

### Performance Gates
- Fail CI if proof generation >7 seconds
- Warn if memory usage increases >20%
- Alert if verification time >100ms

This comprehensive benchmark suite provides production-grade performance monitoring for all aspects of GroveSTARK.
