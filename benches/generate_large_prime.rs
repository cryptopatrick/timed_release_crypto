use criterion::{criterion_group, criterion_main, Criterion};
use timed_release_crypto::generate_large_random_prime;

// Setup the test function.
fn generate_large_prime_benchmark(c: &mut Criterion) {
    c.bench_function("generate large random prime", |b| {
        b.iter(|| generate_large_random_prime(256u64))
    });
}

// We can use the criterion_group! macro to call a number of functions
// using the same benchmark configuration.
// First argument is the name of the group, the rest: functions to benchmark.
criterion_group!(benches, generate_large_random_prime);
// Expands to a main macro that runs all the benchmarks in the group.
criterion_main!(benches);
