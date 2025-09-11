use rayon::prelude::*;
use std::time::Instant;

#[test]
fn test_parallel_execution() {
    // Force Rayon initialization
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .ok();

    println!("\n🔍 Testing Parallel Execution");
    println!("==============================");
    println!("Rayon threads: {}", rayon::current_num_threads());

    // Test with a CPU-intensive task
    let data: Vec<u64> = (0..10_000_000).collect();

    // Serial version
    let start = Instant::now();
    let serial_sum: u64 = data.iter().map(|x| x * x).sum();
    let serial_time = start.elapsed();

    // Parallel version
    let start = Instant::now();
    let parallel_sum: u64 = data.par_iter().map(|x| x * x).sum();
    let parallel_time = start.elapsed();

    println!("Serial time: {:?}", serial_time);
    println!("Parallel time: {:?}", parallel_time);
    println!(
        "Speedup: {:.2}x",
        serial_time.as_secs_f64() / parallel_time.as_secs_f64()
    );

    assert_eq!(serial_sum, parallel_sum);
    assert!(parallel_time < serial_time, "Parallel should be faster!");
}
