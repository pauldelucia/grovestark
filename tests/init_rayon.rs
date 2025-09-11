use rayon::prelude::*;
use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize Rayon thread pool before any tests run
pub fn init_rayon() {
    INIT.call_once(|| {
        let num_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8);

        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("rayon-worker-{}", i))
            .build_global()
            .expect("Failed to initialize Rayon thread pool");

        eprintln!(
            "🚀 RAYON INITIALIZED: {} threads",
            rayon::current_num_threads()
        );

        // Test that Rayon is actually working
        let test_sum: i32 = (0..1000).into_iter().collect::<Vec<_>>().par_iter().sum();
        eprintln!("   Rayon test sum: {} (should be 499500)", test_sum);
        assert_eq!(test_sum, 499500, "Rayon parallel execution test failed");
    });
}

#[test]
fn test_rayon_threads() {
    init_rayon();
    eprintln!("Rayon has {} threads", rayon::current_num_threads());
    assert!(
        rayon::current_num_threads() > 1,
        "Rayon should have multiple threads"
    );
}
