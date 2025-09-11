#[test]
fn test_rayon_threads() {
    println!("Rayon threads: {}", rayon::current_num_threads());
    println!("CPU cores: {}", num_cpus::get());
    println!(
        "Rayon threads env var: {:?}",
        std::env::var("RAYON_NUM_THREADS")
    );
}
