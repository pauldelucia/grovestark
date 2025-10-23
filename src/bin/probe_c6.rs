use grovestark::{GroveSTARK, PrivateInputs, PublicInputs, STARKConfig};

// Minimal prover run to trigger GS_BASIS_PROBE for a single constraint (cid=6)
// without invoking verification. Configure with env:
//   GS_BASIS_PROBE=1 GS_PROBE_CID=6 cargo run --bin probe_c6 --release
fn main() {
    // Ensure basis probe is enabled even if not set in shell
    std::env::set_var("GS_BASIS_PROBE", "1");
    std::env::set_var("GS_PROBE_CID", "6");
    // Start with defaults, but force a lightweight config for quick probing
    let mut cfg = STARKConfig::default();
    cfg.grinding_bits = 0; // disable PoW for speed
    cfg.num_queries = 4; // small number of queries
    cfg.expansion_factor = 16; // small blowup to reduce work
                               // Keep expansion factor reasonable to avoid long runs
    if let Some(v) = std::env::var("GS_EXPANSION_FACTOR")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        cfg.expansion_factor = v;
    }
    if let Some(v) = std::env::var("GS_NUM_QUERIES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        cfg.num_queries = v;
    }
    if let Some(v) = std::env::var("GS_GRINDING_BITS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        cfg.grinding_bits = v;
    }

    let prover = GroveSTARK::with_config(cfg);

    // Minimal witness that passes validation
    let mut witness = PrivateInputs::default();
    witness.signature_r = [1u8; 32];
    witness.signature_s = [1u8; 32];
    witness.document_cbor = vec![0x01];

    // Minimal valid public inputs
    let public = PublicInputs {
        state_root: [1u8; 32],
        contract_id: [2u8; 32],
        message_hash: [3u8; 32],
        timestamp: 1_700_000_000,
    };

    // Run prove() to trigger winter-prover's basis probe; ignore the proof output
    eprintln!("[PROBE] Starting proof for cid=6 basis probe…");
    let _ = prover.prove(witness, public);
    eprintln!("[PROBE] Proof run completed.");
}
