/// Simple test to verify OOD digest comparison
use grovestark::{
    create_witness_from_platform_proofs, stark_winterfell::verify_proof, PublicInputs, STARKConfig,
};

#[test]
fn test_ood_digest_output() {
    eprintln!("\n=== Starting OOD Digest Test ===");

    // Create simple test data with minimal witness
    let doc_proof = vec![0u8; 100];
    let key_proof = vec![0u8; 100];
    let document_json = vec![0u8; 50];
    let public_key = [0x01; 32];
    let signature_r = [0x02; 32];
    let signature_s = [0x03; 32];
    let message = b"test message";
    let private_key = [0x04; 32];

    // Try to create witness (this will fail but that's okay, we just want to test verification)
    let _witness_result = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        message,
        &private_key,
    );

    // Create a mock proof for testing verification
    // This will trigger the OOD digest comparison code
    let mock_proof = vec![0u8; 1000]; // Mock proof bytes

    let public_inputs = PublicInputs {
        message_hash: [0x01; 32],
        timestamp: 1234567890,
        state_root: [0x02; 32],
        contract_id: [0x03; 32],
    };

    let mut config = STARKConfig::default();
    config.grinding_bits = 8; // Lower for testing

    eprintln!("\n🔐 Calling verify_proof with mock data...");
    let result = verify_proof(&mock_proof, &public_inputs, &config);

    match result {
        Ok(verified) => {
            eprintln!("✅ Verification result: {}", verified);
        }
        Err(e) => {
            eprintln!("❌ Verification error (expected with mock data): {}", e);
        }
    }

    eprintln!("\n=== OOD Digest Test Complete ===\n");
}
