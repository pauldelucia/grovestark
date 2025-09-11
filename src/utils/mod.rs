use crate::types::LookupTables;
use std::time::{Duration, Instant};

pub struct Performance;

impl Performance {
    pub fn measure<F, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    pub fn measure_millis<F, R>(f: F) -> (R, u128)
    where
        F: FnOnce() -> R,
    {
        let (result, duration) = Self::measure(f);
        (result, duration.as_millis())
    }
}

pub struct Serialization;

impl Serialization {
    pub fn to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(hex_str)
    }

    pub fn to_base64(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn from_base64(base64_str: &str) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.decode(base64_str)
    }
}

pub struct Optimization;

impl Optimization {
    pub fn create_lookup_tables() -> LookupTables {
        LookupTables::new()
    }

    pub fn parallel_map<T, U, F>(items: Vec<T>, f: F) -> Vec<U>
    where
        T: Send + Sync,
        U: Send,
        F: Fn(&T) -> U + Send + Sync,
    {
        use rayon::prelude::*;
        items.par_iter().map(f).collect()
    }

    pub fn parallel_for_each<T, F>(items: &[T], f: F)
    where
        T: Send + Sync,
        F: Fn(&T) + Send + Sync,
    {
        use rayon::prelude::*;
        items.par_iter().for_each(f);
    }
}

pub struct TestUtils;

impl TestUtils {
    pub fn generate_random_bytes(len: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen()).collect()
    }

    pub fn generate_random_array<const N: usize>() -> [u8; N] {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut array = [0u8; N];
        rng.fill(&mut array[..]);
        array
    }

    pub fn create_test_witness() -> crate::types::PrivateInputs {
        let mut w = crate::types::PrivateInputs::default();
        w.document_cbor = vec![1, 2, 3, 4, 5];
        w.owner_id = [6u8; 32];
        w.identity_id = w.owner_id;
        w.doc_root = [0x44; 32];
        w.keys_root = [0x55; 32];
        w.owner_id_leaf_to_doc_path = vec![crate::types::MerkleNode {
            hash: [7u8; 32],
            is_left: true,
        }];
        w.docroot_to_state_path = vec![crate::types::MerkleNode {
            hash: [0x99u8; 32],
            is_left: false,
        }];
        w.key_leaf_to_keysroot_path = vec![crate::types::MerkleNode {
            hash: [8u8; 32],
            is_left: false,
        }];
        w.identity_leaf_to_state_path = vec![crate::types::MerkleNode {
            hash: [0x77u8; 32],
            is_left: true,
        }];
        w.private_key = [9u8; 32];
        w.signature_r = [10u8; 32];
        w.signature_s = [11u8; 32];
        w
    }

    pub fn create_test_public_inputs() -> crate::types::PublicInputs {
        crate::types::PublicInputs {
            state_root: [12u8; 32],
            contract_id: [13u8; 32],
            message_hash: [14u8; 32],
            timestamp: 1234567890,
        }
    }
}

pub struct Logging;

impl Logging {
    pub fn init() {
        env_logger::init();
    }

    pub fn init_with_level(level: &str) {
        std::env::set_var("RUST_LOG", level);
        env_logger::init();
    }

    pub fn debug(message: &str) {
        log::debug!("{}", message);
    }

    pub fn info(message: &str) {
        log::info!("{}", message);
    }

    pub fn warn(message: &str) {
        log::warn!("{}", message);
    }

    pub fn error(message: &str) {
        log::error!("{}", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_measurement() {
        let (result, duration) = Performance::measure(|| {
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_hex_serialization() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78];
        let hex = Serialization::to_hex(&bytes);
        assert_eq!(hex, "12345678");

        let decoded = Serialization::from_hex(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_parallel_map() {
        let items = vec![1, 2, 3, 4, 5];
        let results = Optimization::parallel_map(items, |&x| x * 2);
        assert_eq!(results, vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn test_random_generation() {
        let bytes = TestUtils::generate_random_bytes(32);
        assert_eq!(bytes.len(), 32);

        let array: [u8; 16] = TestUtils::generate_random_array();
        assert_eq!(array.len(), 16);
    }
}
