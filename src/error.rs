use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Proving failed: {0}")]
    ProvingFailed(String),

    #[error("Field arithmetic error: {0}")]
    FieldArithmetic(String),

    #[error("Merkle tree error: {0}")]
    MerkleTree(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("FRI protocol error: {0}")]
    FRI(String),

    #[error("Trace generation error: {0}")]
    TraceGeneration(String),

    #[error("Constraint evaluation error: {0}")]
    ConstraintEvaluation(String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid point: {0}")]
    InvalidPoint(String),

    #[error("Parser error: {0}")]
    Parser(String),

    #[error("Batch proving error: {0}")]
    BatchProving(String),

    #[error("Platform integration error: {0}")]
    PlatformIntegration(String),

    #[error("Platform error: {0}")]
    PlatformError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Ed25519 decompression error: {0}")]
    Ed25519Decompression(#[from] crate::crypto::ed25519::DecompressError),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Circuit breaker open: {0}")]
    CircuitOpen(String),

    #[error("Max retries exceeded: {0}")]
    MaxRetriesExceeded(String),

    #[error("No recovery strategy available: {0}")]
    NoRecoveryStrategy(String),
}

pub type Result<T> = std::result::Result<T, Error>;
