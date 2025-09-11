//! Resilience patterns for production-ready operation
//!
//! This module provides retry logic, circuit breakers, and other resilience patterns
//! to ensure robust operation in production environments.

pub mod circuit_breaker;
pub mod retry;

pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use retry::{ExponentialBackoff, RetryExecutor, RetryPolicy};
