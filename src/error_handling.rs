//! Comprehensive error handling with retry logic and recovery
//!
//! This module provides production-grade error handling with automatic retries,
//! exponential backoff, and circuit breaker patterns.

use crate::error::{Error, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: usize,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker for preventing cascading failures
#[derive(Debug)]
pub struct CircuitBreaker {
    state: Arc<Mutex<CircuitState>>,
    failure_count: Arc<Mutex<usize>>,
    last_failure_time: Arc<Mutex<Option<Instant>>>,
    config: CircuitBreakerConfig,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: usize,
    /// Duration circuit remains open
    pub reset_timeout: Duration,
    /// Success threshold for closing circuit from half-open
    pub success_threshold: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(60),
            success_threshold: 2,
        }
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(CircuitState::Closed)),
            failure_count: Arc::new(Mutex::new(0)),
            last_failure_time: Arc::new(Mutex::new(None)),
            config,
        }
    }

    pub fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        // Check circuit state and potentially transition
        {
            let mut state = self.state.lock().unwrap();

            if *state == CircuitState::Open {
                // Check if we should transition to half-open
                let last_failure_opt = *self.last_failure_time.lock().unwrap();
                if let Some(last_failure) = last_failure_opt {
                    if last_failure.elapsed() > self.config.reset_timeout {
                        *state = CircuitState::HalfOpen;
                    } else {
                        return Err(Error::CircuitOpen("Circuit breaker is open".into()));
                    }
                } else {
                    // Circuit is open but no failure time recorded - this shouldn't happen
                    // but if it does, return error
                    return Err(Error::CircuitOpen("Circuit breaker is open".into()));
                }
            }
        } // Release the lock here

        // Try the operation
        match f() {
            Ok(result) => {
                // Check if we need to close the circuit
                let mut state = self.state.lock().unwrap();
                if *state == CircuitState::HalfOpen {
                    *state = CircuitState::Closed;
                    *self.failure_count.lock().unwrap() = 0;
                }
                Ok(result)
            }
            Err(e) => {
                self.record_failure();
                Err(e)
            }
        }
    }

    fn record_failure(&self) {
        let mut failure_count = self.failure_count.lock().unwrap();
        *failure_count += 1;

        if *failure_count >= self.config.failure_threshold {
            *self.state.lock().unwrap() = CircuitState::Open;
            *self.last_failure_time.lock().unwrap() = Some(Instant::now());
        }
    }
}

/// Retry executor with exponential backoff
pub struct RetryExecutor {
    config: RetryConfig,
}

impl RetryExecutor {
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    pub async fn execute_async<F, Fut, T>(&self, mut f: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        let mut backoff = self.config.initial_backoff;

        loop {
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempt += 1;

                    if attempt >= self.config.max_attempts {
                        return Err(Error::MaxRetriesExceeded(format!(
                            "Failed after {} attempts: {}",
                            attempt, e
                        )));
                    }

                    // Check if error is retryable
                    if !self.is_retryable(&e) {
                        return Err(e);
                    }

                    // Apply exponential backoff with jitter
                    let jitter = self.calculate_jitter(backoff);
                    std::thread::sleep(backoff + jitter);

                    // Update backoff for next iteration
                    backoff = self.calculate_next_backoff(backoff);
                }
            }
        }
    }

    pub fn execute<F, T>(&self, mut f: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut attempt = 0;
        let mut backoff = self.config.initial_backoff;

        loop {
            match f() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempt += 1;

                    if attempt >= self.config.max_attempts {
                        return Err(Error::MaxRetriesExceeded(format!(
                            "Failed after {} attempts: {}",
                            attempt, e
                        )));
                    }

                    // Check if error is retryable
                    if !self.is_retryable(&e) {
                        return Err(e);
                    }

                    // Apply exponential backoff with jitter
                    let jitter = self.calculate_jitter(backoff);
                    std::thread::sleep(backoff + jitter);

                    // Update backoff for next iteration
                    backoff = self.calculate_next_backoff(backoff);
                }
            }
        }
    }

    fn is_retryable(&self, error: &Error) -> bool {
        match error {
            Error::PlatformIntegration(_) => true,
            Error::NetworkError(_) => true,
            Error::Timeout(_) => true,
            Error::CircuitOpen(_) => false,
            Error::InvalidInput(_) => false,
            Error::InvalidWitness(_) => false,
            Error::CryptoError(_) => false,
            _ => false,
        }
    }

    fn calculate_jitter(&self, backoff: Duration) -> Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let jitter_ms =
            (backoff.as_millis() as f64 * self.config.jitter_factor * rng.gen::<f64>()) as u64;
        Duration::from_millis(jitter_ms)
    }

    fn calculate_next_backoff(&self, current: Duration) -> Duration {
        let next_ms = (current.as_millis() as f64 * self.config.backoff_multiplier) as u64;
        let next = Duration::from_millis(next_ms);

        if next > self.config.max_backoff {
            self.config.max_backoff
        } else {
            next
        }
    }
}

/// Error recovery strategies
pub enum RecoveryStrategy {
    /// Retry with exponential backoff
    Retry(RetryConfig),
    /// Use circuit breaker
    CircuitBreaker(CircuitBreakerConfig),
    /// Fallback to alternative
    Fallback(Box<dyn Fn() -> Result<()> + Send + Sync>),
    /// Log and continue
    LogAndContinue,
    /// Fail fast
    FailFast,
}

/// Error handler with multiple recovery strategies
pub struct ErrorHandler {
    strategies: Vec<RecoveryStrategy>,
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorHandler {
    pub fn new() -> Self {
        Self {
            strategies: vec![RecoveryStrategy::Retry(RetryConfig::default())],
        }
    }

    pub fn with_strategy(mut self, strategy: RecoveryStrategy) -> Self {
        self.strategies.push(strategy);
        self
    }

    pub async fn handle_async<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        for strategy in &self.strategies {
            match strategy {
                RecoveryStrategy::Retry(config) => {
                    let executor = RetryExecutor::new(config.clone());
                    match executor.execute_async(&f).await {
                        Ok(result) => return Ok(result),
                        Err(_) => continue,
                    }
                }
                RecoveryStrategy::FailFast => {
                    return f().await;
                }
                _ => {}
            }
        }

        Err(Error::NoRecoveryStrategy(
            "All recovery strategies failed".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_retry_executor() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let config = RetryConfig {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
        };

        let executor = RetryExecutor::new(config);

        let result = executor.execute(move || {
            let count = counter_clone.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(Error::NetworkError("Simulated failure".into()))
            } else {
                Ok(42)
            }
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_circuit_breaker() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(100),
            success_threshold: 1,
        };

        let breaker = CircuitBreaker::new(config);

        // First failure
        let _ = breaker.call(|| Err::<(), _>(Error::NetworkError("Error 1".into())));

        // Second failure - should open circuit
        let _ = breaker.call(|| Err::<(), _>(Error::NetworkError("Error 2".into())));

        // Circuit should be open
        let result = breaker.call(|| Ok(42));
        assert!(result.is_err());

        // Wait for reset timeout
        std::thread::sleep(Duration::from_millis(150));

        // Circuit should be half-open, success should close it
        let result = breaker.call(|| Ok(42));
        assert!(result.is_ok());
    }
}
