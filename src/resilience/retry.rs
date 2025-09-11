//! Retry logic with exponential backoff for handling transient failures

use crate::error::{Error, Result};
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    /// Add random jitter to delays (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

impl RetryPolicy {
    /// Create a policy for platform API calls
    pub fn for_platform_api() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_factor: 0.2,
        }
    }

    /// Create a policy for proof generation
    pub fn for_proof_generation() -> Self {
        Self {
            max_attempts: 2,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
        }
    }

    /// Create a policy for network requests
    pub fn for_network() -> Self {
        Self {
            max_attempts: 4,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 1.5,
            jitter_factor: 0.3,
        }
    }
}

/// Exponential backoff calculator
pub struct ExponentialBackoff {
    policy: RetryPolicy,
    current_attempt: u32,
    current_delay: Duration,
}

impl ExponentialBackoff {
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            current_delay: policy.initial_delay,
            policy,
            current_attempt: 0,
        }
    }

    /// Get the next delay duration
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.current_attempt >= self.policy.max_attempts {
            return None;
        }

        let delay = self.current_delay;

        // Calculate next delay with exponential backoff
        let next_delay_ms = (delay.as_millis() as f64 * self.policy.backoff_multiplier) as u64;
        let mut next_delay = Duration::from_millis(next_delay_ms);

        // Apply jitter
        if self.policy.jitter_factor > 0.0 {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let jitter = rng.gen_range(0.0..self.policy.jitter_factor);
            let jittered_ms = (next_delay.as_millis() as f64 * (1.0 + jitter)) as u64;
            next_delay = Duration::from_millis(jittered_ms);
        }

        // Cap at max delay
        if next_delay > self.policy.max_delay {
            next_delay = self.policy.max_delay;
        }

        self.current_delay = next_delay;
        self.current_attempt += 1;

        Some(delay)
    }

    /// Reset the backoff state
    pub fn reset(&mut self) {
        self.current_attempt = 0;
        self.current_delay = self.policy.initial_delay;
    }

    /// Get the current attempt number
    pub fn attempt(&self) -> u32 {
        self.current_attempt
    }
}

/// Executor for retrying async operations
pub struct RetryExecutor {
    policy: RetryPolicy,
}

impl RetryExecutor {
    pub fn new(policy: RetryPolicy) -> Self {
        Self { policy }
    }

    /// Execute an async operation with retry logic
    pub async fn execute<F, Fut, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut backoff = ExponentialBackoff::new(self.policy.clone());
        let mut last_error = None;

        while let Some(delay) = backoff.next_delay() {
            // Wait before retry (except for first attempt)
            if backoff.attempt() > 1 {
                log::debug!(
                    "Retrying operation after {:?} (attempt {}/{})",
                    delay,
                    backoff.attempt(),
                    self.policy.max_attempts
                );
                sleep(delay).await;
            }

            match operation().await {
                Ok(result) => {
                    if backoff.attempt() > 1 {
                        log::info!("Operation succeeded after {} attempts", backoff.attempt());
                    }
                    return Ok(result);
                }
                Err(err) => {
                    // Check if error is retryable
                    if !self.is_retryable(&err) {
                        log::error!("Non-retryable error encountered: {}", err);
                        return Err(err);
                    }

                    log::warn!(
                        "Operation failed (attempt {}/{}): {}",
                        backoff.attempt(),
                        self.policy.max_attempts,
                        err
                    );
                    last_error = Some(err);
                }
            }
        }

        // All retries exhausted
        let final_error = last_error.unwrap_or_else(|| {
            Error::MaxRetriesExceeded("Operation failed after all retry attempts".into())
        });

        log::error!(
            "All {} retry attempts exhausted: {}",
            self.policy.max_attempts,
            final_error
        );

        Err(Error::MaxRetriesExceeded(format!(
            "Failed after {} attempts: {}",
            self.policy.max_attempts, final_error
        )))
    }

    /// Execute a synchronous operation with retry logic
    pub fn execute_sync<F, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut backoff = ExponentialBackoff::new(self.policy.clone());
        let mut last_error = None;

        while let Some(delay) = backoff.next_delay() {
            // Wait before retry (except for first attempt)
            if backoff.attempt() > 1 {
                log::debug!(
                    "Retrying operation after {:?} (attempt {}/{})",
                    delay,
                    backoff.attempt(),
                    self.policy.max_attempts
                );
                std::thread::sleep(delay);
            }

            match operation() {
                Ok(result) => {
                    if backoff.attempt() > 1 {
                        log::info!("Operation succeeded after {} attempts", backoff.attempt());
                    }
                    return Ok(result);
                }
                Err(err) => {
                    // Check if error is retryable
                    if !self.is_retryable(&err) {
                        log::error!("Non-retryable error encountered: {}", err);
                        return Err(err);
                    }

                    log::warn!(
                        "Operation failed (attempt {}/{}): {}",
                        backoff.attempt(),
                        self.policy.max_attempts,
                        err
                    );
                    last_error = Some(err);
                }
            }
        }

        // All retries exhausted
        let final_error = last_error.unwrap_or_else(|| {
            Error::MaxRetriesExceeded("Operation failed after all retry attempts".into())
        });

        Err(Error::MaxRetriesExceeded(format!(
            "Failed after {} attempts: {}",
            self.policy.max_attempts, final_error
        )))
    }

    /// Determine if an error is retryable
    fn is_retryable(&self, error: &Error) -> bool {
        match error {
            // Network errors are usually retryable
            Error::NetworkError(_) => true,
            Error::Timeout(_) => true,
            Error::PlatformError(_) => true,

            // Circuit breaker open is not retryable
            Error::CircuitOpen(_) => false,

            // Invalid input/config is not retryable
            Error::InvalidInput(_) => false,
            Error::InvalidConfig(_) => false,
            Error::InvalidWitness(_) => false,

            // Cryptographic errors are not retryable
            Error::FieldArithmetic(_) => false,

            // Default to not retryable for safety
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_exponential_backoff() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
        };

        let mut backoff = ExponentialBackoff::new(policy);

        // First delay should be initial delay
        assert_eq!(backoff.next_delay(), Some(Duration::from_millis(100)));
        assert_eq!(backoff.attempt(), 1);

        // Second delay should be doubled
        assert_eq!(backoff.next_delay(), Some(Duration::from_millis(200)));
        assert_eq!(backoff.attempt(), 2);

        // Third delay should be doubled again
        assert_eq!(backoff.next_delay(), Some(Duration::from_millis(400)));
        assert_eq!(backoff.attempt(), 3);

        // No more delays after max attempts
        assert_eq!(backoff.next_delay(), None);
    }

    #[test]
    fn test_retry_executor_sync() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
        };

        let executor = RetryExecutor::new(policy);
        let counter = Arc::new(AtomicU32::new(0));

        // Test successful retry
        let counter_clone = counter.clone();
        let result = executor.execute_sync(move || {
            let count = counter_clone.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(Error::NetworkError("Temporary failure".into()))
            } else {
                Ok(42)
            }
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_executor_async() {
        let policy = RetryPolicy {
            max_attempts: 2,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
        };

        let executor = RetryExecutor::new(policy);
        let counter = Arc::new(AtomicU32::new(0));

        // Test failure after max attempts
        let counter_clone = counter.clone();
        let result: Result<()> = executor
            .execute(|| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err(Error::NetworkError("Persistent failure".into()))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
