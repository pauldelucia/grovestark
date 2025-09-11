//! Circuit breaker pattern for preventing cascading failures

use crate::error::{Error, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is functioning normally
    Closed,
    /// Circuit is blocking requests due to failures
    Open,
    /// Circuit is testing if the service has recovered
    HalfOpen,
}

/// Configuration for circuit breaker behavior
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Success threshold to close circuit from half-open state
    pub success_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
    /// Time to wait before transitioning from open to half-open
    pub recovery_timeout: Duration,
    /// Maximum number of requests in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            failure_window: Duration::from_secs(60),
            recovery_timeout: Duration::from_secs(30),
            half_open_max_requests: 3,
        }
    }
}

impl CircuitBreakerConfig {
    /// Configuration for platform API calls
    pub fn for_platform_api() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            failure_window: Duration::from_secs(30),
            recovery_timeout: Duration::from_secs(60),
            half_open_max_requests: 5,
        }
    }

    /// Configuration for proof generation
    pub fn for_proof_generation() -> Self {
        Self {
            failure_threshold: 2,
            success_threshold: 1,
            failure_window: Duration::from_secs(120),
            recovery_timeout: Duration::from_secs(30),
            half_open_max_requests: 1,
        }
    }
}

/// Circuit breaker state tracking
struct CircuitBreakerState {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
    half_open_requests: u32,
    failure_times: Vec<Instant>,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
            half_open_requests: 0,
            failure_times: Vec::new(),
        }
    }

    /// Clean up old failure records outside the window
    fn cleanup_old_failures(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.failure_times.retain(|&time| time > cutoff);
        self.failure_count = self.failure_times.len() as u32;
    }
}

/// Circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<Mutex<CircuitBreakerState>>,
    name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(name: String, config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(CircuitBreakerState::new())),
            name,
        }
    }

    /// Get the current state of the circuit
    pub fn state(&self) -> CircuitState {
        let mut state = self.state.lock().unwrap();
        self.update_state(&mut state);
        state.state
    }

    /// Execute an operation through the circuit breaker
    pub fn execute<F, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        // Check if we can execute
        {
            let mut state = self.state.lock().unwrap();
            self.update_state(&mut state);

            match state.state {
                CircuitState::Open => {
                    log::warn!(
                        "Circuit breaker '{}' is OPEN - rejecting request",
                        self.name
                    );
                    return Err(Error::CircuitOpen(format!(
                        "Circuit breaker '{}' is open",
                        self.name
                    )));
                }
                CircuitState::HalfOpen => {
                    if state.half_open_requests >= self.config.half_open_max_requests {
                        log::warn!(
                            "Circuit breaker '{}' is HALF-OPEN but max requests reached",
                            self.name
                        );
                        return Err(Error::CircuitOpen(format!(
                            "Circuit breaker '{}' half-open limit reached",
                            self.name
                        )));
                    }
                    state.half_open_requests += 1;
                    log::debug!(
                        "Circuit breaker '{}' is HALF-OPEN - allowing request {}/{}",
                        self.name,
                        state.half_open_requests,
                        self.config.half_open_max_requests
                    );
                }
                CircuitState::Closed => {
                    log::trace!(
                        "Circuit breaker '{}' is CLOSED - allowing request",
                        self.name
                    );
                }
            }
        }

        // Execute the operation
        let result = operation();

        // Update state based on result
        {
            let mut state = self.state.lock().unwrap();
            match result {
                Ok(_) => self.record_success(&mut state),
                Err(_) => self.record_failure(&mut state),
            }
        }

        result
    }

    /// Execute an async operation through the circuit breaker
    pub async fn execute_async<F, Fut, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        // Check if we can execute
        {
            let mut state = self.state.lock().unwrap();
            self.update_state(&mut state);

            match state.state {
                CircuitState::Open => {
                    log::warn!(
                        "Circuit breaker '{}' is OPEN - rejecting request",
                        self.name
                    );
                    return Err(Error::CircuitOpen(format!(
                        "Circuit breaker '{}' is open",
                        self.name
                    )));
                }
                CircuitState::HalfOpen => {
                    if state.half_open_requests >= self.config.half_open_max_requests {
                        log::warn!(
                            "Circuit breaker '{}' is HALF-OPEN but max requests reached",
                            self.name
                        );
                        return Err(Error::CircuitOpen(format!(
                            "Circuit breaker '{}' half-open limit reached",
                            self.name
                        )));
                    }
                    state.half_open_requests += 1;
                    log::debug!(
                        "Circuit breaker '{}' is HALF-OPEN - allowing request {}/{}",
                        self.name,
                        state.half_open_requests,
                        self.config.half_open_max_requests
                    );
                }
                CircuitState::Closed => {
                    log::trace!(
                        "Circuit breaker '{}' is CLOSED - allowing request",
                        self.name
                    );
                }
            }
        }

        // Execute the operation
        let result = operation().await;

        // Update state based on result
        {
            let mut state = self.state.lock().unwrap();
            match result {
                Ok(_) => self.record_success(&mut state),
                Err(_) => self.record_failure(&mut state),
            }
        }

        result
    }

    /// Record a successful operation
    fn record_success(&self, state: &mut CircuitBreakerState) {
        match state.state {
            CircuitState::HalfOpen => {
                state.success_count += 1;
                log::debug!(
                    "Circuit breaker '{}' success in HALF-OPEN ({}/{})",
                    self.name,
                    state.success_count,
                    self.config.success_threshold
                );

                if state.success_count >= self.config.success_threshold {
                    self.transition_to_closed(state);
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success in closed state
                if state.failure_count > 0 {
                    log::trace!(
                        "Circuit breaker '{}' success - resetting failure count",
                        self.name
                    );
                    state.failure_count = 0;
                    state.failure_times.clear();
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but log it
                log::warn!(
                    "Circuit breaker '{}' recorded success while OPEN (unexpected)",
                    self.name
                );
            }
        }
    }

    /// Record a failed operation
    fn record_failure(&self, state: &mut CircuitBreakerState) {
        let now = Instant::now();

        match state.state {
            CircuitState::Closed => {
                state.failure_times.push(now);
                state.cleanup_old_failures(self.config.failure_window);
                state.failure_count = state.failure_times.len() as u32;
                state.last_failure_time = Some(now);

                log::debug!(
                    "Circuit breaker '{}' failure in CLOSED ({}/{})",
                    self.name,
                    state.failure_count,
                    self.config.failure_threshold
                );

                if state.failure_count >= self.config.failure_threshold {
                    self.transition_to_open(state);
                }
            }
            CircuitState::HalfOpen => {
                log::warn!(
                    "Circuit breaker '{}' failure in HALF-OPEN - reopening",
                    self.name
                );
                state.failure_times.push(now);
                state.last_failure_time = Some(now);
                self.transition_to_open(state);
            }
            CircuitState::Open => {
                // Already open, just update last failure time
                state.last_failure_time = Some(now);
            }
        }
    }

    /// Update state based on timeouts
    fn update_state(&self, state: &mut CircuitBreakerState) {
        if state.state == CircuitState::Open {
            let elapsed = Instant::now() - state.last_state_change;
            if elapsed >= self.config.recovery_timeout {
                self.transition_to_half_open(state);
            }
        }

        // Clean up old failures periodically
        if state.state == CircuitState::Closed {
            state.cleanup_old_failures(self.config.failure_window);
        }
    }

    /// Transition to closed state
    fn transition_to_closed(&self, state: &mut CircuitBreakerState) {
        log::info!("Circuit breaker '{}' transitioning to CLOSED", self.name);
        state.state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.half_open_requests = 0;
        state.failure_times.clear();
        state.last_state_change = Instant::now();
    }

    /// Transition to open state
    fn transition_to_open(&self, state: &mut CircuitBreakerState) {
        log::warn!("Circuit breaker '{}' transitioning to OPEN", self.name);
        state.state = CircuitState::Open;
        state.success_count = 0;
        state.half_open_requests = 0;
        state.last_state_change = Instant::now();
    }

    /// Transition to half-open state
    fn transition_to_half_open(&self, state: &mut CircuitBreakerState) {
        log::info!("Circuit breaker '{}' transitioning to HALF-OPEN", self.name);
        state.state = CircuitState::HalfOpen;
        state.success_count = 0;
        state.half_open_requests = 0;
        state.last_state_change = Instant::now();
    }

    /// Force reset the circuit breaker to closed state
    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        self.transition_to_closed(&mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            failure_window: Duration::from_secs(60),
            recovery_timeout: Duration::from_millis(100),
            half_open_max_requests: 3,
        };

        let cb = CircuitBreaker::new("test".to_string(), config);

        // Initially closed
        assert_eq!(cb.state(), CircuitState::Closed);

        // First failure - still closed
        let _: Result<()> = cb.execute(|| Err(Error::NetworkError("fail".into())));
        assert_eq!(cb.state(), CircuitState::Closed);

        // Second failure - should open
        let _: Result<()> = cb.execute(|| Err(Error::NetworkError("fail".into())));
        assert_eq!(cb.state(), CircuitState::Open);

        // Should reject while open
        let result = cb.execute(|| Ok(42));
        assert!(result.is_err());

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(150));

        // Should be half-open now
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Success in half-open
        let _: Result<i32> = cb.execute(|| Ok(1));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Second success - should close
        let _: Result<i32> = cb.execute(|| Ok(2));
        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
