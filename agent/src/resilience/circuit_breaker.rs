use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: Arc<std::sync::Mutex<CircuitState>>,
    failure_count: AtomicU32,
    last_failure_time: Arc<std::sync::Mutex<Option<Instant>>>,
    threshold: u32,
    reset_timeout: Duration,
    half_open_max_requests: u32,
    half_open_requests: AtomicU32,
    consecutive_successes: AtomicU32,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, reset_timeout_secs: u64) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(CircuitState::Closed)),
            failure_count: AtomicU32::new(0),
            last_failure_time: Arc::new(std::sync::Mutex::new(None)),
            threshold,
            reset_timeout: Duration::from_secs(reset_timeout_secs),
            half_open_max_requests: 1,
            half_open_requests: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
        }
    }

    pub fn is_available(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if *state == CircuitState::Open {
            let last_fail = self.last_failure_time.lock().unwrap();
            if let Some(last) = *last_fail {
                if last.elapsed() >= self.reset_timeout {
                    *state = CircuitState::HalfOpen;
                    self.half_open_requests.store(0, Ordering::Relaxed);
                    self.consecutive_successes.store(0, Ordering::Relaxed);
                    tracing::info!("circuit breaker transitioning to HalfOpen");
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        if *state == CircuitState::Closed {
            return true;
        }
        // HalfOpen logic
        let reqs = self.half_open_requests.fetch_add(1, Ordering::Relaxed);
        reqs < self.half_open_max_requests
    }

    pub fn on_success(&self) {
        let state = *self.state.lock().unwrap();
        match state {
            CircuitState::HalfOpen => {
                let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= 2 {
                    let mut s = self.state.lock().unwrap();
                    *s = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.half_open_requests.store(0, Ordering::Relaxed);
                    self.consecutive_successes.store(0, Ordering::Relaxed);
                    tracing::info!("circuit breaker reset to Closed");
                }
            }
            _ => {}
        }
    }

    pub fn on_failure(&self) {
        let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure_time.lock().unwrap() = Some(Instant::now());

        let state = *self.state.lock().unwrap();
        match state {
            CircuitState::Closed => {
                if failures >= self.threshold {
                    let mut s = self.state.lock().unwrap();
                    *s = CircuitState::Open;
                    tracing::warn!("circuit breaker OPEN after {} failures", failures);
                }
            }
            CircuitState::HalfOpen => {
                let mut s = self.state.lock().unwrap();
                *s = CircuitState::Open;
                self.half_open_requests.store(0, Ordering::Relaxed);
                self.consecutive_successes.store(0, Ordering::Relaxed);
                tracing::warn!("circuit breaker returned to OPEN from HalfOpen");
            }
            _ => {}
        }
    }

    pub fn state(&self) -> CircuitState {
        *self.state.lock().unwrap()
    }

    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_closed_accepts_requests() {
        let cb = CircuitBreaker::new(5, 30);
        assert!(cb.is_available());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_opens_after_threshold() {
        let cb = CircuitBreaker::new(3, 30);
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.on_failure();
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_available());
    }

    #[test]
    fn test_half_open_recovers() {
        let cb = CircuitBreaker::new(2, 1);
        cb.on_failure();
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(cb.is_available());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.on_success();
        cb.on_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_half_open_rejects_extra_requests() {
        let cb = CircuitBreaker::new(2, 1);
        cb.on_failure();
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        std::thread::sleep(Duration::from_millis(1100));
        // first request passes (half_open_max_requests=1)
        assert!(cb.is_available());
        // second request in half-open is rejected
        assert!(!cb.is_available());
    }

    #[test]
    fn test_failure_in_half_open_returns_to_open() {
        let cb = CircuitBreaker::new(2, 1);
        cb.on_failure();
        cb.on_failure();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(cb.is_available());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // failure in half-open → back to open
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // now still open (not enough time elapsed)
        assert!(!cb.is_available());
    }

    #[test]
    fn test_on_success_in_closed_is_noop() {
        let cb = CircuitBreaker::new(3, 30);
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.on_success();
        // still closed, failure count unchanged
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_failure_count_tracking() {
        let cb = CircuitBreaker::new(5, 30);
        assert_eq!(cb.failure_count(), 0);
        cb.on_failure();
        assert_eq!(cb.failure_count(), 1);
        cb.on_failure();
        assert_eq!(cb.failure_count(), 2);
    }

    #[test]
    fn test_high_threshold_does_not_open_prematurely() {
        let cb = CircuitBreaker::new(10, 30);
        for _ in 0..9 {
            cb.on_failure();
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_multiple_breakers_independent() {
        let cb1 = CircuitBreaker::new(2, 30);
        let cb2 = CircuitBreaker::new(5, 30);
        cb1.on_failure();
        cb1.on_failure();
        assert_eq!(cb1.state(), CircuitState::Open);
        assert_eq!(cb2.state(), CircuitState::Closed);
        assert!(cb2.is_available());
    }

    #[test]
    fn test_half_open_requires_two_successes() {
        let cb = CircuitBreaker::new(1, 1);
        cb.on_failure();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(cb.is_available());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.on_success();
        // still half-open, needs one more success
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.on_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
