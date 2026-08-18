use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    http::StatusCode,
    Json,
};
use serde_json::json;
use std::sync::Arc;
use std::time::{Instant, Duration};

pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill: Instant,
    pub capacity: f64,
    pub rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            rate,
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }
}

pub async fn rate_limit_middleware(
    State(state): State<Arc<crate::server::AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if !state.config.rate_limiting.enabled {
        return Ok(next.run(request).await);
    }

    // Get client IP from headers or connection.
    // Sanitize to prevent header-based injection / memory exhaustion with arbitrary strings.
    let connect_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.ip().to_string());

    let raw_ip = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next()) // Take first IP if multiple
        .map(|s| s.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or(connect_ip)
        .unwrap_or_else(|| "unknown".to_string());

    // Only allow IP addresses or "unknown" to prevent arbitrary string key memory leaks
    let bucket_key = if raw_ip.parse::<std::net::IpAddr>().is_ok() {
        raw_ip
    } else {
        "unknown".to_string()
    };

    let state_clone = state.clone();
    let buckets = state_clone
        .services
        .get_rate_limiter()
        .await;

    let allowed = {
        let mut buckets = buckets.lock().await;

        // Perform periodic pruning of idle/full buckets to prevent memory leak
        if buckets.len() > 1000 {
            let now = Instant::now();
            buckets.retain(|_, bucket| {
                bucket.refill();
                // Keep the bucket if it is not fully refilled or has been consumed from recently (within 60s)
                let is_full = bucket.tokens >= bucket.capacity;
                let is_recent = now.duration_since(bucket.last_refill) < Duration::from_secs(60);
                !is_full || is_recent
            });
        }

        let bucket = buckets
            .entry(bucket_key)
            .or_insert_with(|| TokenBucket::new(
                state.config.rate_limiting.burst_size as f64,
                state.config.rate_limiting.requests_per_second as f64,
            ));
        bucket.try_consume(1.0)
    };

    if !allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate limit exceeded",
                "retry_after": 1
            })),
        ));
    }

    Ok(next.run(request).await)
}

