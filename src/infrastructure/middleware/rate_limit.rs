use std::time::{Duration, SystemTime, UNIX_EPOCH};
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
    Error, HttpResponse,
    body::EitherBody,
};
use log::{debug, warn};
use dashmap::DashMap;
use futures::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;
use std::task::{Context, Poll};

// Rate limit configurations for different endpoints
struct RateLimit {
    path: &'static str,
    max_requests: u32,
    window_seconds: u64,
    error_message: &'static str,
}

const RATE_LIMITS: &[RateLimit] = &[
    RateLimit {
        path: "/users/login",
        max_requests: 5,
        window_seconds: 300, // 5 minutes
        error_message: "Too many login attempts",
    },
    RateLimit {
        path: "/users/register",
        max_requests: 3,
        window_seconds: 3600, // 1 hour
        error_message: "Too many registration attempts",
    },
    RateLimit {
        path: "/users/verify-email",
        max_requests: 5,
        window_seconds: 300, // 5 minutes
        error_message: "Too many email verification attempts",
    },
    RateLimit {
        path: "/users/password-reset/request",
        max_requests: 3,
        window_seconds: 1800, // 30 minutes
        error_message: "Too many password reset requests",
    },
    RateLimit {
        path: "/users/password-reset/verify",
        max_requests: 10,
        window_seconds: 300, // 5 minutes
        error_message: "Too many verification attempts",
    },
    RateLimit {
        path: "/password-reset/new",
        max_requests: 10,
        window_seconds: 300, // 5 minutes
        error_message: "Too many verification attempts",
    },
];

pub struct RateLimiter;

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service,
            rate_limits: Arc::new(DashMap::new()),
        }))
    }
}

pub struct RateLimitMiddleware<S> {
    service: S,
    rate_limits: Arc<DashMap<String, Vec<u64>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path();
        
        // Extract base path without query parameters
        let base_path = path.split('?').next().unwrap_or(path);
        debug!("Rate limit checking path: {}", base_path);

        // Skip rate limiting for static files
        if base_path.ends_with(".css") || base_path.ends_with(".js") || 
           base_path.ends_with(".wasm") || base_path.ends_with(".ico") {
            let fut = self.service.call(req);
            return Box::pin(async move {
                fut.await.map(|res| res.map_into_left_body())
            });
        }

        // Find matching rate limit configuration
        let rate_limit = match RATE_LIMITS.iter().find(|rl| {
            debug!("Comparing against rate limit path: {}", rl.path);
            base_path == rl.path
        }) {
            Some(rl) => rl,
            None => {
                // No rate limit for this path
                let fut = self.service.call(req);
                return Box::pin(async move {
                    fut.await.map(|res| res.map_into_left_body())
                });
            }
        };

        let ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut timestamps = self
            .rate_limits
            .entry(ip.clone())
            .or_insert_with(Vec::new)
            .value()
            .clone();

        // Remove timestamps outside the current window
        timestamps.retain(|&ts| now - ts < rate_limit.window_seconds);

        // Clean up old entries from the map periodically (every 10 requests)
        if now % 10 == 0 {
            self.rate_limits.retain(|_, v| {
                v.retain(|&ts| now - ts < rate_limit.window_seconds);
                !v.is_empty()
            });
        }

        debug!(
            "Rate limit check for {}: {}/{} requests in {}s window",
            base_path,
            timestamps.len(),
            rate_limit.max_requests,
            rate_limit.window_seconds
        );

        // Check if rate limit is exceeded
        if timestamps.len() >= rate_limit.max_requests as usize {
            warn!(
                "Rate limit exceeded for {} - {} requests in {}s window",
                base_path,
                timestamps.len(),
                rate_limit.window_seconds
            );
            let reset_time = timestamps[0] + rate_limit.window_seconds;
            let wait_seconds = reset_time.saturating_sub(now);
            let wait_minutes = (wait_seconds + 59) / 60;

            let error_response = HttpResponse::TooManyRequests()
                .append_header(("Retry-After", wait_seconds.to_string()))
                .json(serde_json::json!({
                    "error": rate_limit.error_message,
                    "message": format!("Please wait {} minutes before trying again", wait_minutes),
                    "retry_after": wait_seconds
                }));

            let (http_req, _) = req.into_parts();
            return Box::pin(async move {
                Ok(ServiceResponse::new(
                    http_req,
                    error_response.map_into_right_body()
                ))
            });
        }

        // Add current timestamp and update the map
        timestamps.push(now);
        self.rate_limits.insert(ip, timestamps);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
