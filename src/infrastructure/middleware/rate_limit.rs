use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpResponse};
use futures::future::{ok, Ready, LocalBoxFuture};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

// Struct for rate limiter middleware
#[derive(Clone)]
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    data: Arc<Mutex<HashMap<String, (Instant, usize)>>>,
}

impl RateLimiter {
    // Create a new RateLimiter instance
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimiterMiddleware {
            service,
            max_requests: self.max_requests,
            window: self.window,
            data: self.data.clone(),
        })
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    max_requests: usize,
    window: Duration,
    data: Arc<Mutex<HashMap<String, (Instant, usize)>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = match req.peer_addr() {
            Some(addr) => addr.ip().to_string(),
            None => "unknown".to_string(),
        };

        let mut data = self.data.lock().unwrap();
        let now = Instant::now();

        let entry = data.entry(client_ip).or_insert((now, 0));
        let (last_request_time, request_count) = entry;

        // If the time window has passed, reset the counter
        if now.duration_since(*last_request_time) > self.window {
            *last_request_time = now;
            *request_count = 1;
        } else {
            // If within the time window, increment the counter
            *request_count += 1;
        }

        // Check if the number of requests exceeds the limit
        if *request_count > self.max_requests {
            // Too many requests - return 429 Too Many Requests
            return Box::pin(async move {
                Ok(req.into_response(
                    HttpResponse::TooManyRequests()
                        .body("Too many requests, please try again later.")
                        .into_body(),
                ))
            });
        }

        // If the limit is not exceeded, proceed with the request
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
