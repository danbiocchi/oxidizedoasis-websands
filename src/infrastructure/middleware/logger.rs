use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use futures::future::{ok, Ready};
use log::{debug, info, warn};
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

pub struct RequestLogger;

impl RequestLogger {
    pub fn new() -> Self {
        RequestLogger
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestLoggerMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestLoggerMiddleware { service })
    }
}

pub struct RequestLoggerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = Instant::now();
        let method = req.method().clone();
        let path = req.path().to_string();
        let remote_addr = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
        let headers = req.headers().clone();

        debug!(
            "Incoming request: {} {} from {} with {} headers",
            method,
            path,
            remote_addr,
            headers.len()
        );

        let fut = self.service.call(req);

        Box::pin(async move {
            let response = fut.await?;
            let duration = start_time.elapsed();
            let status = response.status();

            // Log based on status code
            match status.as_u16() {
                200..=299 => {
                    info!(
                        "SUCCESS: {} {} {} [{}ms] from {}",
                        method,
                        path,
                        status.as_u16(),
                        duration.as_millis(),
                        remote_addr
                    );
                }
                400..=499 => {
                    warn!(
                        "CLIENT ERROR: {} {} {} [{}ms] from {}",
                        method,
                        path,
                        status.as_u16(),
                        duration.as_millis(),
                        remote_addr
                    );
                }
                500..=599 => {
                    warn!(
                        "SERVER ERROR: {} {} {} [{}ms] from {}",
                        method,
                        path,
                        status.as_u16(),
                        duration.as_millis(),
                        remote_addr
                    );
                }
                _ => {
                    info!(
                        "OTHER: {} {} {} [{}ms] from {}",
                        method,
                        path,
                        status.as_u16(),
                        duration.as_millis(),
                        remote_addr
                    );
                }
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    #[actix_rt::test]
    async fn test_logger_middleware() {
        let app = test::init_service(
            App::new()
                .wrap(RequestLogger::new())
                .route("/test", web::get().to(|| async { HttpResponse::Ok().body("test") }))
        ).await;

        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_logger_middleware_error() {
        let app = test::init_service(
            App::new()
                .wrap(RequestLogger::new())
                .route("/error", web::get().to(|| async {
                    HttpResponse::InternalServerError().body("error")
                }))
        ).await;

        let req = test::TestRequest::get().uri("/error").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_server_error());
    }
}