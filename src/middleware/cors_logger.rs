use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use futures::future::{ok, Ready};
use futures::Future;
use log::info;
use std::pin::Pin;

pub struct CorsLogger;

impl<S, B> Transform<S, ServiceRequest> for CorsLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CorsLoggerMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CorsLoggerMiddleware { service })
    }
}

pub struct CorsLoggerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for CorsLoggerMiddleware<S>
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
        let origin = req.headers().get("Origin").and_then(|h| h.to_str().ok()).map(|s| s.to_owned());
        let is_cors = origin.is_some();

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            if is_cors {
                info!(
                    "CORS request: Origin: {:?}, Status: {}",
                    origin,
                    res.status()
                );
            }

            Ok(res)
        })
    }
}