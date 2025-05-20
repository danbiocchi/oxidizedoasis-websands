use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    web::{self}, 
    Error, HttpMessage, HttpResponse,
};
use actix_web::error::ResponseError;
use actix_web::http::StatusCode;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::future::{ready, Ready, LocalBoxFuture};
use log::{debug, error, info, warn};
use serde_json::json;
use std::fmt;
// Note: std::future::Future, std::pin::Pin, std::rc::Rc, std::task::{Context, Poll} are often implicitly used by LocalBoxFuture and other types.
// Explicit imports are kept if they were there, but might not be strictly necessary if types are fully qualified or brought in by other `use` statements.
 
 
use std::rc::Rc;
use std::sync::Arc; 
use std::task::{Context, Poll};

use crate::core::auth::jwt::{validate_jwt, TokenType};
use crate::core::auth::token_revocation::TokenRevocationServiceTrait;

#[derive(Debug)]
pub struct AuthError {
    pub message: String,
    pub status_code: StatusCode,
}

impl AuthError {
    pub fn new(message: String, status_code_u16: u16) -> Self {
        let sc = match StatusCode::from_u16(status_code_u16) {
            Ok(s) => {
                // Check if the status code is in a recognized HTTP category.
                // If not (e.g., 999), default to INTERNAL_SERVER_ERROR.
                if s.is_informational() || s.is_success() || s.is_redirection() || s.is_client_error() || s.is_server_error() {
                    s
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
            Err(_) => {
                // If from_u16 failed (e.g. code is truly invalid like 0 or > 999, though from_u16 handles 100-999)
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self {
            message,
            status_code: sc,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Status {}: {}", self.status_code, self.message)
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let error_reason = status.canonical_reason().unwrap_or_else(|| {
            if status.is_client_error() { "Client Error" }
            else if status.is_server_error() { "Server Error" }
            else { "Error" }
        });
        HttpResponse::build(status).json(json!({
            "error": error_reason,
            "message": self.message
        }))
    }
}

pub async fn jwt_auth_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    jwt_auth_validator_internal(req, Some(credentials)).await
}

pub async fn cookie_auth_validator(req: ServiceRequest) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    jwt_auth_validator_internal(req, None).await
}

async fn jwt_auth_validator_internal(
    req: ServiceRequest, credentials: Option<BearerAuth>) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let token_revocation_service_data = req.app_data::<web::Data<Arc<dyn TokenRevocationServiceTrait>>>().cloned();
    if token_revocation_service_data.is_none() {
        error!("TokenRevocationService not found in app_data for jwt_auth_validator_internal");
        return Err((AuthError::new(
            "Internal server configuration error".to_string(),
            500
        ).into(), req));
    }
    let token_revocation_service = token_revocation_service_data.unwrap().into_inner(); 
    
    let token = if let Some(cookie) = req.cookie("access_token") {
        cookie.value().to_string()
    } else if let Some(auth) = credentials {
        auth.token().to_string()
    } else {
        return Err((AuthError::new(
            "No authentication token found".to_string(),
            401
        ).into(), req));
    };

    debug!("Validating JWT token");
    let validation_result = validate_jwt(&token_revocation_service, &token[..], &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            info!("Token validated successfully for user: {}", claims.sub);
            let now = chrono::Utc::now().timestamp();
            let remaining_time = claims.exp - now;
            if remaining_time < 300 { 
                warn!("Token for user {} is about to expire in {} seconds", claims.sub, remaining_time);
            }
            req.extensions_mut().insert(claims);
            Ok(req)
        },
        Err(e) => {
            error!("Token validation failed: {:?}", e);
            Err((AuthError::new(
                "Invalid or expired token".to_string(),
                401
            ).into(), req))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        dev::ServiceRequest,
        http::{header, StatusCode},
        test, web::Data, Error as ActixError, HttpMessage, FromRequest, cookie::Cookie
    };
    use actix_web_httpauth::extractors::bearer::BearerAuth;
    use serde_json::Value;
    use std::sync::Arc;
    use crate::core::auth::jwt::{Claims, TokenType as JwtTokenType}; 
    use crate::core::auth::token_revocation::TokenRevocationServiceTrait;
    use mockall::mock;
    use sqlx::Error as SqlxError;
    use async_trait::async_trait;
    use uuid::Uuid;
    use std::env;
    use std::sync::Mutex;
    use chrono::{Utc, Duration};
    // use bytes::Bytes; // This was for CookieAuthMiddleware tests, not needed for this reverted state

    static ENV_MUTEX: Mutex<()> = Mutex::new(());
    const TEST_JWT_SECRET_AUTH: &str = "test_secret_key_for_auth_middleware";

    async fn run_test_with_env_vars_auth<F, Fut>(vars: Vec<(&str, Option<&str>)>, test_fn: F) -> Fut::Output
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future,
    {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut original_values = Vec::new();

        for (key, _) in &vars {
            original_values.push((key.to_string(), env::var(key).ok()));
        }
        for (key, value) in vars {
            if let Some(v) = value {
                env::set_var(key, v);
            } else {
                env::remove_var(key);
            }
        }
        
        let result = test_fn().await; // Await the future here

        for (key, original_value) in original_values {
            if let Some(orig_val) = original_value {
                env::set_var(key, orig_val);
            } else {
                env::remove_var(&key);
            }
        }
        result
    }

    mock! {
        pub TokenRevocationService {}
        #[async_trait]
        impl TokenRevocationServiceTrait for TokenRevocationService {
            async fn revoke_token<'a>(&self, jti: &'a str, user_id: Uuid, token_type: JwtTokenType, expires_at: chrono::DateTime<Utc>, reason: Option<&'a str>) -> Result<(), SqlxError>;
            async fn is_token_revoked(&self, jti: &str) -> Result<bool, SqlxError>;
            async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError>;
            async fn revoke_all_user_tokens<'a>(&self, user_id: Uuid, reason: Option<&'a str>) -> Result<u64, SqlxError>;
        }
    }

    fn generate_test_token_auth(user_id: Uuid, role: &str, secret: &str, exp_duration_secs: i64) -> String {
        let now = Utc::now();
        let iat_ts = now.timestamp();
        let claims = Claims {
            sub: user_id,
            role: role.to_string(),
            exp: (now + Duration::seconds(exp_duration_secs)).timestamp(),
            iat: iat_ts,
            nbf: iat_ts,
            jti: Uuid::new_v4().to_string(),
            token_type: JwtTokenType::Access,
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
        ).expect("Failed to generate test token for auth middleware")
    }

    #[actix_rt::test] 
    async fn test_auth_error_creation_and_response() {
        let auth_error_401 = AuthError::new("Unauthorized access".to_string(), 401);
        assert_eq!(auth_error_401.message, "Unauthorized access");
        assert_eq!(auth_error_401.status_code, StatusCode::UNAUTHORIZED);

        let response_401 = auth_error_401.error_response();
        assert_eq!(response_401.status(), StatusCode::UNAUTHORIZED);
        let srv_res_401 = test::TestRequest::default().to_srv_response(response_401);
        let body_401 = test::read_body_json::<Value, _>(srv_res_401).await; 
        assert_eq!(body_401["error"], "Unauthorized");
        assert_eq!(body_401["message"], "Unauthorized access");

        let auth_error_500 = AuthError::new("Server broke".to_string(), 500);
        assert_eq!(auth_error_500.message, "Server broke");
        assert_eq!(auth_error_500.status_code, StatusCode::INTERNAL_SERVER_ERROR);
        
        let response_500 = auth_error_500.error_response();
        assert_eq!(response_500.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let srv_res_500 = test::TestRequest::default().to_srv_response(response_500);
        let body_500 = test::read_body_json::<Value, _>(srv_res_500).await; 
        assert_eq!(body_500["error"], "Internal Server Error");
        assert_eq!(body_500["message"], "Server broke");

        let auth_error_invalid_status = AuthError::new("weird error".to_string(), 999); 
        assert_eq!(auth_error_invalid_status.status_code, StatusCode::INTERNAL_SERVER_ERROR); 
    }

    #[actix_rt::test]
    async fn test_jwt_auth_internal_valid_bearer_token() {
        let mut mock_rev_service = MockTokenRevocationService::new();
        mock_rev_service.expect_is_token_revoked().returning(|_| Ok(false));
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);

        let user_id = Uuid::new_v4();
        let token_str = generate_test_token_auth(user_id, "user", TEST_JWT_SECRET_AUTH, 3600);
        let bearer_auth = BearerAuth::from_request(
            &test::TestRequest::default().insert_header((header::AUTHORIZATION, format!("Bearer {}", token_str))).to_http_request(),
            &mut test::TestRequest::default().to_srv_request().into_parts().1 
        ).await.unwrap();
        
        let srv_req = test::TestRequest::default()
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = jwt_auth_validator_internal(srv_req, Some(bearer_auth)).await;
            assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
            let validated_req = result.unwrap();
            let claims = validated_req.extensions().get::<Claims>().unwrap().clone();
            assert_eq!(claims.sub, user_id);
            assert_eq!(claims.role, "user");
        }).await;
    }

    #[actix_rt::test]
    async fn test_jwt_auth_internal_valid_cookie_token() {
        let mut mock_rev_service = MockTokenRevocationService::new();
        mock_rev_service.expect_is_token_revoked().returning(|_| Ok(false));
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);

        let user_id = Uuid::new_v4();
        let token_str = generate_test_token_auth(user_id, "user", TEST_JWT_SECRET_AUTH, 3600);
        
        let srv_req = test::TestRequest::default()
            .cookie(Cookie::new("access_token", token_str.clone()))
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = jwt_auth_validator_internal(srv_req, None).await;
            assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
            let validated_req = result.unwrap();
            let claims = validated_req.extensions().get::<Claims>().unwrap().clone();
            assert_eq!(claims.sub, user_id);
        }).await;
    }

    #[actix_rt::test]
    async fn test_jwt_auth_internal_no_token() {
        let mock_rev_service = MockTokenRevocationService::new(); 
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);
        
        let srv_req = test::TestRequest::default()
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = jwt_auth_validator_internal(srv_req, None).await;
            assert!(result.is_err());
            let (err, _) = result.err().unwrap();
            let http_response = err.error_response();
            assert_eq!(http_response.status(), StatusCode::UNAUTHORIZED);
            let srv_res = test::TestRequest::default().to_srv_response(http_response);
            let body = test::read_body_json::<Value, _>(srv_res).await;
            assert_eq!(body["message"], "No authentication token found");
        }).await;
    }

    #[actix_rt::test]
    async fn test_jwt_auth_internal_invalid_token() {
        let mut mock_rev_service = MockTokenRevocationService::new();
        mock_rev_service.expect_is_token_revoked().returning(|_| Ok(false)).times(0..); 
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);

        let token_str = "this.is.not.a.valid.jwt".to_string();
         let bearer_auth = BearerAuth::from_request(
            &test::TestRequest::default().insert_header((header::AUTHORIZATION, format!("Bearer {}", token_str))).to_http_request(),
            &mut test::TestRequest::default().to_srv_request().into_parts().1
        ).await.unwrap();
        
        let srv_req = test::TestRequest::default()
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = jwt_auth_validator_internal(srv_req, Some(bearer_auth)).await;
            assert!(result.is_err());
            let (err, _) = result.err().unwrap();
            let http_response = err.error_response();
            assert_eq!(http_response.status(), StatusCode::UNAUTHORIZED);
            let srv_res = test::TestRequest::default().to_srv_response(http_response);
            let body = test::read_body_json::<Value, _>(srv_res).await;
            assert_eq!(body["message"], "Invalid or expired token");
        }).await;
    }
    
    #[actix_rt::test]
    async fn test_jwt_auth_validator_wrapper_valid() {
        let mut mock_rev_service = MockTokenRevocationService::new();
        mock_rev_service.expect_is_token_revoked().returning(|_| Ok(false));
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);

        let user_id = Uuid::new_v4();
        let token_str = generate_test_token_auth(user_id, "user", TEST_JWT_SECRET_AUTH, 3600);
        
        let srv_req_for_extraction = test::TestRequest::default()
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token_str)))
            .to_srv_request();
        let (http_req, mut payload) = srv_req_for_extraction.into_parts();
        let bearer_auth = BearerAuth::from_request(&http_req, &mut payload).await.unwrap();
        
        let srv_req = test::TestRequest::default()
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = jwt_auth_validator(srv_req, bearer_auth).await;
            assert!(result.is_ok());
            let validated_req = result.unwrap();
            let claims = validated_req.extensions().get::<Claims>().unwrap().clone();
            assert_eq!(claims.sub, user_id);
        }).await;
    }

    #[actix_rt::test]
    async fn test_cookie_auth_validator_wrapper_valid_cookie() {
        let mut mock_rev_service = MockTokenRevocationService::new();
        mock_rev_service.expect_is_token_revoked().returning(|_| Ok(false));
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);

        let user_id = Uuid::new_v4();
        let token_str = generate_test_token_auth(user_id, "user", TEST_JWT_SECRET_AUTH, 3600);
        
        let srv_req = test::TestRequest::default()
            .cookie(Cookie::new("access_token", token_str.clone()))
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = cookie_auth_validator(srv_req).await;
            assert!(result.is_ok());
            let validated_req = result.unwrap();
            let claims = validated_req.extensions().get::<Claims>().unwrap().clone();
            assert_eq!(claims.sub, user_id);
        }).await;
    }

    #[actix_rt::test]
    async fn test_cookie_auth_validator_wrapper_no_cookie() {
        let mock_rev_service = MockTokenRevocationService::new();
        let app_data_rev_service = Data::new(Arc::new(mock_rev_service) as Arc<dyn TokenRevocationServiceTrait>);
        
        let srv_req = test::TestRequest::default()
            .app_data(app_data_rev_service.clone())
            .to_srv_request();

        run_test_with_env_vars_auth(vec![("JWT_SECRET", Some(TEST_JWT_SECRET_AUTH))], || async {
            let result = cookie_auth_validator(srv_req).await;
            assert!(result.is_err());
            let (err, _) = result.err().unwrap();
            let http_response = err.error_response();
            assert_eq!(http_response.status(), StatusCode::UNAUTHORIZED);
            let srv_res = test::TestRequest::default().to_srv_response(http_response);
            let body = test::read_body_json::<Value, _>(srv_res).await;
            assert_eq!(body["message"], "No authentication token found");
        }).await;
    }
    
    // TODO: Add tests for CookieAuthMiddleware (CSRF, etc.)
}

pub struct CookieAuth;

impl CookieAuth {
    #[allow(dead_code)]
    pub fn new() -> Self {
        CookieAuth
    }
}

impl<S, B> Transform<S, ServiceRequest> for CookieAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CookieAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CookieAuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct CookieAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for CookieAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        
        let csrf_header = req.headers().get("X-CSRF-Token").cloned();
        let csrf_cookie = req.cookie("csrf_token");
        
        if req.method() != actix_web::http::Method::GET {
            if csrf_header.is_none() || csrf_cookie.is_none() {
                return Box::pin(async move {
                    Err(Error::from(AuthError::new(
                        "CSRF token missing".to_string(),
                        403,
                    )))
                });
            }
            if let (Some(header), Some(cookie)) = (csrf_header, csrf_cookie) {
                if header.to_str().unwrap_or("") != cookie.value() {
                    return Box::pin(async move {
                        Err(Error::from(AuthError::new(
                            "CSRF token mismatch".to_string(),
                            403,
                        )))
                    });
                }
            }
        }
        
        Box::pin(async move {
            let token = match req.cookie("access_token") {
                Some(cookie) => cookie.value().to_string(),
                None => {
                    debug!("No access_token cookie found");
                    return Err(Error::from(AuthError::new(
                        "No access_token cookie found".to_string(),
                        401,
                    )));
                }
            };
            
            let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

            let token_revocation_service_data = req.app_data::<web::Data<Arc<dyn TokenRevocationServiceTrait>>>().cloned();
            
            let token_revocation_service = match token_revocation_service_data {
                Some(service_data) => service_data.into_inner(),
                None => {
                    error!("TokenRevocationService not found in app_data for CookieAuthMiddleware");
                    return Err(Error::from(AuthError::new(
                        "Internal server configuration error".to_string(),
                        500,
                    )));
                }
            };

            match validate_jwt(&token_revocation_service, &token, &jwt_secret, Some(TokenType::Access)).await {
                Ok(claims) => {
                    debug!("Token validated successfully for user: {}", claims.sub);
                    req.extensions_mut().insert(claims);
                    service.call(req).await
                },
                Err(e) => {
                    error!("Token validation failed: {:?}", e);
                    Err(Error::from(AuthError::new(
                        "Invalid or expired token".to_string(),
                        401,
                    )))
                }
            }
        })
    }
}

pub async fn cookie_auth_middleware(
    req: ServiceRequest,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let token_revocation_service_data = req.app_data::<web::Data<Arc<dyn TokenRevocationServiceTrait>>>().cloned();
    if token_revocation_service_data.is_none() {
        error!("TokenRevocationService not found in app_data for cookie_auth_middleware");
        return Err((AuthError::new(
            "Internal server configuration error".to_string(),
            500
        ).into(), req));
    }
    let token_revocation_service = token_revocation_service_data.unwrap().into_inner();
    
    let token = match req.cookie("access_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            debug!("No access_token cookie found");
            return Err((
                AuthError::new(
                    "No access token cookie found".to_string(),
                    401
                ).into(),
                req
            ));
        }
    };

    debug!("Validating JWT token from cookie");
    let validation_result = validate_jwt(&token_revocation_service, &token, &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            info!("Cookie token validated successfully for user: {}", claims.sub);
            let now = chrono::Utc::now().timestamp();
            let remaining_time = claims.exp - now;
            if remaining_time < 300 { 
                warn!("Token for user {} is about to expire in {} seconds", claims.sub, remaining_time);
            }
            req.extensions_mut().insert(claims);
            Ok(req)
        },
        Err(e) => {
            error!("Cookie token validation failed: {:?}", e);
            Err((
                AuthError::new(
                    "Invalid or expired token in cookie".to_string(),
                    401
                ).into(),
                req
            ))
        },
    }
}
