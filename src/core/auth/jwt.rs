use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration, DateTime};
use uuid::Uuid;
use log::{debug, error, info, warn};
use std::env;
use std::sync::Arc;
// Import the new traits
use crate::core::auth::token_revocation::TokenRevocationServiceTrait;
use crate::core::auth::active_token::ActiveTokenServiceTrait;

// Static variables removed, services will be passed as arguments.

/// JWT Claims structure with enhanced security
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid,        // Subject (user ID)
    pub exp: i64,         // Expiration time
    pub iat: i64,         // Issued at time
    pub nbf: i64,         // Not valid before time
    pub jti: String,      // JWT ID (unique identifier for this token)
    pub role: String,     // User role
    pub token_type: TokenType, // Token type (access or refresh)
}

/// Token types to distinguish between access and refresh tokens
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

/// Token pair containing both access and refresh tokens
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// Token metadata containing additional information about a token
#[derive(Debug, Clone)]
pub struct TokenMetadata {
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}

/// Get token expiration time based on token type and environment configuration
fn get_token_expiration(token_type: &TokenType) -> i64 {
    let now = Utc::now();
    
    match token_type {
        TokenType::Access => {
            let minutes = env::var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES")
                .unwrap_or_else(|_| "30".to_string())
                .parse::<i64>()
                .unwrap_or(30);
            now.checked_add_signed(Duration::minutes(minutes))
                .expect("valid timestamp")
                .timestamp() // No semicolon
        }
        TokenType::Refresh => {
            let days = env::var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS")
                .unwrap_or_else(|_| "7".to_string())
                .parse::<i64>()
                .unwrap_or(7);
            now.checked_add_signed(Duration::days(days))
                .expect("valid timestamp")
                .timestamp() // No semicolon
        }
    }
}

/// Convert timestamp to DateTime<Utc>
pub(crate) fn timestamp_to_datetime(timestamp: i64) -> DateTime<Utc> { // Made pub(crate)
    use chrono::TimeZone;
    match Utc.timestamp_opt(timestamp, 0) {
        chrono::LocalResult::Single(dt) => dt,
        _ => Utc::now(), 
    }
}

/// Create a new JWT token for a user
pub fn create_jwt(
    user_id: Uuid,
    role: String,
    secret: &str,
    token_type: TokenType
) -> Result<(String, TokenMetadata), jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let expiration = get_token_expiration(&token_type);
    let jti = Uuid::new_v4().to_string();
    
    let claims = Claims {
        sub: user_id,
        exp: expiration,
        iat: now,
        nbf: now,
        jti: jti.clone(), 
        role,
        token_type: token_type.clone(),
    };

    info!("Creating {} token for user {} with expiration in {} seconds",
          if token_type == TokenType::Access { "access" } else { "refresh" },
          user_id,
          expiration - now);

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).map_err(|e| {
        error!("Failed to create JWT: {:?}", e);
        e
    })?;
    
    let metadata = TokenMetadata {
        jti, 
        expires_at: timestamp_to_datetime(expiration),
    };
    
    Ok((token, metadata))
}

/// Create a token pair (access token + refresh token)
pub fn create_token_pair(
    user_id: Uuid,
    role: String,
    secret: &str
) -> Result<TokenPair, jsonwebtoken::errors::Error> {
    let (access_token, _access_metadata) = create_jwt(user_id, role.clone(), secret, TokenType::Access)?;
    let (refresh_token, _refresh_metadata) = create_jwt(user_id, role, secret, TokenType::Refresh)?;
    
    let token_pair = TokenPair {
        access_token,
        refresh_token,
    };
    
    Ok(token_pair)
}

/// Record a token in the active tokens table
pub async fn record_active_token(
    active_token_service: &Arc<dyn ActiveTokenServiceTrait>,
    user_id: Uuid,
    metadata: &TokenMetadata,
    token_type: TokenType
) {
    if let Err(e) = active_token_service.record_token(
        user_id,
        &metadata.jti,
        token_type,
        metadata.expires_at,
        None, // device_info is Option<serde_json::Value>
    ).await {
        error!("Failed to record active token: {:?}", e);
    }
}

/// Validate a JWT token
pub async fn validate_jwt(
    token_revocation_service: &Arc<dyn TokenRevocationServiceTrait>,
    token: &str,
    secret: &str,
    expected_type: Option<TokenType>
) -> Result<Claims, jsonwebtoken::errors::Error> {
    debug!("Attempting to validate JWT");

    let mut validation = Validation::default();
    validation.leeway = 60; 
    validation.validate_nbf = true; // Enable NBF (Not Before) claim validation
    
    match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation) {
        Ok(token_data) => {
            let claims = token_data.claims;
            
            if let Some(expected) = expected_type {
                if claims.token_type != expected {
                    error!("Token type mismatch: expected {:?}, got {:?}", expected, claims.token_type);
                    return Err(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken
                    ));
                }
            }

            if is_token_revoked(token_revocation_service, &claims.jti).await {
                error!("Token has been revoked: {}", claims.jti);
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken
                ));
            }

            debug!("JWT validated successfully for user: {}", claims.sub);
            Ok(claims)
        },
        Err(e) => {
            error!("JWT validation failed: {:?}", e);
            Err(e)
        }
    }
}

// init_token_revocation and init_active_token_service are removed as services will be injected.

pub async fn is_token_revoked(
    token_revocation_service: &Arc<dyn TokenRevocationServiceTrait>,
    jti: &str
) -> bool {
    match token_revocation_service.is_token_revoked(jti).await {
        Ok(is_revoked) => is_revoked,
        Err(e) => {
            error!("Error checking token revocation: {:?}", e);
            true // Default to revoked on error for security
        }
    }
}

pub async fn refresh_token_pair(
    token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
    active_token_service: Arc<dyn ActiveTokenServiceTrait>,
    refresh_token_str: &str,
    secret: &str
) -> Result<TokenPair, jsonwebtoken::errors::Error> {
    let refresh_claims = match validate_jwt(&token_revocation_service, refresh_token_str, secret, Some(TokenType::Refresh)).await {
        Ok(claims) => claims,
        Err(e) => return Err(e),
    };

    let (access_token, access_metadata) = create_jwt(refresh_claims.sub, refresh_claims.role.clone(), secret, TokenType::Access)?;
    let (new_refresh_token, refresh_metadata) = create_jwt(refresh_claims.sub, refresh_claims.role.clone(), secret, TokenType::Refresh)?;

    let sub_clone = refresh_claims.sub;
    let access_meta_clone = access_metadata.clone();
    let refresh_meta_clone = refresh_metadata.clone();
    let active_token_service_clone_for_record = active_token_service.clone();

    tokio::spawn(async move {
        record_active_token(&active_token_service_clone_for_record, sub_clone, &access_meta_clone, TokenType::Access).await;
        record_active_token(&active_token_service_clone_for_record, sub_clone, &refresh_meta_clone, TokenType::Refresh).await;
    });

    let jti_clone = refresh_claims.jti.clone();
    let sub_clone_revoke = refresh_claims.sub;
    let token_revocation_service_clone_for_revoke = token_revocation_service.clone();
    let active_token_service_clone_for_revoke = active_token_service.clone(); 

    tokio::spawn(async move {
        revoke_token(&token_revocation_service_clone_for_revoke, &active_token_service_clone_for_revoke, &jti_clone, sub_clone_revoke, TokenType::Refresh, "Refresh token rotation").await;
    });

    Ok(TokenPair {
        access_token,
        refresh_token: new_refresh_token,
    })
}

pub(crate) async fn revoke_token(
    token_revocation_service: &Arc<dyn TokenRevocationServiceTrait>,
    active_token_service: &Arc<dyn ActiveTokenServiceTrait>,
    jti: &str,
    user_id: Uuid,
    token_type: TokenType,
    reason: &str
) {
    match active_token_service.get_active_token(jti).await {
        Ok(active_token_details) => {
            if let Err(e) = token_revocation_service.revoke_token(
                jti,
                user_id,
                token_type,
                active_token_details.expires_at,
                Some(reason), // Pass reason as &str
            ).await {
                error!("Failed to revoke token {}: {:?}", jti, e);
            }
        }
        Err(e) => {
            error!("Failed to get active token details for JTI {} during revocation attempt: {:?}", jti, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use jsonwebtoken::{decode, DecodingKey, Validation, errors::ErrorKind};
    use std::env;
    use async_trait::async_trait; // For mocking traits
    use sqlx::Error as SqlxError; // For mock trait signatures
    use crate::core::auth::active_token::ActiveToken; // For MockActiveTokenService if needed

    const TEST_SECRET: &str = "test_secret_key_for_jwt_testing_longer_than_16_bytes";

    // Mock implementation for TokenRevocationServiceTrait
    struct MockTokenRevocationService;
    #[async_trait]
    impl TokenRevocationServiceTrait for MockTokenRevocationService {
        async fn revoke_token<'a>(&self, _jti: &'a str, _user_id: Uuid, _token_type: TokenType, _expires_at: DateTime<Utc>, _reason: Option<&'a str>) -> Result<(), SqlxError> {
            Ok(())
        }
        async fn is_token_revoked(&self, _jti: &str) -> Result<bool, SqlxError> {
            Ok(false)
        }
        async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError> {
            Ok(0)
        }
        async fn revoke_all_user_tokens<'a>(&self, _user_id: Uuid, _reason: Option<&'a str>) -> Result<u64, SqlxError> {
            Ok(0)
        }
    }

    // Mock implementation for ActiveTokenServiceTrait
    struct MockActiveTokenService;
    #[async_trait]
    impl ActiveTokenServiceTrait for MockActiveTokenService {
        async fn record_token(&self, _user_id: Uuid, _jti: &str, _token_type: TokenType, _expires_at: DateTime<Utc>, _device_info: Option<serde_json::Value>) -> Result<(), SqlxError> { Ok(()) }
        async fn get_active_token(&self, jti: &str) -> Result<ActiveToken, SqlxError> {
            Ok(ActiveToken {
                id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                jti: jti.to_string(),
                token_type: "Access".to_string(), 
                expires_at: Utc::now() + Duration::hours(1),
                created_at: Utc::now(),
                device_info: None,
            })
        }
        async fn remove_token(&self, _jti: &str) -> Result<bool, SqlxError> { Ok(false) }
        async fn get_user_tokens(&self, _user_id: Uuid) -> Result<Vec<ActiveToken>, SqlxError> { Ok(vec![]) }
        async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError> { Ok(0) }
        async fn remove_all_user_tokens(&self, _user_id: Uuid) -> Result<u64, SqlxError> { Ok(0) }
    }

    fn setup_test_environment() {
        env::set_var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES", "1"); 
        env::set_var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS", "1"); 
    }

    #[test]
    fn test_jwt_generation_creates_valid_access_token_claims() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "user".to_string();
        let token_type = TokenType::Access;

        let (token_str, metadata) =
            create_jwt(user_id, role.clone(), TEST_SECRET, token_type.clone()).unwrap();

        let decoding_key = DecodingKey::from_secret(TEST_SECRET.as_ref());
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.leeway = 0;
        let decoded_token = decode::<Claims>(&token_str, &decoding_key, &validation).unwrap();
        let claims = decoded_token.claims;

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, token_type);
        assert!(!claims.jti.is_empty());
        assert_eq!(claims.jti, metadata.jti);

        let now = Utc::now().timestamp();
        let expected_exp_min = Utc::now()
            .checked_add_signed(Duration::minutes(1)) 
            .unwrap()
            .timestamp();
        
        assert!(claims.iat <= now + 2 && claims.iat >= now - 2); 
        assert!(claims.nbf <= now + 2 && claims.nbf >= now - 2); 
        assert!(claims.exp <= expected_exp_min + 2 && claims.exp >= expected_exp_min - 2, "Access token exp mismatch. Now: {}, Expected: {}, Actual: {}", now, expected_exp_min, claims.exp);
        assert_eq!(metadata.expires_at, timestamp_to_datetime(claims.exp));
    }

    #[test]
    fn test_jwt_generation_creates_valid_refresh_token_claims() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "admin".to_string();
        let token_type = TokenType::Refresh;

        let (token_str, metadata) =
            create_jwt(user_id, role.clone(), TEST_SECRET, token_type.clone()).unwrap();

        let decoding_key = DecodingKey::from_secret(TEST_SECRET.as_ref());
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.leeway = 0;
        let decoded_token = decode::<Claims>(&token_str, &decoding_key, &validation).unwrap();
        let claims = decoded_token.claims;

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, token_type);
        assert!(!claims.jti.is_empty());
        assert_eq!(claims.jti, metadata.jti);

        let now = Utc::now().timestamp();
        let expected_exp_days = Utc::now()
            .checked_add_signed(Duration::days(1))
            .unwrap()
            .timestamp();
        
        assert!(claims.iat <= now + 2 && claims.iat >= now - 2);
        assert!(claims.nbf <= now + 2 && claims.nbf >= now - 2);
        assert!(claims.exp <= expected_exp_days + 2 && claims.exp >= expected_exp_days - 2, "Refresh token exp mismatch. Now: {}, Expected: {}, Actual: {}", now, expected_exp_days, claims.exp);
        assert_eq!(metadata.expires_at, timestamp_to_datetime(claims.exp));
    }

    #[test]
    fn test_create_token_pair_generates_both_tokens() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "user".to_string();

        let token_pair = create_token_pair(user_id, role.clone(), TEST_SECRET).unwrap();

        assert!(!token_pair.access_token.is_empty());
        assert!(!token_pair.refresh_token.is_empty());

        let decoding_key = DecodingKey::from_secret(TEST_SECRET.as_ref());
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.leeway = 0;

        let decoded_access_token =
            decode::<Claims>(&token_pair.access_token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded_access_token.claims.sub, user_id);
        assert_eq!(decoded_access_token.claims.token_type, TokenType::Access);

        let decoded_refresh_token =
            decode::<Claims>(&token_pair.refresh_token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded_refresh_token.claims.sub, user_id);
        assert_eq!(decoded_refresh_token.claims.token_type, TokenType::Refresh);
    }
    
    #[test]
    fn test_get_token_expiration_uses_env_vars_or_defaults() {
        let original_access_exp = env::var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES").ok();
        let original_refresh_exp = env::var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS").ok();

        env::remove_var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES");
        let now = Utc::now();
        let default_access_exp_timestamp = get_token_expiration(&TokenType::Access);
        let expected_default_access_exp = now.checked_add_signed(Duration::minutes(30)).unwrap().timestamp();
        assert!(default_access_exp_timestamp >= expected_default_access_exp - 5 && default_access_exp_timestamp <= expected_default_access_exp + 5);

        env::set_var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES", "60");
        let configured_access_exp_timestamp = get_token_expiration(&TokenType::Access);
        let expected_configured_access_exp = now.checked_add_signed(Duration::minutes(60)).unwrap().timestamp();
        assert!(configured_access_exp_timestamp >= expected_configured_access_exp - 5 && configured_access_exp_timestamp <= expected_configured_access_exp + 5);

        env::remove_var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS");
        let default_refresh_exp_timestamp = get_token_expiration(&TokenType::Refresh);
        let expected_default_refresh_exp = now.checked_add_signed(Duration::days(7)).unwrap().timestamp();
        assert!(default_refresh_exp_timestamp >= expected_default_refresh_exp - 5 && default_refresh_exp_timestamp <= expected_default_refresh_exp + 5);

        env::set_var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS", "30");
        let configured_refresh_exp_timestamp = get_token_expiration(&TokenType::Refresh);
        let expected_configured_refresh_exp = now.checked_add_signed(Duration::days(30)).unwrap().timestamp();
        assert!(configured_refresh_exp_timestamp >= expected_configured_refresh_exp - 5 && configured_refresh_exp_timestamp <= expected_configured_refresh_exp + 5);

        if let Some(val) = original_access_exp {
            env::set_var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES", val);
        } else {
            env::remove_var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES");
        }
        if let Some(val) = original_refresh_exp {
            env::set_var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS", val);
        } else {
            env::remove_var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS");
        }
    }

    #[tokio::test]
    async fn test_validate_jwt_valid_token() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();
        let (token_str, _metadata) =
            create_jwt(user_id, role.clone(), TEST_SECRET, TokenType::Access).unwrap();

        let mock_revocation_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockTokenRevocationService);

        let claims_result = validate_jwt(&mock_revocation_service, &token_str, TEST_SECRET, Some(TokenType::Access)).await;
        assert!(claims_result.is_ok());
        let claims = claims_result.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[tokio::test]
    async fn test_validate_jwt_expired_token() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();
        
        let expired_iat = Utc::now().checked_sub_signed(Duration::minutes(10)).unwrap().timestamp();
        let expired_exp = Utc::now().checked_sub_signed(Duration::minutes(5)).unwrap().timestamp();
        let expired_claims = Claims {
            sub: user_id,
            exp: expired_exp,
            iat: expired_iat,
            nbf: expired_iat,
            jti: Uuid::new_v4().to_string(),
            role: role.clone(),
            token_type: TokenType::Access,
        };
        let token_str = encode(
            &Header::default(),
            &expired_claims,
            &EncodingKey::from_secret(TEST_SECRET.as_ref()),
        ).unwrap();

        let mock_revocation_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockTokenRevocationService);

        let claims_result = validate_jwt(&mock_revocation_service, &token_str, TEST_SECRET, Some(TokenType::Access)).await;
        assert!(claims_result.is_err());
        assert!(matches!(
            claims_result.unwrap_err().kind(),
            jsonwebtoken::errors::ErrorKind::ExpiredSignature
        ));
    }

    // Helper struct for testing revoked tokens
    struct MockRevokedTokenRevocationService;
    #[async_trait]
    impl TokenRevocationServiceTrait for MockRevokedTokenRevocationService {
        async fn revoke_token<'a>(&self, _jti: &'a str, _user_id: Uuid, _token_type: TokenType, _expires_at: DateTime<Utc>, _reason: Option<&'a str>) -> Result<(), SqlxError> { Ok(()) }
        async fn is_token_revoked(&self, _jti: &str) -> Result<bool, SqlxError> { Ok(true) } // Always returns true
        async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError> { Ok(0) }
        async fn revoke_all_user_tokens<'a>(&self, _user_id: Uuid, _reason: Option<&'a str>) -> Result<u64, SqlxError> { Ok(0) }
    }

    #[tokio::test]
    async fn test_validate_jwt_revoked_token() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();
        let (token_str, _metadata) = create_jwt(user_id, role.clone(), TEST_SECRET, TokenType::Access).unwrap();

        let mock_revoked_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockRevokedTokenRevocationService);
        let claims_result = validate_jwt(&mock_revoked_service, &token_str, TEST_SECRET, Some(TokenType::Access)).await;
        assert!(claims_result.is_err());
        assert!(matches!(claims_result.unwrap_err().kind(), jsonwebtoken::errors::ErrorKind::InvalidToken), "Expected InvalidToken for revoked token");
    }


    #[tokio::test]
    async fn test_validate_jwt_token_not_yet_valid() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();

        let future_nbf = Utc::now().checked_add_signed(Duration::minutes(5)).unwrap().timestamp();
        let future_exp = Utc::now().checked_add_signed(Duration::minutes(10)).unwrap().timestamp();
        let future_claims = Claims {
            sub: user_id,
            exp: future_exp,
            iat: Utc::now().timestamp(),
            nbf: future_nbf,
            jti: Uuid::new_v4().to_string(),
            role: role.clone(),
            token_type: TokenType::Access,
        };
        let token_str = encode(
            &Header::default(),
            &future_claims,
            &EncodingKey::from_secret(TEST_SECRET.as_ref()),
        ).unwrap();
        
        let mock_revocation_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockTokenRevocationService);

        let claims_result = validate_jwt(&mock_revocation_service, &token_str, TEST_SECRET, Some(TokenType::Access)).await;
        assert!(claims_result.is_err());
        assert!(matches!(
            claims_result.unwrap_err().kind(),
            jsonwebtoken::errors::ErrorKind::ImmatureSignature
        ));
    }

    #[tokio::test]
    async fn test_validate_jwt_invalid_signature() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();
        let (token_str, _metadata) =
            create_jwt(user_id, role.clone(), TEST_SECRET, TokenType::Access).unwrap();

        let mock_revocation_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockTokenRevocationService);
        
        let claims_result = validate_jwt(&mock_revocation_service, &token_str, "wrong_secret_shhh", Some(TokenType::Access)).await;
        assert!(claims_result.is_err());
        assert!(matches!(
            claims_result.unwrap_err().kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSignature
        ));
    }

    #[tokio::test]
    async fn test_validate_jwt_incorrect_token_type() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();
        let (token_str, _metadata) =
            create_jwt(user_id, role.clone(), TEST_SECRET, TokenType::Refresh).unwrap();

        let mock_revocation_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockTokenRevocationService);

        let claims_result = validate_jwt(&mock_revocation_service, &token_str, TEST_SECRET, Some(TokenType::Access)).await;
        assert!(claims_result.is_err());
        assert!(matches!(
            claims_result.unwrap_err().kind(),
            jsonwebtoken::errors::ErrorKind::InvalidToken
        ));
    }
    
    #[tokio::test]
    async fn test_validate_jwt_missing_expected_type_still_validates_if_token_ok() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let role = "test_role".to_string();
        let (token_str, _metadata) =
            create_jwt(user_id, role.clone(), TEST_SECRET, TokenType::Access).unwrap();

        let mock_revocation_service: Arc<dyn TokenRevocationServiceTrait> = Arc::new(MockTokenRevocationService);

        let claims_result = validate_jwt(&mock_revocation_service, &token_str, TEST_SECRET, None).await;
        assert!(claims_result.is_ok());
        let claims = claims_result.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.token_type, TokenType::Access);
    }
}
