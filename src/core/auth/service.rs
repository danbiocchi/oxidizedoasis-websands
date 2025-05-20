// src/core/auth/service.rs
use bcrypt::verify;
use crate::common::{
    error::{AuthError, AuthErrorType},
    validation::LoginInput,
};
use crate::core::user::{User, UserRepositoryTrait};
use std::sync::Arc;
use super::jwt::{self, Claims, TokenType, TokenPair, create_token_pair, TokenMetadata};
use crate::core::auth::token_revocation::TokenRevocationServiceTrait;
use crate::core::auth::active_token::ActiveTokenServiceTrait;
use log::{info, warn};

pub struct AuthService {
    user_repository: Arc<dyn UserRepositoryTrait>,
    jwt_secret: String,
    token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
    active_token_service: Arc<dyn ActiveTokenServiceTrait>,
}

impl AuthService {
    pub fn new(
        user_repository: Arc<dyn UserRepositoryTrait>,
        jwt_secret: String,
        token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
        active_token_service: Arc<dyn ActiveTokenServiceTrait>,
    ) -> Self {
        Self {
            user_repository,
            jwt_secret,
            token_revocation_service,
            active_token_service,
        }
    }

    pub async fn login(&self, input: LoginInput) -> Result<(TokenPair, User), AuthError> {
        let user = self.user_repository.find_by_username(&input.username)
            .await
            .map_err(|e| {
                warn!("Login: User repository error on find_by_username for {}: {:?}", input.username, e);
                AuthError::new(AuthErrorType::InvalidCredentials)
            })?
            .ok_or_else(|| {
                warn!("Login: User not found by username: {}", input.username);
                AuthError::new(AuthErrorType::InvalidCredentials)
            })?;

        if !user.is_email_verified {
            warn!("Login: Email not verified for user: {}", user.username);
            return Err(AuthError::new(AuthErrorType::EmailNotVerified));
        }

        if !verify(&input.password, &user.password_hash)
            .map_err(|e| {
                warn!("Login: Password verification (bcrypt) error for user {}: {:?}", user.username, e);
                AuthError::new(AuthErrorType::InternalServerError) 
            })? {
            warn!("Login: Invalid password for user: {}", user.username);
            return Err(AuthError::new(AuthErrorType::InvalidCredentials));
        }

        info!("Login: Generating token pair for user: {}", user.id);
        let token_pair = create_token_pair(user.id, user.role.clone(), &self.jwt_secret)
            .map_err(|e| {
                warn!("Login: Failed to create token pair for user {}: {:?}", user.id, e);
                AuthError::new(AuthErrorType::TokenCreationError)
            })?;
            
        if let Err(e) = self.record_tokens_for_user(user.id, &token_pair).await {
            warn!("Login: Failed to record tokens for user {}: {:?}", user.id, e);
        }

        Ok((token_pair, user))
    }

    pub async fn validate_auth(&self, token: &str) -> Result<Claims, AuthError> {
        let claims = match jwt::validate_jwt(&self.token_revocation_service, token, &self.jwt_secret, Some(TokenType::Access)).await {
            Ok(claims) => claims,
            Err(e) => {
                warn!("Token validation failed: {:?}", e);
                return Err(AuthError::new(AuthErrorType::InvalidToken));
            }
        };

        let user = self.user_repository.find_by_id(claims.sub)
            .await
            .map_err(|e| {
                warn!("Validate_auth: User repository error on find_by_id for {}: {:?}", claims.sub, e);
                AuthError::new(AuthErrorType::InvalidToken) 
            })?
            .ok_or_else(|| {
                warn!("Validate_auth: User not found by id from token: {}", claims.sub);
                AuthError::new(AuthErrorType::InvalidToken)
            })?;

        if !user.is_email_verified {
            warn!("Validate_auth: Email not verified for user from token: {}", user.username);
            return Err(AuthError::new(AuthErrorType::EmailNotVerified));
        }

        Ok(claims)
    }
    
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let token_pair = match jwt::refresh_token_pair(
            self.token_revocation_service.clone(), 
            self.active_token_service.clone(),   
            refresh_token,
            &self.jwt_secret
        ).await {
            Ok(token_pair) => token_pair,
            Err(e) => {
                warn!("Token refresh failed: {:?}", e);
                return Err(AuthError::new(AuthErrorType::InvalidToken));
            }
        };
        
        let access_claims = match jwt::validate_jwt(&self.token_revocation_service, &token_pair.access_token, &self.jwt_secret, Some(TokenType::Access)).await {
            Ok(claims) => claims,
            Err(_) => {
                 warn!("Refresh_token: Failed to validate newly created access token during refresh flow.");
                 return Err(AuthError::new(AuthErrorType::TokenCreationError)); 
            }
        };
        
        if let Err(e) = self.record_tokens_for_user(access_claims.sub, &token_pair).await {
            warn!("Refresh_token: Failed to record refreshed tokens for user {}: {:?}", access_claims.sub, e);
        }
        
        info!("Tokens refreshed successfully for user: {}", access_claims.sub);
        Ok(token_pair)
    }
    
    async fn record_tokens_for_user(&self, user_id: uuid::Uuid, token_pair: &TokenPair) -> Result<(), AuthError> {
        let access_claims = match jwt::validate_jwt(&self.token_revocation_service, &token_pair.access_token, &self.jwt_secret, Some(TokenType::Access)).await {
            Ok(claims) => claims,
            Err(e) => {
                warn!("record_tokens_for_user: Failed to validate access token for recording for user {}: {:?}", user_id, e);
                return Err(AuthError::new(AuthErrorType::InternalServerError));
            }
        };
        
        let refresh_claims = match jwt::validate_jwt(&self.token_revocation_service, &token_pair.refresh_token, &self.jwt_secret, Some(TokenType::Refresh)).await {
            Ok(claims) => claims,
            Err(e) => {
                warn!("record_tokens_for_user: Failed to validate refresh token for recording for user {}: {:?}", user_id, e);
                return Err(AuthError::new(AuthErrorType::InternalServerError));
            }
        };
        
        jwt::record_active_token(&self.active_token_service, user_id, &TokenMetadata{jti: access_claims.jti, expires_at: jwt::timestamp_to_datetime(access_claims.exp)}, TokenType::Access).await;
        jwt::record_active_token(&self.active_token_service, user_id, &TokenMetadata{jti: refresh_claims.jti, expires_at: jwt::timestamp_to_datetime(refresh_claims.exp)}, TokenType::Refresh).await;
        
        Ok(())
    }
    
    pub async fn logout(&self, access_token: &str, refresh_token: Option<&str>) -> Result<(), AuthError> {
        let access_claims = match jwt::validate_jwt(&self.token_revocation_service, access_token, &self.jwt_secret, Some(TokenType::Access)).await {
            Ok(claims) => claims,
            Err(e) => {
                warn!("Logout: Failed to validate access token: {:?}", e);
                return Err(AuthError::new(AuthErrorType::InvalidToken));
            }
        };
        
        jwt::revoke_token(&self.token_revocation_service, &self.active_token_service, &access_claims.jti, access_claims.sub, TokenType::Access, "User logout").await;
        
        if let Some(rt_str) = refresh_token {
            match jwt::validate_jwt(&self.token_revocation_service, rt_str, &self.jwt_secret, Some(TokenType::Refresh)).await {
                Ok(refresh_claims) => {
                     jwt::revoke_token(&self.token_revocation_service, &self.active_token_service, &refresh_claims.jti, refresh_claims.sub, TokenType::Refresh, "User logout").await;
                },
                Err(e) => {
                    warn!("Logout: Failed to validate refresh token, not revoking: {:?}", e);
                }
            }
        }
        
        info!("User {} logged out successfully", access_claims.sub);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::user::{MockUserRepositoryTrait}; 
    use crate::core::auth::jwt::{self, Claims, TokenType, TokenPair, TokenMetadata};
    use crate::core::auth::active_token::{MockActiveTokenServiceTrait, ActiveToken};
    use crate::core::auth::token_revocation::MockTokenRevocationServiceTrait;
    use crate::common::validation::LoginInput;
    use crate::common::error::{AuthErrorType}; 
    use mockall::predicate;
    use uuid::Uuid;
    use chrono::{Utc, Duration}; 
    use std::sync::Arc;
    use sqlx::Error as SqlxError; 

    fn create_test_user(id: Uuid, username: &str, email_verified: bool, role: &str) -> User {
        User {
            id,
            username: username.to_string(),
            email: Some(format!("{}@example.com", username)), 
            password_hash: bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap(),
            is_email_verified: email_verified,
            verification_token: None,
            verification_token_expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: role.to_string(),
            is_active: true,
        }
    }
    
    const TEST_JWT_SECRET: &str = "test_auth_service_jwt_secret_very_secure";

    fn setup_mock_services() -> (Arc<dyn TokenRevocationServiceTrait>, Arc<dyn ActiveTokenServiceTrait>) {
        let mut mock_trs = MockTokenRevocationServiceTrait::new();
        mock_trs.expect_is_token_revoked().returning(|_| Ok(false)); 
        mock_trs.expect_revoke_token().returning(|_,_,_,_,_| Ok(())); 
        mock_trs.expect_revoke_all_user_tokens().returning(|_,_| Ok(0));
        mock_trs.expect_cleanup_expired_tokens().returning(|| Ok(0));

        let mut mock_ats = MockActiveTokenServiceTrait::new();
        mock_ats.expect_record_token().returning(|_,_,_,_,_| Ok(())); 
        mock_ats.expect_get_active_token().returning(|jti| {
            Ok(ActiveToken {
                id: Uuid::new_v4(),
                user_id: Uuid::new_v4(), 
                jti: jti.to_string(),
                token_type: "Access".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
                created_at: Utc::now(),
                device_info: None,
            })
        });
        mock_ats.expect_remove_token().returning(|_| Ok(true));
        mock_ats.expect_get_user_tokens().returning(|_| Ok(vec![]));
        mock_ats.expect_remove_all_user_tokens().returning(|_| Ok(0));
        mock_ats.expect_cleanup_expired_tokens().returning(|| Ok(0));

        (Arc::new(mock_trs), Arc::new(mock_ats))
    }

    #[tokio::test]
    async fn test_login_successful() {
        let mut mock_user_repo = MockUserRepositoryTrait::new(); 
        let test_user_id = Uuid::new_v4();
        let test_username = "testuser";
        let test_user = create_test_user(test_user_id, test_username, true, "user");
        let cloned_user = test_user.clone();

        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(test_username))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user.clone())));
        
        let (mock_trs_arc, _) = setup_mock_services(); // We get a generic Arc<dyn ActiveTokenServiceTrait> here
        
        // For specific expectations, create a new concrete mock, set expectations, then wrap.
        let mut mock_ats_for_login = MockActiveTokenServiceTrait::new();
        mock_ats_for_login.expect_record_token().times(2).returning(|_,_,_,_,_| Ok(()));
        let mock_ats_arc_for_login: Arc<dyn ActiveTokenServiceTrait> = Arc::new(mock_ats_for_login);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo), 
            TEST_JWT_SECRET.to_string(),
            mock_trs_arc.clone(), 
            mock_ats_arc_for_login.clone() // Use the specifically prepared mock
        );

        let login_input = LoginInput {
            username: test_username.to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(login_input).await;

        assert!(result.is_ok());
        let (token_pair, logged_in_user) = result.unwrap();
        assert_eq!(logged_in_user.id, test_user_id);
        assert!(!token_pair.access_token.is_empty());
        assert!(!token_pair.refresh_token.is_empty());

        let claims = jwt::validate_jwt(&mock_trs_arc, &token_pair.access_token, TEST_JWT_SECRET, Some(TokenType::Access)).await.unwrap();
        assert_eq!(claims.sub, test_user_id);
        assert_eq!(claims.role, "user");
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_username = "unknownuser";

        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(test_username))
            .times(1)
            .returning(|_| Ok(None));

        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let login_input = LoginInput {
            username: test_username.to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(login_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidCredentials);
        assert_eq!(auth_error.message, "Invalid credentials");
    }

    #[tokio::test]
    async fn test_login_email_not_verified() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_user_id = Uuid::new_v4();
        let test_username = "unverifieduser";
        let test_user = create_test_user(test_user_id, test_username, false, "user"); 
        let cloned_user = test_user.clone();

        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(test_username))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user.clone())));
        
        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let login_input = LoginInput {
            username: test_username.to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(login_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::EmailNotVerified);
        assert_eq!(auth_error.message, "Email not verified");
    }

    #[tokio::test]
    async fn test_login_incorrect_password() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_user_id = Uuid::new_v4();
        let test_username = "testuser";
        let test_user = create_test_user(test_user_id, test_username, true, "user");
        let cloned_user = test_user.clone();

        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(test_username))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user.clone())));

        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let login_input = LoginInput {
            username: test_username.to_string(),
            password: "wrongpassword".to_string(), 
        };

        let result = auth_service.login(login_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_login_user_repo_error() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_username = "testuser";

        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(test_username))
            .times(1)
            .returning(|_| Err(sqlx::Error::RowNotFound)); 
        
        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let login_input = LoginInput {
            username: test_username.to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(login_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_validate_auth_successful() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_user_id = Uuid::new_v4();
        let test_user = create_test_user(test_user_id, "testuser", true, "user");
        let cloned_user = test_user.clone();

        mock_user_repo.expect_find_by_id()
            .with(predicate::eq(test_user_id))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user.clone())));

        let token_pair = jwt::create_token_pair(test_user_id, "user".to_string(), TEST_JWT_SECRET).unwrap();
        let token_str = token_pair.access_token;
        
        let (mock_trs_for_jwt_val, _) : (Arc<dyn TokenRevocationServiceTrait>, Arc<dyn ActiveTokenServiceTrait>) = setup_mock_services(); 
        jwt::validate_jwt(&mock_trs_for_jwt_val, &token_str, TEST_JWT_SECRET, Some(TokenType::Access)).await.expect("Token for test_validate_auth_successful should be valid");
        
        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );
        
        let result = auth_service.validate_auth(&token_str).await;
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub, test_user_id);
        assert_eq!(claims.role, "user");
    }

    #[tokio::test]
    async fn test_validate_auth_invalid_token_signature() {
        let mock_user_repo = MockUserRepositoryTrait::new(); 
        let (mock_trs, mock_ats) = setup_mock_services();

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );
        
        let token_pair_diff_secret = jwt::create_token_pair(Uuid::new_v4(), "user".to_string(), "a_different_secret").unwrap();
        let token_str = token_pair_diff_secret.access_token;

        let (fresh_mock_trs, _) : (Arc<dyn TokenRevocationServiceTrait>, Arc<dyn ActiveTokenServiceTrait>) = setup_mock_services();
        jwt::validate_jwt(&fresh_mock_trs, &token_str, "a_different_secret", Some(TokenType::Access)).await.expect("Token created with different secret should be valid with that secret");

        let result = auth_service.validate_auth(&token_str).await; 
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidToken);
    }

    #[tokio::test]
    async fn test_validate_auth_user_not_found_by_id() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_user_id = Uuid::new_v4(); 

        mock_user_repo.expect_find_by_id()
            .with(predicate::eq(test_user_id))
            .times(1)
            .returning(|_| Ok(None));
        
        let token_pair = jwt::create_token_pair(test_user_id, "user".to_string(), TEST_JWT_SECRET).unwrap();
        let token_str = token_pair.access_token;

        let (fresh_mock_trs, _) : (Arc<dyn TokenRevocationServiceTrait>, Arc<dyn ActiveTokenServiceTrait>) = setup_mock_services();
        jwt::validate_jwt(&fresh_mock_trs, &token_str, TEST_JWT_SECRET, Some(TokenType::Access)).await.expect("Token for test_validate_auth_user_not_found_by_id should be valid");

        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let result = auth_service.validate_auth(&token_str).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidToken); 
    }

    #[tokio::test]
    async fn test_validate_auth_user_email_not_verified() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let test_user_id = Uuid::new_v4();
        let test_user = create_test_user(test_user_id, "unverified_user_for_validate", false, "user");
        let cloned_user = test_user.clone();

        mock_user_repo.expect_find_by_id()
            .with(predicate::eq(test_user_id))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user.clone())));

        let token_pair = jwt::create_token_pair(test_user_id, "user".to_string(), TEST_JWT_SECRET).unwrap();
        let token_str = token_pair.access_token;

        let (fresh_mock_trs, _) : (Arc<dyn TokenRevocationServiceTrait>, Arc<dyn ActiveTokenServiceTrait>) = setup_mock_services();
        jwt::validate_jwt(&fresh_mock_trs, &token_str, TEST_JWT_SECRET, Some(TokenType::Access)).await.expect("Token for test_validate_auth_user_email_not_verified should be valid");
        
        let (mock_trs, mock_ats) = setup_mock_services();
        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let result = auth_service.validate_auth(&token_str).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::EmailNotVerified);
    }

    #[tokio::test]
    async fn test_refresh_token_successful() {
        let mock_user_repo = MockUserRepositoryTrait::new(); 
        let test_user_id = Uuid::new_v4();
        
        let mut mock_ats_concrete = MockActiveTokenServiceTrait::new(); 
        mock_ats_concrete.expect_record_token().times(2).returning(|_,_,_,_,_| Ok(())); 
        mock_ats_concrete.expect_get_active_token().returning(move |jti| { 
             Ok(ActiveToken {
                id: Uuid::new_v4(), user_id: test_user_id, jti: jti.to_string(), token_type: "Refresh".to_string(),
                expires_at: Utc::now() + Duration::days(1), created_at: Utc::now(), device_info: None,
            })
        });
        let mock_ats: Arc<dyn ActiveTokenServiceTrait> = Arc::new(mock_ats_concrete);


        let mut mock_trs_concrete = MockTokenRevocationServiceTrait::new(); 
        mock_trs_concrete.expect_is_token_revoked().returning(|_| Ok(false)).times(4); // Adjusted from 3 to 4
        mock_trs_concrete.expect_revoke_token().times(1).returning(|_,_,_,_,_| Ok(())); 
        let mock_trs: Arc<dyn TokenRevocationServiceTrait> = Arc::new(mock_trs_concrete);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs.clone(),
            mock_ats.clone()
        );

        let initial_token_pair = jwt::create_token_pair(test_user_id, "user".to_string(), TEST_JWT_SECRET).unwrap();
        let refresh_token_str = initial_token_pair.refresh_token;

        let result = auth_service.refresh_token(&refresh_token_str).await;
        assert!(result.is_ok(), "refresh_token failed: {:?}", result.err());
        let new_token_pair = result.unwrap();

        assert!(!new_token_pair.access_token.is_empty());
        assert!(!new_token_pair.refresh_token.is_empty());
        assert_ne!(new_token_pair.refresh_token, refresh_token_str, "New refresh token should be different from the old one");

        let (fresh_mock_trs_val, _) : (Arc<dyn TokenRevocationServiceTrait>, Arc<dyn ActiveTokenServiceTrait>) = setup_mock_services(); 
        let claims = jwt::validate_jwt(&fresh_mock_trs_val, &new_token_pair.access_token, TEST_JWT_SECRET, Some(TokenType::Access)).await.unwrap();
        assert_eq!(claims.sub, test_user_id);
    }

    #[tokio::test]
    async fn test_refresh_token_invalid_refresh_token() {
        let mock_user_repo = MockUserRepositoryTrait::new(); 
        let (mock_trs, mock_ats) = setup_mock_services();

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let invalid_refresh_token = "this.is.not.a.valid.token";
        let result = auth_service.refresh_token(invalid_refresh_token).await;

        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidToken);
    }

    #[tokio::test]
    async fn test_logout_successful_with_refresh_token() {
        let mock_user_repo = MockUserRepositoryTrait::new(); 
        let test_user_id = Uuid::new_v4();

        let mut mock_trs_concrete = MockTokenRevocationServiceTrait::new(); 
        mock_trs_concrete.expect_is_token_revoked().returning(|_| Ok(false)).times(2); 
        mock_trs_concrete.expect_revoke_token()
            .times(2) 
            .returning(|_jti, _uid, _tt, _exp, _reason| Ok(()));
        let mock_trs: Arc<dyn TokenRevocationServiceTrait> = Arc::new(mock_trs_concrete);
        
        let mut mock_ats_concrete = MockActiveTokenServiceTrait::new();
        mock_ats_concrete.expect_get_active_token().times(2).returning(move |jti| { 
            Ok(ActiveToken {
                id: Uuid::new_v4(), user_id: test_user_id, jti: jti.to_string(), token_type: "Access".to_string(), 
                expires_at: Utc::now() + Duration::hours(1), created_at: Utc::now(), device_info: None,
            })
        });
        let mock_ats: Arc<dyn ActiveTokenServiceTrait> = Arc::new(mock_ats_concrete);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let token_pair = jwt::create_token_pair(test_user_id, "user".to_string(), TEST_JWT_SECRET).unwrap();
        
        let result = auth_service.logout(&token_pair.access_token, Some(&token_pair.refresh_token)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_logout_successful_access_token_only() {
        let mock_user_repo = MockUserRepositoryTrait::new();
        let test_user_id = Uuid::new_v4();

        let mut mock_trs_concrete = MockTokenRevocationServiceTrait::new(); 
        mock_trs_concrete.expect_is_token_revoked().returning(|_| Ok(false)).once(); 
        mock_trs_concrete.expect_revoke_token()
            .with(
                predicate::always(), // jti
                predicate::eq(test_user_id), // user_id
                predicate::always(), // token_type as &str - simplified
                predicate::always(), // expires_at
                predicate::always()  // reason_detail - simplified
            )
            .times(1)
            .returning(|_,_,_,_,_| Ok(()));
        let mock_trs: Arc<dyn TokenRevocationServiceTrait> = Arc::new(mock_trs_concrete);
        
        let mut mock_ats_concrete = MockActiveTokenServiceTrait::new();
        mock_ats_concrete.expect_get_active_token().once().returning(move |jti| { 
            Ok(ActiveToken {
                id: Uuid::new_v4(), user_id: test_user_id, jti: jti.to_string(), token_type: "Access".to_string(),
                expires_at: Utc::now() + Duration::hours(1), created_at: Utc::now(), device_info: None,
            })
        });
        let mock_ats: Arc<dyn ActiveTokenServiceTrait> = Arc::new(mock_ats_concrete);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let token_pair = jwt::create_token_pair(test_user_id, "user".to_string(), TEST_JWT_SECRET).unwrap();
        
        let result = auth_service.logout(&token_pair.access_token, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_logout_invalid_access_token() {
        let mock_user_repo = MockUserRepositoryTrait::new();
        let (mock_trs, mock_ats) = setup_mock_services(); 

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats
        );

        let result = auth_service.logout("invalid.access.token", None).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidToken);
    }
}
