// src/core/auth/service.rs
use bcrypt::verify;
use crate::common::{
    error::{AuthError, AuthErrorType},
    validation::{LoginInput, RegisterInput},
};
use crate::core::user::{User, UserRepositoryTrait, NewUser};
use std::sync::Arc;
use super::jwt::{self, Claims, TokenType, TokenPair, create_token_pair, TokenMetadata};
use crate::core::auth::token_revocation::TokenRevocationServiceTrait;
use crate::core::auth::active_token::ActiveTokenServiceTrait;
use crate::core::email::service::EmailServiceTrait;
use log::{info, warn, error};
use uuid::Uuid;
use chrono::{Utc, Duration};

pub struct AuthService {
    user_repository: Arc<dyn UserRepositoryTrait>,
    jwt_secret: String,
    token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
    active_token_service: Arc<dyn ActiveTokenServiceTrait>,
    email_service: Arc<dyn EmailServiceTrait>,
}

impl AuthService {
    pub fn new(
        user_repository: Arc<dyn UserRepositoryTrait>,
        jwt_secret: String,
        token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
        active_token_service: Arc<dyn ActiveTokenServiceTrait>,
        email_service: Arc<dyn EmailServiceTrait>,
    ) -> Self {
        Self {
            user_repository,
            jwt_secret,
            token_revocation_service,
            active_token_service,
            email_service,
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

    pub async fn register(&self, input: RegisterInput) -> Result<User, AuthError> {
        if self.user_repository.find_by_username(&input.username).await.map_err(|db_err: sqlx::Error| {
            error!("Registration: DB error checking username {}: {:?}", input.username, db_err);
            AuthError::new(AuthErrorType::InternalServerError)
        })?.is_some() {
            warn!("Registration: Username {} already exists.", input.username);
            return Err(AuthError::new_with_message(AuthErrorType::UserAlreadyExists, "Username already exists."));
        }

        if self.user_repository.find_user_by_email(&input.email).await.map_err(|db_err: sqlx::Error| {
            error!("Registration: DB error checking email {}: {:?}", input.email, db_err);
            AuthError::new(AuthErrorType::InternalServerError)
        })?.is_some() {
            warn!("Registration: Email {} already exists.", input.email);
            return Err(AuthError::new_with_message(AuthErrorType::UserAlreadyExists, "Email already exists."));
        }

        let password_hash = bcrypt::hash(&input.password, bcrypt::DEFAULT_COST)
            .map_err(|e| {
                error!("Registration: Failed to hash password for {}: {:?}", input.username, e);
                AuthError::new(AuthErrorType::InternalServerError)
            })?;

        let verification_token = Uuid::new_v4().to_string();
        let verification_token_expires_at = Utc::now() + Duration::days(1);

        let new_user_data = NewUser {
            username: input.username.clone(),
            email: Some(input.email.clone()),
            password_hash,
            is_email_verified: false,
            role: "user".to_string(),
            verification_token: Some(verification_token.clone()),
            verification_token_expires_at: Some(verification_token_expires_at),
        };

        let user = self.user_repository.create_user(new_user_data).await.map_err(|db_err: sqlx::Error| {
            error!("Registration: Failed to create user {}: {:?}", input.username, db_err);
            AuthError::new(AuthErrorType::InternalServerError)
        })?;

        if let Err(email_err) = self.email_service.send_verification_email(&user.email.clone().unwrap_or_default(), &verification_token).await {
            warn!("Registration: Failed to send verification email to {} for user {}: {:?}", user.email.clone().unwrap_or_default(), user.username, email_err);
        } else {
            info!("Registration: Verification email sent to {} for user {}", user.email.clone().unwrap_or_default(), user.username);
        }
        
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*; 
    use crate::core::user::{MockUserRepositoryTrait, NewUser};
    use crate::core::email::service::MockEmailServiceTrait;
    use crate::core::auth::jwt::{self, Claims, TokenType, TokenPair, TokenMetadata};
    use crate::core::auth::active_token::{MockActiveTokenServiceTrait, ActiveToken};
    use crate::core::auth::token_revocation::MockTokenRevocationServiceTrait;
    use crate::common::validation::{LoginInput, RegisterInput};
    use crate::common::error::{AuthErrorType};
    use mockall::{predicate, Sequence};
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

    fn setup_mock_email_service() -> Arc<dyn EmailServiceTrait> {
        let mut mock_email_service = MockEmailServiceTrait::new();
        mock_email_service.expect_send_verification_email()
            .returning(|_, _| Ok(()));
        mock_email_service.expect_send_password_reset_email()
            .returning(|_, _| Ok(()));
        Arc::new(mock_email_service)
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
        
        let (mock_trs_arc, _) = setup_mock_services();
        let mut mock_ats_for_login = MockActiveTokenServiceTrait::new();
        mock_ats_for_login.expect_record_token().times(2).returning(|_,_,_,_,_| Ok(()));
        let mock_ats_arc_for_login: Arc<dyn ActiveTokenServiceTrait> = Arc::new(mock_ats_for_login);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs_arc.clone(),
            mock_ats_arc_for_login.clone(),
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
        );

        let login_input = LoginInput {
            username: test_username.to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(login_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::EmailNotVerified);
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
        mock_trs_concrete.expect_is_token_revoked().returning(|_| Ok(false)).times(4);
        mock_trs_concrete.expect_revoke_token().times(1).returning(|_,_,_,_,_| Ok(())); 
        let mock_trs: Arc<dyn TokenRevocationServiceTrait> = Arc::new(mock_trs_concrete);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs.clone(),
            mock_ats.clone(),
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
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
                predicate::always(), 
                predicate::eq(test_user_id), 
                predicate::always(), 
                predicate::always(), 
                predicate::always()
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
            mock_ats,
            setup_mock_email_service()
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
            mock_ats,
            setup_mock_email_service()
        );

        let result = auth_service.logout("invalid.access.token", None).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidToken);
    }

    // Tests for register method
    #[tokio::test]
    async fn test_register_successful() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let mut mock_email_service = MockEmailServiceTrait::new();
        let (mock_trs, mock_ats) = setup_mock_services();

        let register_input = RegisterInput {
            username: "newuser".to_string(),
            email: "newuser@example.com".to_string(),
            password: "Password123!".to_string(),
            password_confirm: "Password123!".to_string(),
        };

        let expected_user_id = Uuid::new_v4();
        let cloned_input_username = register_input.username.clone();
        let cloned_input_email = register_input.email.clone();
        // let cloned_input_password = register_input.password.clone(); // This was the problematic line if register_input is moved later

        // Expectations
        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(register_input.username.clone()))
            .times(1)
            .returning(|_| Ok(None));
        mock_user_repo.expect_find_user_by_email()
            .with(predicate::eq(register_input.email.clone()))
            .times(1)
            .returning(|_| Ok(None));
        
        // Clone password specifically for the closure to avoid moving from `register_input`
        let password_for_closure_verification = register_input.password.clone();
        mock_user_repo.expect_create_user()
            .withf(move |new_user: &NewUser| {
                new_user.username == cloned_input_username &&
                new_user.email == Some(cloned_input_email.clone()) &&
                bcrypt::verify(&password_for_closure_verification, &new_user.password_hash).unwrap_or(false) && 
                !new_user.is_email_verified &&
                new_user.role == "user" &&
                new_user.verification_token.is_some() &&
                new_user.verification_token_expires_at.is_some()
            })
            .times(1)
            .returning(move |new_user_data| {
                Ok(User {
                    id: expected_user_id,
                    username: new_user_data.username.clone(),
                    email: new_user_data.email.clone(),
                    password_hash: new_user_data.password_hash.clone(),
                    is_email_verified: new_user_data.is_email_verified,
                    verification_token: new_user_data.verification_token.clone(),
                    verification_token_expires_at: new_user_data.verification_token_expires_at,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    role: new_user_data.role.clone(),
                    is_active: true,
                })
            });

        mock_email_service.expect_send_verification_email()
            .withf(move |email: &str, token: &str| {
                email == "newuser@example.com" && !token.is_empty()
            })
            .times(1)
            .returning(|_, _| Ok(()));

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats,
            Arc::new(mock_email_service),
        );

        let result = auth_service.register(register_input.clone()).await; // register_input is cloned here for the main call

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.id, expected_user_id);
        assert_eq!(user.username, "newuser"); // Use literal to avoid clone issues with register_input if it were moved
        assert_eq!(user.email.unwrap(), "newuser@example.com");
        assert!(!user.is_email_verified);
        assert!(user.verification_token.is_some());
    }

    #[tokio::test]
    async fn test_register_username_exists() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let mock_email_service = setup_mock_email_service(); 
        let (mock_trs, mock_ats) = setup_mock_services();

        let register_input = RegisterInput {
            username: "existinguser".to_string(),
            email: "newemail@example.com".to_string(),
            password: "Password123!".to_string(),
            password_confirm: "Password123!".to_string(),
        };
        
        let existing_user_id = Uuid::new_v4();
        let existing_user = create_test_user(existing_user_id, "existinguser", true, "user");

        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(register_input.username.clone()))
            .times(1)
            .returning(move |_| Ok(Some(existing_user.clone())));
        mock_user_repo.expect_find_user_by_email().times(0); 
        mock_user_repo.expect_create_user().times(0);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats,
            mock_email_service,
        );

        let result = auth_service.register(register_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_register_email_exists() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let mock_email_service = setup_mock_email_service();
        let (mock_trs, mock_ats) = setup_mock_services();

        let register_input = RegisterInput {
            username: "newusername".to_string(),
            email: "existingemail@example.com".to_string(),
            password: "Password123!".to_string(),
            password_confirm: "Password123!".to_string(),
        };
        
        let existing_user_id = Uuid::new_v4();
        let existing_user_with_email = User {
            id: existing_user_id,
            username: "anotheruser".to_string(), 
            email: Some("existingemail@example.com".to_string()),
            password_hash: bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap(),
            is_email_verified: true,
            verification_token: None,
            verification_token_expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: "user".to_string(),
            is_active: true,
        };

        let mut seq = Sequence::new();
        mock_user_repo.expect_find_by_username()
            .with(predicate::eq(register_input.username.clone()))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(None));
        mock_user_repo.expect_find_user_by_email() 
            .with(predicate::eq(register_input.email.clone()))
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(Some(existing_user_with_email.clone())));
        mock_user_repo.expect_create_user().times(0);

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats,
            mock_email_service,
        );

        let result = auth_service.register(register_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_register_email_send_failure_still_creates_user() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let mut mock_email_service = MockEmailServiceTrait::new();
        let (mock_trs, mock_ats) = setup_mock_services();

        let register_input = RegisterInput {
            username: "emailfailuser".to_string(),
            email: "emailfail@example.com".to_string(),
            password: "Password123!".to_string(),
            password_confirm: "Password123!".to_string(),
        };
        let expected_user_id = Uuid::new_v4();
        let cloned_input_username = register_input.username.clone();
        let cloned_input_email = register_input.email.clone();

        mock_user_repo.expect_find_by_username().returning(|_| Ok(None));
        mock_user_repo.expect_find_user_by_email().returning(|_| Ok(None)); 
        mock_user_repo.expect_create_user()
            .withf(move |new_user: &NewUser| {
                new_user.username == cloned_input_username &&
                new_user.email == Some(cloned_input_email.clone())
            })
            .times(1)
            .returning(move |new_user_data| {
                Ok(User {
                    id: expected_user_id, 
                    username: new_user_data.username.clone(),
                    email: new_user_data.email.clone(),
                    password_hash: new_user_data.password_hash.clone(),
                    is_email_verified: new_user_data.is_email_verified,
                    verification_token: new_user_data.verification_token.clone(),
                    verification_token_expires_at: new_user_data.verification_token_expires_at,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    role: new_user_data.role.clone(),
                    is_active: true,
                })
            });

        mock_email_service.expect_send_verification_email()
            .withf(move |email: &str, token: &str| {
                email == "emailfail@example.com" && !token.is_empty()
            })
            .times(1)
            .returning(|_, _| Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Simulated email send failure")) as Box<dyn std::error::Error + Send + Sync>));

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats,
            Arc::new(mock_email_service),
        );

        let result = auth_service.register(register_input.clone()).await;
        assert!(result.is_ok()); 
        let user = result.unwrap();
        assert_eq!(user.username, "emailfailuser"); // Use literal
    }

    #[tokio::test]
    async fn test_register_user_repo_create_user_fails() {
        let mut mock_user_repo = MockUserRepositoryTrait::new();
        let mock_email_service = setup_mock_email_service(); 
        let (mock_trs, mock_ats) = setup_mock_services();

        let register_input = RegisterInput {
            username: "dbfailuser".to_string(),
            email: "dbfail@example.com".to_string(),
            password: "Password123!".to_string(),
            password_confirm: "Password123!".to_string(),
        };

        mock_user_repo.expect_find_by_username().returning(|_| Ok(None));
        mock_user_repo.expect_find_user_by_email().returning(|_| Ok(None)); 
        mock_user_repo.expect_create_user()
            .times(1)
            .returning(|_| Err(SqlxError::RowNotFound)); 

        let auth_service = AuthService::new(
            Arc::new(mock_user_repo),
            TEST_JWT_SECRET.to_string(),
            mock_trs,
            mock_ats,
            mock_email_service,
        );
        
        let result = auth_service.register(register_input).await;
        assert!(result.is_err());
        let auth_error = result.unwrap_err();
        assert_eq!(auth_error.error_type, AuthErrorType::InternalServerError);
    }
}
