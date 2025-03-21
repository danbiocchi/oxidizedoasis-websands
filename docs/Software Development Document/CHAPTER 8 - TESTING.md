# OxidizedOasis-WebSands Software Development Document

Version: 1.0.0
Last Updated: 2025-03-21
Status: Release

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|---------|
| 1.0.0 | 2025-03-21 | Initial chapter completion | Technical Team |
| 0.1.0 | 2025-03-15 | Chapter outline created | Technical Team |


8. [Testing](#8-testing)
    - 8.1 [Test Approach](#81-test-approach)
        - 8.1.1 [Testing Strategy](#811-testing-strategy)
        - 8.1.2 [Testing Tools](#812-testing-tools)
    - 8.2 [Test Categories](#82-test-categories)
        - 8.2.1 [Unit Testing](#821-unit-testing)
        - 8.2.2 [Integration Testing](#822-integration-testing)
    - 8.3 [Test Environment](#83-test-environment)
        - 8.3.1 [Environment Setup](#831-environment-setup)
        - 8.3.2 [Test Data](#832-test-data)
    - 8.4 [Security Testing](#84-security-testing)
        - 8.4.1 [Penetration Testing](#841-penetration-testing)
        - 8.4.2 [Security Scanning](#842-security-scanning)

# 8. Testing

## 8.1 Test Approach

### 8.1.1 Testing Strategy

The project implements a comprehensive testing strategy to ensure quality and reliability:

1. **Testing Pyramid**
   ```mermaid
   graph TD
       A[Testing Pyramid] --> B[Unit Tests]
       A --> C[Integration Tests]
       A --> D[End-to-End Tests]
       A --> E[Manual Tests]
       
       B --> B1[Service Tests]
       B --> B2[Repository Tests]
       B --> B3[Utility Tests]
       B --> B4[Model Tests]
       
       C --> C1[API Tests]
       C --> C2[Database Tests]
       C --> C3[External Service Tests]
       
       D --> D1[User Flow Tests]
       D --> D2[UI Tests]
       D --> D3[Performance Tests]
       
       E --> E1[Exploratory Testing]
       E --> E2[Acceptance Testing]
       E --> E3[Usability Testing]
   ```

2. **Test-Driven Development**
   - Write tests before implementation
   - Red-Green-Refactor cycle
   - Focus on behavior, not implementation
   - Small, incremental changes
   - Continuous test execution

3. **Testing Quadrants**

   | | Business-Facing | Technology-Facing |
   |---|---|---|
   | **Supporting Team** | Q2: Functional Tests<br>- Acceptance Tests<br>- User Story Tests<br>- Prototypes | Q1: Unit Tests<br>- Component Tests<br>- Integration Tests<br>- API Tests |
   | **Critiquing Product** | Q3: Exploratory Tests<br>- Usability Tests<br>- User Acceptance Tests<br>- Alpha/Beta Tests | Q4: Performance Tests<br>- Load Tests<br>- Security Tests<br>- Maintainability Tests |

4. **Continuous Testing**
   ```mermaid
   graph LR
       A[Code Changes] --> B[Automated Tests]
       B --> C[Test Results]
       C --> D{Pass?}
       D -->|Yes| E[Deploy]
       D -->|No| F[Fix Issues]
       F --> A
   ```

5. **Test Coverage Goals**
   - Unit test coverage: 90%+ for core business logic
   - Integration test coverage: 80%+ for API endpoints
   - End-to-end test coverage: Key user flows
   - Security test coverage: All authentication and authorization flows

### 8.1.2 Testing Tools

The project uses various testing tools to implement the testing strategy:

1. **Testing Framework**

   | Tool | Purpose | Configuration |
   |------|---------|---------------|
   | Rust Test | Unit testing | Built-in Rust test framework |
   | Tokio Test | Async testing | Tokio runtime for async tests |
   | Mockall | Mocking | Mock generation for dependencies |
   | Reqwest | HTTP client | API testing |
   | Cucumber | BDD testing | Behavior-driven development |
   | wasm-bindgen-test | WebAssembly testing | Frontend testing |

2. **Test Organization**
   ```
   src/
   ├── lib.rs                 # Library code with unit tests
   ├── main.rs                # Application entry point
   ├── api/
   │   ├── auth.rs            # Auth API with unit tests
   │   └── users.rs           # User API with unit tests
   ├── core/
   │   ├── services/
   │   │   └── user_service.rs # User service with unit tests
   │   └── models/
   │       └── user.rs        # User model with unit tests
   tests/
   ├── common/                # Shared test utilities
   │   ├── mod.rs
   │   └── helpers.rs
   ├── integration/           # Integration tests
   │   ├── api_tests.rs
   │   └── db_tests.rs
   ├── e2e/                   # End-to-end tests
   │   └── user_flows.rs
   └── security/              # Security tests
       └── auth_tests.rs
   ```

3. **Test Runners**
   ```bash
   # Run all tests
   cargo test
   
   # Run unit tests only
   cargo test --lib
   
   # Run integration tests only
   cargo test --test '*'
   
   # Run specific test
   cargo test user_registration
   
   # Run tests with logging
   RUST_LOG=debug cargo test
   
   # Run tests with coverage
   cargo tarpaulin --out Html
   ```

4. **Mocking Framework**
   ```rust
   // Example of mocking with Mockall
   #[cfg(test)]
   mod tests {
       use super::*;
       use mockall::predicate::*;
       use mockall::*;
       
       mock! {
           UserRepository {
               fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DbError>;
               fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError>;
               fn create(&self, user: &NewUser) -> Result<User, DbError>;
           }
       }
       
       #[tokio::test]
       async fn test_get_user_by_id_success() {
           // Arrange
           let user_id = Uuid::new_v4();
           let expected_user = User {
               id: user_id,
               username: "testuser".to_string(),
               email: "test@example.com".to_string(),
               // Other fields...
           };
           
           let mut mock_repo = MockUserRepository::new();
           mock_repo
               .expect_find_by_id()
               .with(eq(user_id))
               .times(1)
               .returning(move |_| Ok(Some(expected_user.clone())));
           
           let user_service = UserService::new(Arc::new(mock_repo));
           
           // Act
           let result = user_service.get_user_by_id(user_id).await;
           
           // Assert
           assert!(result.is_ok());
           let user = result.unwrap();
           assert_eq!(user.id, user_id);
           assert_eq!(user.username, "testuser");
           assert_eq!(user.email, "test@example.com");
       }
   }
   ```

5. **Test Reporting**
   - JUnit XML format for CI integration
   - HTML coverage reports
   - Test execution time tracking
   - Failure analysis tools
   - Test result dashboards

## 8.2 Test Categories

### 8.2.1 Unit Testing

Unit tests verify the functionality of individual components in isolation:

1. **Unit Test Structure**
   ```rust
   // Example of unit test structure
   #[cfg(test)]
   mod tests {
       use super::*;
       
       // Test fixture setup
       fn setup() -> UserService {
           // Create dependencies
           let repository = Arc::new(MockUserRepository::new());
           let email_service = Arc::new(MockEmailService::new());
           
           // Create service under test
           UserService::new(repository, email_service)
       }
       
       #[tokio::test]
       async fn test_validate_password_valid() {
           // Arrange
           let service = setup();
           let password = "StrongP@ssw0rd";
           
           // Act
           let result = service.validate_password(password);
           
           // Assert
           assert!(result.is_ok());
       }
       
       #[tokio::test]
       async fn test_validate_password_too_short() {
           // Arrange
           let service = setup();
           let password = "Short1!";
           
           // Act
           let result = service.validate_password(password);
           
           // Assert
           assert!(result.is_err());
           let err = result.unwrap_err();
           assert!(matches!(err, ValidationError::TooShort { .. }));
       }
       
       // More tests...
   }
   ```

2. **Unit Test Categories**
   ```mermaid
   graph TD
       A[Unit Tests] --> B[Service Tests]
       A --> C[Repository Tests]
       A --> D[Model Tests]
       A --> E[Utility Tests]
       A --> F[API Handler Tests]
       
       B --> B1[Business Logic Tests]
       B --> B2[Validation Tests]
       B --> B3[Error Handling Tests]
       
       C --> C1[Query Tests]
       C --> C2[Transaction Tests]
       C --> C3[Error Mapping Tests]
       
       D --> D1[Validation Tests]
       D --> D2[Serialization Tests]
       D --> D3[Method Tests]
       
       E --> E1[Helper Function Tests]
       E --> E2[Extension Method Tests]
       
       F --> F1[Request Handling Tests]
       F --> F2[Response Formatting Tests]
       F --> F3[Middleware Tests]
   ```

3. **Test Doubles**
   - **Mocks**: Objects that record interactions for verification
   - **Stubs**: Objects that provide canned answers
   - **Fakes**: Working implementations with shortcuts
   - **Spies**: Objects that record interactions without verification
   - **Dummies**: Objects passed around but not used

4. **Unit Test Best Practices**
   - Test one thing per test
   - Use descriptive test names
   - Follow Arrange-Act-Assert pattern
   - Minimize test dependencies
   - Avoid test interdependence
   - Keep tests fast and deterministic
   - Test edge cases and error conditions

5. **Example Unit Tests**
   ```rust
   // Example of service unit tests
   #[tokio::test]
   async fn test_create_user_success() {
       // Arrange
       let mut mock_repo = MockUserRepository::new();
       mock_repo
           .expect_find_by_email()
           .with(eq("test@example.com"))
           .times(1)
           .returning(|_| Ok(None));
       
       mock_repo
           .expect_find_by_username()
           .with(eq("testuser"))
           .times(1)
           .returning(|_| Ok(None));
       
       let new_user = User {
           id: Uuid::new_v4(),
           username: "testuser".to_string(),
           email: "test@example.com".to_string(),
           // Other fields...
       };
       
       mock_repo
           .expect_create()
           .times(1)
           .returning(move |_, _, _, _, _| Ok(new_user.clone()));
       
       let mut mock_email = MockEmailService::new();
       mock_email
           .expect_send_verification_email()
           .times(1)
           .returning(|_| Ok(()));
       
       let service = UserService::new(Arc::new(mock_repo), Arc::new(mock_email));
       
       let input = UserRegistration {
           username: "testuser".to_string(),
           email: "test@example.com".to_string(),
           password: "StrongP@ssw0rd".to_string(),
           first_name: Some("Test".to_string()),
           last_name: Some("User".to_string()),
       };
       
       // Act
       let result = service.create_user(input).await;
       
       // Assert
       assert!(result.is_ok());
       let user = result.unwrap();
       assert_eq!(user.username, "testuser");
       assert_eq!(user.email, "test@example.com");
   }
   ```

### 8.2.2 Integration Testing

Integration tests verify the interaction between components:

1. **Integration Test Structure**
   ```rust
   // Example of integration test structure
   use oxidizedoasis_websands::{
       api,
       common::config::Config,
       core::services::{AuthService, UserService},
       infrastructure::repositories::{AuthRepository, UserRepository},
   };
   use sqlx::PgPool;
   use actix_web::{test, web, App};
   
   // Test fixture
   async fn setup() -> (test::TestServer, PgPool) {
       // Load test configuration
       let config = Config::load_test_config().expect("Failed to load test config");
       
       // Create database connection
       let pool = PgPool::connect(&config.database.url)
           .await
           .expect("Failed to connect to database");
       
       // Run migrations
       sqlx::migrate!("./migrations")
           .run(&pool)
           .await
           .expect("Failed to run migrations");
       
       // Create repositories
       let user_repository = UserRepository::new(pool.clone());
       let auth_repository = AuthRepository::new(pool.clone());
       
       // Create services
       let user_service = web::Data::new(UserService::new(
           Arc::new(user_repository),
           Arc::new(MockEmailService::new()),
       ));
       
       let auth_service = web::Data::new(AuthService::new(
           Arc::new(auth_repository),
           config.auth.jwt_secret.clone(),
           config.auth.token_expiry,
       ));
       
       // Create test server
       let server = test::start(move || {
           App::new()
               .app_data(user_service.clone())
               .app_data(auth_service.clone())
               .configure(api::configure_routes)
       });
       
       (server, pool)
   }
   
   #[actix_rt::test]
   async fn test_user_registration_and_login() {
       // Arrange
       let (server, pool) = setup().await;
       
       // Act - Register user
       let registration = UserRegistration {
           username: "testuser".to_string(),
           email: "test@example.com".to_string(),
           password: "StrongP@ssw0rd".to_string(),
           first_name: Some("Test".to_string()),
           last_name: Some("User".to_string()),
       };
       
       let register_req = test::TestRequest::post()
           .uri("/api/v1/users/register")
           .set_json(&registration)
           .to_request();
       
       let register_resp = test::call_service(&server, register_req).await;
       
       // Assert - Registration successful
       assert_eq!(register_resp.status(), 201);
       
       // Act - Login
       let login = LoginRequest {
           username_or_email: "test@example.com".to_string(),
           password: "StrongP@ssw0rd".to_string(),
       };
       
       let login_req = test::TestRequest::post()
           .uri("/api/v1/auth/login")
           .set_json(&login)
           .to_request();
       
       let login_resp = test::call_service(&server, login_req).await;
       
       // Assert - Login successful
       assert_eq!(login_resp.status(), 200);
       
       let login_body: LoginResponse = test::read_body_json(login_resp).await;
       assert!(!login_body.access_token.is_empty());
       assert!(!login_body.refresh_token.is_empty());
       
       // Clean up
       sqlx::query!("DELETE FROM users WHERE email = $1", "test@example.com")
           .execute(&pool)
           .await
           .expect("Failed to clean up test data");
   }
   ```

2. **Integration Test Categories**
   ```mermaid
   graph TD
       A[Integration Tests] --> B[API Tests]
       A --> C[Database Tests]
       A --> D[Service Integration Tests]
       A --> E[External Service Tests]
       
       B --> B1[Endpoint Tests]
       B --> B2[Middleware Tests]
       B --> B3[Error Handling Tests]
       
       C --> C1[Repository Tests]
       C --> C2[Migration Tests]
       C --> C3[Transaction Tests]
       
       D --> D1[Service Interaction Tests]
       D --> D2[End-to-End Flow Tests]
       
       E --> E1[Email Service Tests]
       E --> E2[Storage Service Tests]
       E --> E3[Third-party API Tests]
   ```

3. **Database Integration Testing**
   ```rust
   // Example of database integration test
   #[sqlx::test]
   async fn test_user_repository_create_and_find(pool: PgPool) {
       // Arrange
       let repository = UserRepository::new(pool.clone());
       let username = "testuser";
       let email = "test@example.com";
       let password_hash = "hashed_password";
       
       // Act - Create user
       let user = repository.create(
           username,
           email,
           password_hash,
           Some("Test"),
           Some("User"),
       ).await.expect("Failed to create user");
       
       // Assert - User created correctly
       assert_eq!(user.username, username);
       assert_eq!(user.email, email);
       assert_eq!(user.password_hash, password_hash);
       assert_eq!(user.first_name, Some("Test".to_string()));
       assert_eq!(user.last_name, Some("User".to_string()));
       
       // Act - Find by ID
       let found_by_id = repository.find_by_id(user.id)
           .await
           .expect("Failed to find user by ID");
       
       // Assert - Found by ID
       assert!(found_by_id.is_some());
       let found_user = found_by_id.unwrap();
       assert_eq!(found_user.id, user.id);
       
       // Act - Find by email
       let found_by_email = repository.find_by_email(email)
           .await
           .expect("Failed to find user by email");
       
       // Assert - Found by email
       assert!(found_by_email.is_some());
       let found_user = found_by_email.unwrap();
       assert_eq!(found_user.email, email);
       
       // Clean up
       sqlx::query!("DELETE FROM users WHERE id = $1", user.id)
           .execute(&pool)
           .await
           .expect("Failed to clean up test data");
   }
   ```

4. **API Integration Testing**
   ```rust
   // Example of API integration test
   #[actix_rt::test]
   async fn test_protected_endpoint_with_valid_token() {
       // Arrange
       let (server, pool) = setup().await;
       
       // Create a user and get a token
       let user_id = Uuid::new_v4();
       let username = "testuser";
       let email = "test@example.com";
       
       sqlx::query!(
           r#"
           INSERT INTO users (id, username, email, password_hash, is_email_verified, created_at, updated_at, role)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           "#,
           user_id,
           username,
           email,
           "hashed_password",
           true,
           Utc::now(),
           Utc::now(),
           "user"
       )
       .execute(&pool)
       .await
       .expect("Failed to create test user");
       
       // Generate a token
       let auth_service = AuthService::new(
           Arc::new(AuthRepository::new(pool.clone())),
           "test_secret".to_string(),
           Duration::hours(1),
       );
       
       let token = auth_service.generate_access_token(user_id, username)
           .expect("Failed to generate token");
       
       // Act - Call protected endpoint
       let req = test::TestRequest::get()
           .uri("/api/v1/users/me")
           .header("Authorization", format!("Bearer {}", token))
           .to_request();
       
       let resp = test::call_service(&server, req).await;
       
       // Assert - Access granted
       assert_eq!(resp.status(), 200);
       
       // Clean up
       sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
           .execute(&pool)
           .await
           .expect("Failed to clean up test data");
   }
   ```

5. **Integration Test Best Practices**
   - Use a dedicated test database
   - Clean up test data after each test
   - Test realistic scenarios
   - Minimize external dependencies
   - Use transactions for isolation
   - Test error conditions and edge cases
   - Verify side effects

## 8.3 Test Environment

### 8.3.1 Environment Setup

The test environment is configured to support various testing needs:

1. **Test Environment Architecture**
   ```mermaid
   graph TD
       A[Test Environments] --> B[Local Development]
       A --> C[CI Environment]
       A --> D[Staging Environment]
       
       B --> B1[Unit Tests]
       B --> B2[Integration Tests]
       B --> B3[Manual Testing]
       
       C --> C1[Automated Tests]
       C --> C2[Build Verification]
       C --> C3[Code Quality Checks]
       
       D --> D1[System Tests]
       D --> D2[Performance Tests]
       D --> D3[Security Tests]
   ```

2. **Local Test Environment**
   ```yaml
   # Example docker-compose.yml for local testing
   version: '3.8'
   
   services:
     postgres:
       image: postgres:14
       environment:
         POSTGRES_USER: postgres
         POSTGRES_PASSWORD: postgres
         POSTGRES_DB: test_db
       ports:
         - "5432:5432"
       volumes:
         - postgres_data:/var/lib/postgresql/data
     
     redis:
       image: redis:6
       ports:
         - "6379:6379"
     
     mailhog:
       image: mailhog/mailhog
       ports:
         - "1025:1025"  # SMTP server
         - "8025:8025"  # Web UI
   
   volumes:
     postgres_data:
   ```

3. **Test Configuration**
   ```rust
   // Example of test configuration
   #[derive(Debug, Clone)]
   pub struct TestConfig {
       pub database: DatabaseConfig,
       pub redis: RedisConfig,
       pub email: EmailConfig,
       pub auth: AuthConfig,
   }
   
   impl TestConfig {
       pub fn new() -> Self {
           Self {
               database: DatabaseConfig {
                   url: "postgres://postgres:postgres@localhost:5432/test_db".to_string(),
                   max_connections: 5,
                   min_connections: 1,
                   max_lifetime: Some(Duration::minutes(30)),
                   idle_timeout: Some(Duration::minutes(10)),
                   connect_timeout: Duration::seconds(3),
               },
               redis: RedisConfig {
                   url: "redis://localhost:6379".to_string(),
               },
               email: EmailConfig {
                   smtp_host: "localhost".to_string(),
                   smtp_port: 1025,
                   smtp_username: "".to_string(),
                   smtp_password: "".to_string(),
                   from_email: "test@example.com".to_string(),
                   from_name: "Test System".to_string(),
               },
               auth: AuthConfig {
                   jwt_secret: "test_secret_key_for_testing_only".to_string(),
                   token_expiry: Duration::minutes(15),
                   refresh_token_expiry: Duration::days(7),
               },
           }
       }
   }
   ```

4. **CI Test Environment**
   ```yaml
   # Example GitHub Actions test environment
   name: Tests
   
   on:
     push:
       branches: [ main, develop ]
     pull_request:
       branches: [ main, develop ]
   
   jobs:
     test:
       runs-on: ubuntu-latest
       
       services:
         postgres:
           image: postgres:14
           env:
             POSTGRES_USER: postgres
             POSTGRES_PASSWORD: postgres
             POSTGRES_DB: test_db
           ports:
             - 5432:5432
           options: >-
             --health-cmd pg_isready
             --health-interval 10s
             --health-timeout 5s
             --health-retries 5
         
         redis:
           image: redis:6
           ports:
             - 6379:6379
           options: >-
             --health-cmd "redis-cli ping"
             --health-interval 10s
             --health-timeout 5s
             --health-retries 5
       
       steps:
         - uses: actions/checkout@v3
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
             components: rustfmt, clippy
         
         - name: Cache dependencies
           uses: actions/cache@v3
           with:
             path: |
               ~/.cargo/registry
               ~/.cargo/git
               target
             key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Run migrations
           run: |
             cargo install sqlx-cli --no-default-features --features postgres
             sqlx database create --database-url postgres://postgres:postgres@localhost:5432/test_db
             sqlx migrate run --database-url postgres://postgres:postgres@localhost:5432/test_db
         
         - name: Run tests
           run: cargo test --verbose
           env:
             DATABASE_URL: postgres://postgres:postgres@localhost:5432/test_db
             REDIS_URL: redis://localhost:6379
             RUST_LOG: debug
   ```

5. **Test Environment Management**
   - Containerized environments for consistency
   - Database reset between test runs
   - Seeded test data for specific scenarios
   - Environment variable configuration
   - Test-specific service mocks

### 8.3.2 Test Data

Test data is managed to support various testing scenarios:

1. **Test Data Management**
   ```mermaid
   graph TD
       A[Test Data] --> B[Static Test Data]
       A --> C[Generated Test Data]
       A --> D[Fixtures]
       
       B --> B1[Reference Data]
       B --> B2[Test Cases]
       
       C --> C1[Random Data]
       C --> C2[Boundary Values]
       C --> C3[Edge Cases]
       
       D --> D1[User Fixtures]
       D --> D2[Configuration Fixtures]
       D --> D3[Response Fixtures]
   ```

2. **Test Data Generation**
   ```rust
   // Example of test data generation
   pub struct TestDataGenerator {
       rng: ThreadRng,
   }
   
   impl TestDataGenerator {
       pub fn new() -> Self {
           Self {
               rng: thread_rng(),
           }
       }
       
       pub fn generate_user(&mut self) -> NewUser {
           let username = format!("user_{}", self.random_string(8));
           let email = format!("{}@example.com", self.random_string(10));
           
           NewUser {
               username,
               email,
               password: format!("Password{}!", self.random_number(1000, 9999)),
               first_name: Some(self.random_name()),
               last_name: Some(self.random_name()),
           }
       }
       
       pub fn generate_admin_user(&mut self) -> NewUser {
           let mut user = self.generate_user();
           user.username = format!("admin_{}", self.random_string(8));
           user
       }
       
       fn random_string(&mut self, length: usize) -> String {
           const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
           
           (0..length)
               .map(|_| {
                   let idx = self.rng.gen_range(0..CHARSET.len());
                   CHARSET[idx] as char
               })
               .collect()
       }
       
       fn random_number(&mut self, min: u32, max: u32) -> u32 {
           self.rng.gen_range(min..=max)
       }
       
       fn random_name(&mut self) -> String {
           const NAMES: &[&str] = &[
               "James", "Mary", "John", "Patricia", "Robert", "Jennifer",
               "Michael", "Linda", "William", "Elizabeth", "David", "Barbara",
               "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah",
               "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
           ];
           
           NAMES[self.rng.gen_range(0..NAMES.len())].to_string()
       }
   }
   ```

3. **Test Fixtures**
   ```rust
   // Example of test fixtures
   pub struct TestFixtures {
       pool: PgPool,
   }
   
   impl TestFixtures {
       pub async fn new(pool: PgPool) -> Self {
           Self { pool }
       }
       
       pub async fn create_user(&self, role: &str) -> User {
           let id = Uuid::new_v4();
           let username = format!("test_user_{}", id.simple());
           let email = format!("{}@example.com", username);
           
           let user = sqlx::query_as!(
               User,
               r#"
               INSERT INTO users (
                   id, username, email, password_hash, is_email_verified,
                   created_at, updated_at, role
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING *
               "#,
               id,
               username,
               email,
               "hashed_password",
               true,
               Utc::now(),
               Utc::now(),
               role
           )
           .fetch_one(&self.pool)
           .await
           .expect("Failed to create test user");
           
           user
       }
       
       pub async fn create_user_with_profile(&self) -> (User, ProfileSettings) {
           let user = self.create_user("user").await;
           
           let profile = sqlx::query_as!(
               ProfileSettings,
               r#"
               INSERT INTO profile_settings (
                   id, user_id, notification_email, notification_security,
                   ui_theme, ui_density, security_two_factor,
                   created_at, updated_at
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING *
               "#,
               Uuid::new_v4(),
               user.id,
               true,
               true,
               "light",
               "normal",
               false,
               Utc::now(),
               Utc::now()
           )
           .fetch_one(&self.pool)
           .await
           .expect("Failed to create test profile");
           
           (user, profile)
       }
       
       pub async fn create_access_token(&self, user: &User) -> String {
           let auth_service = AuthService::new(
               Arc::new(AuthRepository::new(self.pool.clone())),
               "test_secret".to_string(),
               Duration::hours(1),
           );
           
           auth_service.generate_access_token(user.id, &user.username)
               .expect("Failed to generate token")
       }
       
       pub async fn cleanup(&self) {
           sqlx::query!("DELETE FROM profile_settings")
               .execute(&self.pool)
               .await
               .expect("Failed to clean up profile_settings");
               
           sqlx::query!("DELETE FROM users")
               .execute(&self.pool)
               .await
               .expect("Failed to clean up users");
       }
   }
   ```

4. **Database Seeding**
   ```rust
   // Example of database seeding for tests
   async fn seed_test_database(pool: &PgPool) -> Result<(), sqlx::Error> {
       // Create roles
       sqlx::query!(
           r#"
           INSERT INTO roles (id, name, description, created_at, updated_at)
           VALUES 
               ($1, $2, $3, $4, $5),
               ($6, $7, $8, $9, $10),
               ($11, $12, $13, $14, $15)
           ON CONFLICT (name) DO NOTHING
           "#,
           Uuid::new_v4(), "user", "Regular user", Utc::now(), Utc::now(),
           Uuid::new_v4(), "admin", "Administrator", Utc::now(), Utc::now(),
           Uuid::new_v4(), "system", "System user", Utc::now(), Utc::now()
       )
       .execute(pool)
       .await?;
       
       // Create permissions
       sqlx::query!(
           r#"
           INSERT INTO permissions (id, resource, action, created_at, updated_at)
           VALUES 
               ($1, $2, $3, $4, $5),
               ($6, $7, $8, $9, $10),
               ($11, $12, $13, $14, $15)
           ON CONFLICT (resource, action) DO NOTHING
           "#,
           Uuid::new_v4(), "user", "read", Utc::now(), Utc::now(),
           Uuid::new_v4(), "user", "write", Utc::now(), Utc::now(),
           Uuid::new_v4(), "admin", "access", Utc::now(), Utc::now()
       )
       .execute(pool)
       .await?;
       
       Ok(())
   }
   ```

5. **Test Data Cleanup**
   ```rust
   // Example of test data cleanup
   async fn cleanup_test_data(pool: &PgPool) -> Result<(), sqlx::Error> {
       // Use a transaction for atomicity
       let mut tx = pool.begin().await?;
       
       // Delete data in reverse order of dependencies
       sqlx::query!("DELETE FROM role_permissions")
           .execute(&mut *tx)
           .await?;
           
       sqlx::query!("DELETE FROM active_tokens")
           .execute(&mut *tx)
           .await?;
           
       sqlx::query!("DELETE FROM revoked_tokens")
           .execute(&mut *tx)
           .await?;
           
       sqlx::query!("DELETE FROM password_resets")
           .execute(&mut *tx)
           .await?;
           
       sqlx::query!("DELETE FROM profile_settings")
           .execute(&mut *tx)
           .await?;
           
       sqlx::query!("DELETE FROM security_events")
           .execute(&mut *tx)
           .await?;
           
       sqlx::query!("DELETE FROM users")
           .execute(&mut *tx)
           .await?;
           
       // Commit transaction
       tx.commit().await?;
       
       Ok(())
   }
   ```

## 8.4 Security Testing

### 8.4.1 Penetration Testing

Penetration testing verifies the system's security against attacks:

1. **Penetration Testing Approach**
   ```mermaid
   graph TD
       A[Penetration Testing] --> B[Reconnaissance]
       B --> C[Scanning]
       C --> D[Vulnerability Assessment]
       D --> E[Exploitation]
       E --> F[Post-Exploitation]
       F --> G[Reporting]
       
       B --> B1[Information Gathering]
       B --> B2[Target Identification]
       
       C --> C1[Port Scanning]
       C --> C2[Service Enumeration]
       
       D --> D1[Vulnerability Scanning]
       D --> D2[Manual Testing]
       
       E --> E1[Exploit Development]
       E --> E2[Exploit Execution]
       
       F --> F1[Privilege Escalation]
       F --> F2[Data Exfiltration]
       
       G --> G1[Findings Documentation]
       G --> G2[Remediation Recommendations]
   ```

2. **Security Test Cases**

   | Test Category | Test Case | Description |
   |---------------|-----------|-------------|
   | Authentication | Brute Force Attack | Attempt to guess credentials through repeated login attempts |
   | Authentication | Credential Stuffing | Test for reuse of compromised credentials |
   | Authentication | Session Hijacking | Attempt to steal or forge session tokens |
   | Authorization | Privilege Escalation | Attempt to access resources with elevated privileges |
   | Authorization | Insecure Direct Object Reference | Attempt to access resources by manipulating identifiers |
   | Input Validation | SQL Injection | Attempt to inject SQL commands into queries |
   | Input Validation | Cross-Site Scripting (XSS) | Attempt to inject malicious scripts |
   | Input Validation | Command Injection | Attempt to inject operating system commands |
   | API Security | Rate Limiting Bypass | Attempt to bypass rate limiting controls |
   | API Security | Insecure Endpoints | Test for unprotected sensitive endpoints |

3. **OWASP Top 10 Testing**
   - Injection
   - Broken Authentication
   - Sensitive Data Exposure
   - XML External Entities (XXE)
   - Broken Access Control
   - Security Misconfiguration
   - Cross-Site Scripting (XSS)
   - Insecure Deserialization
   - Using Components with Known Vulnerabilities
   - Insufficient Logging & Monitoring

4. **Penetration Testing Tools**
   - OWASP ZAP for web application scanning
   - Burp Suite for API testing
   - Metasploit for exploitation
   - Nmap for network scanning
   - SQLmap for SQL injection testing
   - Hydra for brute force testing

5. **Penetration Testing Process**
   - Scheduled quarterly penetration tests
   - Pre-deployment security assessments
   - Third-party security audits
   - Bug bounty program
   - Continuous vulnerability scanning

### 8.4.2 Security Scanning

Security scanning identifies vulnerabilities in the codebase and dependencies:

1. **Security Scanning Process**
   ```mermaid
   graph TD
       A[Security Scanning] --> B[Static Analysis]
       A --> C[Dependency Scanning]
       A --> D[Dynamic Analysis]
       A --> E[Container Scanning]
       
       B --> B1[Code Quality]
       B --> B2[Security Patterns]
       B --> B3[Secrets Detection]
       
       C --> C1[Vulnerability Checking]
       C --> C2[License Compliance]
       C --> C3[Outdated Dependencies]
       
       D --> D1[Runtime Analysis]
       D --> D2[Fuzzing]
       
       E --> E1[Base Image Scanning]
       E --> E2[Configuration Scanning]
   ```

2. **Static Analysis Tools**
   ```yaml
   # Example GitHub Actions workflow for security scanning
   name: Security Scan
   
   on:
     push:
       branches: [ main, develop ]
     pull_request:
       branches: [ main, develop ]
     schedule:
       - cron: '0 0 * * 0'  # Weekly scan
   
   jobs:
     security_scan:
       runs-on: ubuntu-latest
       
       steps:
         - uses: actions/checkout@v3
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
             components: rustfmt, clippy
         
         - name: Cargo audit
           uses: actions-rs/audit-check@v1
           with:
             token: ${{ secrets.GITHUB_TOKEN }}
         
         - name: Run Clippy with security lints
           run: |
             cargo clippy --all-features -- -D warnings -W clippy::all -W clippy::pedantic -W clippy::nursery -W clippy::cargo
         
         - name: Check for secrets
           uses: gitleaks/gitleaks-action@v2
           env:
             GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
   ```

3. **Dependency Scanning**
   ```toml
   # Example cargo-audit configuration
   # .cargo/audit.toml
   [advisories]
   ignore = [
       "RUSTSEC-2020-0071",  # Unmaintained dependency with no security impact
   ]
   
   [output]
   format = "json"
   
   [database]
   path = "~/.cargo/advisory-db"
   url = "https://github.com/RustSec/advisory-db"
   fetch = true
   ```

4. **Container Scanning**
   ```yaml
   # Example container scanning configuration
   name: Container Scan
   
   on:
     push:
       branches: [ main, develop ]
   
   jobs:
     container_scan:
       runs-on: ubuntu-latest
       
       steps:
         - uses: actions/checkout@v3
         
         - name: Build Docker image
           run: docker build -t oxidizedoasis/websands:${{ github.sha }} .
         
         - name: Scan image for vulnerabilities
           uses: aquasecurity/trivy-action@master
           with:
             image-ref: 'oxidizedoasis/websands:${{ github.sha }}'
             format: 'table'
             exit-code: '1'
             ignore-unfixed: true
             severity: 'CRITICAL,HIGH'
   ```

5. **Security Scanning Best Practices**
   - Integrate scanning into CI/CD pipeline
   - Establish security gates for deployment
   - Regular dependency updates
   - Automated vulnerability patching
   - Security scanning reports and metrics
   - Developer security training