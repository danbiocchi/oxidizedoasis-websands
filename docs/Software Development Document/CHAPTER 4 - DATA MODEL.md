# OxidizedOasis-WebSands Software Development Document

Version: 1.0.0
Last Updated: 2025-03-21
Status: Release

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|---------|
| 1.0.0 | 2025-03-21 | Initial chapter completion | Technical Team |
| 0.1.0 | 2025-03-15 | Chapter outline created | Technical Team |


4. [Data Model](#4-data-model)
    - 4.1 [Database Schema](#41-database-schema)
        - 4.1.1 [Table Structures](#411-table-structures)
        - 4.1.2 [Indexes and Constraints](#412-indexes-and-constraints)
    - 4.2 [Entity Relationships](#42-entity-relationships)
        - 4.2.2 [Relationship Definitions](#422-relationship-definitions)
    - 4.3 [Data Access Layer](#43-data-access-layer)
        - 4.3.1 [Repository Pattern](#431-repository-pattern)
        - 4.3.2 [SQLx Integration](#432-sqlx-integration)

# 4. Data Model

## 4.1 Database Schema

### 4.1.1 Table Structures

The database schema consists of several core tables that store the application's data:

1. **Users Table**
   ```sql
   CREATE TABLE users (
       id UUID PRIMARY KEY,
       username VARCHAR(50) NOT NULL UNIQUE,
       email VARCHAR(255) NOT NULL UNIQUE,
       password_hash VARCHAR(255) NOT NULL,
       first_name VARCHAR(100),
       last_name VARCHAR(100),
       is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
       verification_token VARCHAR(255),
       verification_token_expires_at TIMESTAMP WITH TIME ZONE,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
       role VARCHAR(20) NOT NULL DEFAULT 'user',
       is_active BOOLEAN NOT NULL DEFAULT TRUE,
       last_login_at TIMESTAMP WITH TIME ZONE
   );
   ```

   **Purpose**: Stores user account information including authentication credentials, personal details, and account status.

   **Key Fields**:
   - `id`: Unique identifier using UUID v4
   - `username`: User's chosen unique identifier
   - `email`: User's email address for communications and recovery
   - `password_hash`: Bcrypt-hashed password
   - `is_email_verified`: Flag indicating email verification status
   - `role`: User's role for authorization purposes

2. **Profile Settings Table**
   ```sql
   CREATE TABLE profile_settings (
       id UUID PRIMARY KEY,
       user_id UUID NOT NULL UNIQUE,
       notification_email BOOLEAN NOT NULL DEFAULT TRUE,
       notification_security BOOLEAN NOT NULL DEFAULT TRUE,
       ui_theme VARCHAR(20) NOT NULL DEFAULT 'light',
       ui_density VARCHAR(20) NOT NULL DEFAULT 'normal',
       security_two_factor BOOLEAN NOT NULL DEFAULT FALSE,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
       CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
   );
   ```

   **Purpose**: Stores user preferences and settings separate from core account information.

   **Key Fields**:
   - `user_id`: Reference to the users table
   - `notification_*`: Notification preferences
   - `ui_*`: User interface preferences
   - `security_*`: Security-related settings

3. **Active Tokens Table**
   ```sql
   CREATE TABLE active_tokens (
       id UUID PRIMARY KEY,
       user_id UUID NOT NULL,
       refresh_token VARCHAR(255) NOT NULL UNIQUE,
       expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       device_info VARCHAR(255),
       ip_address VARCHAR(45),
       CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
   );
   ```

   **Purpose**: Tracks active refresh tokens for authenticated sessions.

   **Key Fields**:
   - `user_id`: Reference to the users table
   - `refresh_token`: Unique token for refreshing access tokens
   - `expires_at`: Expiration timestamp
   - `device_info`: Information about the device used
   - `ip_address`: IP address of the client

4. **Revoked Tokens Table**
   ```sql
   CREATE TABLE revoked_tokens (
       id UUID PRIMARY KEY,
       token_id VARCHAR(255) NOT NULL UNIQUE,
       revoked_at TIMESTAMP WITH TIME ZONE NOT NULL,
       reason VARCHAR(100),
       CONSTRAINT uk_token_id UNIQUE(token_id)
   );
   ```

   **Purpose**: Tracks explicitly revoked tokens for security purposes.

   **Key Fields**:
   - `token_id`: Identifier of the revoked token
   - `revoked_at`: When the token was revoked
   - `reason`: Reason for revocation (security event, logout, etc.)

5. **Password Resets Table**
   ```sql
   CREATE TABLE password_resets (
       id UUID PRIMARY KEY,
       user_id UUID NOT NULL,
       token VARCHAR(255) NOT NULL UNIQUE,
       expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       is_used BOOLEAN NOT NULL DEFAULT FALSE,
       CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
   );
   ```

   **Purpose**: Manages password reset requests and tokens.

   **Key Fields**:
   - `user_id`: Reference to the users table
   - `token`: Unique token for password reset
   - `expires_at`: Expiration timestamp
   - `is_used`: Flag indicating if the token has been used

6. **Roles Table**
   ```sql
   CREATE TABLE roles (
       id UUID PRIMARY KEY,
       name VARCHAR(50) NOT NULL UNIQUE,
       description TEXT,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       updated_at TIMESTAMP WITH TIME ZONE NOT NULL
   );
   ```

   **Purpose**: Defines available roles for role-based access control.

   **Key Fields**:
   - `name`: Unique role name
   - `description`: Detailed description of the role's purpose

7. **Permissions Table**
   ```sql
   CREATE TABLE permissions (
       id UUID PRIMARY KEY,
       resource VARCHAR(100) NOT NULL,
       action VARCHAR(50) NOT NULL,
       conditions JSONB,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
       UNIQUE(resource, action)
   );
   ```

   **Purpose**: Defines granular permissions for access control.

   **Key Fields**:
   - `resource`: The resource being protected
   - `action`: The action being controlled
   - `conditions`: JSON conditions for contextual permission evaluation

8. **Role Permissions Table**
   ```sql
   CREATE TABLE role_permissions (
       role_id UUID NOT NULL,
       permission_id UUID NOT NULL,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       PRIMARY KEY (role_id, permission_id),
       CONSTRAINT fk_role FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
       CONSTRAINT fk_permission FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
   );
   ```

   **Purpose**: Maps roles to permissions in a many-to-many relationship.

   **Key Fields**:
   - `role_id`: Reference to the roles table
   - `permission_id`: Reference to the permissions table

9. **Security Events Table**
   ```sql
   CREATE TABLE security_events (
       id UUID PRIMARY KEY,
       event_type VARCHAR(50) NOT NULL,
       user_id UUID,
       ip_address VARCHAR(45) NOT NULL,
       user_agent TEXT,
       details JSONB,
       severity VARCHAR(20) NOT NULL,
       created_at TIMESTAMP WITH TIME ZONE NOT NULL,
       CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
   );
   ```

   **Purpose**: Logs security-related events for auditing and monitoring.

   **Key Fields**:
   - `event_type`: Type of security event
   - `user_id`: Associated user (if applicable)
   - `ip_address`: Source IP address
   - `details`: JSON details about the event
   - `severity`: Event severity level

### 4.1.2 Indexes and Constraints

The database schema includes various indexes and constraints to ensure data integrity and query performance:

1. **Primary Key Constraints**
   - Every table has a UUID primary key
   - Junction tables use composite primary keys

2. **Foreign Key Constraints**
   ```sql
   -- Example of foreign key constraints
   CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
   CONSTRAINT fk_role FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
   CONSTRAINT fk_permission FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
   ```

   **Purpose**: Ensures referential integrity between related tables.
   
   **Behavior**:
   - `ON DELETE CASCADE`: Automatically removes related records when the parent is deleted
   - `ON DELETE SET NULL`: Sets the foreign key to NULL when the parent is deleted

3. **Unique Constraints**
   ```sql
   -- Example of unique constraints
   CONSTRAINT uk_username UNIQUE(username)
   CONSTRAINT uk_email UNIQUE(email)
   CONSTRAINT uk_token UNIQUE(token)
   CONSTRAINT uk_resource_action UNIQUE(resource, action)
   ```

   **Purpose**: Prevents duplicate values in columns or column combinations.

4. **Check Constraints**
   ```sql
   -- Example of check constraints
   CONSTRAINT chk_password_length CHECK (LENGTH(password_hash) >= 60)
   CONSTRAINT chk_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
   ```

   **Purpose**: Enforces business rules at the database level.

5. **Indexes**
   ```sql
   -- Example of indexes
   CREATE INDEX idx_users_email ON users(email);
   CREATE INDEX idx_users_username ON users(username);
   CREATE INDEX idx_active_tokens_user_id ON active_tokens(user_id);
   CREATE INDEX idx_active_tokens_expires_at ON active_tokens(expires_at);
   CREATE INDEX idx_security_events_user_id ON security_events(user_id);
   CREATE INDEX idx_security_events_created_at ON security_events(created_at);
   ```

   **Purpose**: Improves query performance for frequently accessed columns.
   
   **Types**:
   - B-tree indexes for equality and range queries
   - Hash indexes for equality-only queries
   - GIN indexes for JSONB columns

6. **Default Values**
   ```sql
   -- Example of default values
   is_email_verified BOOLEAN NOT NULL DEFAULT FALSE
   role VARCHAR(20) NOT NULL DEFAULT 'user'
   is_active BOOLEAN NOT NULL DEFAULT TRUE
   created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
   ```

   **Purpose**: Provides sensible defaults for columns when not explicitly specified.

7. **Timestamp Triggers**
   ```sql
   -- Example of a timestamp trigger function
   CREATE OR REPLACE FUNCTION update_timestamp()
   RETURNS TRIGGER AS $$
   BEGIN
       NEW.updated_at = NOW();
       RETURN NEW;
   END;
   $$ LANGUAGE plpgsql;

   -- Example of applying the trigger
   CREATE TRIGGER update_users_timestamp
   BEFORE UPDATE ON users
   FOR EACH ROW
   EXECUTE FUNCTION update_timestamp();
   ```

   **Purpose**: Automatically updates timestamp columns when records are modified.

## 4.2 Entity Relationships

### 4.2.2 Relationship Definitions

The database schema implements several types of entity relationships:

1. **One-to-One Relationships**
   ```mermaid
   erDiagram
       users ||--|| profile_settings : has
       users {
           uuid id PK
           string username
           string email
       }
       profile_settings {
           uuid id PK
           uuid user_id FK
           boolean notification_email
           string ui_theme
       }
   ```

   **Implementation**:
   - Foreign key with unique constraint
   - Cascade delete to maintain referential integrity
   
   **Examples**:
   - User to Profile Settings: Each user has exactly one profile settings record

2. **One-to-Many Relationships**
   ```mermaid
   erDiagram
       users ||--o{ active_tokens : has
       users ||--o{ password_resets : requests
       users {
           uuid id PK
           string username
           string email
       }
       active_tokens {
           uuid id PK
           uuid user_id FK
           string refresh_token
           timestamp expires_at
       }
       password_resets {
           uuid id PK
           uuid user_id FK
           string token
           timestamp expires_at
       }
   ```

   **Implementation**:
   - Foreign key without unique constraint
   - Cascade delete to maintain referential integrity
   
   **Examples**:
   - User to Active Tokens: Each user can have multiple active sessions
   - User to Password Resets: Each user can have multiple password reset requests
   - User to Security Events: Each user can have multiple security events

3. **Many-to-Many Relationships**
   ```mermaid
   erDiagram
       roles ||--o{ role_permissions : has
       permissions ||--o{ role_permissions : assigned_to
       roles {
           uuid id PK
           string name
           string description
       }
       permissions {
           uuid id PK
           string resource
           string action
       }
       role_permissions {
           uuid role_id FK
           uuid permission_id FK
       }
   ```

   **Implementation**:
   - Junction table with composite primary key
   - Foreign keys to both parent tables
   - Cascade delete to maintain referential integrity
   
   **Examples**:
   - Roles to Permissions: Each role can have multiple permissions, and each permission can be assigned to multiple roles

4. **Complete Entity Relationship Diagram**
   ```mermaid
   erDiagram
       users ||--|| profile_settings : has
       users ||--o{ active_tokens : has
       users ||--o{ password_resets : requests
       users ||--o{ security_events : generates
       users }|--|| roles : assigned
       
       roles ||--o{ role_permissions : has
       permissions ||--o{ role_permissions : assigned_to
       
       users {
           uuid id PK
           string username UK
           string email UK
           string password_hash
           boolean is_email_verified
           string role FK
       }
       
       profile_settings {
           uuid id PK
           uuid user_id FK,UK
           boolean notification_email
           boolean notification_security
           string ui_theme
           string ui_density
           boolean security_two_factor
       }
       
       active_tokens {
           uuid id PK
           uuid user_id FK
           string refresh_token UK
           timestamp expires_at
           string device_info
           string ip_address
       }
       
       revoked_tokens {
           uuid id PK
           string token_id UK
           timestamp revoked_at
           string reason
       }
       
       password_resets {
           uuid id PK
           uuid user_id FK
           string token UK
           timestamp expires_at
           boolean is_used
       }
       
       roles {
           uuid id PK
           string name UK
           string description
       }
       
       permissions {
           uuid id PK
           string resource
           string action
           jsonb conditions
       }
       
       role_permissions {
           uuid role_id PK,FK
           uuid permission_id PK,FK
       }
       
       security_events {
           uuid id PK
           string event_type
           uuid user_id FK
           string ip_address
           string user_agent
           jsonb details
           string severity
       }
   ```

   **Key**:
   - PK: Primary Key
   - FK: Foreign Key
   - UK: Unique Key

## 4.3 Data Access Layer

### 4.3.1 Repository Pattern

The application implements the Repository pattern to abstract database operations:

1. **Repository Structure**
   ```mermaid
   classDiagram
       class Repository~T~ {
           <<interface>>
           +create(item: T) Future~T~
           +findById(id: UUID) Future~Option~T~~
           +findAll() Future~Vec~T~~
           +update(id: UUID, item: T) Future~T~
           +delete(id: UUID) Future~bool~
       }
       
       class UserRepository {
           -pool: PgPool
           +create(user: UserCreate) Future~User~
           +findById(id: UUID) Future~Option~User~~
           +findByEmail(email: String) Future~Option~User~~
           +findByUsername(username: String) Future~Option~User~~
           +update(id: UUID, user: UserUpdate) Future~User~
           +delete(id: UUID) Future~bool~
           +verifyEmail(id: UUID, token: String) Future~bool~
           +updatePassword(id: UUID, password: String) Future~bool~
           +findByVerificationToken(token: String) Future~Option~User~~
       }
       
       class TokenRepository {
           -pool: PgPool
           +createRefreshToken(token: RefreshTokenCreate) Future~RefreshToken~
           +findByToken(token: String) Future~Option~RefreshToken~~
           +deleteByUserId(userId: UUID) Future~i64~
           +deleteByToken(token: String) Future~bool~
           +revokeToken(tokenId: String, reason: String) Future~bool~
           +isTokenRevoked(tokenId: String) Future~bool~
       }
       
       Repository <|.. UserRepository
       Repository <|.. TokenRepository
   ```

2. **Repository Implementation**
   ```rust
   // Example of a repository implementation
   pub struct UserRepository {
       pool: PgPool,
   }
   
   impl UserRepository {
       pub fn new(pool: PgPool) -> Self {
           Self { pool }
       }
       
       pub async fn create(&self, user: UserCreate) -> Result<User, DbError> {
           sqlx::query_as!(
               User,
               r#"
               INSERT INTO users (
                   id, username, email, password_hash, 
                   is_email_verified, verification_token,
                   verification_token_expires_at, created_at, 
                   updated_at, role
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               RETURNING *
               "#,
               Uuid::new_v4(),
               user.username,
               user.email,
               user.password_hash,
               false,
               user.verification_token,
               user.verification_token_expires_at,
               Utc::now(),
               Utc::now(),
               "user"
           )
           .fetch_one(&self.pool)
           .await
           .map_err(DbError::from)
       }
       
       pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
           sqlx::query_as!(
               User,
               "SELECT * FROM users WHERE email = $1",
               email
           )
           .fetch_optional(&self.pool)
           .await
           .map_err(DbError::from)
       }
       
       // Additional methods...
   }
   ```

3. **Repository Benefits**
   - Abstracts database access logic
   - Centralizes query definitions
   - Facilitates testing through mocking
   - Provides type-safe data access
   - Encapsulates transaction management

4. **Repository Usage**
   ```rust
   // Example of repository usage in a service
   pub struct UserService {
       user_repository: Arc<UserRepository>,
       token_repository: Arc<TokenRepository>,
   }
   
   impl UserService {
       pub async fn create_user(&self, input: UserInput) -> Result<User, ServiceError> {
           // Check if user already exists
           if let Some(_) = self.user_repository.find_by_email(&input.email).await? {
               return Err(ServiceError::UserAlreadyExists);
           }
           
           // Hash password
           let password_hash = hash_password(&input.password)?;
           
           // Generate verification token
           let verification_token = generate_secure_token();
           let expires_at = Utc::now() + Duration::hours(24);
           
           // Create user
           let user_create = UserCreate {
               username: input.username,
               email: input.email,
               password_hash,
               verification_token: Some(verification_token.clone()),
               verification_token_expires_at: Some(expires_at),
           };
           
           let user = self.user_repository.create(user_create).await?;
           
           Ok(user)
       }
       
       // Additional methods...
   }
   ```

### 4.3.2 SQLx Integration

The application uses SQLx for type-safe database access:

1. **SQLx Configuration**
   ```rust
   // Database configuration
   pub struct DatabaseConfig {
       pub connection_string: String,
       pub max_connections: u32,
       pub min_connections: u32,
       pub max_lifetime: Duration,
       pub idle_timeout: Duration,
       pub connect_timeout: Duration,
   }
   
   // Database pool setup
   pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool, Error> {
       let pool = PgPoolOptions::new()
           .max_connections(config.max_connections)
           .min_connections(config.min_connections)
           .max_lifetime(config.max_lifetime)
           .idle_timeout(config.idle_timeout)
           .connect_timeout(config.connect_timeout)
           .connect(&config.connection_string)
           .await?;
       
       Ok(pool)
   }
   ```

2. **Type-Safe Queries**
   ```rust
   // Example of a type-safe query
   pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, Error> {
       sqlx::query_as!(
           User,
           "SELECT * FROM users WHERE id = $1",
           id
       )
       .fetch_optional(pool)
       .await
   }
   ```

3. **Migrations Management**
   ```rust
   // Migration runner
   pub async fn run_migrations(pool: &PgPool) -> Result<(), Error> {
       sqlx::migrate!("./migrations")
           .run(pool)
           .await?;
       
       Ok(())
   }
   ```

4. **Transaction Management**
   ```rust
   // Example of transaction usage
   pub async fn create_user_with_profile(
       pool: &PgPool,
       user: UserCreate,
       profile: ProfileCreate
   ) -> Result<(User, Profile), Error> {
       let mut tx = pool.begin().await?;
       
       // Create user
       let user = sqlx::query_as!(
           User,
           r#"
           INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING *
           "#,
           Uuid::new_v4(),
           user.username,
           user.email,
           user.password_hash,
           Utc::now(),
           Utc::now()
       )
       .fetch_one(&mut *tx)
       .await?;
       
       // Create profile
       let profile = sqlx::query_as!(
           Profile,
           r#"
           INSERT INTO profile_settings (id, user_id, created_at, updated_at)
           VALUES ($1, $2, $3, $4)
           RETURNING *
           "#,
           Uuid::new_v4(),
           user.id,
           Utc::now(),
           Utc::now()
       )
       .fetch_one(&mut *tx)
       .await?;
       
       // Commit transaction
       tx.commit().await?;
       
       Ok((user, profile))
   }
   ```

5. **Error Handling**
   ```rust
   // Database error wrapper
   #[derive(Debug, Error)]
   pub enum DbError {
       #[error("Database error: {0}")]
       Sqlx(#[from] sqlx::Error),
       
       #[error("Record not found")]
       NotFound,
       
       #[error("Unique constraint violation: {0}")]
       UniqueViolation(String),
       
       #[error("Foreign key constraint violation: {0}")]
       ForeignKeyViolation(String),
       
       #[error("Check constraint violation: {0}")]
       CheckViolation(String),
       
       #[error("Database connection error: {0}")]
       ConnectionError(String),
   }
   
   // Error mapping
   impl From<sqlx::Error> for DbError {
       fn from(error: sqlx::Error) -> Self {
           match &error {
               sqlx::Error::RowNotFound => DbError::NotFound,
               sqlx::Error::Database(db_error) => {
                   if let Some(code) = db_error.code() {
                       match code.as_ref() {
                           "23505" => DbError::UniqueViolation(db_error.message().to_string()),
                           "23503" => DbError::ForeignKeyViolation(db_error.message().to_string()),
                           "23514" => DbError::CheckViolation(db_error.message().to_string()),
                           _ => DbError::Sqlx(error),
                       }
                   } else {
                       DbError::Sqlx(error)
                   }
               }
               _ => DbError::Sqlx(error),
           }
       }
   }
   ```

6. **Query Macros**
   ```rust
   // Example of query macros
   
   // Query for a single record
   let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
       .fetch_one(&pool)
       .await?;
   
   // Query for optional record
   let user = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
       .fetch_optional(&pool)
       .await?;
   
   // Query for multiple records
   let users = sqlx::query_as!(User, "SELECT * FROM users WHERE role = $1", role)
       .fetch_all(&pool)
       .await?;
   
   // Execute without returning records
   let rows_affected = sqlx::query!("DELETE FROM users WHERE id = $1", id)
       .execute(&pool)
       .await?
       .rows_affected();