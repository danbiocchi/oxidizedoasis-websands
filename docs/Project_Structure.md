# OxidizedOasis-WebSands Project Structure

```mermaid
graph LR
    A[oxidizedoasis-websands] --> B[docs]
    A --> C[migrations]
    A --> D[src]
    A --> E[static]
    A --> F[tests]
    A --> G[Root Files]

    B --> B1[archive]
    B1 --> B1a[Logging_Plan.md]
    B1 --> B1b[Project_Structure.md]
    B1 --> B1c[Security_Audit.md]
    B1 --> B1d[Security_Backlog.md]
    B1 --> B1e[Software_Development_Document.md]
    B1 --> B1f[Testing_Backlog.md]
    B1 --> B1g[User_Guide.md]

    C --> C1[20240901010340_initial_schema.sql]

    D --> D1[config]
    D --> D2[handlers]
    D --> D3[middleware]
    D --> D4[models]
    D --> D5[auth.rs]
    D --> D6[email.rs]
    D --> D7[main.rs]
    D --> D8[validation.rs]

    D1 --> D1a[mod.rs]
    D1 --> D1b[config.rs]

    D2 --> D2a[mod.rs]
    D2 --> D2b[admin.rs]
    D2 --> D2c[user.rs]

    D3 --> D3a[mod.rs]
    D3 --> D3b[cors_logger.rs]
    D3 --> D3c[middleware.rs]

    D4 --> D4a[mod.rs]
    D4 --> D4b[session.rs]
    D4 --> D4c[user.rs]

    E --> E1[css]
    E --> E2[images]
    E --> E3[templates]

    E1 --> E1a[dashboard.css]
    E1 --> E1b[styles.css]

    E2 --> E2a[signup-page-screenshot.png]

    E3 --> E3a[already_verified.html]
    E3 --> E3b[email_verified.html]
    E3 --> E3c[error.html]
    E3 --> E3d[expired_token.html]
    E3 --> E3e[invalid_token.html]
    E3 --> E3f[token_failure.html]
    E3 --> E3g[verification_resent.html]
    
    E --> E4[admin_dashboard.html]
    E --> E5[dashboard.html]
    E --> E6[index.html]

    F --> F1[e2e]
    F --> F2[user_crud_tests.rs]
    F --> F3[user_tests.rs]

    G --> G1[.env files]
    G --> G2[.gitignore]
    G --> G3[Cargo.lock]
    G --> G4[Cargo.toml]
    G --> G5[readme.md]

    classDef default fill:#f9f9f9,stroke:#333,stroke-width:1px;
    classDef rootDir fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef mainDir fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef subDir fill:#fff3e0,stroke:#ef6c00,stroke-width:1px;
    classDef file fill:#ffffff,stroke:#616161,stroke-width:1px;
    
    class A rootDir;
    class B,C,D,E,F,G mainDir;
    class B1,D1,D2,D3,D4,E1,E2,E3,F1 subDir;
    class B1a,B1b,B1c,B1d,B1e,B1f,B1g,C1,D1a,D1b,D2a,D2b,D2c,D3a,D3b,D3c,D4a,D4b,D4c,D5,D6,D7,D8,E1a,E1b,E2a,E3a,E3b,E3c,E3d,E3e,E3f,E3g,E4,E5,E6,F2,F3,G1,G2,G3,G4,G5 file;
```

## Directory and File Descriptions

### `/docs`
Contains project documentation, including software development documents, security audits, and user guides.

### `/migrations`
Stores database migration scripts for managing database schema changes.

### `/src`
The main source code directory for the application.

- `/config`: Manages application configuration and environment variables.
- `/handlers`: Contains request handlers for different routes and functionalities.
- `/middleware`: Implements custom middleware for request/response processing.
- `/models`: Defines data models and structures used throughout the application.
- `auth.rs`: Implements authentication logic, including JWT token generation and validation.
- `email.rs`: Handles email-related functionality, such as sending verification emails.
- `main.rs`: The entry point of the application, setting up the server and routes.
- `validation.rs`: Implements input validation logic for user inputs and data.

### `/static`
Contains static files served by the application.

- `/css`: Stores CSS files for styling the frontend.
- `/images`: Contains image assets used in the application.
- HTML files: Templates for various pages (admin dashboard, user dashboard, etc.).

### `/tests`
Directory for integration tests.

### Root Files
- `.env` and `.env.test`: Environment variables for development and testing.
- `.gitignore`: Specifies intentionally untracked files to ignore.
- `Cargo.lock`: Ensures consistent builds by locking dependency versions.
- `Cargo.toml`: Cargo manifest file specifying project dependencies and metadata.
- `readme.md`: Provides an overview and instructions for the project.


# OxidizedOasis-WebSands Plain-Text Project Structure
```
# OxidizedOasis-WebSands Plain-Text Project Structure

oxidizedoasis-websands/
│
├── docs/                          # Project documentation
│   ├── archive/                   # Archived documents
│   │   ├── Logging_Plan.md        # Logging strategy and plan
│   │   ├── Project_Structure.md   # Documentation for project structure
│   │   ├── Security_Audit.md      # Security audit details
│   │   ├── Security_Backlog.md    # Security-related backlogs
│   │   ├── Software_Development_Document.md  # Development process documentation
│   │   ├── Testing_Backlog.md     # Testing backlog documentation
│   │   └── User_Guide.md          # User guide for the application
│
├── migrations/                    # Database migration scripts
│   └── 20240901010340_initial_schema.sql  # Initial database schema migration
│
├── src/                           # Source code directory
│   ├── config/                    # Configuration management
│   │   ├── mod.rs                 # Module declaration file
│   │   └── config.rs              # Application configuration handling
│   │
│   ├── handlers/                  # Request handlers
│   │   ├── mod.rs                 # Module declaration file
│   │   ├── admin.rs               # Admin-specific handlers
│   │   └── user.rs                # User-related handlers
│   │
│   ├── middleware/                # Custom middleware
│   │   ├── mod.rs                 # Module declaration file
│   │   ├── cors_logger.rs         # CORS logging middleware
│   │   └── middleware.rs          # General middleware implementations
│   │
│   ├── models/                    # Data models
│   │   ├── mod.rs                 # Module declaration file
│   │   ├── session.rs             # Session model
│   │   └── user.rs                # User model
│   │
│   ├── auth.rs                    # Authentication logic
│   ├── email.rs                   # Email service implementation
│   ├── main.rs                    # Application entry point
│   └── validation.rs              # Input validation logic
│
├── static/                        # Static files
│   ├── css/                       # CSS stylesheets
│   │   ├── dashboard.css          # Dashboard-specific styles
│   │   └── styles.css             # Global styles
│   │
│   ├── images/                    # Image assets
│   │   └── signup-page-screenshot.png  # Signup page screenshot for documentation or UI reference
│   │
│   ├── templates/                 # HTML templates for various pages
│   │   ├── already_verified.html  # Template for already verified users
│   │   ├── email_verified.html    # Template for email verification success
│   │   ├── error.html             # Error page template
│   │   ├── expired_token.html     # Token expired template
│   │   ├── invalid_token.html     # Invalid token template
│   │   ├── token_failure.html     # Token failure template
│   │   └── verification_resent.html  # Template for resent verification
│   │
│   ├── admin_dashboard.html       # Admin dashboard template
│   ├── dashboard.html             # User dashboard template
│   ├── index.html                 # Main landing page
│
├── tests/                         # Test directory (integration tests)
│   ├── e2e/                       # End-to-end test scripts
│   ├── user_crud_tests.rs         # CRUD operation tests for users
│   └── user_tests.rs              # General user tests
│
├── .env                           # Environment variables for development
├── .env.test                      # Environment variables for testing
├── .gitignore                     # Git ignore file
├── Cargo.lock                     # Cargo lock file (dependency versions)
├── Cargo.toml                     # Cargo manifest file (project dependencies)
└── readme.md                      # Project readme file
```
