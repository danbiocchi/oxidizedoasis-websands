# OxidizedOasis-WebSands Project Structure

```mermaid
graph TD
    A[oxidizedoasis-websands] --> B[docs]
    A --> C[migrations]
    A --> D[src]
    A --> E[static]
    A --> F[tests]
    A --> G[Root Files]

    B --> B1[Software_Development_Document.md]
    B --> B2[Security_Audit.md]
    B --> B3[Security_Backlog.md]
    B --> B4[User_Guide.md]
    B --> B5[Logging_Plan.md]

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
    E --> E3[admin_dashboard.html]
    E --> E4[dashboard.html]
    E --> E5[email_verified.html]
    E --> E6[index.html]
    E --> E7[token_failure.html]

    E1 --> E1a[dashboard.css]
    E1 --> E1b[styles.css]

    E2 --> E2a[signup-page-screenshot.png]

    G --> G1[.env]
    G --> G2[.env.test]
    G --> G3[.gitignore]
    G --> G4[Cargo.lock]
    G --> G5[Cargo.toml]
    G --> G6[readme.md]

    classDef default fill:#f9f,stroke:#333,stroke-width:2px;
    classDef directory fill:#bbf,stroke:#333,stroke-width:2px;
    classDef file fill:#ffd,stroke:#333,stroke-width:1px;
    
    class A,B,C,D,E,F,G directory;
    class B1,B2,B3,B4,B5,C1,D1a,D1b,D2a,D2b,D2c,D3a,D3b,D3c,D4a,D4b,D4c,D5,D6,D7,D8,E1a,E1b,E2a,E3,E4,E5,E6,E7,G1,G2,G3,G4,G5,G6 file;
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

This Mermaid chart provides a visual representation of the OxidizedOasis-WebSands project structure, making it easy to understand the project's organization at a glance.



# OxidizedOasis-WebSands Plain-Text Project Structure
```
oxidizedoasis-websands/
│
├── docs/                          # Project documentation
│   ├── Software_Development_Document.md
│   ├── Security_Audit.md
│   ├── Security_Backlog.md
│   ├── User_Guide.md
│   └── Logging_Plan.md
│
├── migrations/                    # Database migration scripts
│   └── 20240901010340_initial_schema.sql
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
│   │   └── signup-page-screenshot.png
│   │
│   ├── admin_dashboard.html       # Admin dashboard template
│   ├── dashboard.html             # User dashboard template
│   ├── email_verified.html        # Email verification success page
│   ├── index.html                 # Main landing page
│   └── token_failure.html         # Token verification failure page
│
├── tests/                         # Test directory (integration tests)
│
├── .env                           # Environment variables for development
├── .env.test                      # Environment variables for testing
├── .gitignore                     # Git ignore file
├── Cargo.lock                     # Cargo lock file (dependency versions)
├── Cargo.toml                     # Cargo manifest file (project dependencies)
└── readme.md                      # Project readme file
```
