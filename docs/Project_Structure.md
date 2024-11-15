# Project Structure
frontend/
├── dist/                    # Build output directory
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── mod.rs          # Components module declarations
│   │   ├── nav.rs          # Navigation bar component
│   │   ├── footer.rs       # Footer component
│   │   ├── dashboard.rs    # Dashboard component
│   │   ├── login.rs        # Login form component
│   │   └── not_found.rs    # 404 page component
│   │
│   ├── pages/              # Page-level components
│   │   ├── mod.rs          # Pages module declarations
│   │   ├── home.rs         # Home page
│   │   ├── about.rs        # About page
│   │   ├── dashboard.rs    # Dashboard page
│   │   ├── login.rs        # Login page
│   │   ├── register.rs     # Registration page
│   │   ├── email_verified.rs  # Email verification confirmation
│   │   └── registration_complete.rs  # Registration success
│   │
│   ├── services/           # Business logic and state management
│   │   ├── lib.rs          # Library entry point
│   │   ├── confetti.rs     # Confetti animation service
│   │   └── auth.rs         # Authentication service
│   │
│   ├── routes.rs           # Route definitions
│   └── lib.rs              # Main application entry
│
├── static/
│   └── styles.css          # Global styles
│
├── Cargo.toml              # Dependencies and build configuration
├── index.html             # HTML template
└── Trunk.toml             # Trunk bundler configuration

src/
├── api/
│   ├── handlers/
│   │   ├── mod.rs
│   │   └── user_handler.rs
│   ├── responses/
│   │   ├── mod.rs
│   │   └── user_response.rs
│   ├── routes/
│   │   ├── mod.rs
│   │   └── user_routes.rs
│   └── mod.rs
│
├── common/
│   ├── error/
│   │   ├── mod.rs
│   │   ├── api_error.rs
│   │   ├── auth_error.rs
│   │   └── db_error.rs
│   ├── utils/
│   │   ├── mod.rs
│   │   ├── string.rs
│   │   ├── time.rs
│   │   └── validation.rs
│   ├── validation/
│   │   ├── mod.rs
│   │   ├── password.rs    # Password validation rules
│   │   └── user.rs        # User input validation
│   └── mod.rs
│
├── core/
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs         # JWT implementation
│   │   └── service.rs     # Authentication service
│   ├── email/
│   │   ├── mod.rs
│   │   ├── service.rs     # Email service implementation
│   │   └── templates.rs   # Email templates
│   ├── user/
│   │   ├── mod.rs
│   │   ├── model.rs       # User domain model
│   │   ├── repository.rs  # User data access
│   │   └── service.rs     # User business logic
│   └── mod.rs
│
├── infrastructure/
│   ├── config/
│   │   ├── mod.rs
│   │   └── app_config.rs  # Application configuration
│   ├── database/
│   │   ├── mod.rs
│   │   ├── connection.rs  # Database connection setup
│   │   └── migrations.rs  # Database migrations
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs        # Authentication middleware
│   │   ├── cors.rs        # CORS configuration
│   │   ├── logger.rs      # Request logging
│   │   └── rate_limit.rs  # Rate limiting
│   └── mod.rs
│
├── lib.rs                  # Library exports
└── main.rs                # Application entry point