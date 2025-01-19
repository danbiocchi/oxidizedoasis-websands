# Project Structure
frontend/
├── dist/                    # Build output directory
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── mod.rs          # Components module declarations
│   │   ├── nav.rs          # Navigation bar component
│   │   ├── footer.rs       # Footer component
│   │   ├── icons.rs        # Icon components
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
│   │   ├── registration_complete.rs  # Registration success
│   │   ├── password_reset_request.rs # Password reset request page
│   │   ├── password_reset_verify.rs  # Password reset verification
│   │   ├── password_reset_new.rs     # New password entry page
│   │   └── not_found.rs    # 404 page
│   │
│   ├── services/           # Business logic and state management
│   │   ├── mod.rs          # Services module declarations
│   │   ├── auth.rs         # Authentication service
│   │   ├── auth_context.rs # Authentication context provider
│   │   ├── confetti.rs     # Confetti animation service
│   │   ├── confetti_context.rs # Confetti context provider
│   │   └── reset_token_context.rs # Password reset token context
│   │
│   ├── routes.rs           # Route definitions
│   └── lib.rs              # Main application entry
│
├── static/
│   ├── favicon.svg         # Site favicon
│   └── css/                # Organized CSS structure
│       ├── main.css        # Main CSS entry point
│       ├── core/           # Core styles
│       │   ├── base.css    # Base styles
│       │   ├── reset.css   # CSS reset
│       │   └── variables.css # CSS variables
│       ├── components/     # Component styles
│       │   ├── buttons.css
│       │   ├── cards.css
│       │   ├── footer.css
│       │   ├── loaders.css
│       │   ├── forms/
│       │   │   ├── inputs.css
│       │   │   └── validation.css
│       │   └── nav/
│       │       ├── navbar.css
│       │       └── sidebar.css
│       ├── layouts/        # Layout styles
│       │   ├── containers.css
│       │   └── grid.css
│       ├── pages/          # Page-specific styles
│       │   ├── about/
│       │   ├── auth/
│       │   ├── dashboard/
│       │   └── home/
│       └── utils/          # Utility styles
│           ├── animations.css
│           ├── breakpoints.css
│           └── helpers.css
│
├── Cargo.toml              # Dependencies and build configuration
├── index.html              # HTML template
└── Trunk.toml              # Trunk bundler configuration

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
└── main.rs                 # Application entry point

tests/                      # Integration tests
├── user_crud_tests.rs      # User CRUD operation tests
└── user_tests.rs           # General user functionality tests
