# Project Structure

This document outlines the structure of the Oxidized Oasis WebSands project, a full-stack web application built with Rust. The project is organized into frontend and backend components, each with their own distinct architecture.

## Frontend (`/frontend`)

```
frontend/
├── dist/                    # Build output directory
├── src/                     # Source code directory
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
├── static/                 # Static assets
│   ├── favicon.svg        # Site favicon
│   └── css/               # CSS structure
│       ├── main.css       # Main CSS entry point
│       ├── core/          # Core styles
│       │   ├── base.css   # Base styles
│       │   ├── reset.css  # CSS reset
│       │   └── variables.css # CSS variables
│       ├── components/    # Component styles
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
│       ├── layouts/       # Layout styles
│       │   ├── containers.css
│       │   └── grid.css
│       ├── pages/         # Page-specific styles
│       │   ├── about/
│       │   ├── auth/
│       │   ├── dashboard/
│       │   └── home/
│       └── utils/         # Utility styles
│           ├── animations.css
│           ├── breakpoints.css
│           └── helpers.css
│
├── Cargo.toml             # Dependencies and build configuration
├── index.html            # HTML template
└── Trunk.toml           # Trunk bundler configuration
```

### Frontend Architecture Rationale

The frontend architecture follows several key principles:

1. **Component-Based Structure**
   - Separates reusable UI components from page-specific components
   - Enables component reusability and maintains DRY principles
   - Makes testing and maintenance easier by isolating component logic

2. **State Management**
   - Services directory handles business logic and state management
   - Uses context providers for global state
   - Keeps components focused on presentation while services handle data

3. **CSS Organization**
   - Modular CSS architecture with clear separation of concerns
   - Prevents CSS specificity issues
   - Makes styles more maintainable

4. **Routing System**
   - Centralized routing configuration
   - Consistent navigation management
   - Easy to maintain and modify application flow

## Backend (`/src`)

```
src/
├── api/                  # API Layer
│   ├── handlers/         # Request handlers
│   │   ├── mod.rs
│   │   └── user_handler.rs
│   ├── responses/        # Response structures
│   │   ├── mod.rs
│   │   └── user_response.rs
│   ├── routes/          # Route definitions
│   │   ├── mod.rs
│   │   ├── user_routes.rs
│   │   └── admin/       # Admin-specific routes
│   │       ├── mod.rs
│   │       ├── logs.rs
│   │       ├── security.rs
│   │       └── user_management.rs
│   └── mod.rs
│
├── common/              # Shared utilities and error handling
│   ├── error/          # Error definitions
│   │   ├── mod.rs
│   │   ├── api_error.rs
│   │   ├── auth_error.rs
│   │   └── db_error.rs
│   ├── utils/          # Utility functions
│   │   ├── mod.rs
│   │   ├── string.rs
│   │   ├── time.rs
│   │   └── validation.rs
│   ├── validation/     # Input validation
│   │   ├── mod.rs
│   │   ├── password.rs # Password validation rules
│   │   └── user.rs     # User input validation
│   └── mod.rs
│
├── core/               # Core business logic
│   ├── auth/          # Authentication
│   │   ├── mod.rs
│   │   ├── jwt.rs     # JWT implementation
│   │   └── service.rs # Authentication service
│   ├── email/         # Email functionality
│   │   ├── mod.rs
│   │   ├── service.rs # Email service implementation
│   │   └── templates.rs # Email templates
│   ├── user/          # User management
│   │   ├── mod.rs
│   │   ├── model.rs   # User domain model
│   │   ├── repository.rs # User data access
│   │   └── service.rs # User business logic
│   └── mod.rs
│
├── infrastructure/     # Infrastructure layer
│   ├── config/        # Configuration
│   │   ├── mod.rs
│   │   └── app_config.rs # Application configuration
│   ├── database/      # Database management
│   │   ├── mod.rs
│   │   ├── connection.rs # Database connection setup
│   │   └── migrations.rs # Database migrations
│   ├── middleware/    # HTTP middleware
│   │   ├── mod.rs
│   │   ├── admin.rs   # Admin authentication
│   │   ├── auth.rs    # User authentication
│   │   ├── cors.rs    # CORS configuration
│   │   ├── logger.rs  # Request logging
│   │   └── rate_limit.rs # Rate limiting
│   └── mod.rs
│
├── lib.rs             # Library exports
└── main.rs            # Application entry point
```

### Backend Architecture Rationale

The backend implements Clean Architecture principles for several reasons:

1. **API Layer**
   - Separates web-specific code from business logic
   - Easy to modify endpoints without affecting core functionality
   - Simplified testing of API endpoints

2. **Common Layer**
   - Reduces code duplication
   - Centralizes error handling and validation
   - Provides consistent patterns across the application

3. **Core Layer**
   - Contains pure business logic and domain models
   - Easy to test in isolation
   - Protected from external system changes

4. **Infrastructure Layer**
   - External services can be swapped easily
   - Centralized configuration
   - Flexible middleware management

## Tests (`/tests`)

```
tests/
├── user_crud_tests.rs  # User CRUD operation tests
└── user_tests.rs       # General user functionality tests
```

### Testing Strategy Rationale

The testing structure provides:

1. **Organized Test Separation**
   - CRUD tests isolated from general functionality
   - Clear identification of test purposes
   - Easy to maintain and extend

2. **Integration Focus**
   - Full system interaction testing
   - Verifies component integration
   - Catches real-world usage issues

## Database Migrations (`/migrations`)

```
migrations/
├── 20240901010340_initial_schema.sql
└── 20240902010341_add_password_reset.sql
```

### Migration Strategy Rationale

The migration system provides:

1. **Version Control**
   - Timestamped ordering
   - Documented changes
   - Easy rollback capability

2. **Incremental Updates**
   - Single-purpose changes
   - Clear database evolution
   - Safe production updates

## Overall Architecture Benefits

This project structure delivers:

1. **Maintainability**
   - Clear separation of concerns
   - Modular design
   - Consistent patterns

2. **Scalability**
   - Independent layer scaling
   - Easy feature addition
   - Clear team work distribution

3. **Security**
   - Separated authentication
   - Centralized security
   - Protected sensitive logic

4. **Performance**
   - Optimized asset organization
   - Independent service optimization
   - Strategic caching capability
