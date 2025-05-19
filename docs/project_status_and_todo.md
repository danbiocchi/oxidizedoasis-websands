# OxidizedOasis-WebSands: Project Status & To-Do List

**Last Updated:** 2025-05-19

## 1. Project Status Overview

This document outlines the current status of the OxidizedOasis-WebSands project and provides a comprehensive to-do list to guide future development. The project has a functional baseline for core authentication and user management.

**Core Project Objective:** To build a secure, scalable, and maintainable web platform where users can upload, manage, and analyze various types of drone-collected data (imagery, LiDAR, etc.) using an LLM-powered chat interface that leverages Retrieval Augmented Generation (RAG) to provide actionable intelligence.

This document aims to re-establish a clear understanding of completed work, pending tasks, and the roadmap ahead, especially after a recent pause in development.

## 2. Key State Clarifications

*   **Login Persistence:** HttpOnly cookies are implemented for token storage, providing persistent user sessions.
*   **User Creation & Authentication:** These are implemented full-stack with JWT, password hashing (bcrypt), email verification, and role-based access.
*   **Database Schema:** Migrations for users, refresh tokens, revoked tokens, active tokens, and password reset tokens are in place.

## 3. Detailed Feature Status Breakdown

### A. Fully Implemented (Frontend & Backend)
*   **Core Authentication:**
    *   User registration with email verification flow.
    *   Login with username/password.
    *   Logout.
    *   JWT-based access and refresh tokens.
    *   HttpOnly cookies for token storage.
    *   CSRF protection for token-related endpoints.
    *   Token refresh mechanism.
*   **Admin User Management:**
    *   Listing all users.
    *   Inspecting detailed user information.
    *   Editing basic user fields (username, email, role).
    *   Deleting users.
*   **Basic User Profile:** Users can view their own profile information.
*   **Settings Page (Basic Structure):** Frontend UI for settings is in place with a tabbed interface. Some basic profile edits (like username) are functional via existing user services.
*   **Password Reset Flow:** Fully implemented from request to new password setting.
*   **Basic Request Logging:** Middleware (`src/infrastructure/middleware/logger.rs`) for logging HTTP requests is present.

### B. Partially Implemented / Frontend-Only / Backend Required (Standard Web App Features)
*   **Settings Page - Full Functionality:**
    *   Backend logic for persisting user preferences (e.g., notifications, appearance settings) is largely missing.
    *   Backend for secure account deletion process needs full implementation.
*   **Comprehensive Application & Security Logging:**
    *   Beyond basic HTTP request logs, detailed application-level event logging (e.g., security events, critical errors, significant user actions, data processing steps) for auditing and monitoring needs robust backend implementation.
*   **Error Handling & Reporting:**
    *   While basic error types exist (`src/common/error/`), a more robust system for capturing, reporting, and displaying user-friendly errors consistently across the application is needed.
*   **User Interface (UI) & User Experience (UX) Refinements:**
    *   Ongoing need for general improvements across the application for consistency, responsiveness, and accessibility based on new features.

### C. Partially Implemented / Frontend-Only / Backend Required (Drone Data & RAG Core Objective)
*   **Dashboard - Drone Data Management (`frontend/src/pages/dashboard/data.rs`):**
    *   Frontend component for data interaction exists.
    *   **CRITICAL Backend Gaps:**
        *   No specific API endpoints for handling diverse drone data types (video, imagery, rasters, LiDAR).
        *   No backend services for processing these data types (e.g., metadata extraction, thumbnail generation, format conversion, pre-processing for RAG).
        *   No specialized storage solutions considered or implemented (e.g., object storage for large files, geospatial databases for rasters/LiDAR).
        *   No backend logic for creating embeddings or indexing data for RAG.
*   **Dashboard - LLM Chat for Drone Data Intelligence (`frontend/src/pages/dashboard/chat.rs`):**
    *   Frontend component for chat interface exists.
    *   **CRITICAL Backend Gaps:**
        *   No real-time communication infrastructure (e.g., WebSockets) specifically for chat.
        *   No backend service to:
            *   Receive user queries via chat.
            *   Retrieve relevant drone data chunks/embeddings (the "R" in RAG).
            *   Construct prompts for an LLM, augmenting with retrieved data.
            *   Interface with an LLM.
            *   Process and return LLM-generated intelligence to the user.

### D. Features In Progress (Backend and/or Frontend work remaining)
*   **Self User Edit Protection:** (Task in `memory-bank/progress.md`)
    *   Goal: Prevent users from inadvertently locking themselves out or performing problematic self-edits via the admin panel.
    *   Requires frontend checks (disable buttons/fields) and backend validation.
*   **Email Update Functionality:** (Task in `memory-bank/progress.md` & `memory-bank/activeContext.md`)
    *   Architectural decision pending on whether email changes require re-verification.
    *   Backend and frontend implementation based on the decision.
*   **API Logic Check Review:** (Task in `memory-bank/progress.md` & `memory-bank/activeContext.md`)
    *   Ongoing review of all API endpoints for proper validation, security, and business logic.

### E. Planned Major Enhancements / Future Considerations (Standard Web App & Project Specific)
*   **Enhanced JWT Security:** Implement `audience` (aud) and `issuer` (iss) claims.
*   **System Monitoring & Alerting:** For performance, errors, security events, and RAG pipeline health.
*   **Comprehensive Test Suite:** Unit, Integration, End-to-End (E2E), Performance, and Security testing.
*   **Performance Optimization:** Backend (API, database, RAG pipeline) & Frontend (rendering, WebAssembly load times).
*   **Scalability Enhancements:** Database scaling, caching strategies, load balancing for backend services.
*   **Containerization Strategy:** Docker/Kubernetes for deployment and scaling.
*   **API Documentation Framework:** (e.g., OpenAPI/Swagger).
*   **CI/CD Pipeline Enhancements:** Automated testing, security scans, deployment automation.
*   **Advanced Data Visualization for Drone Data:** Frontend components to display maps, 3D models, imagery previews.
*   **Two-Factor Authentication (2FA):** Lower priority, for future consideration.

## 4. Comprehensive To-Do List

### Phase 1: Strengthen Core Platform & Begin Drone Data Backend

#### Task Group 1.1: Solidify Existing Features & Address "In Progress" Items
1.  **Finalize Self User Edit Protection:**
    *   **Frontend:** Implement logic in `UserDetail` component (`frontend/src/pages/dashboard/admin/user_detail.rs`) to disable relevant fields/actions if the admin is viewing their own profile. Fetch current user ID and compare.
    *   **Backend:** Implement validation in user update handlers (e.g., in `src/api/handlers/admin/user_management.rs` or `src/core/user/service.rs`) to prevent self-modification of critical fields (e.g., role, active status by oneself).
2.  **Finalize Email Update Functionality:**
    *   **Decision:** Determine if email changes require re-verification.
    *   **Backend:** Implement logic in user service (`src/core/user/service.rs`) and API handler (`src/api/handlers/user_handler.rs` or settings specific) to handle email updates, including sending new verification emails if required.
    *   **Frontend:** Update settings/profile page (`frontend/src/pages/dashboard/settings.rs` or `profile.rs`) to allow email changes and guide through re-verification if needed.
3.  **Complete API Logic Check Review:**
    *   Systematically review each API endpoint defined in `src/api/routes/` for:
        *   Input validation (completeness, correctness).
        *   Authorization checks (correct roles/permissions).
        *   Error handling (proper error types, user-friendly messages).
        *   Correct business logic execution.
    *   Document findings and create sub-tasks for any identified fixes.
4.  **Settings Page - Backend Functionality:**
    *   **User Preferences Storage:** Design/refine `user_preferences` table (if needed, or extend `users` table).
    *   **Notification Preferences:**
        *   Backend: API endpoint and service logic in `src/core/user/service.rs` to save/retrieve user notification settings.
        *   Frontend: Connect UI toggles in `frontend/src/pages/dashboard/settings/tabs/NotificationSettings.rs` to backend.
    *   **Appearance/Theme Preferences:**
        *   Backend: API and service logic to save/retrieve user theme settings.
        *   Frontend: Connect UI options in `frontend/src/pages/dashboard/settings/tabs/AppearanceSettings.rs` to backend.
    *   **Secure Account Deletion:**
        *   Backend: Implement a secure API endpoint and service logic for account deletion. This should include:
            *   Password re-verification.
            *   Consideration for data anonymization vs. hard delete.
            *   Revocation of all active tokens.
            *   Queuing deletion of associated drone data.
        *   Frontend: UI for account deletion in `frontend/src/pages/dashboard/settings/tabs/AccountSettings.rs` with strong confirmations.

#### Task Group 1.2: Enhance Foundational Web Application Aspects
1.  **Comprehensive Logging System - Backend:**
    *   **Setup:** Integrate `tracing` and `tracing-subscriber` in `main.rs`. Configure structured logging (e.g., JSON format via `tracing-json`).
    *   **Instrumentation:**
        *   Add `#[tracing::instrument]` to service layer methods in `src/core/` modules.
        *   Implement detailed logging within handlers (`src/api/handlers/`) for request parameters, outcomes.
        *   Log authentication events (login success/failure, token events) in `src/core/auth/service.rs`.
        *   Log authorization failures in middleware (`src/infrastructure/middleware/auth.rs`, `admin.rs`).
        *   Log critical errors and unhandled exceptions globally.
    *   **Configuration:** Set up configurable log levels (DEBUG, INFO, WARN, ERROR) and outputs (console for dev, file for prod, consider log aggregation service).
2.  **Improved Error Handling - Backend & Frontend:**
    *   **Backend:** Review and standardize API error responses in `src/common/error/api_error.rs`. Ensure consistent structure and HTTP status codes. Map all internal errors (DbError, AuthError, etc.) to appropriate ApiError.
    *   **Frontend:** Enhance error display components. Provide clear, user-friendly messages. Implement a global error boundary in Yew if applicable.
    *   **Reporting:** Consider integrating an error reporting service (e.g., Sentry) for both frontend and backend.
3.  **Basic System Monitoring - Backend:**
    *   **Health Check:** Implement a dedicated health check endpoint (e.g., `/api/health`) that verifies database connectivity and other critical dependencies.
    *   **Metrics:** Expose basic application metrics (e.g., request count, error rate, response times) via a Prometheus-compatible endpoint (e.g., using `actix-web-prom`).
4.  **Strengthen Security - JWT & General:**
    *   **JWT Claims:** Add `audience` (aud) and `issuer` (iss) claims to JWTs in `src/core/auth/jwt.rs`. Update token validation logic to verify these claims.
    *   **CORS Policy:** Review and harden CORS policy in `src/infrastructure/middleware/cors.rs` to be as restrictive as possible.
    *   **Security Headers:** Review and ensure all recommended security headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Strict-Transport-Security, Referrer-Policy) are correctly implemented via middleware.
    *   **Dependency Audit:** Regularly audit dependencies (Cargo.lock, package.json if any JS is used via Trunk) for known vulnerabilities.

#### Task Group 1.3: Drone Data Backend - Foundational Layer
1.  **Drone Data Ingestion API Design & Initial Implementation:**
    *   **API Routes:** Define versioned API endpoints in `src/api/routes/admin/` (if admin uploads) or a new `drone_data_routes.rs` for user uploads (e.g., `/api/v1/drone-data/upload`).
    *   **Handlers:** Implement handlers in `src/api/handlers/` for receiving files (e.g., using `actix-multipart` for `multipart/form-data`). Include validation for file types, sizes.
2.  **Drone Data Service - Initial Structure (`src/core/drone_data_service.rs`):**
    *   Create the service module.
    *   Implement functions for:
        *   Identifying data type (from MIME type, file extension, or content inspection).
        *   Basic validation (file size, allowed types per user/mission).
        *   Extracting initial metadata (e.g., EXIF from images, basic video info).
3.  **Storage Strategy - Initial Setup:**
    *   **Object Storage Integration:** Abstract object storage operations (upload, download, delete). Implement an adapter for a chosen provider (e.g., `aws-sdk-s3` for S3, or a local equivalent like MinIO for development). Store credentials securely via config.
    *   **Configuration:** Add object storage configuration to `src/infrastructure/config/app_config.rs`.
4.  **Database Schema for Drone Data - Core Metadata:**
    *   Create new SQL migration files in `migrations/`:
        *   `CREATE TABLE drone_missions (id UUID PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE, name VARCHAR(255) NOT NULL, description TEXT, mission_date TIMESTAMP WITH TIME ZONE, location_geojson TEXT, created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(), updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW());`
        *   `CREATE TABLE drone_data_files (id UUID PRIMARY KEY, mission_id UUID REFERENCES drone_missions(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE, file_name VARCHAR(255) NOT NULL, original_file_name VARCHAR(255), storage_path VARCHAR(1024) NOT NULL UNIQUE, data_type VARCHAR(50) NOT NULL, mime_type VARCHAR(100), file_size BIGINT NOT NULL, upload_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(), processing_status VARCHAR(50) DEFAULT 'uploaded', metadata JSONB, thumbnail_path VARCHAR(1024), created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(), updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW());`
        *   Add necessary indexes on foreign keys and frequently queried columns.

### Phase 2: Develop RAG Pipeline & Enhance Web Platform

#### Task Group 2.1: RAG Pipeline - Backend Development
1.  **Data Pre-processing for RAG (extend `drone_data_service`):**
    *   **Text Extraction:** Implement logic for extracting text from various drone data types (e.g., image OCR, video ASR if feasible, metadata fields).
    *   **Chunking Strategy:** Develop methods to break down extracted text and other data into manageable chunks suitable for embedding.
    *   **Embedding Generation:** Integrate with an embedding model API (e.g., OpenAI, Cohere) or a self-hosted model. Store embeddings alongside data chunks or in the vector DB. This might be an asynchronous process.
2.  **Vector Database Integration:**
    *   **Selection:** Choose a vector database (e.g., Pinecone, Weaviate, Qdrant, FAISS with a wrapper).
    *   **Setup & Configuration:** Install and configure the chosen vector DB.
    *   **Indexing Service:** Create a service (`src/core/vector_db_service.rs`) to handle indexing of drone data embeddings and associated metadata.
3.  **LLM Interaction Service (`src/core/llm_service.rs`):**
    *   **LLM API Client:** Implement a client to connect to your chosen LLM API (e.g., OpenAI, Anthropic).
    *   **RAG Retrieval Logic:**
        *   Function to take a user query, generate an embedding for it.
        *   Query the `vector_db_service` to find semantically similar drone data chunks.
        *   Filter/rank retrieved chunks based on relevance, metadata (date, location).
    *   **Prompt Engineering:** Develop strategies to construct effective prompts for the LLM, incorporating the user's query and the retrieved data context.
    *   **Response Handling:** Process LLM responses, potentially format them for chat.
4.  **Real-time Chat Backend (WebSockets):**
    *   **Actix Actors:** Implement WebSocket connection handling using Actix actors in `src/api/ws_chat_handler.rs` (or similar).
    *   **Message Handling:** Route incoming user messages to the `llm_service` for RAG processing.
    *   **Streaming Responses:** If the LLM supports streaming, implement streaming back to the client.
    *   **Session Management:** Manage chat sessions and history.
    *   **Database:** Store chat history in a new `chat_messages` table (`migrations/`).

#### Task Group 2.2: Testing & Quality Assurance
1.  **Unit Tests:**
    *   For `drone_data_service` (data type identification, metadata extraction, chunking).
    *   For `llm_service` (prompt construction, LLM client interaction - mock API).
    *   For `vector_db_service` (indexing, querying - mock DB or use in-memory version).
    *   For WebSocket actor logic.
2.  **Integration Tests:**
    *   End-to-end drone data upload: API -> service -> object storage -> DB metadata.
    *   RAG pipeline: Simulate user query -> embedding -> vector search -> prompt -> (mocked) LLM response.
    *   WebSocket chat: Test connection, message send/receive.
3.  **Security Testing (Focus on New Components):**
    *   Test access controls for drone data APIs.
    *   Ensure chat messages are properly isolated per user/session.
    *   Validate input to LLM prompts to prevent injection if applicable.

#### Task Group 2.3: Frontend Integration & UX
1.  **Drone Data Upload UI (`frontend/src/pages/dashboard/data.rs`):**
    *   Connect to new drone data upload APIs.
    *   Implement robust file selection, progress indicators, error handling.
    *   Display list of uploaded data with metadata and status.
2.  **Chat Interface UI (`frontend/src/pages/dashboard/chat.rs`):**
    *   Connect to WebSocket backend.
    *   Render chat history, user messages, LLM responses (handle streaming).
    *   Implement UI for loading states, errors.
3.  **Drone Data Visualization (Basic):**
    *   Frontend components to display thumbnails for images/videos.
    *   Show key metadata alongside data listings.
    *   Consider a simple map view if location data is available.
4.  **User Feedback Mechanisms:** Implement simple ways for users to report issues with RAG responses or data processing.

### Phase 3: Optimization, Scalability & Advanced Features

#### Task Group 3.1: Performance & Scalability
1.  **Performance Profiling:** Identify bottlenecks in:
    *   Drone data ingestion and pre-processing.
    *   Embedding generation.
    *   Vector database queries.
    *   LLM API response times.
    *   WebSocket message latency.
2.  **Database Optimization:** Advanced indexing for `drone_data_files`, `chat_messages`, and any vector DB metadata tables. Review query plans.
3.  **Caching Strategy:**
    *   Cache LLM responses for identical (or very similar) queries if appropriate.
    *   Cache frequently accessed drone data metadata.
4.  **Asynchronous Task Processing:**
    *   For drone data pre-processing, embedding generation, and other long-running tasks, implement a background job queue (e.g., using Redis with a Rust worker framework like `celery-rust` or custom Actix actors).
    *   Update frontend to reflect processing status.

#### Task Group 3.2: Advanced RAG & Drone Data Features
1.  **Advanced Retrieval Strategies:**
    *   Implement hybrid search (keyword + semantic) in `vector_db_service`.
    *   Allow filtering retrieved chunks by metadata (date range, location, data type).
    *   Implement re-ranking of retrieved results.
2.  **Support for More Drone Data Types:** Expand `drone_data_service` to handle new formats and extract relevant information for RAG.
3.  **Data Annotation/Labeling Interface (Future):** If manual annotation is needed to improve RAG.
4.  **User-defined Data Grouping/Projects:** Allow users to organize their drone data.

#### Task Group 3.3: DevOps & Production Readiness
1.  **Containerization (Docker):**
    *   Create optimized `Dockerfile` for the Rust backend.
    *   Create `Dockerfile` for the Yew frontend (e.g., using a multi-stage build with Trunk and a static web server like Nginx).
    *   `docker-compose.yml` for local development (app, database, vector DB, object storage).
2.  **CI/CD Pipeline (e.g., GitHub Actions):**
    *   Automate `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`.
    *   Build Docker images.
    *   Push images to a container registry.
    *   Automated deployments to staging/production environments.
3.  **Configuration Management:** Robust system for managing secrets and configurations for different environments (e.g., using environment variables, Vault, or cloud provider's secret manager).
4.  **Backup and Recovery Strategy:** For PostgreSQL database, vector database, and object storage.

#### Task Group 3.4: Advanced Monitoring & Alerting
1.  **RAG Pipeline Monitoring:** Track retrieval accuracy, embedding generation time, LLM response quality (e.g., user feedback).
2.  **Alerts:** For data processing pipeline failures, high LLM API error rates, vector DB issues, critical security anomalies.
3.  **Distributed Tracing:** Implement tracing across services (API, data service, LLM service, vector DB) using OpenTelemetry.

### Ongoing Tasks (Throughout All Phases)
*   **Security Hardening:** Continuous review of code, dependencies, and infrastructure for security best practices. Penetration testing at milestones.
*   **Documentation:**
    *   Update `Software Development Document` and `Architecture_Review.md` with new components and decisions.
    *   Maintain API documentation (e.g., using OpenAPI specs generated from code or manually).
    *   Write comprehensive inline code comments and module-level documentation (`#[doc = "..."]`).
*   **Dependency Management:** Regularly update dependencies (`cargo update`) and audit for vulnerabilities (`cargo audit`).
*   **Code Refactoring:** Proactively refactor code to improve readability, maintainability, and performance. Address technical debt.
*   **User Feedback Iteration:** Collect user feedback on the chat interface and RAG quality, and iterate on improvements.

This comprehensive to-do list should provide a solid roadmap for developing OxidizedOasis-WebSands into a powerful drone data analysis platform.
