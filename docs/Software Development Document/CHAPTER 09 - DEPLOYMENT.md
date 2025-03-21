# OxidizedOasis-WebSands Software Development Document

Version: 1.0.0
Last Updated: 2025-03-21
Status: Release

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|---------|
| 1.0.0 | 2025-03-21 | Initial chapter completion | Technical Team |
| 0.1.0 | 2025-03-15 | Chapter outline created | Technical Team |


9. [Deployment](#9-deployment)
    - 9.1 [Deployment Architecture](#91-deployment-architecture)
        - 9.1.1 [Infrastructure Overview](#911-infrastructure-overview)
        - 9.1.2 [Component Distribution](#912-component-distribution)
    - 9.2 [Deployment Process](#92-deployment-process)
        - 9.2.1 [Build Process](#921-build-process)
        - 9.2.2 [Deployment Steps](#922-deployment-steps)
    - 9.3 [System Dependencies](#93-system-dependencies)
        - 9.3.1 [Runtime Dependencies](#931-runtime-dependencies)
        - 9.3.2 [External Services](#932-external-services)
    - 9.4 [Configuration Management](#94-configuration-management)
        - 9.4.1 [Environment Configuration](#941-environment-configuration)
        - 9.4.2 [Secrets Management](#942-secrets-management)

# 9. Deployment

## 9.1 Deployment Architecture

### 9.1.1 Infrastructure Overview

The system is deployed using a cloud-native architecture:

1. **Cloud Infrastructure**
   ```mermaid
   graph TD
       A[Cloud Infrastructure] --> B[Kubernetes Cluster]
       A --> C[Database Services]
       A --> D[Storage Services]
       A --> E[Networking]
       
       B --> B1[API Nodes]
       B --> B2[Frontend Nodes]
       B --> B3[Monitoring]
       
       C --> C1[PostgreSQL]
       C --> C2[Redis]
       
       D --> D1[Object Storage]
       D --> D2[Backups]
       
       E --> E1[Load Balancer]
       E --> E2[CDN]
       E --> E3[DNS]
   ```

2. **Deployment Environments**

   | Environment | Purpose | Infrastructure |
   |-------------|---------|---------------|
   | Development | Local development | Docker Compose |
   | Testing | Automated testing | CI/CD Pipeline |
   | Staging | Pre-production validation | Kubernetes (small) |
   | Production | Live system | Kubernetes (full) |
   | Disaster Recovery | Backup system | Kubernetes (standby) |

3. **High-Level Architecture**
   ```mermaid
   graph TD
       A[Users] --> B[CDN]
       A --> C[Load Balancer]
       
       B --> D[Static Assets]
       
       C --> E[API Gateway]
       
       E --> F[API Service]
       E --> G[WebSocket Service]
       
       F --> H[Database]
       F --> I[Redis Cache]
       F --> J[Object Storage]
       
       G --> I
       
       K[Monitoring] --> F
       K --> G
       K --> H
       K --> I
   ```

4. **Network Architecture**
   ```mermaid
   graph TD
       A[Internet] --> B[CDN]
       A --> C[Load Balancer]
       
       B --> D[Public Subnet]
       C --> D
       
       D --> E[Private Subnet]
       
       E --> F[Database Subnet]
       E --> G[Cache Subnet]
       
       D --> D1[Ingress Controller]
       D --> D2[Static Content]
       
       E --> E1[API Pods]
       E --> E2[Worker Pods]
       
       F --> F1[PostgreSQL]
       G --> G1[Redis]
   ```

5. **Scalability Architecture**
   - Horizontal scaling for API services
   - Vertical scaling for databases
   - Read replicas for database scaling
   - CDN for static content delivery
   - Auto-scaling based on load metrics
   - Multi-region deployment for global availability

### 9.1.2 Component Distribution

The system components are distributed across the infrastructure:

1. **Component Deployment**
   ```mermaid
   graph TD
       A[Components] --> B[Frontend Components]
       A --> C[Backend Components]
       A --> D[Data Components]
       A --> E[Infrastructure Components]
       
       B --> B1[Static Assets]
       B --> B2[WebAssembly Bundle]
       
       C --> C1[API Service]
       C --> C2[Worker Service]
       C --> C3[WebSocket Service]
       
       D --> D1[PostgreSQL Database]
       D --> D2[Redis Cache]
       D --> D3[Object Storage]
       
       E --> E1[Ingress Controller]
       E --> E2[Service Mesh]
       E --> E3[Monitoring Stack]
   ```

2. **Container Architecture**
   ```yaml
   # Example Kubernetes deployment for API service
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: api-service
     namespace: oxidizedoasis
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: api-service
     template:
       metadata:
         labels:
           app: api-service
       spec:
         containers:
         - name: api-service
           image: oxidizedoasis/api-service:1.0.0
           ports:
           - containerPort: 8080
           resources:
             limits:
               cpu: "1"
               memory: "1Gi"
             requests:
               cpu: "500m"
               memory: "512Mi"
           env:
           - name: DATABASE_URL
             valueFrom:
               secretKeyRef:
                 name: database-credentials
                 key: url
           - name: REDIS_URL
             valueFrom:
               secretKeyRef:
                 name: redis-credentials
                 key: url
           - name: JWT_SECRET
             valueFrom:
               secretKeyRef:
                 name: jwt-credentials
                 key: secret
           livenessProbe:
             httpGet:
               path: /health
               port: 8080
             initialDelaySeconds: 30
             periodSeconds: 10
           readinessProbe:
             httpGet:
               path: /health
               port: 8080
             initialDelaySeconds: 5
             periodSeconds: 5
   ```

3. **Service Architecture**
   ```yaml
   # Example Kubernetes service for API service
   apiVersion: v1
   kind: Service
   metadata:
     name: api-service
     namespace: oxidizedoasis
   spec:
     selector:
       app: api-service
     ports:
     - port: 80
       targetPort: 8080
     type: ClusterIP
   ```

4. **Ingress Configuration**
   ```yaml
   # Example Kubernetes ingress for API service
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: api-ingress
     namespace: oxidizedoasis
     annotations:
       kubernetes.io/ingress.class: nginx
       cert-manager.io/cluster-issuer: letsencrypt-prod
       nginx.ingress.kubernetes.io/ssl-redirect: "true"
       nginx.ingress.kubernetes.io/use-regex: "true"
       nginx.ingress.kubernetes.io/rewrite-target: /$1
   spec:
     tls:
     - hosts:
       - api.oxidizedoasis.com
       secretName: api-tls-secret
     rules:
     - host: api.oxidizedoasis.com
       http:
         paths:
         - path: /(.*)
           pathType: Prefix
           backend:
             service:
               name: api-service
               port:
                 number: 80
   ```

5. **Static Content Distribution**
   ```yaml
   # Example Kubernetes deployment for static content
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: frontend
     namespace: oxidizedoasis
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: frontend
     template:
       metadata:
         labels:
           app: frontend
       spec:
         containers:
         - name: frontend
           image: oxidizedoasis/frontend:1.0.0
           ports:
           - containerPort: 80
           resources:
             limits:
               cpu: "200m"
               memory: "256Mi"
             requests:
               cpu: "100m"
               memory: "128Mi"
           livenessProbe:
             httpGet:
               path: /index.html
               port: 80
             initialDelaySeconds: 10
             periodSeconds: 10
           readinessProbe:
             httpGet:
               path: /index.html
               port: 80
             initialDelaySeconds: 5
             periodSeconds: 5
   ```

## 9.2 Deployment Process

### 9.2.1 Build Process

The build process prepares the application for deployment:

1. **Build Pipeline**
   ```mermaid
   graph TD
       A[Source Code] --> B[Build]
       B --> C[Test]
       C --> D[Package]
       D --> E[Publish]
       
       B --> B1[Backend Build]
       B --> B2[Frontend Build]
       
       B1 --> B11[Compile Rust]
       B1 --> B12[Generate API Docs]
       
       B2 --> B21[Compile WebAssembly]
       B2 --> B22[Optimize Assets]
       
       C --> C1[Unit Tests]
       C --> C2[Integration Tests]
       C --> C3[Security Scans]
       
       D --> D1[Docker Images]
       D --> D2[Static Assets]
       D --> D3[Documentation]
       
       E --> E1[Container Registry]
       E --> E2[CDN]
       E --> E3[Documentation Site]
   ```

2. **CI/CD Pipeline**
   ```yaml
   # Example GitHub Actions workflow for CI/CD
   name: CI/CD Pipeline
   
   on:
     push:
       branches: [ main, develop ]
     pull_request:
       branches: [ main ]
   
   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
         
         - name: Cache dependencies
           uses: actions/cache@v3
           with:
             path: |
               ~/.cargo/registry
               ~/.cargo/git
               target
             key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Build backend
           run: cargo build --release
         
         - name: Build frontend
           run: |
             cd frontend
             rustup target add wasm32-unknown-unknown
             cargo install trunk
             trunk build --release
         
         - name: Run tests
           run: cargo test --release
         
         - name: Build Docker image
           run: |
             docker build -t oxidizedoasis/api-service:${{ github.sha }} -f Dockerfile.api .
             docker build -t oxidizedoasis/frontend:${{ github.sha }} -f Dockerfile.frontend .
         
         - name: Login to Docker Hub
           if: github.event_name != 'pull_request'
           uses: docker/login-action@v2
           with:
             username: ${{ secrets.DOCKERHUB_USERNAME }}
             password: ${{ secrets.DOCKERHUB_TOKEN }}
         
         - name: Push Docker images
           if: github.event_name != 'pull_request'
           run: |
             docker push oxidizedoasis/api-service:${{ github.sha }}
             docker push oxidizedoasis/frontend:${{ github.sha }}
             
             if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
               docker tag oxidizedoasis/api-service:${{ github.sha }} oxidizedoasis/api-service:latest
               docker tag oxidizedoasis/frontend:${{ github.sha }} oxidizedoasis/frontend:latest
               docker push oxidizedoasis/api-service:latest
               docker push oxidizedoasis/frontend:latest
             fi
   
     deploy-staging:
       needs: build
       if: github.event_name != 'pull_request'
       runs-on: ubuntu-latest
       environment: staging
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up kubectl
           uses: azure/setup-kubectl@v3
           
         - name: Set Kubernetes context
           uses: azure/k8s-set-context@v3
           with:
             kubeconfig: ${{ secrets.KUBE_CONFIG_STAGING }}
         
         - name: Deploy to staging
           run: |
             # Update image tags in Kubernetes manifests
             sed -i "s|image: oxidizedoasis/api-service:.*|image: oxidizedoasis/api-service:${{ github.sha }}|g" kubernetes/staging/api-deployment.yaml
             sed -i "s|image: oxidizedoasis/frontend:.*|image: oxidizedoasis/frontend:${{ github.sha }}|g" kubernetes/staging/frontend-deployment.yaml
             
             # Apply Kubernetes manifests
             kubectl apply -f kubernetes/staging/
             
             # Wait for deployments to be ready
             kubectl rollout status deployment/api-service -n oxidizedoasis
             kubectl rollout status deployment/frontend -n oxidizedoasis
   
     deploy-production:
       needs: deploy-staging
       if: github.ref == 'refs/heads/main'
       runs-on: ubuntu-latest
       environment: production
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up kubectl
           uses: azure/setup-kubectl@v3
           
         - name: Set Kubernetes context
           uses: azure/k8s-set-context@v3
           with:
             kubeconfig: ${{ secrets.KUBE_CONFIG_PRODUCTION }}
         
         - name: Deploy to production
           run: |
             # Update image tags in Kubernetes manifests
             sed -i "s|image: oxidizedoasis/api-service:.*|image: oxidizedoasis/api-service:${{ github.sha }}|g" kubernetes/production/api-deployment.yaml
             sed -i "s|image: oxidizedoasis/frontend:.*|image: oxidizedoasis/frontend:${{ github.sha }}|g" kubernetes/production/frontend-deployment.yaml
             
             # Apply Kubernetes manifests
             kubectl apply -f kubernetes/production/
             
             # Wait for deployments to be ready
             kubectl rollout status deployment/api-service -n oxidizedoasis
             kubectl rollout status deployment/frontend -n oxidizedoasis
   ```

3. **Docker Build**
   ```dockerfile
   # Example Dockerfile for API service
   FROM rust:1.68 as builder
   
   WORKDIR /usr/src/app
   
   # Copy manifests
   COPY Cargo.toml Cargo.lock ./
   
   # Copy source code
   COPY src ./src
   COPY migrations ./migrations
   
   # Build the application
   RUN cargo build --release
   
   # Runtime stage
   FROM debian:bullseye-slim
   
   # Install runtime dependencies
   RUN apt-get update && apt-get install -y \
       ca-certificates \
       libpq5 \
       && rm -rf /var/lib/apt/lists/*
   
   # Copy the binary from builder
   COPY --from=builder /usr/src/app/target/release/oxidizedoasis-websands /usr/local/bin/
   
   # Copy migrations
   COPY --from=builder /usr/src/app/migrations /usr/local/bin/migrations
   
   # Set the working directory
   WORKDIR /usr/local/bin
   
   # Expose the port
   EXPOSE 8080
   
   # Run the binary
   CMD ["oxidizedoasis-websands"]
   ```

4. **Frontend Build**
   ```dockerfile
   # Example Dockerfile for frontend
   FROM rust:1.68 as builder
   
   # Install wasm-pack
   RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   
   # Install trunk
   RUN cargo install trunk
   
   # Add wasm target
   RUN rustup target add wasm32-unknown-unknown
   
   WORKDIR /usr/src/app
   
   # Copy frontend files
   COPY frontend/Cargo.toml frontend/Cargo.lock ./
   COPY frontend/src ./src
   COPY frontend/index.html ./
   COPY frontend/static ./static
   
   # Build the frontend
   RUN trunk build --release
   
   # Runtime stage
   FROM nginx:alpine
   
   # Copy the built assets
   COPY --from=builder /usr/src/app/dist /usr/share/nginx/html
   
   # Copy nginx configuration
   COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
   
   # Expose the port
   EXPOSE 80
   
   # Start nginx
   CMD ["nginx", "-g", "daemon off;"]
   ```

5. **Build Artifacts**
   - Backend binary
   - WebAssembly bundle
   - Static assets
   - Docker images
   - API documentation
   - Database migration scripts

### 9.2.2 Deployment Steps

The deployment process moves the application to the target environment:

1. **Deployment Workflow**
   ```mermaid
   graph TD
       A[Start Deployment] --> B[Prepare Environment]
       B --> C[Deploy Infrastructure]
       C --> D[Deploy Database Changes]
       D --> E[Deploy Application]
       E --> F[Post-Deployment Verification]
       F --> G[Finalize Deployment]
       
       B --> B1[Configure Environment]
       B --> B2[Set Up Secrets]
       
       C --> C1[Apply Infrastructure as Code]
       C --> C2[Verify Infrastructure]
       
       D --> D1[Run Database Migrations]
       D --> D2[Verify Database State]
       
       E --> E1[Deploy Backend]
       E --> E2[Deploy Frontend]
       
       F --> F1[Run Health Checks]
       F --> F2[Run Smoke Tests]
       
       G --> G1[Update Documentation]
       G --> G2[Notify Stakeholders]
   ```

2. **Kubernetes Deployment**
   ```yaml
   # Example Kubernetes deployment script
   #!/bin/bash
   set -e
   
   # Set variables
   NAMESPACE="oxidizedoasis"
   ENVIRONMENT=$1
   VERSION=$2
   
   # Check inputs
   if [ -z "$ENVIRONMENT" ] || [ -z "$VERSION" ]; then
     echo "Usage: $0 <environment> <version>"
     exit 1
   fi
   
   # Validate environment
   if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
     echo "Environment must be 'staging' or 'production'"
     exit 1
   fi
   
   echo "Deploying version $VERSION to $ENVIRONMENT..."
   
   # Create namespace if it doesn't exist
   kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
   
   # Apply ConfigMaps
   echo "Applying ConfigMaps..."
   kubectl apply -f kubernetes/$ENVIRONMENT/configmaps.yaml
   
   # Apply Secrets
   echo "Applying Secrets..."
   kubectl apply -f kubernetes/$ENVIRONMENT/secrets.yaml
   
   # Update image tags in deployments
   echo "Updating image tags..."
   sed -i "s|image: oxidizedoasis/api-service:.*|image: oxidizedoasis/api-service:$VERSION|g" kubernetes/$ENVIRONMENT/api-deployment.yaml
   sed -i "s|image: oxidizedoasis/frontend:.*|image: oxidizedoasis/frontend:$VERSION|g" kubernetes/$ENVIRONMENT/frontend-deployment.yaml
   
   # Apply deployments
   echo "Applying deployments..."
   kubectl apply -f kubernetes/$ENVIRONMENT/api-deployment.yaml
   kubectl apply -f kubernetes/$ENVIRONMENT/frontend-deployment.yaml
   
   # Apply services
   echo "Applying services..."
   kubectl apply -f kubernetes/$ENVIRONMENT/api-service.yaml
   kubectl apply -f kubernetes/$ENVIRONMENT/frontend-service.yaml
   
   # Apply ingress
   echo "Applying ingress..."
   kubectl apply -f kubernetes/$ENVIRONMENT/ingress.yaml
   
   # Wait for deployments to be ready
   echo "Waiting for deployments to be ready..."
   kubectl rollout status deployment/api-service -n $NAMESPACE
   kubectl rollout status deployment/frontend -n $NAMESPACE
   
   echo "Deployment completed successfully!"
   ```

3. **Database Migration**
   ```rust
   // Example database migration process
   pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
       println!("Running database migrations...");
       
       let migration_results = sqlx::migrate!("./migrations")
           .run(pool)
           .await?;
       
       println!("Applied {} migrations", migration_results.len());
       
       Ok(())
   }
   ```

4. **Deployment Strategies**
   - **Rolling Update**: Gradually replace instances
   - **Blue-Green**: Switch between two identical environments
   - **Canary**: Release to a subset of users
   - **Feature Flags**: Control feature availability

5. **Post-Deployment Verification**
   ```bash
   # Example post-deployment verification script
   #!/bin/bash
   set -e
   
   ENVIRONMENT=$1
   API_URL=$2
   
   # Check inputs
   if [ -z "$ENVIRONMENT" ] || [ -z "$API_URL" ]; then
     echo "Usage: $0 <environment> <api_url>"
     exit 1
   fi
   
   echo "Running post-deployment verification for $ENVIRONMENT at $API_URL..."
   
   # Check API health
   echo "Checking API health..."
   HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $API_URL/health)
   
   if [ "$HEALTH_RESPONSE" != "200" ]; then
     echo "Health check failed with status $HEALTH_RESPONSE"
     exit 1
   fi
   
   echo "Health check passed!"
   
   # Run smoke tests
   echo "Running smoke tests..."
   
   # Test public endpoint
   PUBLIC_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $API_URL/api/v1/public/info)
   if [ "$PUBLIC_RESPONSE" != "200" ]; then
     echo "Public endpoint test failed with status $PUBLIC_RESPONSE"
     exit 1
   fi
   
   echo "Public endpoint test passed!"
   
   # Test authentication
   echo "Testing authentication..."
   AUTH_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username_or_email":"test@example.com","password":"Test123!"}' \
     -o /dev/null -w "%{http_code}" $API_URL/api/v1/auth/login)
   
   if [ "$AUTH_RESPONSE" != "401" ]; then
     echo "Authentication test failed with status $AUTH_RESPONSE"
     exit 1
   fi
   
   echo "Authentication test passed!"
   
   echo "All verification tests passed!"
   ```

## 9.3 System Dependencies

### 9.3.1 Runtime Dependencies

The system requires specific runtime dependencies:

1. **Backend Runtime Dependencies**

   | Dependency | Version | Purpose |
   |------------|---------|---------|
   | Rust Runtime | 1.68+ | Application execution |
   | PostgreSQL | 14+ | Database |
   | Redis | 6.2+ | Caching and rate limiting |
   | OpenSSL | 1.1.1+ | TLS support |
   | libpq | 13+ | PostgreSQL client |

2. **Frontend Runtime Dependencies**

   | Dependency | Version | Purpose |
   |------------|---------|---------|
   | WebAssembly | 1.0 | Browser execution |
   | Modern Browser | Latest | Client runtime |
   | JavaScript | ES2020+ | Browser scripting |
   | HTML | 5 | Document structure |
   | CSS | 3 | Styling |

3. **Infrastructure Dependencies**

   | Dependency | Version | Purpose |
   |------------|---------|---------|
   | Kubernetes | 1.24+ | Container orchestration |
   | Docker | 20.10+ | Containerization |
   | Nginx | 1.20+ | Web server and reverse proxy |
   | Cert-Manager | 1.8+ | TLS certificate management |
   | Prometheus | 2.35+ | Monitoring |
   | Grafana | 8.5+ | Visualization |

4. **Dependency Management**
   ```mermaid
   graph TD
       A[Dependency Management] --> B[Application Dependencies]
       A --> C[Infrastructure Dependencies]
       A --> D[External Service Dependencies]
       
       B --> B1[Cargo.toml]
       B --> B2[Cargo.lock]
       
       C --> C1[Kubernetes Manifests]
       C --> C2[Helm Charts]
       
       D --> D1[Service Level Agreements]
       D --> D2[API Contracts]
   ```

5. **Dependency Versioning**
   ```toml
   # Example Cargo.toml with version constraints
   [dependencies]
   actix-web = "4.9.0"
   sqlx = { version = "0.8.2", features = ["runtime-tokio-rustls", "postgres", "uuid", "chrono", "json"] }
   tokio = { version = "1.28.0", features = ["full"] }
   serde = { version = "1.0.163", features = ["derive"] }
   serde_json = "1.0.96"
   uuid = { version = "1.3.3", features = ["v4", "serde"] }
   chrono = { version = "0.4.24", features = ["serde"] }
   tracing = "0.1.37"
   tracing-subscriber = { version = "0.3.17", features = ["env-filter", "json"] }
   jsonwebtoken = "9.2.0"
   bcrypt = "0.15.0"
   redis = { version = "0.23.0", features = ["tokio-comp", "connection-manager"] }
   ```

### 9.3.2 External Services

The system integrates with external services:

1. **External Service Dependencies**
   ```mermaid
   graph TD
       A[External Services] --> B[Email Service]
       A --> C[Storage Service]
       A --> D[Monitoring Service]
       A --> E[Analytics Service]
       
       B --> B1[SMTP Provider]
       B --> B2[Email Templates]
       
       C --> C1[Object Storage]
       C --> C2[CDN]
       
       D --> D1[Logging Service]
       D --> D2[Alerting Service]
       
       E --> E1[User Analytics]
       E --> E2[Performance Analytics]
   ```

2. **Service Integration**
   ```rust
   // Example email service integration
   pub struct EmailService {
       smtp_config: SmtpConfig,
       template_engine: TemplateEngine,
   }
   
   impl EmailService {
       pub fn new(smtp_config: SmtpConfig, template_dir: &str) -> Self {
           Self {
               smtp_config,
               template_engine: TemplateEngine::new(template_dir),
           }
       }
       
       pub async fn send_verification_email(&self, user: &User) -> Result<(), EmailError> {
           // Generate verification URL
           let verification_url = format!(
               "https://{}/verify-email?token={}",
               self.smtp_config.app_domain,
               user.verification_token.as_ref().unwrap()
           );
           
           // Prepare template data
           let mut data = tera::Context::new();
           data.insert("username", &user.username);
           data.insert("verification_url", &verification_url);
           
           // Render email template
           let subject = "Verify Your Email Address";
           let body_html = self.template_engine.render("verification_email.html", &data)?;
           let body_text = self.template_engine.render("verification_email.txt", &data)?;
           
           // Send email
           self.send_email(&user.email, subject, &body_html, &body_text).await
       }
       
       async fn send_email(
           &self,
           to_email: &str,
           subject: &str,
           body_html: &str,
           body_text: &str
       ) -> Result<(), EmailError> {
           // Create email message
           let email = Message::builder()
               .from(format!("{} <{}>", self.smtp_config.from_name, self.smtp_config.from_email).parse()?)
               .to(to_email.parse()?)
               .subject(subject)
               .multipart(
                   MultiPart::alternative()
                       .singlepart(
                           SinglePart::builder()
                               .header(header::ContentType::TEXT_PLAIN)
                               .body(body_text.to_string())
                       )
                       .singlepart(
                           SinglePart::builder()
                               .header(header::ContentType::TEXT_HTML)
                               .body(body_html.to_string())
                       )
               )?;
           
           // Configure SMTP transport
           let creds = Credentials::new(
               self.smtp_config.smtp_username.clone(),
               self.smtp_config.smtp_password.clone()
           );
           
           let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&self.smtp_config.smtp_host)?
               .port(self.smtp_config.smtp_port)
               .credentials(creds)
               .build();
           
           // Send email
           mailer.send(email).await?;
           
           Ok(())
       }
   }
   ```

3. **Service Configuration**
   ```yaml
   # Example external service configuration
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: external-services-config
     namespace: oxidizedoasis
   data:
     email.host: "smtp.sendgrid.net"
     email.port: "587"
     email.from_name: "OxidizedOasis"
     email.from_email: "noreply@oxidizedoasis.com"
     email.app_domain: "app.oxidizedoasis.com"
     
     storage.endpoint: "https://s3.amazonaws.com"
     storage.region: "us-east-1"
     storage.bucket: "oxidizedoasis-assets"
     storage.cdn_domain: "assets.oxidizedoasis.com"
     
     monitoring.log_level: "info"
     monitoring.metrics_endpoint: "https://metrics.oxidizedoasis.com"
     monitoring.tracing_endpoint: "https://tracing.oxidizedoasis.com"
   ```

4. **Service Fallbacks**
   ```rust
   // Example service with fallback
   pub struct StorageService {
       primary_client: S3Client,
       fallback_client: Option<S3Client>,
       config: StorageConfig,
   }
   
   impl StorageService {
       pub async fn store_file(
           &self,
           file_data: &[u8],
           file_name: &str,
           content_type: &str
       ) -> Result<StoredFile, StorageError> {
           // Try primary storage
           match self.store_file_internal(&self.primary_client, file_data, file_name, content_type).await {
               Ok(file) => Ok(file),
               Err(err) => {
                   // Log the error
                   tracing::error!("Primary storage error: {:?}", err);
                   
                   // Try fallback if available
                   if let Some(fallback) = &self.fallback_client {
                       tracing::info!("Attempting fallback storage");
                       self.store_file_internal(fallback, file_data, file_name, content_type).await
                   } else {
                       Err(err)
                   }
               }
           }
       }
       
       async fn store_file_internal(
           &self,
           client: &S3Client,
           file_data: &[u8],
           file_name: &str,
           content_type: &str
       ) -> Result<StoredFile, StorageError> {
           // Implementation...
       }
   }
   ```

5. **Service Health Checks**
   ```rust
   // Example service health check
   pub async fn check_external_services_health() -> HashMap<String, ServiceHealth> {
       let mut results = HashMap::new();
       
       // Check database
       results.insert(
           "database".to_string(),
           check_database_health().await,
       );
       
       // Check Redis
       results.insert(
           "redis".to_string(),
           check_redis_health().await,
       );
       
       // Check email service
       results.insert(
           "email".to_string(),
           check_email_health().await,
       );
       
       // Check storage service
       results.insert(
           "storage".to_string(),
           check_storage_health().await,
       );
       
       results
   }
   
   async fn check_database_health() -> ServiceHealth {
       // Implementation...
   }
   
   async fn check_redis_health() -> ServiceHealth {
       // Implementation...
   }
   
   async fn check_email_health() -> ServiceHealth {
       // Implementation...
   }
   
   async fn check_storage_health() -> ServiceHealth {
       // Implementation...
   }
   ```

## 9.4 Configuration Management

### 9.4.1 Environment Configuration

The system uses environment-specific configuration:

1. **Configuration Sources**
   ```mermaid
   graph TD
       A[Configuration Sources] --> B[Environment Variables]
       A --> C[Configuration Files]
       A --> D[Kubernetes ConfigMaps]
       A --> E[Kubernetes Secrets]
       
       B --> B1[Runtime Variables]
       B --> B2[Build Variables]
       
       C --> C1[Default Config]
       C --> C2[Environment-specific Config]
       
       D --> D1[Application Config]
       D --> D2[Service Config]
       
       E --> E1[Sensitive Data]
       E --> E2[Credentials]
   ```

2. **Configuration Loading**
   ```rust
   // Example configuration loading
   pub struct Config {
       pub server: ServerConfig,
       pub database: DatabaseConfig,
       pub redis: RedisConfig,
       pub auth: AuthConfig,
       pub email: EmailConfig,
       pub storage: StorageConfig,
   }
   
   impl Config {
       pub fn load() -> Result<Self, ConfigError> {
           // Set up configuration builder
           let config_builder = config::Config::builder()
               // Start with default configuration
               .add_source(config::File::with_name("config/default"))
               // Add environment-specific configuration
               .add_source(config::File::with_name(&format!("config/{}", 
                   std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string())))
                   .required(false))
               // Override with environment variables
               .add_source(config::Environment::with_prefix("APP").separator("__"));
           
           // Build configuration
           let config = config_builder.build()?;
           
           // Deserialize into our config structure
           let config: Self = config.try_deserialize()?;
           
           Ok(config)
       }
   }
   ```

3. **Environment-Specific Configuration**
   ```yaml
   # Example Kubernetes ConfigMap for environment-specific configuration
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: app-config
     namespace: oxidizedoasis
   data:
     APP_ENV: "production"
     APP_SERVER__HOST: "0.0.0.0"
     APP_SERVER__PORT: "8080"
     APP_SERVER__WORKERS: "4"
     APP_SERVER__KEEP_ALIVE: "75"
     APP_SERVER__SHUTDOWN_TIMEOUT: "30"
     
     APP_REDIS__POOL_SIZE: "10"
     
     APP_AUTH__TOKEN_EXPIRY: "900"  # 15 minutes in seconds
     APP_AUTH__REFRESH_TOKEN_EXPIRY: "604800"  # 7 days in seconds
     
     APP_CORS__ALLOWED_ORIGINS: "https://app.oxidizedoasis.com"
     APP_CORS__ALLOWED_METHODS: "GET,POST,PUT,DELETE"
     APP_CORS__ALLOWED_HEADERS: "Content-Type,Authorization"
     APP_CORS__MAX_AGE: "86400"  # 24 hours in seconds
     
     APP_RATE_LIMIT__ENABLED: "true"
     APP_RATE_LIMIT__REQUESTS_PER_MINUTE: "60"
   ```

4. **Configuration Validation**
   ```rust
   // Example configuration validation
   impl ServerConfig {
       pub fn validate(&self) -> Result<(), ConfigError> {
           if self.port == 0 {
               return Err(ConfigError::InvalidValue("server.port cannot be 0".to_string()));
           }
           
           if self.workers == 0 {
               return Err(ConfigError::InvalidValue("server.workers cannot be 0".to_string()));
           }
           
           if self.keep_alive == 0 {
               return Err(ConfigError::InvalidValue("server.keep_alive cannot be 0".to_string()));
           }
           
           if self.shutdown_timeout == 0 {
               return Err(ConfigError::InvalidValue("server.shutdown_timeout cannot be 0".to_string()));
           }
           
           Ok(())
       }
   }
   
   impl Config {
       pub fn validate(&self) -> Result<(), ConfigError> {
           self.server.validate()?;
           self.database.validate()?;
           self.redis.validate()?;
           self.auth.validate()?;
           self.email.validate()?;
           self.storage.validate()?;
           
           Ok(())
       }
   }
   ```

5. **Configuration Documentation**
   ```markdown
   # Configuration Reference
   
   ## Environment Variables
   
   The application can be configured using environment variables with the prefix `APP__`.
   
   ### Server Configuration
   
   | Variable | Description | Default | Required |
   |----------|-------------|---------|----------|
   | APP_SERVER__HOST | Host to bind the server to | 0.0.0.0 | No |
   | APP_SERVER__PORT | Port to bind the server to | 8080 | No |
   | APP_SERVER__WORKERS | Number of worker threads | 4 | No |
   | APP_SERVER__KEEP_ALIVE | Keep-alive timeout in seconds | 75 | No |
   | APP_SERVER__SHUTDOWN_TIMEOUT | Graceful shutdown timeout in seconds | 30 | No |
   
   ### Database Configuration
   
   | Variable | Description | Default | Required |
   |----------|-------------|---------|----------|
   | APP_DATABASE__URL | PostgreSQL connection URL | - | Yes |
   | APP_DATABASE__MAX_CONNECTIONS | Maximum number of connections | 5 | No |
   | APP_DATABASE__MIN_CONNECTIONS | Minimum number of connections | 1 | No |
   
   ### Redis Configuration
   
   | Variable | Description | Default | Required |
   |----------|-------------|---------|----------|
   | APP_REDIS__URL | Redis connection URL | - | Yes |
   | APP_REDIS__POOL_SIZE | Redis connection pool size | 5 | No |
   
   ### Authentication Configuration
   
   | Variable | Description | Default | Required |
   |----------|-------------|---------|----------|
   | APP_AUTH__JWT_SECRET | Secret for JWT signing | - | Yes |
   | APP_AUTH__TOKEN_EXPIRY | Access token expiry in seconds | 900 | No |
   | APP_AUTH__REFRESH_TOKEN_EXPIRY | Refresh token expiry in seconds | 604800 | No |
   ```

### 9.4.2 Secrets Management

The system securely manages sensitive information:

1. **Secrets Management Approach**
   ```mermaid
   graph TD
       A[Secrets Management] --> B[Kubernetes Secrets]
       A --> C[Environment Variables]
       A --> D[External Vault]
       
       B --> B1[Database Credentials]
       B --> B2[API Keys]
       B --> B3[TLS Certificates]
       
       C --> C1[Runtime Secrets]
       C --> C2[Build Secrets]
       
       D --> D1[HashiCorp Vault]
       D --> D2[AWS Secrets Manager]
   ```

2. **Kubernetes Secrets**
   ```yaml
   # Example Kubernetes Secret
   apiVersion: v1
   kind: Secret
   metadata:
     name: database-credentials
     namespace: oxidizedoasis
   type: Opaque
   data:
     url: cG9zdGdyZXNxbDovL3VzZXJuYW1lOnBhc3N3b3JkQGRiLmV4YW1wbGUuY29tOjU0MzIvZGJuYW1l  # Base64 encoded
     username: dXNlcm5hbWU=  # Base64 encoded
     password: cGFzc3dvcmQ=  # Base64 encoded
   ```

3. **Secret Injection**
   ```yaml
   # Example secret injection into a Kubernetes deployment
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: api-service
     namespace: oxidizedoasis
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: api-service
     template:
       metadata:
         labels:
           app: api-service
       spec:
         containers:
         - name: api-service
           image: oxidizedoasis/api-service:1.0.0
           env:
           - name: APP_DATABASE__URL
             valueFrom:
               secretKeyRef:
                 name: database-credentials
                 key: url
           - name: APP_REDIS__URL
             valueFrom:
               secretKeyRef:
                 name: redis-credentials
                 key: url
           - name: APP_AUTH__JWT_SECRET
             valueFrom:
               secretKeyRef:
                 name: jwt-credentials
                 key: secret
           - name: APP_EMAIL__SMTP_USERNAME
             valueFrom:
               secretKeyRef:
                 name: email-credentials
                 key: username
           - name: APP_EMAIL__SMTP_PASSWORD
             valueFrom:
               secretKeyRef:
                 name: email-credentials
                 key: password
   ```

4. **External Vault Integration**
   ```rust
   // Example HashiCorp Vault integration
   pub struct VaultClient {
       client: reqwest::Client,
       vault_addr: String,
       token: String,
   }
   
   impl VaultClient {
       pub fn new(vault_addr: String, token: String) -> Self {
           Self {
               client: reqwest::Client::new(),
               vault_addr,
               token,
           }
       }
       
       pub async fn get_secret(&self, path: &str) -> Result<HashMap<String, String>, VaultError> {
           let url = format!("{}/v1/{}", self.vault_addr, path);
           
           let response = self.client
               .get(&url)
               .header("X-Vault-Token", &self.token)
               .send()
               .await?;
           
           if !response.status().is_success() {
               return Err(VaultError::RequestFailed(response.status().as_u16()));
           }
           
           let vault_response: VaultResponse = response.json().await?;
           
           Ok(vault_response.data)
       }
   }
   
   pub struct SecretManager {
       vault_client: Option<VaultClient>,
   }
   
   impl SecretManager {
       pub fn new() -> Self {
           // Initialize Vault client if configured
           let vault_client = match (std::env::var("VAULT_ADDR"), std::env::var("VAULT_TOKEN")) {
               (Ok(addr), Ok(token)) => Some(VaultClient::new(addr, token)),
               _ => None,
           };
           
           Self { vault_client }
       }
       
       pub async fn get_database_credentials(&self) -> Result<DatabaseCredentials, SecretError> {
           if let Some(vault) = &self.vault_client {
               // Get credentials from Vault
               let secrets = vault.get_secret("database/creds/api-service").await?;
               
               Ok(DatabaseCredentials {
                   username: secrets.get("username").cloned().ok_or(SecretError::MissingKey("username"))?,
                   password: secrets.get("password").cloned().ok_or(SecretError::MissingKey("password"))?,
               })
           } else {
               // Fall back to environment variables
               Ok(DatabaseCredentials {
                   username: std::env::var("APP_DATABASE__USERNAME")?,
                   password: std::env::var("APP_DATABASE__PASSWORD")?,
               })
           }
       }
   }
   ```

5. **Secret Rotation**
   ```rust
   // Example secret rotation
   pub struct SecretRotator {
       vault_client: VaultClient,
       kubernetes_client: K8sClient,
   }
   
   impl SecretRotator {
       pub async fn rotate_database_credentials(&self) -> Result<(), RotationError> {
           // Generate new credentials in Vault
           let new_credentials = self.vault_client
               .generate_database_credentials("api-service")
               .await?;
           
           // Update Kubernetes secret
           self.kubernetes_client
               .update_secret("database-credentials", "oxidizedoasis", &new_credentials)
               .await?;
           
           // Trigger rolling update of deployments
           self.kubernetes_client
               .restart_deployment("api-service", "oxidizedoasis")
               .await?;
           
           Ok(())
       }
       
       pub async fn schedule_rotation(&self) -> Result<(), RotationError> {
           // Schedule periodic rotation
           tokio::spawn(async move {
               let mut interval = tokio::time::interval(Duration::from_secs(86400));  // 24 hours
               
               loop {
                   interval.tick().await;
                   
                   match self.rotate_database_credentials().await {
                       Ok(_) => tracing::info!("Successfully rotated database credentials"),
                       Err(err) => tracing::error!("Failed to rotate database credentials: {:?}", err),
                   }
               }
           });
           
           Ok(())
       }
   }