# JWT Token Flow Diagrams

This document provides visual representations of the JWT token flows in the OxidizedOasis-WebSands application.

## Authentication Flow

```mermaid
sequenceDiagram
    participant User
    participant Client
    participant API
    participant AuthService
    participant Database
    
    User->>Client: Enter Credentials
    Client->>API: POST /users/login
    API->>AuthService: Validate Credentials
    AuthService->>Database: Verify User
    Database-->>AuthService: User Data
    AuthService->>AuthService: Generate Token Pair
    AuthService-->>API: Return Tokens
    API-->>Client: Return Tokens
    Client->>Client: Store Tokens
```

## Protected Resource Access

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthService
    participant Database
    participant Resource
    
    Client->>API: Request with Access Token
    API->>AuthService: Validate Token
    AuthService->>Database: Check Revocation
    Database-->>AuthService: Token Status
    AuthService-->>API: Validation Result
    API->>Resource: Fetch Resource
    Resource-->>API: Resource Data
    API-->>Client: Protected Resource
```

## Token Refresh Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthService
    participant Database
    
    Note over Client: Access Token Expired
    Client->>Client: Detect Expired Token
    Client->>API: POST /users/refresh with Refresh Token
    API->>AuthService: Validate Refresh Token
    AuthService->>Database: Check Revocation
    Database-->>AuthService: Token Status
    AuthService->>AuthService: Generate New Access Token
    AuthService-->>API: New Access Token
    API-->>Client: New Access Token
    Client->>Client: Store New Access Token
    Client->>API: Retry Original Request
```

## Logout Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthService
    participant RevocationService
    participant Database
    
    Client->>API: POST /api/users/logout with Access Token
    Note right of Client: Optional Refresh Token in Body
    API->>AuthService: Process Logout
    AuthService->>AuthService: Validate Access Token
    AuthService->>RevocationService: Revoke Access Token
    RevocationService->>Database: Store Revocation
    
    alt Refresh Token Provided
        AuthService->>AuthService: Validate Refresh Token
        AuthService->>RevocationService: Revoke Refresh Token
        RevocationService->>Database: Store Revocation
    end
    
    AuthService-->>API: Logout Success
    API-->>Client: Logout Response
    Client->>Client: Remove Tokens from Storage
```

## Token Validation Process

```mermaid
flowchart TD
    A[Start Validation] --> B{Decode Token}
    B -->|Success| C{Validate Signature}
    B -->|Failure| Z[Return Error]
    C -->|Valid| D{Check Expiration}
    C -->|Invalid| Z
    D -->|Not Expired| E{Check NBF}
    D -->|Expired| Z
    E -->|Valid| F{Check Token Type}
    E -->|Invalid| Z
    F -->|Matches Expected| G{Check Revocation}
    F -->|Mismatch| Z
    G -->|Not Revoked| H[Return Valid Claims]
    G -->|Revoked| Z
```

## Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: User Login
    Created --> Active: Token Issued
    Active --> Expired: Time Elapsed
    Active --> Revoked: User Logout
    Active --> Revoked: Admin Action
    Active --> Refreshed: Token Refresh
    Refreshed --> Active: New Access Token
    Expired --> [*]
    Revoked --> [*]
```

## Token Data Structure

```mermaid
classDiagram
    class TokenPair {
        +String access_token
        +String refresh_token
    }
    
    class Claims {
        +Uuid sub
        +i64 exp
        +i64 iat
        +i64 nbf
        +String jti
        +String role
        +TokenType token_type
    }
    
    class TokenType {
        <<enumeration>>
        Access
        Refresh
    }
    
    TokenPair --> Claims : contains
    Claims --> TokenType : has
```

## Token Revocation Database

```mermaid
erDiagram
    REVOKED_TOKENS {
        uuid id PK
        string jti UK
        uuid user_id FK
        string token_type
        timestamp expires_at
        timestamp revoked_at
        string reason
    }
    
    USERS ||--o{ REVOKED_TOKENS : "has revoked tokens"
```

## Security Improvement Comparison

```mermaid
graph TD
    subgraph "Previous Implementation"
        A[Single Token] --> B[No Expiration]
        B --> C[No Revocation]
        C --> D[Limited Claims]
    end
    
    subgraph "Current Implementation"
        E[Token Pair] --> F[Configurable Expiration]
        F --> G[Token Revocation]
        G --> H[Enhanced Claims]
    end
    
    A -.-> E
    B -.-> F
    C -.-> G
    D -.-> H
    
    style A fill:#ffcccc
    style B fill:#ffcccc
    style C fill:#ffcccc
    style D fill:#ffcccc
    style E fill:#ccffcc
    style F fill:#ccffcc
    style G fill:#ccffcc
    style H fill:#ccffcc
```

## Recommended Security Enhancements

```mermaid
graph TD
    A[Current JWT Implementation] --> B[Refresh Token Rotation]
    A --> C[Secure Token Storage]
    A --> D[Complete Revocation System]
    A --> E[Additional JWT Claims]
    
    B --> F[Enhanced Security]
    C --> F
    D --> F
    E --> F
    
    style A fill:#aaddff
    style B fill:#ccffcc
    style C fill:#ccffcc
    style D fill:#ccffcc
    style E fill:#ccffcc
    style F fill:#aaffaa