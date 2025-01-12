graph LR
    A[OxidizedOasis] --> B[Frontend]
    A --> C[Backend]

    %% Frontend Section
    B --> D[Components]
    B --> E[Pages]
    B --> F[Services]

    %% Frontend Components
    D --> D1[Nav]
    D --> D2[Footer]
    D --> D3[Login]

    %% Frontend Pages
    E --> E1[Home]
    E --> E2[About]
    E --> E3[Dashboard]
    E --> E4[Register]
    E --> E5[EmailVerified]

    %% Frontend Services
    F --> F1[AuthContext]
    F --> F2[ConfettiContext]

    %% Backend Section
    C --> G[Infrastructure]
    C --> H[Core]
    C --> I[API]
    C --> J[Common]

    %% Infrastructure
    G --> G1[Config]
    G --> G2[Database]
    G --> G3[Middleware]

    %% Core
    H --> H1[Auth Service]
    H --> H2[User Service]
    H --> H3[Email Service]

    %% API
    I --> I1[Handlers]
    I --> I2[Routes]
    I --> I3[Responses]

    %% Common
    J --> J1[Error Handling]
    J --> J2[Utils]
    J --> J3[Validation]

    %% Styling
    classDef frontend fill:#42A5F5,stroke:#1976D2,color:white
    classDef backend fill:#66BB6A,stroke:#43A047,color:white
    classDef service fill:#FFB74D,stroke:#FB8C00,color:black
    classDef component fill:#CE93D8,stroke:#AB47BC,color:white
    classDef page fill:#B39DDB,stroke:#7E57C2,color:white
    classDef infrastructure fill:#4DB6AC,stroke:#00897B,color:white
    classDef core fill:#EF5350,stroke:#E53935,color:white
    classDef api fill:#FF8A65,stroke:#F4511E,color:white
    classDef common fill:#9CCC65,stroke:#7CB342,color:white
    classDef root fill:#546E7A,stroke:#37474F,color:white,stroke-width:4px

    %% Apply styles
    class A root
    class B,D,E,F frontend
    class C,G,H,I,J backend
    class F1,F2,H1,H2,H3 service
    class D1,D2,D3 component
    class E1,E2,E3,E4,E5 page
    class G1,G2,G3 infrastructure
    class H1,H2,H3 core
    class I1,I2,I3 api
    class J1,J2,J3 common