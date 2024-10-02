```
oxidizedoasis-websands/
├── Cargo.toml
├── Cargo.lock
├── .env
├── .gitignore
├── README.md
├── src/
│   ├── main.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   └── admin.rs
│   ├── models/
│   │   ├── mod.rs
│   │   └── user.rs
│   ├── auth.rs
│   ├── email.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   └── cors_logger.rs
│   ├── validation.rs
│   └── config.rs
├── migrations/
│   └── ... (your SQL migration files)
├── frontend/
│   ├── Cargo.toml
│   ├── index.html
│   ├── src/
│   │   ├── main.rs
│   │   ├── app.rs
│   │   ├── components/
│   │   │   ├── mod.rs
│   │   │   ├── header.rs
│   │   │   ├── footer.rs
│   │   │   ├── login_form.rs
│   │   │   └── ... (other component files)
│   │   └── pages/
│   │       ├── mod.rs
│   │       ├── home.rs
│   │       ├── login.rs
│   │       ├── about.rs
│   │       └── ... (other page files)
│   ├── static/
│   │   ├── css/
│   │   │   ├── styles.css
│   │   │   └── ... (other CSS files)
│   │   └── images/
│   │       └── ... (image files)
│   └── dist/  (generated after build, not in source control)
│       ├── index.html
│       ├── oxidizedoasis-websands-xxxxxxxxxxxxxxxx.js
│       └── oxidizedoasis-websands-xxxxxxxxxxxxxxxx.wasm
└── tests/
    └── ... (your test files)
```
