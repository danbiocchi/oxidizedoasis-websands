#[derive(Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
}

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub audience: String,
    pub issuer: String, // Add the issuer field
}

#[derive(Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: String,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            server: ServerConfig {
                host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: std::env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string()),
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")?,
                max_connections: std::env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()?,
            },
            jwt: JwtConfig {
                secret: std::env::var("JWT_SECRET")?,
                audience: std::env::var("JWT_AUDIENCE")
                    .unwrap_or_else(|_| "oxidizedoasis".to_string()),
                issuer: std::env::var("JWT_ISSUER") // Add the issuer field
                    .unwrap_or_else(|_| "oxidizedoasis".to_string()), // Default value for issuer
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to ensure serial execution of tests modifying environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to temporarily set an environment variable
    fn with_env_var<F, R>(key: &str, value: Option<&str>, func: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _lock = ENV_MUTEX.lock().unwrap();
        let original_value = env::var(key).ok();
        
        if let Some(v) = value {
            env::set_var(key, v);
        } else {
            env::remove_var(key);
        }

        let result = func();

        if let Some(orig_val) = original_value {
            env::set_var(key, orig_val);
        } else {
            env::remove_var(key);
        }
        result
    }
    
    // Helper to run a test with multiple env vars set
    fn with_env_vars<F, R>(vars: Vec<(&str, Option<&str>)>, func: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut original_values = Vec::new();

        for (key, _) in &vars {
            original_values.push((key.to_string(), env::var(key).ok()));
        }

        for (key, value) in vars {
            if let Some(v) = value {
                env::set_var(key, v);
            } else {
                env::remove_var(key);
            }
        }

        let result = func();

        for (key, original_value) in original_values {
            if let Some(orig_val) = original_value {
                env::set_var(key, orig_val);
            } else {
                env::remove_var(&key);
            }
        }
        result
    }

    #[test]
    fn test_from_env_all_vars_set() {
        let vars = vec![
            ("SERVER_HOST", Some("0.0.0.0")),
            ("SERVER_PORT", Some("9000")),
            ("DATABASE_URL", Some("postgres://test:test@localhost/testdb")),
            ("DB_MAX_CONNECTIONS", Some("10")),
            ("JWT_SECRET", Some("supersecretjwtkey")),
            ("JWT_AUDIENCE", Some("test_audience")),
            ("JWT_ISSUER", Some("test_issuer")), // Add test for issuer
        ];
        with_env_vars(vars, || {
            let config_result = AppConfig::from_env();
            assert!(config_result.is_ok());
            let config = config_result.unwrap();
            assert_eq!(config.server.host, "0.0.0.0");
            assert_eq!(config.server.port, "9000");
            assert_eq!(config.database.url, "postgres://test:test@localhost/testdb");
            assert_eq!(config.database.max_connections, 10);
            assert_eq!(config.jwt.secret, "supersecretjwtkey");
            assert_eq!(config.jwt.audience, "test_audience");
            assert_eq!(config.jwt.issuer, "test_issuer"); // Assert issuer value
        });
    }

    #[test]
    fn test_from_env_defaults_used() {
         let vars = vec![
            ("SERVER_HOST", None), // Will use default
            ("SERVER_PORT", None), // Will use default
            ("DATABASE_URL", Some("postgres://default:default@localhost/defaultdb")),
            ("DB_MAX_CONNECTIONS", None), // Will use default
        ];
        with_env_vars(vars, || {
            let config_result = AppConfig::from_env();
            assert!(config_result.is_ok());
            let config = config_result.unwrap();
            assert_eq!(config.server.host, "127.0.0.1");
            assert_eq!(config.server.port, "8080");
            assert_eq!(config.database.url, "postgres://default:default@localhost/defaultdb");
            assert_eq!(config.database.max_connections, 5);
            // JWT_SECRET is required, so it must be set even for default tests
            assert_eq!(config.jwt.secret, "test_default_secret");
            assert_eq!(config.jwt.audience, "oxidizedoasis");
            assert_eq!(config.jwt.issuer, "oxidizedoasis"); // Assert default issuer value
        });
    }

    #[test]
    fn test_from_env_database_url_missing() {
        let vars = vec![
            ("DATABASE_URL", None),
            ("JWT_SECRET", Some("some_secret")), // JWT_SECRET is required, so provide it
        ];
       with_env_vars(vars, || {
            let config_result = AppConfig::from_env();
            assert!(config_result.is_err());
            let error_msg = config_result.err().unwrap().to_string();
            // std::env::VarError is "environment variable not found"
            assert!(error_msg.contains("environment variable not found") || error_msg.contains("DATABASE_URL"));
        });
    }

    #[test]
    fn test_from_env_jwt_secret_missing() {
        let vars = vec![
            ("DATABASE_URL", Some("postgres://test:test@localhost/testdb")),
            ("JWT_SECRET", None),
        ];
        with_env_vars(vars, || {
            let config_result = AppConfig::from_env();
            assert!(config_result.is_err());
            let error_msg = config_result.err().unwrap().to_string();
            assert!(error_msg.contains("environment variable not found") || error_msg.contains("JWT_SECRET"));
        });
    }

    #[test]
    fn test_from_env_db_max_connections_invalid_format() {
         let vars = vec![
            ("DATABASE_URL", Some("postgres://test:test@localhost/testdb")),
            ("DB_MAX_CONNECTIONS", Some("not_a_number")),
        ];
        with_env_vars(vars, || {
            let config_result = AppConfig::from_env();
            assert!(config_result.is_err());
            let error_msg = config_result.err().unwrap().to_string();
            // This will be a ParseIntError
            assert!(error_msg.contains("invalid digit"));
        });
    }
}
