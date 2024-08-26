use std::env;

#[allow(dead_code)]
pub struct Config {
    pub database_url: String,
}

impl Config {
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self, env::VarError> {
        let database_url = env::var("DATABASE_URL")?;

        Ok(Config { database_url })
    }
}