use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppErr {
    #[error("sql err: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("password hash error: {0}")]
    PasswordHashError(#[from] argon2::password_hash::Error),
}
