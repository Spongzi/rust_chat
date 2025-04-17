use std::mem;

use crate::AppErr;
use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{
        self, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use sqlx::PgPool;

use super::User;

impl User {
    /// Find user by email
    pub async fn find_by_email(email: &str, pool: &PgPool) -> Result<Option<Self>, AppErr> {
        let user = sqlx::query_as("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    /// Create a new user
    pub async fn create(
        fullname: &str,
        email: &str,
        password: &str,
        pool: &sqlx::PgPool,
    ) -> Result<Self, AppErr> {
        // we need to hash the password before storing it in the database
        let password_hash = hash_password(password)?;

        let user = sqlx::query_as(
            "INSERT INTO users (fullname, email, password_hash) VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(fullname)
        .bind(email)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    /// verify the email and password
    pub async fn verify(
        email: &str,
        password: &str,
        pool: &PgPool,
    ) -> Result<Option<Self>, AppErr> {
        let user: Option<User> = sqlx::query_as(
            "SELECT id, fullname, email, password_hash, created_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        match user {
            Some(mut user) => {
                let password_hash = mem::take(&mut user.password_hash);

                let is_valid = verify_password(password, &password_hash.unwrap_or_default())?;
                if is_valid { Ok(Some(user)) } else { Ok(None) }
            }
            None => Ok(None),
        }
    }
}

fn hash_password(password: &str) -> Result<String, AppErr> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppErr> {
    let argon2 = Argon2::default();

    let password_hash = PasswordHash::new(password_hash)?;

    let is_valid = argon2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok();

    Ok(is_valid)
}

// #[cfg(test)]
// mod test {
//     use std::path::Path;

//     use sqlx_db_tester::TestPg;

//     use super::*;

//     async fn create_user_shold_work() {
//         let tdb = TestPg::new(
//             "postgres://spongzi:Sx615615@pgm-bp1ih0n53o7402f45o.pg.rds.aliyuncs.com:5432/chat"
//                 .to_string(),
//             Path::new("./migrations"),
//         );

//         let pool = tdb.get_pool().await.unwrap();
//         let user = User::create("spongzi", "spongzi@outlook.com", "spongzi", &pool);
//     }
// }
