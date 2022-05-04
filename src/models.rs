use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub uuid: Uuid,
    pub full_name: String,
    pub email: String,
    pub password: String,
    pub sessions: Vec<Session>,
}

impl User {
    pub fn validate(&self) -> bool {
        validator::validate_email(&self.email)
    }
}

#[serde_with::serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub session_name: String,
    pub opaque_token: String,
    #[serde_as(as = "mongodb::bson::DateTime")]
    pub last_used: chrono::DateTime<Utc>,
}
