use axum::{http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Session authentication is invalid or missing")]
    SessionIsInvalid,
    #[error("Failed to authenticate user")]
    AuthenticationError,
    #[error("Failed to register user")]
    RegistrationError,
    #[error("Internal server error")]
    InternalError,
    #[error("Cryptography error")]
    CryptoError {
        #[from]
        source: jsonwebtoken::errors::Error,
    },
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AuthError::CryptoError { ref source } => tracing::warn!("{}", source),
            _ => (),
        }
        (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
    }
}

#[derive(Deserialize)]
pub struct SessionPayload {
    session: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_global_id: String,
    exp: usize,
    iat: usize,
}

pub async fn generate_acsess_token(
    Json(SessionPayload { session }): Json<SessionPayload>,
) -> Result<String, AuthError> {
    if session != "TestSession" {
        return Err(AuthError::SessionIsInvalid);
    }
    let now = chrono::Utc::now();
    let exp = now
        .checked_add_signed(chrono::Duration::minutes(15))
        .expect("Valid timestamp");

    let claims = Claims {
        user_global_id: String::from("SomeBigUniqueIdMaybe GUID"),
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };
    let header = Header::new(Algorithm::ES384);

    let key = std::fs::read_to_string("ec-private.pem").unwrap();

    let encoding_key = EncodingKey::from_ec_pem(key.as_bytes()).unwrap();
    let pub_token = encode(&header, &claims, &encoding_key)?;
    Ok(pub_token)
}
