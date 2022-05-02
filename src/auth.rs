use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_global_id: String,
    exp: usize,
    iat: usize,
}

pub fn generate_acsess_token(user: &models::User) -> anyhow::Result<String> {
    // Capture current time
    let now = chrono::Utc::now();
    // Set exparation time, #TODO: Fix hardocoded 15min
    let exp = now
        .checked_add_signed(chrono::Duration::minutes(15))
        .expect("Valid timestamp");

    // Define claims. #TODO: Add audince, issuer, etc.
    let claims = Claims {
        user_global_id: user.uuid.to_string(),
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };

    let header = Header::new(Algorithm::ES384);
    // #TODO: Add key management
    let key = std::fs::read_to_string("ec-private.pem").unwrap();
    let encoding_key = EncodingKey::from_ec_pem(key.as_bytes()).unwrap();
    let pub_token = encode(&header, &claims, &encoding_key)?;
    Ok(pub_token)
}
