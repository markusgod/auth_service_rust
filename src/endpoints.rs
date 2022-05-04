use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use mongodb::bson::doc;
use mongodb::Collection;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::models::User;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    full_name: String,
    email: String,
    password: String,
}

impl From<RegisterRequest> for User {
    fn from(request: RegisterRequest) -> Self {
        Self {
            uuid: uuid::Uuid::new_v4(),
            full_name: request.full_name,
            email: request.email,
            password: request.password,
            sessions: vec![],
        }
    }
}

// #TODO: Rework this error handling
#[derive(Debug, Error)]
pub enum EndpointError {
    #[error(transparent)]
    MongoError(#[from] mongodb::error::Error),
    #[error("Email {} already taken", .0)]
    EmailAlreadyTaken(String),
    #[error("{} is not a valid email", .0)]
    InvalidEmail(String),
    #[error(transparent)]
    UnknownError(#[from] anyhow::Error),
    #[error("Unauthorized")]
    Unauthorized,
}

impl IntoResponse for EndpointError {
    fn into_response(self) -> axum::response::Response {
        let res = match self {
            EndpointError::MongoError(_) => {
                tracing::error!("{}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "DB Error".to_string())
            }
            EndpointError::UnknownError(_) => {
                tracing::error!("{}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            EndpointError::EmailAlreadyTaken(_) => {
                tracing::trace!("{}", self);
                (StatusCode::CONFLICT, self.to_string())
            }
            EndpointError::InvalidEmail(_) => {
                tracing::trace!("{}", self);
                (StatusCode::PRECONDITION_FAILED, self.to_string())
            }
            EndpointError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
        };
        res.into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    session_uuid: String,
}

pub async fn register_user(
    Json(request): Json<RegisterRequest>,
    Extension(mongo_users_collection): Extension<Collection<User>>,
) -> std::result::Result<Json<SessionResponse>, EndpointError> {
    let mut user: User = request.into();
    if !user.validate() {
        return Err(EndpointError::InvalidEmail(user.email));
    }
    if let Some(_user) = mongo_users_collection
        .find_one(doc! { "email":  &user.email}, None)
        .await?
    {
        return Err(EndpointError::EmailAlreadyTaken(user.email));
    }

    use rand::distributions::Alphanumeric;
    let session_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // #TODO: Add check session token is not already in use.

    user.sessions.push(crate::models::Session {
        session_name: "Registration session".to_owned(),
        opaque_token: session_token,
        last_used: chrono::Utc::now(),
    });

    let insert_result = mongo_users_collection.insert_one(&user, None).await?;
    tracing::trace!("{:?}", insert_result);
    let session = user.sessions.first().expect("We just created session.");
    Ok(Json(SessionResponse {
        session_uuid: session.opaque_token.clone(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct AccsessTokenRequest {
    session_uuid: String,
}

#[derive(Debug, Serialize)]
pub struct AccsessTokenResponse {
    accsess_token: String,
}

pub async fn get_accsess_token(
    Json(request): Json<AccsessTokenRequest>,
    Extension(mongo_users_collection): Extension<Collection<User>>,
) -> std::result::Result<Json<AccsessTokenResponse>, EndpointError> {
    if let Some(user) = mongo_users_collection
        .find_one(doc! { "sessions.opaque_token": &request.session_uuid}, None)
        .await?
    {
        tracing::trace!("{:?}", user);
        let update_res = mongo_users_collection
            .update_one(
                doc! {"sessions.opaque_token": &request.session_uuid},
                doc! {"$set" : doc! {
                    "sessions.$.last_used": mongodb::bson::datetime::DateTime::from(chrono::Utc::now())
                }},
                None,
            )
            .await?;
        tracing::trace!("{:?}", update_res);
        let accsess_token = crate::auth::generate_acsess_token(&user)?;
        Ok(Json(AccsessTokenResponse { accsess_token }))
    } else {
        Err(EndpointError::Unauthorized)
    }
}
