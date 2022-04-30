use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use mongodb::bson::doc;
use mongodb::Collection;
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
}

impl IntoResponse for EndpointError {
    fn into_response(self) -> axum::response::Response {
        let res = match self {
            EndpointError::MongoError(err) => {
                tracing::error!("{}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "DB Error".to_string())
            }
            EndpointError::UnknownError(err) => {
                tracing::error!("{}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            EndpointError::EmailAlreadyTaken(err) => {
                tracing::trace!("{}", err);
                (StatusCode::CONFLICT, err)
            }
            EndpointError::InvalidEmail(err) => {
                tracing::trace!("{}", err);
                (StatusCode::PRECONDITION_FAILED, err)
            }
        };
        res.into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    session_uuid: uuid::Uuid,
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

    user.sessions.push(crate::models::Session {
        session_name: "Registration session".to_owned(),
        session_uuid: uuid::Uuid::new_v4(),
        last_used: chrono::Utc::now(),
    });

    let insert_result = mongo_users_collection.insert_one(&user, None).await?;
    tracing::trace!("{:?}", insert_result);
    let session = user.sessions.first().expect("We just created session.");
    Ok(Json(SessionResponse {
        session_uuid: session.session_uuid,
    }))
}
