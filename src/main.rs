mod auth;
mod endpoints;
mod models;

use anyhow::Ok;
use axum::{routing::post, Extension};
use mongodb::{options::ClientOptions, Client};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let settings = config::Config::builder()
        .add_source(config::File::with_name("auth_service_config"))
        .add_source(config::Environment::with_prefix("AUTH_SERVICE"))
        .build()?;
    let mongo_db = mongodb(&settings).await?;
    let mongo_users_collection = mongo_db.collection::<models::User>("Users");

    let app = axum::Router::new()
        .route("/get_accsess_token", post(auth::generate_acsess_token))
        .route("/api/register", post(endpoints::register_user))
        .layer(Extension(mongo_users_collection));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn mongodb(settings: &config::Config) -> anyhow::Result<mongodb::Database> {
    let mongo_app_name = settings
        .get_string("MONGO_APP_NAME")
        .unwrap_or_else(|_| String::from("AUTH_SERVICE_RUST"));
    let mongo_uri = settings.get_string("MONGO_URI")?;
    let db_name = settings.get_string("MONGO_DB_NAME")?;

    let mut mongo_client_options = ClientOptions::parse(mongo_uri).await?;
    mongo_client_options.app_name = Some(mongo_app_name);
    tracing::trace!("Detected client options: {:?}", mongo_client_options);

    Ok(Client::with_options(mongo_client_options)?.database(&db_name))
}

/*
// I have no idea why.

trait AuthRouterExt {
    fn add_app_routes(self) -> axum::Router;
}

impl AuthRouterExt for axum::Router {
    fn add_app_routes(self) -> axum::Router {
        self.route("/get_accsess_token", post(auth::generate_acsess_token))
            .route("/api/register", post(endpoints::register_user))
    }
}

 */
