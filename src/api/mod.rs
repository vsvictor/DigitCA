pub mod auth;
pub mod dto;
pub mod handlers;
pub mod openapi;

use std::sync::Arc;

use axum::{
    http::{HeaderValue, Method, header},
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    ldap_auth::Authorizer,
    ldap_publish::LdapPublisher,
    service::CaService,
    storage::CaRepository,
};

/// Загальний стан REST API, що шариться між запитами.
#[derive(Clone)]
pub struct AppState {
    pub service: Arc<CaService<Box<dyn CaRepository + Send + Sync>>>,
    pub ldap: Arc<dyn Authorizer + Send + Sync>,
    pub publisher: LdapPublisher,
    pub enforce_https_basic_auth: bool,
}

/// Будує axum Router зі всіма маршрутами REST API.
pub fn router(state: AppState, cors_allowed_origins: &[String]) -> Router {
    let mut app = Router::new()
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", openapi::ApiDoc::openapi()))
        // Стан сервера
        .route("/health", get(handlers::health))
        // Root CA
        .route(
            "/api/v1/ca/root",
            post(handlers::init_root).get(handlers::export_root),
        )
        // Intermediate CA
        .route(
            "/api/v1/ca/intermediate",
            post(handlers::init_intermediate).get(handlers::export_intermediate),
        )
        // Сертифікати
        .route(
            "/api/v1/certificates",
            post(handlers::issue_certificate).get(handlers::list_certificates),
        )
        .route(
            "/api/v1/certificates/:serial",
            get(handlers::get_certificate),
        )
        .route(
            "/api/v1/certificates/:serial/revoke",
            post(handlers::revoke_certificate),
        )
        .route(
            "/api/v1/certificates/:serial/verify",
            get(handlers::verify_certificate),
        )
        .route(
            "/api/v1/certificates/:serial/chain",
            get(handlers::get_certificate_chain),
        )
        .route("/crl/root.crl", get(handlers::get_root_crl))
        .route(
            "/crl/intermediate.crl",
            get(handlers::get_intermediate_crl),
        )
        // Аудит
        .route("/api/v1/audit", get(handlers::audit_log))
        // LDAP-директорія
        .route("/api/v1/ldap/certificates", get(handlers::ldap_search_by_cn))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    if let Some(cors) = build_cors_layer(cors_allowed_origins) {
        app = app.layer(cors);
    }

    app
}

fn build_cors_layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }

    if origins.iter().any(|o| o == "*") {
        return Some(CorsLayer::permissive());
    }

    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    if parsed.is_empty() {
        return None;
    }

    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
    )
}


