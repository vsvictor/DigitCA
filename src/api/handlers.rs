use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::{
    error::AppError,
    models::IssueRequest,
};

use super::{
    auth::AuthenticatedUser,
    dto::{
        AuditQuery, CertificateListResponse, CertificateResponse, InitIntermediateBody,
        InitRootBody, IssueCertificateBody, IssueCertificateResponse, LdapSearchQuery, ListQuery,
        MessageResponse,
        PemResponse, RevokeBody, SerialResponse, VerifyResponse,
    },
    AppState,
};

fn map_err(err: AppError) -> Response {
    let status = match &err {
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::AccessDenied => StatusCode::FORBIDDEN,
        AppError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        AppError::Config(_) => StatusCode::BAD_REQUEST,
        AppError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, err.to_string()).into_response()
}

// ── Утиліти ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/health",
    responses((status = 200, description = "Сервіс працює", body = MessageResponse)),
    tag = "System"
)]
pub async fn health() -> impl IntoResponse {
    Json(MessageResponse { message: "DigitCA OK".to_string() })
}

// ── Root CA ───────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/ca/root",
    request_body = InitRootBody,
    responses((status = 201, body = SerialResponse)),
    security(("basic_auth" = [])),
    tag = "CA"
)]
pub async fn init_root(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<InitRootBody>,
) -> Result<impl IntoResponse, Response> {
    let serial = state
        .service
        .init_root(&body.common_name, body.validity_days, &user.username)
        .await
        .map_err(map_err)?;
    Ok((StatusCode::CREATED, Json(SerialResponse { serial })))
}

#[utoipa::path(
    get,
    path = "/api/v1/ca/root",
    responses((status = 200, body = PemResponse)),
    security(("basic_auth" = [])),
    tag = "CA"
)]
pub async fn export_root(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, Response> {
    let pem = state.service.root_pem(&user.username).await.map_err(map_err)?;
    Ok(Json(PemResponse { pem }))
}

// ── Intermediate CA ───────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/ca/intermediate",
    request_body = InitIntermediateBody,
    responses((status = 201, body = SerialResponse)),
    security(("basic_auth" = [])),
    tag = "CA"
)]
pub async fn init_intermediate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<InitIntermediateBody>,
) -> Result<impl IntoResponse, Response> {
    let serial = state
        .service
        .init_intermediate(&body.common_name, body.validity_days, &user.username)
        .await
        .map_err(map_err)?;
    Ok((StatusCode::CREATED, Json(SerialResponse { serial })))
}

#[utoipa::path(
    get,
    path = "/api/v1/ca/intermediate",
    responses((status = 200, body = PemResponse)),
    security(("basic_auth" = [])),
    tag = "CA"
)]
pub async fn export_intermediate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, Response> {
    let pem = state
        .service
        .intermediate_pem(&user.username)
        .await
        .map_err(map_err)?;
    Ok(Json(PemResponse { pem }))
}

// ── Сертифікати ───────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/certificates",
    request_body = IssueCertificateBody,
    responses((status = 201, body = IssueCertificateResponse)),
    security(("basic_auth" = [])),
    tag = "Certificates"
)]
pub async fn issue_certificate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<IssueCertificateBody>,
) -> Result<impl IntoResponse, Response> {
    let cert = state
        .service
        .issue(
            IssueRequest {
                common_name: body.common_name,
                profile: body.profile,
                issuer: body.issuer,
                dns_names: body.dns_names,
                ip_sans: body.ip_sans,
                validity_days: body.validity_days,
            },
            &user.username,
        )
        .await
        .map_err(map_err)?;

    // Публікуємо у LDAP (м'яка помилка — не зупиняємо відповідь)
    let _ = state.publisher.publish_certificate(&cert).await;

    let key_pem = cert.key_pem.clone();
    let response = IssueCertificateResponse {
        certificate: CertificateResponse::from(cert),
        key_pem,
    };
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    get,
    path = "/api/v1/certificates",
    params(ListQuery),
    responses((status = 200, body = CertificateListResponse)),
    security(("basic_auth" = [])),
    tag = "Certificates"
)]
pub async fn list_certificates(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, Response> {
    let all = state
        .service
        .list(q.include_revoked, &user.username)
        .await
        .map_err(map_err)?;

    let total = all.len();
    let per_page = q.per_page.max(1) as usize;
    let page = q.page.max(1) as usize;
    let skip = (page - 1) * per_page;

    let data: Vec<CertificateResponse> = all
        .into_iter()
        .skip(skip)
        .take(per_page)
        .map(CertificateResponse::from)
        .collect();

    Ok(Json(CertificateListResponse { data, page: page as u32, per_page: per_page as u32, total }))
}

#[utoipa::path(
    get,
    path = "/api/v1/certificates/{serial}",
    params(("serial" = String, Path, description = "Серійний номер сертифіката")),
    responses((status = 200, body = CertificateResponse)),
    security(("basic_auth" = [])),
    tag = "Certificates"
)]
pub async fn get_certificate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(serial): Path<String>,
) -> Result<impl IntoResponse, Response> {
    let cert = state.service.get(&serial, &user.username).await.map_err(map_err)?;
    Ok(Json(CertificateResponse::from(cert)))
}

#[utoipa::path(
    post,
    path = "/api/v1/certificates/{serial}/revoke",
    params(("serial" = String, Path, description = "Серійний номер сертифіката")),
    request_body = RevokeBody,
    responses((status = 200, body = MessageResponse)),
    security(("basic_auth" = [])),
    tag = "Certificates"
)]
pub async fn revoke_certificate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(serial): Path<String>,
    Json(body): Json<RevokeBody>,
) -> Result<impl IntoResponse, Response> {
    state
        .service
        .revoke(&serial, body.reason.as_storage_str(), &user.username)
        .await
        .map_err(map_err)?;

    // Позначаємо відкликаним у LDAP
    let _ = state.publisher.unpublish_certificate(&serial).await;

    Ok(Json(MessageResponse {
        message: format!("Сертифікат {serial} відкликано"),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/certificates/{serial}/verify",
    params(("serial" = String, Path, description = "Серійний номер сертифіката")),
    responses((status = 200, body = VerifyResponse)),
    security(("basic_auth" = [])),
    tag = "Certificates"
)]
pub async fn verify_certificate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(serial): Path<String>,
) -> Result<impl IntoResponse, Response> {
    let result = state.service.verify(&serial, &user.username).await.map_err(map_err)?;
    Ok(Json(VerifyResponse {
        serial: result.serial,
        signature_valid: result.signature_valid,
        revoked: result.revoked,
        time_valid: result.time_valid,
    }))
}

/// Повертає повний PEM-ланцюжок: leaf → intermediate (якщо є) → root CA.
/// GET /api/v1/certificates/:serial/chain
#[utoipa::path(
    get,
    path = "/api/v1/certificates/{serial}/chain",
    params(("serial" = String, Path, description = "Серійний номер сертифіката")),
    responses((status = 200, body = PemResponse)),
    security(("basic_auth" = [])),
    tag = "Certificates"
)]
pub async fn get_certificate_chain(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(serial): Path<String>,
) -> Result<impl IntoResponse, Response> {
    let pem = state.service.chain_pem(&serial, &user.username).await.map_err(map_err)?;
    Ok(Json(PemResponse { pem }))
}

#[utoipa::path(
    get,
    path = "/crl/root.crl",
    responses((status = 200, body = PemResponse), (status = 404, description = "Root CA не ініціалізовано")),
    security(("basic_auth" = [])),
    tag = "CRL"
)]
pub async fn get_root_crl(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, Response> {
    let pem = state.service.root_crl_pem(&user.username).await.map_err(map_err)?;
    Ok(Json(PemResponse { pem }))
}

#[utoipa::path(
    get,
    path = "/crl/intermediate.crl",
    responses((status = 200, body = PemResponse), (status = 404, description = "Intermediate CA не ініціалізовано")),
    security(("basic_auth" = [])),
    tag = "CRL"
)]
pub async fn get_intermediate_crl(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, Response> {
    let pem = state
        .service
        .intermediate_crl_pem(&user.username)
        .await
        .map_err(map_err)?;
    Ok(Json(PemResponse { pem }))
}

// ── Аудит ─────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/audit",
    params(AuditQuery),
    responses((status = 200, body = [crate::models::AuditEvent])),
    security(("basic_auth" = [])),
    tag = "Audit"
)]
pub async fn audit_log(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Query(q): Query<AuditQuery>,
) -> Result<impl IntoResponse, Response> {
    let events = state.service.audit_log(q.limit).await.map_err(map_err)?;
    Ok(Json(events))
}

// ── LDAP-директорія ───────────────────────────────────────────────────────────

/// Пошук сертифікатів у LDAP-каталозі за Common Name.
/// GET /api/v1/ldap/certificates?cn=service.internal
#[utoipa::path(
    get,
    path = "/api/v1/ldap/certificates",
    params(LdapSearchQuery),
    responses((status = 200, body = [crate::ldap_publish::LdapCertEntry])),
    security(("basic_auth" = [])),
    tag = "LDAP"
)]
pub async fn ldap_search_by_cn(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<LdapSearchQuery>,
) -> Result<impl IntoResponse, Response> {
    let _ = user; // авторизація вже виконана
    let entries = state
        .publisher
        .search_by_cn(&q.cn)
        .await
        .map_err(map_err)?;
    Ok(Json(entries))
}


