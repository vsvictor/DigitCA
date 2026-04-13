use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};


use super::AppState;

/// Екстрактор для Basic-автентифікації через LDAP.
/// Повертає `AuthenticatedUser` з username який використовується в аудит-логах.
pub struct AuthenticatedUser {
    pub username: String,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !auth_header.starts_with("Basic ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Basic realm=\"digitca\"")],
                "Потрібна Basic автентифікація (Authorization: Basic base64(user:pass))",
            )
                .into_response());
        }

        let encoded = &auth_header[6..];
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Неправильний Base64 у заголовку").into_response())?;
        let credentials = String::from_utf8(decoded)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Неправильне кодування облікових даних").into_response())?;

        let (username, password) = credentials
            .split_once(':')
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Формат має бути user:password").into_response())?;

        state
            .ldap
            .authorize(username, password)
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    [("WWW-Authenticate", "Basic realm=\"digitca\"")],
                    "Автентифікацію відхилено",
                )
                    .into_response()
            })?;

        Ok(AuthenticatedUser {
            username: username.to_string(),
        })
    }
}

