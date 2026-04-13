use utoipa::{Modify, OpenApi};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use super::{dto, handlers};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "basic_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Basic)
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::health,
        handlers::init_root,
        handlers::export_root,
        handlers::init_intermediate,
        handlers::export_intermediate,
        handlers::issue_certificate,
        handlers::list_certificates,
        handlers::get_certificate,
        handlers::revoke_certificate,
        handlers::verify_certificate,
        handlers::get_certificate_chain,
        handlers::get_root_crl,
        handlers::get_intermediate_crl,
        handlers::audit_log,
        handlers::ldap_search_by_cn
    ),
    components(
        schemas(
            dto::InitRootBody,
            dto::InitIntermediateBody,
            dto::IssueCertificateBody,
            dto::RevokeBody,
            dto::SerialResponse,
            dto::MessageResponse,
            dto::PemResponse,
            dto::VerifyResponse,
            dto::CertificateResponse,
            dto::IssueCertificateResponse,
            dto::CertificateListResponse,
            crate::models::CertificateProfile,
            crate::models::IssueIssuer,
            crate::models::IssuerKind,
            crate::models::CertStatus,
            crate::models::AuditEvent,
            crate::models::AuditEventKind,
            crate::models::RevocationReason,
            crate::ldap_publish::LdapCertEntry
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "System", description = "Системні endpoint-и"),
        (name = "CA", description = "Операції Root/Intermediate CA"),
        (name = "Certificates", description = "Випуск і керування сертифікатами"),
        (name = "CRL", description = "Certificate Revocation List"),
        (name = "Audit", description = "Аудит подій"),
        (name = "LDAP", description = "LDAP пошук сертифікатів")
    )
)]
pub struct ApiDoc;

