use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::models::{
    CertStatus, CertificateProfile, CertificateRecord, IssueIssuer, IssuerKind, RevocationReason,
};

// ── Тіла запитів ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct InitRootBody {
    pub common_name: String,
    #[serde(default = "default_root_days")]
    pub validity_days: u32,
}
fn default_root_days() -> u32 { 3650 }

#[derive(Debug, Deserialize, ToSchema)]
pub struct InitIntermediateBody {
    pub common_name: String,
    #[serde(default = "default_int_days")]
    pub validity_days: u32,
}
fn default_int_days() -> u32 { 1825 }

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueCertificateBody {
    pub common_name: String,
    #[serde(default)]
    pub profile: CertificateProfile,
    #[serde(default)]
    pub issuer: IssueIssuer,
    #[serde(default)]
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub ip_sans: Vec<String>,
    #[serde(default = "default_cert_days")]
    pub validity_days: u32,
}
fn default_cert_days() -> u32 { 365 }

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeBody {
    #[serde(default = "default_reason")]
    pub reason: RevocationReason,
}
fn default_reason() -> RevocationReason { RevocationReason::Unspecified }

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    #[serde(default)]
    pub include_revoked: bool,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}
fn default_page() -> u32 { 1 }
fn default_per_page() -> u32 { 50 }

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
}
fn default_limit() -> u32 { 50 }

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LdapSearchQuery {
    pub cn: String,
}

// ── Відповіді ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct SerialResponse {
    pub serial: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PemResponse {
    pub pem: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    pub serial: String,
    pub signature_valid: bool,
    pub revoked: bool,
    pub time_valid: bool,
}

/// Публічне представлення сертифіката — без приватного ключа.
/// Використовується у GET /certificates та GET /certificates/:serial.
#[derive(Debug, Serialize, ToSchema)]
pub struct CertificateResponse {
    pub serial: String,
    pub common_name: String,
    pub profile: CertificateProfile,
    pub dns_names: Vec<String>,
    pub ip_sans: Vec<String>,
    pub cert_pem: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issuer_kind: Option<IssuerKind>,
    pub issuer_serial: Option<String>,
    pub status: CertStatus,
}

impl From<CertificateRecord> for CertificateResponse {
    fn from(r: CertificateRecord) -> Self {
        Self {
            serial: r.serial,
            common_name: r.common_name,
            profile: r.profile,
            dns_names: r.dns_names,
            ip_sans: r.ip_sans,
            cert_pem: r.cert_pem,
            issued_at: r.issued_at,
            not_before: r.not_before,
            not_after: r.not_after,
            issuer_kind: r.issuer_kind,
            issuer_serial: r.issuer_serial,
            status: r.status,
        }
    }
}

/// Відповідь на видачу сертифіката — включає приватний ключ (лише один раз).
#[derive(Debug, Serialize, ToSchema)]
pub struct IssueCertificateResponse {
    #[serde(flatten)]
    pub certificate: CertificateResponse,
    pub key_pem: String,
}

/// Відповідь зі списком сертифікатів + метадані пагінації.
#[derive(Debug, Serialize, ToSchema)]
pub struct CertificateListResponse {
    pub data: Vec<CertificateResponse>,
    pub page: u32,
    pub per_page: u32,
    pub total: usize,
}
