use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCaRecord {
    pub name: String,
    pub serial: String,
    pub cert_pem: String,
    pub key_pem: String,
    #[serde(default)]
    pub key_encrypted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntermediateCaRecord {
    pub name: String,
    pub serial: String,
    pub issuer_serial: String,
    pub cert_pem: String,
    pub key_pem: String,
    #[serde(default)]
    pub key_encrypted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ValueEnum, ToSchema)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum CertificateProfile {
    ServerTls,
    ClientAuth,
}

impl Default for CertificateProfile {
    fn default() -> Self {
        Self::ServerTls
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ValueEnum, ToSchema)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum IssueIssuer {
    Auto,
    Root,
    Intermediate,
}

impl Default for IssueIssuer {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IssuerKind {
    Root,
    Intermediate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub serial: String,
    pub common_name: String,
    #[serde(default)]
    pub profile: CertificateProfile,
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub ip_sans: Vec<String>,
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde(default)]
    pub issuer_kind: Option<IssuerKind>,
    #[serde(default)]
    pub issuer_serial: Option<String>,
    pub status: CertStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub serial: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    InitRoot,
    InitIntermediate,
    IssueCertificate,
    RevokeCertificate,
    GetCertificate,
    ListCertificates,
    VerifyCertificate,
    ExportRoot,
    ExportIntermediate,
    ExportChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    pub id: String,
    pub kind: AuditEventKind,
    pub actor: String,
    pub target_serial: Option<String>,
    pub details: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct IssueRequest {
    pub common_name: String,
    pub profile: CertificateProfile,
    pub issuer: IssueIssuer,
    pub dns_names: Vec<String>,
    pub ip_sans: Vec<String>,
    pub validity_days: u32,
}

#[derive(Debug, Clone)]
pub struct CrlEntry {
    pub serial: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReason {
    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim();
        let lower = normalized.to_ascii_lowercase();
        match lower.as_str() {
            "unspecified" => Some(Self::Unspecified),
            "keycompromise" | "key_compromise" | "key-compromise" => Some(Self::KeyCompromise),
            "cacompromise" | "ca_compromise" | "ca-compromise" => Some(Self::CaCompromise),
            "affiliationchanged" | "affiliation_changed" | "affiliation-changed" => {
                Some(Self::AffiliationChanged)
            }
            "superseded" => Some(Self::Superseded),
            "cessationofoperation" | "cessation_of_operation" | "cessation-of-operation" => {
                Some(Self::CessationOfOperation)
            }
            "certificatehold" | "certificate_hold" | "certificate-hold" => Some(Self::CertificateHold),
            "removefromcrl" | "remove_from_crl" | "remove-from-crl" => Some(Self::RemoveFromCrl),
            "privilegewithdrawn" | "privilege_withdrawn" | "privilege-withdrawn" => {
                Some(Self::PrivilegeWithdrawn)
            }
            "aacompromise" | "aa_compromise" | "aa-compromise" => Some(Self::AaCompromise),
            _ => None,
        }
    }

    pub fn as_storage_str(&self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "caCompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCrl => "removeFromCrl",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aaCompromise",
        }
    }

    pub fn as_crl_reason_code(&self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RevocationReason;

    #[test]
    fn revocation_reason_parsing_supports_aliases() {
        assert_eq!(RevocationReason::parse("keyCompromise"), Some(RevocationReason::KeyCompromise));
        assert_eq!(RevocationReason::parse("key_compromise"), Some(RevocationReason::KeyCompromise));
        assert_eq!(RevocationReason::parse("key-compromise"), Some(RevocationReason::KeyCompromise));
        assert_eq!(
            RevocationReason::parse("cessationOfOperation"),
            Some(RevocationReason::CessationOfOperation)
        );
        assert_eq!(RevocationReason::parse("unknownReason"), None);
    }

    #[test]
    fn revocation_reason_has_stable_crl_codes() {
        assert_eq!(RevocationReason::Unspecified.as_crl_reason_code(), 0);
        assert_eq!(RevocationReason::KeyCompromise.as_crl_reason_code(), 1);
        assert_eq!(RevocationReason::CaCompromise.as_crl_reason_code(), 2);
        assert_eq!(RevocationReason::AffiliationChanged.as_crl_reason_code(), 3);
        assert_eq!(RevocationReason::Superseded.as_crl_reason_code(), 4);
        assert_eq!(RevocationReason::CessationOfOperation.as_crl_reason_code(), 5);
        assert_eq!(RevocationReason::CertificateHold.as_crl_reason_code(), 6);
        assert_eq!(RevocationReason::RemoveFromCrl.as_crl_reason_code(), 8);
        assert_eq!(RevocationReason::PrivilegeWithdrawn.as_crl_reason_code(), 9);
        assert_eq!(RevocationReason::AaCompromise.as_crl_reason_code(), 10);
    }
}

