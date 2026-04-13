use chrono::Utc;
use uuid::Uuid;

use crate::{
    ca::CertificateAuthority,
    error::{AppError, AppResult},
    models::{
        AuditEvent, AuditEventKind, CertificateRecord, CrlEntry, IntermediateCaRecord,
        IssueIssuer, IssueRequest, IssuerKind, RevocationReason,
    },
    storage::CaRepository,
};

pub struct CaService<R> {
    storage: R,
    root_key_passphrase: Option<String>,
    intermediate_key_passphrase: Option<String>,
}

impl<R> CaService<R>
where
    R: CaRepository,
{
    pub fn new(
        storage: R,
        root_key_passphrase: Option<String>,
        intermediate_key_passphrase: Option<String>,
    ) -> Self {
        Self {
            storage,
            root_key_passphrase,
            intermediate_key_passphrase,
        }
    }

    pub async fn init_root(&self, common_name: &str, validity_days: u32, actor: &str) -> AppResult<String> {
        let root = CertificateAuthority::create_root(
            common_name,
            validity_days,
            self.root_key_passphrase.as_deref(),
        )?;
        let serial = root.serial.clone();
        self.storage.upsert_root(&root).await?;
        self.audit(AuditEventKind::InitRoot, actor, None, format!("Root CA '{common_name}' ініціалізовано, serial={serial}")).await;
        Ok(serial)
    }

    pub async fn init_intermediate(&self, common_name: &str, validity_days: u32, actor: &str) -> AppResult<String> {
        let root = self
            .storage
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA не ініціалізовано".to_string()))?;

        let intermediate = CertificateAuthority::create_intermediate(
            &root,
            common_name,
            validity_days,
            self.root_key_passphrase.as_deref(),
            self.intermediate_key_passphrase.as_deref(),
        )?;
        let serial = intermediate.serial.clone();
        self.storage.upsert_intermediate(&intermediate).await?;
        self.audit(AuditEventKind::InitIntermediate, actor, None, format!("Intermediate CA '{common_name}' ініціалізовано, serial={serial}")).await;
        Ok(serial)
    }

    pub async fn issue(&self, req: IssueRequest, actor: &str) -> AppResult<CertificateRecord> {
        let root = self
            .storage
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA не ініціалізовано".to_string()))?;
        let intermediate = self.storage.get_intermediate().await?;

        let cert = match req.issuer {
            IssueIssuer::Root => {
                CertificateAuthority::issue_from_root(&root, req, self.root_key_passphrase.as_deref())?
            }
            IssueIssuer::Intermediate => {
                let intermediate = intermediate.ok_or_else(|| {
                    AppError::NotFound("intermediate CA не ініціалізовано".to_string())
                })?;
                CertificateAuthority::issue_from_intermediate(
                    &intermediate,
                    req,
                    self.intermediate_key_passphrase.as_deref(),
                )?
            }
            IssueIssuer::Auto => {
                if let Some(intermediate) = intermediate {
                    CertificateAuthority::issue_from_intermediate(
                        &intermediate,
                        req,
                        self.intermediate_key_passphrase.as_deref(),
                    )?
                } else {
                    CertificateAuthority::issue_from_root(&root, req, self.root_key_passphrase.as_deref())?
                }
            }
        };

        self.storage.insert_certificate(&cert).await?;
        self.audit(
            AuditEventKind::IssueCertificate,
            actor,
            Some(cert.serial.clone()),
            format!("Видано '{}' profile={:?} issuer={:?}", cert.common_name, cert.profile, cert.issuer_kind),
        ).await;
        Ok(cert)
    }

    pub async fn revoke(&self, serial: &str, reason: &str, actor: &str) -> AppResult<()> {
        let parsed_reason = RevocationReason::parse(reason).ok_or_else(|| {
            AppError::Validation(
                "reason має бути одним із: unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCrl, privilegeWithdrawn, aaCompromise".to_string(),
            )
        })?;

        let cert = self.storage.get_certificate(serial).await?;
        if cert.is_none() {
            return Err(AppError::NotFound(serial.to_string()));
        }
        self.storage
            .revoke_certificate(serial, parsed_reason.as_storage_str())
            .await?;
        self.audit(
            AuditEventKind::RevokeCertificate,
            actor,
            Some(serial.to_string()),
            format!("Відкликано serial={serial}, reason={}", parsed_reason.as_storage_str()),
        ).await;
        Ok(())
    }

    pub async fn get(&self, serial: &str, actor: &str) -> AppResult<CertificateRecord> {
        let cert = self
            .storage
            .get_certificate(serial)
            .await?
            .ok_or_else(|| AppError::NotFound(serial.to_string()))?;
        self.audit(AuditEventKind::GetCertificate, actor, Some(serial.to_string()), format!("Отримано serial={serial}")).await;
        Ok(cert)
    }

    pub async fn list(&self, include_revoked: bool, actor: &str) -> AppResult<Vec<CertificateRecord>> {
        let certs = self.storage.list_certificates(include_revoked).await?;
        self.audit(AuditEventKind::ListCertificates, actor, None, format!("Список сертифікатів, include_revoked={include_revoked}, count={}", certs.len())).await;
        Ok(certs)
    }

    pub async fn verify(&self, serial: &str, actor: &str) -> AppResult<VerificationResult> {
        let cert = self
            .storage
            .get_certificate(serial)
            .await?
            .ok_or_else(|| AppError::NotFound(serial.to_string()))?;
        let root = self
            .storage
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA не ініціалізовано".to_string()))?;
        let intermediate = self.storage.get_intermediate().await?;

        let signature_valid = match cert.issuer_kind.as_ref().unwrap_or(&IssuerKind::Root) {
            IssuerKind::Root => CertificateAuthority::verify_signature(&cert.cert_pem, &root.cert_pem)?,
            IssuerKind::Intermediate => {
                let intermediate = intermediate.ok_or_else(|| {
                    AppError::NotFound("intermediate CA не ініціалізовано".to_string())
                })?;
                let leaf_ok = CertificateAuthority::verify_signature(&cert.cert_pem, &intermediate.cert_pem)?;
                let intermediate_ok =
                    CertificateAuthority::verify_signature(&intermediate.cert_pem, &root.cert_pem)?;
                leaf_ok && intermediate_ok
            }
        };
        let revoked = self.storage.is_revoked(serial).await?;
        let now = Utc::now();
        let time_valid = now >= cert.not_before && now <= cert.not_after;

        self.audit(
            AuditEventKind::VerifyCertificate,
            actor,
            Some(serial.to_string()),
            format!("Перевірено serial={serial}: signature={signature_valid}, revoked={revoked}, time={time_valid}"),
        ).await;

        Ok(VerificationResult {
            serial: serial.to_string(),
            signature_valid,
            revoked,
            time_valid,
        })
    }

    pub async fn root_pem(&self, actor: &str) -> AppResult<String> {
        let root = self
            .storage
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA не ініціалізовано".to_string()))?;
        self.audit(AuditEventKind::ExportRoot, actor, None, "Root CA PEM експортовано".to_string()).await;
        Ok(root.cert_pem)
    }

    pub async fn intermediate_pem(&self, actor: &str) -> AppResult<String> {
        let intermediate: IntermediateCaRecord = self
            .storage
            .get_intermediate()
            .await?
            .ok_or_else(|| AppError::NotFound("intermediate CA не ініціалізовано".to_string()))?;
        self.audit(AuditEventKind::ExportIntermediate, actor, None, "Intermediate CA PEM експортовано".to_string()).await;
        Ok(intermediate.cert_pem)
    }

    /// Повертає повний PEM-ланцюжок: leaf → intermediate (якщо є) → root CA.
    pub async fn chain_pem(&self, serial: &str, actor: &str) -> AppResult<String> {
        let cert = self
            .storage
            .get_certificate(serial)
            .await?
            .ok_or_else(|| AppError::NotFound(serial.to_string()))?;
        let root = self
            .storage
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA не ініціалізовано".to_string()))?;
        let intermediate = self.storage.get_intermediate().await?;

        let chain = match cert.issuer_kind.as_ref().unwrap_or(&IssuerKind::Root) {
            IssuerKind::Intermediate => {
                let int = intermediate.ok_or_else(|| {
                    AppError::NotFound("intermediate CA не ініціалізовано".to_string())
                })?;
                format!("{}\n{}\n{}", cert.cert_pem.trim(), int.cert_pem.trim(), root.cert_pem.trim())
            }
            IssuerKind::Root => {
                format!("{}\n{}", cert.cert_pem.trim(), root.cert_pem.trim())
            }
        };

        self.audit(
            AuditEventKind::ExportChain,
            actor,
            Some(serial.to_string()),
            format!("Ланцюжок сертифіката serial={serial} експортовано"),
        )
        .await;
        Ok(chain)
    }

    pub async fn root_crl_pem(&self, actor: &str) -> AppResult<String> {
        let root = self
            .storage
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA не ініціалізовано".to_string()))?;

        let revocations = self.storage.list_revocations().await?;
        let mut entries = Vec::new();
        for rev in revocations {
            if let Some(cert) = self.storage.get_certificate(&rev.serial).await? {
                if cert.issuer_kind.as_ref().unwrap_or(&IssuerKind::Root) == &IssuerKind::Root {
                    entries.push(CrlEntry {
                        serial: rev.serial,
                        revoked_at: rev.revoked_at,
                        reason: RevocationReason::parse(&rev.reason)
                            .unwrap_or(RevocationReason::Unspecified),
                    });
                }
            }
        }

        let pem = CertificateAuthority::build_crl_pem(
            &root.cert_pem,
            &root.key_pem,
            root.key_encrypted,
            self.root_key_passphrase.as_deref(),
            &entries,
        )?;

        self.audit(
            AuditEventKind::ExportRoot,
            actor,
            None,
            format!("Root CRL експортовано, entries={}", entries.len()),
        )
        .await;

        Ok(pem)
    }

    pub async fn intermediate_crl_pem(&self, actor: &str) -> AppResult<String> {
        let intermediate = self
            .storage
            .get_intermediate()
            .await?
            .ok_or_else(|| AppError::NotFound("intermediate CA не ініціалізовано".to_string()))?;

        let revocations = self.storage.list_revocations().await?;
        let mut entries = Vec::new();
        for rev in revocations {
            if let Some(cert) = self.storage.get_certificate(&rev.serial).await? {
                if cert.issuer_kind == Some(IssuerKind::Intermediate) {
                    entries.push(CrlEntry {
                        serial: rev.serial,
                        revoked_at: rev.revoked_at,
                        reason: RevocationReason::parse(&rev.reason)
                            .unwrap_or(RevocationReason::Unspecified),
                    });
                }
            }
        }

        let pem = CertificateAuthority::build_crl_pem(
            &intermediate.cert_pem,
            &intermediate.key_pem,
            intermediate.key_encrypted,
            self.intermediate_key_passphrase.as_deref(),
            &entries,
        )?;

        self.audit(
            AuditEventKind::ExportIntermediate,
            actor,
            None,
            format!("Intermediate CRL експортовано, entries={}", entries.len()),
        )
        .await;

        Ok(pem)
    }

    pub async fn audit_log(&self, limit: u32) -> AppResult<Vec<AuditEvent>> {
        self.storage.list_audit(limit).await
    }

    async fn audit(&self, kind: AuditEventKind, actor: &str, target_serial: Option<String>, details: String) {
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            kind,
            actor: actor.to_string(),
            target_serial,
            details,
            occurred_at: Utc::now(),
        };
        let _ = self.storage.insert_audit(&event).await;
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub serial: String,
    pub signature_valid: bool,
    pub revoked: bool,
    pub time_valid: bool,
}
