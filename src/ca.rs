use chrono::{Duration, Utc};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    symm::Cipher,
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509Crl, X509NameBuilder, X509,
    },
};
use openssl_sys as ffi;
use std::os::raw::{c_int, c_long};

unsafe extern "C" {
    fn ASN1_ENUMERATED_new() -> *mut ffi::ASN1_ENUMERATED;
    fn ASN1_ENUMERATED_set(a: *mut ffi::ASN1_ENUMERATED, v: c_long) -> c_int;
}

use crate::{
    error::{AppError, AppResult},
    models::{
        CertStatus, CertificateProfile, CertificateRecord, CrlEntry, IntermediateCaRecord, IssueRequest,
        IssuerKind, RootCaRecord,
    },
};

pub struct CertificateAuthority;

impl CertificateAuthority {
    pub fn build_crl_pem(
        issuer_cert_pem: &str,
        issuer_key_pem: &str,
        issuer_key_encrypted: bool,
        issuer_key_passphrase: Option<&str>,
        revoked_entries: &[CrlEntry],
    ) -> AppResult<String> {
        let issuer_cert =
            X509::from_pem(issuer_cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let issuer_key = load_private_key(
            issuer_key_pem,
            issuer_key_encrypted,
            issuer_key_passphrase,
            "issuer ключа",
        )?;

        unsafe {
            let crl_ptr = ffi::X509_CRL_new();
            if crl_ptr.is_null() {
                return Err(AppError::Crypto("не вдалося створити X509_CRL".to_string()));
            }

            let fail = |msg: &str, ptr: *mut ffi::X509_CRL| {
                ffi::X509_CRL_free(ptr);
                AppError::Crypto(msg.to_string())
            };

            if ffi::X509_CRL_set_version(crl_ptr, 1) != 1 {
                return Err(fail("не вдалося встановити версію CRL", crl_ptr));
            }

            if ffi::X509_CRL_set_issuer_name(crl_ptr, issuer_cert.subject_name().as_ptr()) != 1 {
                return Err(fail("не вдалося встановити issuer CRL", crl_ptr));
            }

            let last_update = Asn1Time::days_from_now(0).map_err(|e| AppError::Crypto(e.to_string()))?;
            let next_update = Asn1Time::days_from_now(7).map_err(|e| AppError::Crypto(e.to_string()))?;

            if ffi::X509_CRL_set1_lastUpdate(crl_ptr, last_update.as_ptr()) != 1 {
                return Err(fail("не вдалося встановити lastUpdate CRL", crl_ptr));
            }
            if ffi::X509_CRL_set1_nextUpdate(crl_ptr, next_update.as_ptr()) != 1 {
                return Err(fail("не вдалося встановити nextUpdate CRL", crl_ptr));
            }

            for entry in revoked_entries {
                let rev_ptr = ffi::X509_REVOKED_new();
                if rev_ptr.is_null() {
                    return Err(fail("не вдалося створити X509_REVOKED", crl_ptr));
                }

                let serial_bn = BigNum::from_hex_str(&entry.serial)
                    .map_err(|e| AppError::Crypto(format!("некоректний serial '{}': {e}", entry.serial)))?;
                let serial_asn1 = serial_bn
                    .to_asn1_integer()
                    .map_err(|e| AppError::Crypto(e.to_string()))?;
                if ffi::X509_REVOKED_set_serialNumber(rev_ptr, serial_asn1.as_ptr() as *mut _) != 1 {
                    ffi::X509_REVOKED_free(rev_ptr);
                    return Err(fail("не вдалося встановити serial у CRL entry", crl_ptr));
                }

                let revoked_time = Asn1Time::from_unix(entry.revoked_at.timestamp())
                    .map_err(|e| AppError::Crypto(e.to_string()))?;
                if ffi::X509_REVOKED_set_revocationDate(rev_ptr, revoked_time.as_ptr() as *mut _) != 1 {
                    ffi::X509_REVOKED_free(rev_ptr);
                    return Err(fail("не вдалося встановити revoked_at у CRL entry", crl_ptr));
                }

                let reason_enum = ASN1_ENUMERATED_new();
                if reason_enum.is_null() {
                    ffi::X509_REVOKED_free(rev_ptr);
                    return Err(fail("не вдалося створити ASN1_ENUMERATED для reasonCode", crl_ptr));
                }
                if ASN1_ENUMERATED_set(reason_enum, entry.reason.as_crl_reason_code() as c_long) != 1 {
                    ffi::ASN1_ENUMERATED_free(reason_enum);
                    ffi::X509_REVOKED_free(rev_ptr);
                    return Err(fail("не вдалося встановити ASN1_ENUMERATED значення reasonCode", crl_ptr));
                }
                let add_reason_result = ffi::X509_REVOKED_add1_ext_i2d(
                    rev_ptr,
                    ffi::NID_crl_reason,
                    reason_enum as *mut _,
                    0,
                    0,
                );
                ffi::ASN1_ENUMERATED_free(reason_enum);
                if add_reason_result != 1 {
                    ffi::X509_REVOKED_free(rev_ptr);
                    return Err(fail("не вдалося додати reasonCode extension", crl_ptr));
                }

                if ffi::X509_CRL_add0_revoked(crl_ptr, rev_ptr) != 1 {
                    ffi::X509_REVOKED_free(rev_ptr);
                    return Err(fail("не вдалося додати revoked entry до CRL", crl_ptr));
                }
            }

            if ffi::X509_CRL_sort(crl_ptr) != 1 {
                return Err(fail("не вдалося відсортувати CRL", crl_ptr));
            }

            if ffi::X509_CRL_sign(crl_ptr, issuer_key.as_ptr(), ffi::EVP_sha256()) == 0 {
                return Err(fail("не вдалося підписати CRL", crl_ptr));
            }

            let crl = X509Crl::from_ptr(crl_ptr);
            let pem = String::from_utf8(crl.to_pem().map_err(|e| AppError::Crypto(e.to_string()))?)
                .map_err(|e| AppError::Crypto(e.to_string()))?;
            Ok(pem)
        }
    }

    pub fn create_root(
        common_name: &str,
        validity_days: u32,
        key_passphrase: Option<&str>,
    ) -> AppResult<RootCaRecord> {
        let key = Rsa::generate(4096).map_err(|e| AppError::Crypto(e.to_string()))?;
        let pkey = PKey::from_rsa(key).map_err(|e| AppError::Crypto(e.to_string()))?;
        let name = build_common_name(common_name)?;

        let mut builder = X509::builder().map_err(|e| AppError::Crypto(e.to_string()))?;
        prepare_base_builder(&mut builder, &name, &name, &pkey, validity_days)?;

        let basic = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        builder
            .append_extension(basic)
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        let key_usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        builder
            .append_extension(key_usage)
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        builder
            .sign(&pkey, MessageDigest::sha256())
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        let cert = builder.build();
        let cert_pem = pem_from_cert(&cert)?;
        let (key_pem, key_encrypted) = private_key_to_pem(&pkey, key_passphrase)?;

        Ok(RootCaRecord {
            name: common_name.to_string(),
            serial: serial_hex_from_cert(&cert)?,
            cert_pem,
            key_pem,
            key_encrypted,
            created_at: Utc::now(),
        })
    }

    pub fn create_intermediate(
        root: &RootCaRecord,
        common_name: &str,
        validity_days: u32,
        root_key_passphrase: Option<&str>,
        intermediate_key_passphrase: Option<&str>,
    ) -> AppResult<IntermediateCaRecord> {
        let root_cert = X509::from_pem(root.cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let root_key = load_private_key(
            &root.key_pem,
            root.key_encrypted,
            root_key_passphrase,
            "root ключа",
        )?;

        let key = Rsa::generate(4096).map_err(|e| AppError::Crypto(e.to_string()))?;
        let pkey = PKey::from_rsa(key).map_err(|e| AppError::Crypto(e.to_string()))?;
        let name = build_common_name(common_name)?;

        let mut builder = X509::builder().map_err(|e| AppError::Crypto(e.to_string()))?;
        prepare_base_builder(
            &mut builder,
            &name,
            root_cert.subject_name(),
            &pkey,
            validity_days,
        )?;

        let basic = BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(0)
            .build()
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        builder
            .append_extension(basic)
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        let key_usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        builder
            .append_extension(key_usage)
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        builder
            .sign(&root_key, MessageDigest::sha256())
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        let cert = builder.build();
        let cert_pem = pem_from_cert(&cert)?;
        let (key_pem, key_encrypted) = private_key_to_pem(&pkey, intermediate_key_passphrase)?;

        Ok(IntermediateCaRecord {
            name: common_name.to_string(),
            serial: serial_hex_from_cert(&cert)?,
            issuer_serial: root.serial.clone(),
            cert_pem,
            key_pem,
            key_encrypted,
            created_at: Utc::now(),
        })
    }

    pub fn issue_from_root(
        root: &RootCaRecord,
        req: IssueRequest,
        root_key_passphrase: Option<&str>,
    ) -> AppResult<CertificateRecord> {
        let root_cert = X509::from_pem(root.cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let root_key = load_private_key(
            &root.key_pem,
            root.key_encrypted,
            root_key_passphrase,
            "root ключа",
        )?;

        issue_with_issuer(
            &root_cert,
            &root_key,
            root.serial.clone(),
            IssuerKind::Root,
            req,
        )
    }

    pub fn issue_from_intermediate(
        intermediate: &IntermediateCaRecord,
        req: IssueRequest,
        intermediate_key_passphrase: Option<&str>,
    ) -> AppResult<CertificateRecord> {
        let intermediate_cert =
            X509::from_pem(intermediate.cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let intermediate_key = load_private_key(
            &intermediate.key_pem,
            intermediate.key_encrypted,
            intermediate_key_passphrase,
            "intermediate ключа",
        )?;

        issue_with_issuer(
            &intermediate_cert,
            &intermediate_key,
            intermediate.serial.clone(),
            IssuerKind::Intermediate,
            req,
        )
    }

    pub fn verify_signature(cert_pem: &str, issuer_cert_pem: &str) -> AppResult<bool> {
        let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let issuer_cert = X509::from_pem(issuer_cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let pub_key = issuer_cert
            .public_key()
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        cert.verify(&pub_key)
            .map_err(|e| AppError::Crypto(e.to_string()))
    }
}

fn issue_with_issuer(
    issuer_cert: &X509,
    issuer_key: &PKey<Private>,
    issuer_serial: String,
    issuer_kind: IssuerKind,
    req: IssueRequest,
) -> AppResult<CertificateRecord> {
    validate_issue_request(&req)?;

    let leaf_key = Rsa::generate(2048).map_err(|e| AppError::Crypto(e.to_string()))?;
    let leaf_pkey = PKey::from_rsa(leaf_key).map_err(|e| AppError::Crypto(e.to_string()))?;
    let name = build_common_name(&req.common_name)?;

    let mut builder = X509::builder().map_err(|e| AppError::Crypto(e.to_string()))?;
    prepare_base_builder(
        &mut builder,
        &name,
        issuer_cert.subject_name(),
        &leaf_pkey,
        req.validity_days,
    )?;

    let basic = BasicConstraints::new()
        .critical()
        .build()
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .append_extension(basic)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    let key_usage = match req.profile {
        CertificateProfile::ServerTls => KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build(),
        CertificateProfile::ClientAuth => KeyUsage::new().critical().digital_signature().build(),
    }
    .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .append_extension(key_usage)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    let ext_key_usage = match req.profile {
        CertificateProfile::ServerTls => ExtendedKeyUsage::new().server_auth().build(),
        CertificateProfile::ClientAuth => ExtendedKeyUsage::new().client_auth().build(),
    }
    .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .append_extension(ext_key_usage)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    if !req.dns_names.is_empty() || !req.ip_sans.is_empty() {
        let mut san = SubjectAlternativeName::new();
        for dns in &req.dns_names {
            san.dns(dns);
        }
        for ip in &req.ip_sans {
            san.ip(ip);
        }
        let san_ext = san
            .build(&builder.x509v3_context(Some(issuer_cert), None))
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        builder
            .append_extension(san_ext)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
    }

    builder
        .sign(issuer_key, MessageDigest::sha256())
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    let cert = builder.build();
    let cert_pem = pem_from_cert(&cert)?;
    let (key_pem, _) = private_key_to_pem(&leaf_pkey, None)?;

    let now = Utc::now();
    Ok(CertificateRecord {
        serial: serial_hex_from_cert(&cert)?,
        common_name: req.common_name,
        profile: req.profile,
        dns_names: req.dns_names,
        ip_sans: req.ip_sans,
        cert_pem,
        key_pem,
        issued_at: now,
        not_before: now,
        not_after: now + Duration::days(req.validity_days as i64),
        issuer_kind: Some(issuer_kind),
        issuer_serial: Some(issuer_serial),
        status: CertStatus::Active,
    })
}

fn validate_issue_request(req: &IssueRequest) -> AppResult<()> {
    if req.common_name.trim().is_empty() {
        return Err(AppError::Validation("common_name не може бути порожнім".to_string()));
    }

    if req.validity_days == 0 {
        return Err(AppError::Validation("validity_days має бути > 0".to_string()));
    }

    if matches!(req.profile, CertificateProfile::ServerTls)
        && req.dns_names.is_empty()
        && req.ip_sans.is_empty()
    {
        return Err(AppError::Validation(
            "для профілю server-tls потрібно вказати хоча б один DNS або IP SAN".to_string(),
        ));
    }

    Ok(())
}

fn build_common_name(common_name: &str) -> AppResult<openssl::x509::X509Name> {
    let mut name_builder = X509NameBuilder::new().map_err(|e| AppError::Crypto(e.to_string()))?;
    name_builder
        .append_entry_by_text("CN", common_name)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(name_builder.build())
}

fn prepare_base_builder(
    builder: &mut openssl::x509::X509Builder,
    subject_name: &openssl::x509::X509NameRef,
    issuer_name: &openssl::x509::X509NameRef,
    pub_key: &PKey<Private>,
    validity_days: u32,
) -> AppResult<()> {
    builder
        .set_version(2)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    let serial = random_serial_hex()?;
    let serial_bn = BigNum::from_hex_str(&serial).map_err(|e| AppError::Crypto(e.to_string()))?;
    let serial_asn1 = serial_bn
        .to_asn1_integer()
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .set_serial_number(&serial_asn1)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    builder
        .set_subject_name(subject_name)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .set_issuer_name(issuer_name)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .set_pubkey(pub_key)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    let not_before = Asn1Time::days_from_now(0).map_err(|e| AppError::Crypto(e.to_string()))?;
    let not_after = Asn1Time::days_from_now(validity_days).map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    Ok(())
}

fn pem_from_cert(cert: &X509) -> AppResult<String> {
    String::from_utf8(cert.to_pem().map_err(|e| AppError::Crypto(e.to_string()))?)
        .map_err(|e| AppError::Crypto(e.to_string()))
}

fn serial_hex_from_cert(cert: &X509) -> AppResult<String> {
    cert.serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|hex| hex.to_string())
        .map_err(|e| AppError::Crypto(e.to_string()))
}

fn private_key_to_pem(pkey: &PKey<Private>, key_passphrase: Option<&str>) -> AppResult<(String, bool)> {
    let key_encrypted = key_passphrase.is_some_and(|pass| !pass.is_empty());
    let pem_bytes = match key_passphrase.filter(|pass| !pass.is_empty()) {
        Some(passphrase) => pkey
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes())
            .map_err(|e| AppError::Crypto(e.to_string()))?,
        None => pkey
            .private_key_to_pem_pkcs8()
            .map_err(|e| AppError::Crypto(e.to_string()))?,
    };

    let pem = String::from_utf8(pem_bytes).map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok((pem, key_encrypted))
}

fn load_private_key(
    key_pem: &str,
    key_encrypted: bool,
    key_passphrase: Option<&str>,
    label: &str,
) -> AppResult<PKey<Private>> {
    if key_encrypted {
        let passphrase = key_passphrase.filter(|pass| !pass.is_empty()).ok_or_else(|| {
            AppError::Config(format!("потрібна passphrase для розшифрування {label}"))
        })?;

        PKey::private_key_from_pem_passphrase(key_pem.as_bytes(), passphrase.as_bytes())
            .map_err(|e| AppError::Crypto(e.to_string()))
    } else {
        PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))
    }
}

fn random_serial_hex() -> AppResult<String> {
    let mut bn = BigNum::new().map_err(|e| AppError::Crypto(e.to_string()))?;
    bn.rand(128, MsbOption::MAYBE_ZERO, false)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(bn.to_hex_str().map_err(|e| AppError::Crypto(e.to_string()))?.to_string())
}

#[cfg(test)]
mod tests {
    use super::CertificateAuthority;
    use crate::{
        error::AppError,
        models::{CertificateProfile, IssueIssuer, IssueRequest, IssuerKind},
    };

    #[test]
    fn root_and_leaf_are_generated() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, None)
            .expect("root must be created");
        let cert = CertificateAuthority::issue_from_root(
            &root,
            IssueRequest {
                common_name: "service.internal".to_string(),
                profile: CertificateProfile::ServerTls,
                issuer: IssueIssuer::Root,
                dns_names: vec!["service.internal".to_string()],
                ip_sans: vec![],
                validity_days: 90,
            },
            None,
        )
        .expect("leaf must be issued");

        assert!(root.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(cert.issuer_kind, Some(IssuerKind::Root));
    }

    #[test]
    fn encrypted_root_requires_passphrase_for_issue() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, Some("super-secret"))
            .expect("encrypted root must be created");

        let result = CertificateAuthority::issue_from_root(
            &root,
            IssueRequest {
                common_name: "service.internal".to_string(),
                profile: CertificateProfile::ServerTls,
                issuer: IssueIssuer::Root,
                dns_names: vec!["service.internal".to_string()],
                ip_sans: vec![],
                validity_days: 90,
            },
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn encrypted_root_can_issue_with_passphrase() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, Some("super-secret"))
            .expect("encrypted root must be created");

        let cert = CertificateAuthority::issue_from_root(
            &root,
            IssueRequest {
                common_name: "secure.internal".to_string(),
                profile: CertificateProfile::ServerTls,
                issuer: IssueIssuer::Root,
                dns_names: vec!["secure.internal".to_string()],
                ip_sans: vec![],
                validity_days: 90,
            },
            Some("super-secret"),
        )
        .expect("leaf must be issued with correct passphrase");

        assert!(root.key_encrypted);
        assert_eq!(cert.common_name, "secure.internal");
    }

    #[test]
    fn server_tls_profile_requires_dns_san() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, None)
            .expect("root must be created");

        let result = CertificateAuthority::issue_from_root(
            &root,
            IssueRequest {
                common_name: "service.internal".to_string(),
                profile: CertificateProfile::ServerTls,
                issuer: IssueIssuer::Root,
                dns_names: vec![],
                ip_sans: vec![],
                validity_days: 90,
            },
            None,
        );

        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn server_tls_profile_allows_ip_san_without_dns() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, None)
            .expect("root must be created");

        let cert = CertificateAuthority::issue_from_root(
            &root,
            IssueRequest {
                common_name: "internal-service".to_string(),
                profile: CertificateProfile::ServerTls,
                issuer: IssueIssuer::Root,
                dns_names: vec![],
                ip_sans: vec!["192.168.1.1".to_string()],
                validity_days: 90,
            },
            None,
        )
        .expect("server-tls must be issued with IP SAN");

        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn client_auth_profile_allows_empty_dns_san() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, None)
            .expect("root must be created");

        let cert = CertificateAuthority::issue_from_root(
            &root,
            IssueRequest {
                common_name: "device-123".to_string(),
                profile: CertificateProfile::ClientAuth,
                issuer: IssueIssuer::Root,
                dns_names: vec![],
                ip_sans: vec![],
                validity_days: 90,
            },
            None,
        )
        .expect("client auth cert must be issued without DNS SAN");

        assert_eq!(cert.profile, CertificateProfile::ClientAuth);
        assert!(cert.dns_names.is_empty());
    }

    #[test]
    fn intermediate_can_issue_and_chain_is_verifiable() {
        let root = CertificateAuthority::create_root("DigitCA Root", 365, Some("root-secret"))
            .expect("root must be created");
        let intermediate = CertificateAuthority::create_intermediate(
            &root,
            "DigitCA Intermediate",
            365,
            Some("root-secret"),
            Some("intermediate-secret"),
        )
        .expect("intermediate must be created");

        let leaf = CertificateAuthority::issue_from_intermediate(
            &intermediate,
            IssueRequest {
                common_name: "service.internal".to_string(),
                profile: CertificateProfile::ServerTls,
                issuer: IssueIssuer::Intermediate,
                dns_names: vec!["service.internal".to_string()],
                ip_sans: vec![],
                validity_days: 90,
            },
            Some("intermediate-secret"),
        )
        .expect("leaf must be issued by intermediate");

        let leaf_ok = CertificateAuthority::verify_signature(&leaf.cert_pem, &intermediate.cert_pem)
            .expect("leaf signature must be checked");
        let intermediate_ok =
            CertificateAuthority::verify_signature(&intermediate.cert_pem, &root.cert_pem)
                .expect("intermediate signature must be checked");

        assert!(leaf_ok);
        assert!(intermediate_ok);
        assert_eq!(leaf.issuer_kind, Some(IssuerKind::Intermediate));
        assert_eq!(leaf.issuer_serial.as_deref(), Some(intermediate.serial.as_str()));
    }
}
