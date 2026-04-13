use std::collections::HashSet;

use ldap3::{drive, LdapConnAsync, Mod};

use crate::{
    config::LdapConfig,
    error::{AppError, AppResult},
    models::{CertStatus, CertificateRecord},
};

/// Публікує метадані сертифікатів у LDAP-каталог.
///
/// Структура запису (ou=certificates,<base_dn>):
/// ```text
/// dn: cn=<serial>,ou=certificates,<base_dn>
/// objectClass: top
/// objectClass: device
/// cn:          <serial>
/// description: <common_name>
/// l:           active | revoked
/// owner:       <profile>
/// serialNumber: <not_after>
/// ```
#[derive(Clone)]
pub struct LdapPublisher {
    config: LdapConfig,
    enabled: bool,
}

impl LdapPublisher {
    pub fn new(config: LdapConfig, enabled: bool) -> Self {
        Self { config, enabled }
    }

    pub fn disabled() -> Self {
        Self {
            config: LdapConfig {
                url: String::new(),
                bind_dn: String::new(),
                bind_password: String::new(),
                base_dn: String::new(),
                user_attr: String::new(),
                required_group: None,
            },
            enabled: false,
        }
    }

    /// Публікує виданий сертифікат до LDAP-каталогу.
    pub async fn publish_certificate(&self, cert: &CertificateRecord) -> AppResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let (conn, mut ldap) = LdapConnAsync::new(&self.config.url)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?;
        drive!(conn);

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| AppError::Ldap(e.to_string()))?;

        self.ensure_certs_ou(&mut ldap).await?;

        let cert_dn = format!(
            "cn={},ou=certificates,{}",
            cert.serial, self.config.base_dn
        );
        let status = match cert.status {
            CertStatus::Active => "active",
            CertStatus::Revoked => "revoked",
        };
        let profile = format!("{:?}", cert.profile);
        let not_after = cert.not_after.to_rfc3339();

        let add_res = ldap
            .add(
                &cert_dn,
                vec![
                    ("objectClass", HashSet::from(["top", "device"])),
                    ("cn", HashSet::from([cert.serial.as_str()])),
                    ("description", HashSet::from([cert.common_name.as_str()])),
                    ("l", HashSet::from([status])),
                    ("owner", HashSet::from([profile.as_str()])),
                    ("serialNumber", HashSet::from([not_after.as_str()])),
                ],
            )
            .await;

        // rc == 68 → LDAP_ALREADY_EXISTS — замінюємо атрибути
        if matches!(add_res, Ok(ref r) if r.rc == 68) {
            ldap.modify(
                &cert_dn,
                vec![
                    Mod::Replace("description", HashSet::from([cert.common_name.as_str()])),
                    Mod::Replace("l", HashSet::from([status])),
                    Mod::Replace("owner", HashSet::from([profile.as_str()])),
                ],
            )
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?;
        }

        ldap.unbind().await.map_err(|e| AppError::Ldap(e.to_string()))?;
        Ok(())
    }

    /// Позначає сертифікат як revoked у LDAP-каталозі.
    pub async fn unpublish_certificate(&self, serial: &str) -> AppResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let (conn, mut ldap) = LdapConnAsync::new(&self.config.url)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?;
        drive!(conn);

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| AppError::Ldap(e.to_string()))?;

        let cert_dn = format!(
            "cn={},ou=certificates,{}",
            serial, self.config.base_dn
        );

        let _ = ldap
            .modify(&cert_dn, vec![Mod::Replace("l", HashSet::from(["revoked"]))])
            .await;

        ldap.unbind().await.map_err(|e| AppError::Ldap(e.to_string()))?;
        Ok(())
    }

    /// Шукає сертифікати в LDAP-каталозі за Common Name.
    pub async fn search_by_cn(&self, common_name: &str) -> AppResult<Vec<LdapCertEntry>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let (conn, mut ldap) = LdapConnAsync::new(&self.config.url)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?;
        drive!(conn);

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| AppError::Ldap(e.to_string()))?;

        let base = format!("ou=certificates,{}", self.config.base_dn);
        let filter = format!("(description={})", ldap_escape(common_name));

        let (entries, _res) = ldap
            .search(
                &base,
                ldap3::Scope::Subtree,
                &filter,
                vec!["cn", "description", "l", "owner", "serialNumber"],
            )
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| AppError::Ldap(e.to_string()))?;

        let results = entries
            .into_iter()
            .map(ldap3::SearchEntry::construct)
            .filter_map(|e| {
                let serial = e.attrs.get("cn")?.first()?.clone();
                let cn = e.attrs.get("description")?.first()?.clone();
                let status = e.attrs.get("l").and_then(|v| v.first()).cloned().unwrap_or_default();
                let profile = e.attrs.get("owner").and_then(|v| v.first()).cloned().unwrap_or_default();
                let not_after = e.attrs.get("serialNumber").and_then(|v| v.first()).cloned().unwrap_or_default();
                Some(LdapCertEntry { serial, common_name: cn, status, profile, not_after })
            })
            .collect();

        ldap.unbind().await.map_err(|e| AppError::Ldap(e.to_string()))?;
        Ok(results)
    }

    async fn ensure_certs_ou(&self, ldap: &mut ldap3::Ldap) -> AppResult<()> {
        let ou_dn = format!("ou=certificates,{}", self.config.base_dn);
        let _ = ldap
            .add(
                &ou_dn,
                vec![
                    ("objectClass", HashSet::from(["top", "organizationalUnit"])),
                    ("ou", HashSet::from(["certificates"])),
                ],
            )
            .await;
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LdapCertEntry {
    pub serial: String,
    pub common_name: String,
    pub status: String,
    pub profile: String,
    pub not_after: String,
}

fn ldap_escape(s: &str) -> String {
    s.replace('\\', "\\5C")
        .replace('*', "\\2A")
        .replace('(', "\\28")
        .replace(')', "\\29")
        .replace('\0', "\\00")
}



