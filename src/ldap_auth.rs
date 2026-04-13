use async_trait::async_trait;
use ldap3::{drive, LdapConnAsync, Scope, SearchEntry};

use crate::{
    config::LdapConfig,
    error::{AppError, AppResult},
};

#[derive(Clone)]
pub struct LdapAuthorizer {
    config: LdapConfig,
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize(&self, username: &str, password: &str) -> AppResult<()>;
}

impl LdapAuthorizer {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Authorizer for LdapAuthorizer {
    async fn authorize(&self, username: &str, password: &str) -> AppResult<()> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.config.url)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?;
        drive!(conn);

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| AppError::Ldap(e.to_string()))?;

        let filter = format!("({}={})", self.config.user_attr, username);
        let (entries, _res) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                vec!["dn", "memberOf"],
            )
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| AppError::Ldap(e.to_string()))?;

        let Some(entry) = entries.first() else {
            return Err(AppError::AccessDenied);
        };

        let user_entry = SearchEntry::construct(entry.clone());
        ldap.simple_bind(&user_entry.dn, password)
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?
            .success()
            .map_err(|_| AppError::AccessDenied)?;

        if let Some(required_group) = &self.config.required_group {
            let direct_member_of = user_entry
                .attrs
                .get("memberOf")
                .map(|groups| groups.iter().any(|g| g.eq_ignore_ascii_case(required_group)))
                .unwrap_or(false);

            let in_group = if direct_member_of {
                true
            } else {
                let (group_entries, _res) = ldap
                    .search(
                        required_group,
                        Scope::Base,
                        "(objectClass=*)",
                        vec!["member", "uniqueMember", "memberUid"],
                    )
                    .await
                    .map_err(|e| AppError::Ldap(e.to_string()))?
                    .success()
                    .map_err(|e| AppError::Ldap(e.to_string()))?;

                group_entries
                    .first()
                    .cloned()
                    .map(SearchEntry::construct)
                    .map_or(false, |group| {
                    let user_dn_matches = ["member", "uniqueMember"].iter().any(|attr| {
                        group
                            .attrs
                            .get(*attr)
                            .map(|values: &Vec<String>| {
                                values
                                    .iter()
                                    .any(|value: &String| value.eq_ignore_ascii_case(&user_entry.dn))
                            })
                            .unwrap_or(false)
                    });
                    let user_uid_matches = group
                        .attrs
                        .get("memberUid")
                        .map(|values: &Vec<String>| values.iter().any(|value: &String| value == username))
                        .unwrap_or(false);

                    user_dn_matches || user_uid_matches
                })
            };

            if !in_group {
                return Err(AppError::AccessDenied);
            }
        }

        ldap.unbind()
            .await
            .map_err(|e| AppError::Ldap(e.to_string()))?;
        Ok(())
    }
}
