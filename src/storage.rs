use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{
    bson::{doc, from_document, to_document, Document},
    options::{ClientOptions, FindOptions, ReplaceOptions},
    Client, Collection, Database,
};

use crate::{
    error::{AppError, AppResult},
    models::{AuditEvent, CertificateRecord, IntermediateCaRecord, RevocationRecord, RootCaRecord},
};

pub struct MongoStorage {
    db: Database,
}

impl Clone for MongoStorage {
    fn clone(&self) -> Self {
        Self { db: self.db.clone() }
    }
}

#[async_trait]
pub trait CaRepository: Send + Sync {
    async fn upsert_root(&self, root: &RootCaRecord) -> AppResult<()>;
    async fn get_root(&self) -> AppResult<Option<RootCaRecord>>;
    async fn upsert_intermediate(&self, intermediate: &IntermediateCaRecord) -> AppResult<()>;
    async fn get_intermediate(&self) -> AppResult<Option<IntermediateCaRecord>>;
    async fn insert_certificate(&self, cert: &CertificateRecord) -> AppResult<()>;
    async fn get_certificate(&self, serial: &str) -> AppResult<Option<CertificateRecord>>;
    async fn list_certificates(&self, include_revoked: bool) -> AppResult<Vec<CertificateRecord>>;
    async fn revoke_certificate(&self, serial: &str, reason: &str) -> AppResult<()>;
    async fn is_revoked(&self, serial: &str) -> AppResult<bool>;
    async fn list_revocations(&self) -> AppResult<Vec<RevocationRecord>>;
    async fn insert_audit(&self, event: &AuditEvent) -> AppResult<()>;
    async fn list_audit(&self, limit: u32) -> AppResult<Vec<AuditEvent>>;
}

#[derive(Clone, Default)]
pub struct InMemoryStorage {
    root: Arc<Mutex<Option<RootCaRecord>>>,
    intermediate: Arc<Mutex<Option<IntermediateCaRecord>>>,
    certificates: Arc<Mutex<HashMap<String, CertificateRecord>>>,
    revocations: Arc<Mutex<HashMap<String, RevocationRecord>>>,
    audit: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MongoStorage {
    pub async fn connect(uri: &str, db_name: &str) -> AppResult<Self> {
        let mut options = ClientOptions::parse(uri)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        options.app_name = Some("DigitCA".to_string());

        let client = Client::with_options(options).map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(Self {
            db: client.database(db_name),
        })
    }

    fn raw_collection(&self, name: &str) -> Collection<Document> {
        self.db.collection(name)
    }
}

#[async_trait]
impl CaRepository for MongoStorage {
    async fn upsert_root(&self, root: &RootCaRecord) -> AppResult<()> {
        let coll = self.raw_collection("ca_root");
        let mut doc = to_document(root).map_err(|e| AppError::Storage(e.to_string()))?;
        doc.insert("_id", "default");

        coll.replace_one(
            doc! {"_id": "default"},
            doc,
            ReplaceOptions::builder().upsert(true).build(),
        )
        .await
        .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_root(&self) -> AppResult<Option<RootCaRecord>> {
        let coll = self.raw_collection("ca_root");
        let doc = coll
            .find_one(doc! {"_id": "default"}, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        match doc {
            Some(d) => {
                let mut cleaned = d;
                cleaned.remove("_id");
                let root = from_document(cleaned).map_err(|e| AppError::Storage(e.to_string()))?;
                Ok(Some(root))
            }
            None => Ok(None),
        }
    }

    async fn upsert_intermediate(&self, intermediate: &IntermediateCaRecord) -> AppResult<()> {
        let coll = self.raw_collection("ca_intermediate");
        let mut doc = to_document(intermediate).map_err(|e| AppError::Storage(e.to_string()))?;
        doc.insert("_id", "default");

        coll.replace_one(
            doc! {"_id": "default"},
            doc,
            ReplaceOptions::builder().upsert(true).build(),
        )
        .await
        .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_intermediate(&self) -> AppResult<Option<IntermediateCaRecord>> {
        let coll = self.raw_collection("ca_intermediate");
        let doc = coll
            .find_one(doc! {"_id": "default"}, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        match doc {
            Some(d) => {
                let mut cleaned = d;
                cleaned.remove("_id");
                let intermediate = from_document(cleaned).map_err(|e| AppError::Storage(e.to_string()))?;
                Ok(Some(intermediate))
            }
            None => Ok(None),
        }
    }

    async fn insert_certificate(&self, cert: &CertificateRecord) -> AppResult<()> {
        let coll = self.raw_collection("certificates");
        let mut doc = to_document(cert).map_err(|e| AppError::Storage(e.to_string()))?;
        doc.insert("_id", cert.serial.clone());
        coll.insert_one(doc, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_certificate(&self, serial: &str) -> AppResult<Option<CertificateRecord>> {
        let coll = self.raw_collection("certificates");
        let doc = coll
            .find_one(doc! {"_id": serial}, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        match doc {
            Some(d) => {
                let mut cleaned = d;
                cleaned.remove("_id");
                let cert = from_document(cleaned).map_err(|e| AppError::Storage(e.to_string()))?;
                Ok(Some(cert))
            }
            None => Ok(None),
        }
    }

    async fn list_certificates(&self, include_revoked: bool) -> AppResult<Vec<CertificateRecord>> {
        let coll = self.raw_collection("certificates");
        let filter = if include_revoked {
            doc! {}
        } else {
            doc! {"status": "active"}
        };

        let mut cursor = coll
            .find(filter, FindOptions::builder().sort(doc! {"issued_at": -1}).build())
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await.map_err(|e| AppError::Storage(e.to_string()))? {
            let mut cleaned = doc;
            cleaned.remove("_id");
            out.push(from_document(cleaned).map_err(|e| AppError::Storage(e.to_string()))?);
        }
        Ok(out)
    }

    async fn revoke_certificate(&self, serial: &str, reason: &str) -> AppResult<()> {
        let cert_coll = self.raw_collection("certificates");
        let rev_coll = self.raw_collection("revocations");

        let update = doc! {
            "$set": {
                "status": "revoked",
            }
        };
        cert_coll
            .update_one(doc! {"_id": serial}, update, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let rev = RevocationRecord {
            serial: serial.to_string(),
            reason: reason.to_string(),
            revoked_at: Utc::now(),
        };
        let mut doc = to_document(&rev).map_err(|e| AppError::Storage(e.to_string()))?;
        doc.insert("_id", serial.to_string());
        rev_coll
            .replace_one(
                doc! {"_id": serial},
                doc,
                ReplaceOptions::builder().upsert(true).build(),
            )
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn is_revoked(&self, serial: &str) -> AppResult<bool> {
        let coll = self.raw_collection("revocations");
        let found = coll
            .find_one(doc! {"_id": serial}, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(found.is_some())
    }

    async fn list_revocations(&self) -> AppResult<Vec<RevocationRecord>> {
        let coll = self.raw_collection("revocations");
        let mut cursor = coll
            .find(doc! {}, FindOptions::builder().sort(doc! {"revoked_at": -1}).build())
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await.map_err(|e| AppError::Storage(e.to_string()))? {
            let mut cleaned = doc;
            cleaned.remove("_id");
            out.push(from_document(cleaned).map_err(|e| AppError::Storage(e.to_string()))?);
        }
        Ok(out)
    }

    async fn insert_audit(&self, event: &AuditEvent) -> AppResult<()> {
        let coll = self.raw_collection("audit_log");
        let mut doc = to_document(event).map_err(|e| AppError::Storage(e.to_string()))?;
        doc.insert("_id", event.id.clone());
        coll.insert_one(doc, None)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_audit(&self, limit: u32) -> AppResult<Vec<AuditEvent>> {
        let coll = self.raw_collection("audit_log");
        let options = FindOptions::builder()
            .sort(doc! {"occurred_at": -1})
            .limit(limit as i64)
            .build();

        let mut cursor = coll
            .find(doc! {}, options)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await.map_err(|e| AppError::Storage(e.to_string()))? {
            let mut cleaned = doc;
            cleaned.remove("_id");
            out.push(from_document(cleaned).map_err(|e| AppError::Storage(e.to_string()))?);
        }
        Ok(out)
    }
}

#[async_trait]
impl CaRepository for InMemoryStorage {
    async fn upsert_root(&self, root: &RootCaRecord) -> AppResult<()> {
        *self.root.lock().expect("root mutex poisoned") = Some(root.clone());
        Ok(())
    }

    async fn get_root(&self) -> AppResult<Option<RootCaRecord>> {
        Ok(self.root.lock().expect("root mutex poisoned").clone())
    }

    async fn upsert_intermediate(&self, intermediate: &IntermediateCaRecord) -> AppResult<()> {
        *self
            .intermediate
            .lock()
            .expect("intermediate mutex poisoned") = Some(intermediate.clone());
        Ok(())
    }

    async fn get_intermediate(&self) -> AppResult<Option<IntermediateCaRecord>> {
        Ok(self
            .intermediate
            .lock()
            .expect("intermediate mutex poisoned")
            .clone())
    }

    async fn insert_certificate(&self, cert: &CertificateRecord) -> AppResult<()> {
        self.certificates
            .lock()
            .expect("certificates mutex poisoned")
            .insert(cert.serial.clone(), cert.clone());
        Ok(())
    }

    async fn get_certificate(&self, serial: &str) -> AppResult<Option<CertificateRecord>> {
        Ok(self
            .certificates
            .lock()
            .expect("certificates mutex poisoned")
            .get(serial)
            .cloned())
    }

    async fn list_certificates(&self, include_revoked: bool) -> AppResult<Vec<CertificateRecord>> {
        let mut values: Vec<_> = self
            .certificates
            .lock()
            .expect("certificates mutex poisoned")
            .values()
            .filter(|cert| include_revoked || cert.status == crate::models::CertStatus::Active)
            .cloned()
            .collect();
        values.sort_by(|left, right| right.issued_at.cmp(&left.issued_at));
        Ok(values)
    }

    async fn revoke_certificate(&self, serial: &str, reason: &str) -> AppResult<()> {
        let mut certificates = self
            .certificates
            .lock()
            .expect("certificates mutex poisoned");
        let cert = certificates
            .get_mut(serial)
            .ok_or_else(|| AppError::NotFound(serial.to_string()))?;
        cert.status = crate::models::CertStatus::Revoked;

        self.revocations
            .lock()
            .expect("revocations mutex poisoned")
            .insert(
                serial.to_string(),
                RevocationRecord {
                    serial: serial.to_string(),
                    reason: reason.to_string(),
                    revoked_at: Utc::now(),
                },
            );
        Ok(())
    }

    async fn is_revoked(&self, serial: &str) -> AppResult<bool> {
        Ok(self
            .revocations
            .lock()
            .expect("revocations mutex poisoned")
            .contains_key(serial))
    }

    async fn list_revocations(&self) -> AppResult<Vec<RevocationRecord>> {
        Ok(self
            .revocations
            .lock()
            .expect("revocations mutex poisoned")
            .values()
            .cloned()
            .collect())
    }

    async fn insert_audit(&self, event: &AuditEvent) -> AppResult<()> {
        self.audit
            .lock()
            .expect("audit mutex poisoned")
            .push(event.clone());
        Ok(())
    }

    async fn list_audit(&self, limit: u32) -> AppResult<Vec<AuditEvent>> {
        let log = self.audit.lock().expect("audit mutex poisoned");
        let mut events: Vec<AuditEvent> = log.iter().cloned().collect();
        events.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        events.truncate(limit as usize);
        Ok(events)
    }
}

// ── Делегування для Box<dyn CaRepository> ────────────────────────────────────

#[async_trait]
impl CaRepository for Box<dyn CaRepository + Send + Sync> {
    async fn upsert_root(&self, root: &RootCaRecord) -> AppResult<()> {
        (**self).upsert_root(root).await
    }
    async fn get_root(&self) -> AppResult<Option<RootCaRecord>> {
        (**self).get_root().await
    }
    async fn upsert_intermediate(&self, intermediate: &IntermediateCaRecord) -> AppResult<()> {
        (**self).upsert_intermediate(intermediate).await
    }
    async fn get_intermediate(&self) -> AppResult<Option<IntermediateCaRecord>> {
        (**self).get_intermediate().await
    }
    async fn insert_certificate(&self, cert: &CertificateRecord) -> AppResult<()> {
        (**self).insert_certificate(cert).await
    }
    async fn get_certificate(&self, serial: &str) -> AppResult<Option<CertificateRecord>> {
        (**self).get_certificate(serial).await
    }
    async fn list_certificates(&self, include_revoked: bool) -> AppResult<Vec<CertificateRecord>> {
        (**self).list_certificates(include_revoked).await
    }
    async fn revoke_certificate(&self, serial: &str, reason: &str) -> AppResult<()> {
        (**self).revoke_certificate(serial, reason).await
    }
    async fn is_revoked(&self, serial: &str) -> AppResult<bool> {
        (**self).is_revoked(serial).await
    }
    async fn list_revocations(&self) -> AppResult<Vec<RevocationRecord>> {
        (**self).list_revocations().await
    }
    async fn insert_audit(&self, event: &AuditEvent) -> AppResult<()> {
        (**self).insert_audit(event).await
    }
    async fn list_audit(&self, limit: u32) -> AppResult<Vec<AuditEvent>> {
        (**self).list_audit(limit).await
    }
}


