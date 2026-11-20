use crate::SecretString;

/// Opaque, secret journal payload. Revision is a random compare-and-swap token.
/// Native implementations must not log or stringify the payload.
pub struct StoredEntry {
    pub revision: String,
    pub payload: SecretString,
}

impl StoredEntry {
    pub fn new(revision: String, payload: String) -> Self {
        Self {
            revision,
            payload: SecretString::new(payload),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("secure storage operation failed")]
pub struct StorageError;

/// Implement using integrity-protected, non-backed-up platform storage.
/// compare_exchange must atomically compare the current revision and durably
/// replace/delete the whole entry. Return only after persistence completes.
/// Failure must never be reported as success; absence is distinct from failure.
/// Calls are short synchronous transactions; native facades should call the SDK
/// off the main/UI thread. All instances sharing a key must share the CAS lock.
pub trait SecureStore: Send + Sync {
    fn load(&self, key: &str) -> Result<Option<StoredEntry>, StorageError>;
    fn compare_exchange(
        &self,
        key: &str,
        expected_revision: Option<&str>,
        replacement: Option<StoredEntry>,
    ) -> Result<bool, StorageError>;
}
