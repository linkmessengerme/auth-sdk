use std::fmt;
use zeroize::Zeroizing;

/// A secret that is redacted in Debug and erased on drop where Rust owns its buffer.
/// Explicit exposure and FFI create copies; callers must protect those copies too.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self::new(self.expose_secret().to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Only private journal DTOs opt in to serialization. Public secret wrappers do
// not implement Serialize, so ordinary diagnostic serialization stays explicit.
pub(crate) mod serialized {
    use super::SecretString;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &SecretString,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.expose_secret())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretString, D::Error> {
        String::deserialize(deserializer).map(SecretString::new)
    }
}
