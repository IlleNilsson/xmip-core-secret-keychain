#![forbid(unsafe_code)]

//! The macOS keychain as the key home's store (ADR-0063 clause 4).
//!
//! A key-encryption key is thirty-two random bytes kept as a generic
//! password item of the Service Identity's keychain: the service is the one
//! [`Keychain::new`] is given, `Xmip` by convention, and the account is the
//! key's name. The keychain encrypts it and hands it only to the identity
//! that owns it.
//!
//! [`Keychain`] is a [`secret::KekHolder`]; wrap it in [`secret::Held`] for a
//! [`secret::KeyStore`]. macOS only: on any other platform this crate is
//! empty.
//!
//! Built and checked for macOS targets only where a macOS toolchain is at
//! hand; the estate's machines run Windows and Linux, so its tests have
//! not run there (README).

#[cfg(target_os = "macos")]
use secret::{KekHolder, KekName, SecretError, Store};
#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};
#[cfg(target_os = "macos")]
use zeroize::Zeroizing;

/// `errSecItemNotFound`: the keychain has no such item.
#[cfg(target_os = "macos")]
const ITEM_NOT_FOUND: i32 = -25300;

/// Key-encryption keys as generic password items under one service.
#[cfg(target_os = "macos")]
pub struct Keychain {
    service: String,
}

#[cfg(target_os = "macos")]
impl Keychain {
    /// A store keeping its keys as items of `service` in the keychain of
    /// the identity this process runs as.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

#[cfg(target_os = "macos")]
impl KekHolder for Keychain {
    fn store(&self) -> Store {
        Store {
            technology: "keychain",
            place: format!("service {}", self.service),
        }
    }

    fn read(&self, name: &KekName) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        match get_generic_password(&self.service, name.as_str()) {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(SecretError::store(format!("keychain: {error}"))),
        }
    }

    fn create(&self, name: &KekName, material: &[u8]) -> Result<(), SecretError> {
        // set_generic_password replaces an item that exists, so the check
        // is made first: a key already there is never replaced (KekHolder).
        if self.read(name)?.is_some() {
            return Err(SecretError::store(format!(
                "keychain: '{name}' exists in service {}",
                self.service
            )));
        }
        set_generic_password(&self.service, name.as_str(), material)
            .map_err(|error| SecretError::store(format!("keychain: {error}")))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use secret::{DataKey, Held, KeyStore};

    fn name(text: &str) -> KekName {
        KekName::new(&format!("{text}-{}", std::process::id())).expect("name")
    }

    #[test]
    fn a_key_wraps_and_unwraps_through_the_keychain() {
        let store = Held::new(Keychain::new("Xmip test"));
        let kek = name("round");
        let key = DataKey::generate().expect("key");
        let wrapped = store.wrap(&kek, &key).expect("wrapped");
        let back = store.unwrap(&kek, &wrapped).expect("unwrapped");
        let sealed = key.seal(b"a", b"payload").expect("sealed");
        assert_eq!(back.open(b"a", &sealed).expect("opened"), b"payload");
    }

    #[test]
    fn a_missing_key_is_refused_by_name() {
        let store = Held::new(Keychain::new("Xmip test"));
        assert!(matches!(
            store.unwrap(&name("absent"), &[0; 60]),
            Err(SecretError::MissingKek { .. })
        ));
    }
}
