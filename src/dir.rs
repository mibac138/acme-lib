use std::sync::Arc;

use crate::acc::AcmeKey;
use crate::api::{ApiAccount, ApiDirectory};
use crate::persist::{Persist, PersistKey, PersistKind};
use crate::req::{req_expect_header, req_get, req_handle_error};
use crate::trans::{NoncePool, Transport};
use crate::util::read_json;
use crate::{Account, Result};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Entry point for accessing an ACME API.
#[derive(Clone)]
pub struct Directory<P: Persist> {
    persist: P,
    nonce_pool: Arc<NoncePool>,
    api_directory: ApiDirectory,
}

impl<P: Persist> Directory<P> {
    /// Create a directory over a persistence implementation and directory url.
    pub fn from_url(persist: P, url: &str) -> Result<Directory<P>> {
        let res = req_handle_error(req_get(&url))?;
        let api_directory: ApiDirectory = read_json(res)?;
        let nonce_pool = Arc::new(NoncePool::new(&api_directory.newNonce));
        Ok(Directory {
            persist,
            nonce_pool,
            api_directory,
        })
    }

    pub fn lets_encrypt(persist: P) -> Result<Directory<P>> {
        Self::from_url(persist, LETS_ENCRYPT)
    }

    pub fn lets_encrypt_staging(persist: P) -> Result<Directory<P>> {
        Self::from_url(persist, LETS_ENCRYPT_STAGING)
    }

    /// Access an account identified by a contact email.
    ///
    /// If a persisted private key exists for the contact email, it will be read
    /// and used for further access. This way we reuse the same ACME API account.
    ///
    /// If one doesn't exist, it is created and the corresponding public key is
    /// uploaded to the ACME API thus creating the account.
    ///
    /// Either way the `newAccount` API endpoint is called and thereby ensures the
    /// account is active and working.
    ///
    /// This is the same as calling
    /// `account_with_realm(contact_email, ["mailto: <contact_email>"]`)
    pub fn account(&self, contact_email: &str) -> Result<Account<P>> {
        // Contact email is the persistence realm when using this method.
        let contact = vec![format!("mailto:{}", contact_email)];
        self.account_with_realm(contact_email, contact)
    }

    /// Access an account using a lower level method. The contact is optional
    /// against the ACME API provider and there might be situations where you
    /// either don't need it at all, or need it to be something else than
    /// an email address.
    ///
    /// The `realm` parameter is a persistence realm, i.e. a namespace in the
    /// persistence where all values belonging to this Account will be stored.
    ///
    /// If a persisted private key exists for the `realm`, it will be read
    /// and used for further access. This way we reuse the same ACME API account.
    ///
    /// If one doesn't exist, it is created and the corresponding public key is
    /// uploaded to the ACME API thus creating the account.
    ///
    /// Either way the `newAccount` API endpoint is called and thereby ensures the
    /// account is active and working.
    pub fn account_with_realm(&self, realm: &str, contact: Vec<String>) -> Result<Account<P>> {
        // key in persistence for acme account private key
        let pem_key = PersistKey::new(realm, PersistKind::AccountPrivateKey, "acme_account");

        // Get the key from a saved PEM, or from creating a new
        let mut is_new = false;
        let pem = self.persist().get(&pem_key)?;
        let acme_key = if let Some(pem) = pem {
            // we got a persisted private key. read it.
            debug!("Read persisted acme account key");
            AcmeKey::from_pem(&pem)?
        } else {
            // create a new key (and new account)
            debug!("Create new acme account key");
            is_new = true;
            AcmeKey::new()
        };

        // Prepare making a call to newAccount. This is fine to do both for
        // new keys and existing. For existing the spec says to return a 200
        // with the Location header set to the key id (kid).
        let acc = ApiAccount {
            contact,
            termsOfServiceAgreed: Some(true),
            ..Default::default()
        };

        let mut transport = Transport::new(&self.nonce_pool, acme_key);
        let res = transport.call_jwk(&self.api_directory.newAccount, &acc)?;
        let kid = req_expect_header(&res, "location")?;
        debug!("Key id is: {}", kid);
        let api_account: ApiAccount = read_json(res)?;

        // fill in the server returned key id
        transport.set_key_id(kid);

        // If we did create a new key, save it back to the persistence.
        if is_new {
            debug!("Persist acme account key");
            let pem = transport.acme_key().to_pem();
            self.persist().put(&pem_key, &pem)?;
        }

        // The finished account
        Ok(Account::new(
            self.persist.clone(),
            transport,
            realm,
            api_account,
            self.api_directory.clone(),
        ))
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_directory(&self) -> &ApiDirectory {
        &self.api_directory
    }

    pub(crate) fn persist(&self) -> &P {
        &self.persist
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::persist::*;
    #[test]
    fn test_create_directory() -> Result<()> {
        let server = crate::test::with_directory_server();
        let persist = MemoryPersist::new();
        let _ = Directory::from_url(persist, &server.dir_url)?;
        Ok(())
    }

    #[test]
    fn test_create_acount() -> Result<()> {
        let server = crate::test::with_directory_server();
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, &server.dir_url)?;
        let _ = dir.account("foo@bar.com")?;
        Ok(())
    }

    #[test]
    fn test_persisted_acount() -> Result<()> {
        let server = crate::test::with_directory_server();
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, &server.dir_url)?;
        let acc1 = dir.account("foo@bar.com")?;
        let acc2 = dir.account("foo@bar.com")?;
        let acc3 = dir.account("karlfoo@bar.com")?;
        assert_eq!(acc1.acme_private_key_pem(), acc2.acme_private_key_pem());
        assert!(acc1.acme_private_key_pem() != acc3.acme_private_key_pem());
        Ok(())
    }

    // #[test]
    // fn test_the_whole_hog() -> Result<()> {
    //     std::env::set_var("RUST_LOG", "acme_lib=trace");
    //     let _ = env_logger::try_init();

    //     use crate::cert::create_p384_key;

    //     let url = DirectoryUrl::LetsEncryptStaging;
    //     let persist = FilePersist::new(".");
    //     let dir = Directory::from_url(persist, url)?;
    //     let acc = dir.account("foo@bar.com")?;

    //     let mut ord = acc.new_order("myspecialsite.com", &[])?;

    //     let ord = loop {
    //         if let Some(ord) = ord.confirm_validations() {
    //             break ord;
    //         }

    //         let auths = ord.authorizations()?;
    //         let chall = auths[0].dns_challenge();

    //         info!("Proof: {}", chall.dns_proof());

    //         use std::thread;
    //         use std::time::Duration;
    //         thread::sleep(Duration::from_millis(60_000));

    //         chall.validate(5000)?;

    //         ord.refresh()?;
    //     };

    //     let (pkey_pri, pkey_pub) = create_p384_key();

    //     let ord = ord.finalize_pkey(pkey_pri, pkey_pub, 5000)?;

    //     let cert = ord.download_and_save_cert()?;
    //     println!(
    //         "{}{}{}",
    //         cert.private_key(),
    //         cert.certificate(),
    //         cert.valid_days_left()
    //     );
    //     Ok(())
    // }
}
