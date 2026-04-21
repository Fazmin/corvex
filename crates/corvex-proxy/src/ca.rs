//! Self-signed certificate authority for HTTPS interception.
//!
//! On first start we generate a P-256 EC CA, persist the cert and key
//! to disk under the Tauri `app_data_dir`, and present the user with
//! an "Export CA" action so they can install it into their OS / browser
//! trust store. On every subsequent start we load the existing CA from
//! disk — users install the CA once per machine.
//!
//! During TLS interception the proxy mints a leaf certificate per SNI
//! value, signs it with the CA key, and hands it to the `SslAcceptor`.
//! Leaves are cached in a small LRU so each host only pays the cost
//! once per session.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lru::LruCache;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Name, X509NameBuilder, X509};

/// CA-related configuration; today just filesystem layout.
#[derive(Debug, Clone)]
pub struct CaConfig {
    pub dir: PathBuf,
    pub common_name: String,
    pub organization: String,
    pub leaf_validity_days: u32,
    pub leaf_cache_capacity: usize,
}

impl CaConfig {
    pub fn for_dir<P: Into<PathBuf>>(dir: P) -> Self {
        Self {
            dir: dir.into(),
            common_name: "Corvex Local CA".to_string(),
            organization: "Corvex".to_string(),
            leaf_validity_days: 90,
            leaf_cache_capacity: 512,
        }
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("ca.key")
    }
}

/// Loaded CA material plus an in-memory cache of per-host leaves.
pub struct Authority {
    config: CaConfig,
    cert: X509,
    key: PKey<Private>,
    leaves: Mutex<LruCache<String, LeafMaterial>>,
}

/// Minted leaf certificate + matching private key for a single SNI host.
#[derive(Clone)]
pub struct LeafMaterial {
    pub cert: X509,
    pub key: PKey<Private>,
}

impl Authority {
    /// Load the CA from disk, generating it if missing. Safe to call
    /// repeatedly — subsequent calls reuse the on-disk material.
    pub fn load_or_generate(config: CaConfig) -> anyhow::Result<Self> {
        fs::create_dir_all(&config.dir)?;
        let cert_path = config.cert_path();
        let key_path = config.key_path();

        let (cert, key) = if cert_path.exists() && key_path.exists() {
            load_existing(&cert_path, &key_path)?
        } else {
            let (cert, key) = generate_ca(&config)?;
            persist(&cert_path, &key_path, &cert, &key)?;
            (cert, key)
        };

        let capacity =
            std::num::NonZeroUsize::new(config.leaf_cache_capacity.max(16)).expect("cap");
        Ok(Self {
            config,
            cert,
            key,
            leaves: Mutex::new(LruCache::new(capacity)),
        })
    }

    pub fn is_initialised(&self) -> bool {
        self.config.cert_path().exists() && self.config.key_path().exists()
    }

    /// Lightweight sanity check before starting the listener. The
    /// current implementation always succeeds once [`load_or_generate`]
    /// has run; the method exists so callers don't have to know.
    pub fn ensure_ready(&self) -> anyhow::Result<()> {
        if !self.is_initialised() {
            anyhow::bail!("CA material missing from disk");
        }
        Ok(())
    }

    pub fn cert_pem(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.cert.to_pem()?)
    }

    pub fn cert_path(&self) -> PathBuf {
        self.config.cert_path()
    }

    /// Return (minting on cache miss) a leaf certificate for the given
    /// SNI hostname.
    pub fn leaf_for(&self, sni: &str) -> anyhow::Result<LeafMaterial> {
        let key = sni.to_ascii_lowercase();
        {
            let mut cache = self.leaves.lock().expect("leaf cache poisoned");
            if let Some(existing) = cache.get(&key) {
                return Ok(existing.clone());
            }
        }
        let minted = self.mint_leaf(&key)?;
        let mut cache = self.leaves.lock().expect("leaf cache poisoned");
        cache.put(key, minted.clone());
        Ok(minted)
    }

    fn mint_leaf(&self, sni: &str) -> anyhow::Result<LeafMaterial> {
        let leaf_key = ec_p256_key()?;
        let subject = name_builder(sni, &self.config.organization)?;

        let mut builder = X509::builder()?;
        builder.set_version(2)?; // v3
        builder.set_subject_name(&subject)?;
        builder.set_issuer_name(self.cert.subject_name())?;
        builder.set_pubkey(&leaf_key)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(self.config.leaf_validity_days)?;
        let serial = random_serial()?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        builder.set_serial_number(&serial)?;

        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
        let ctx = builder.x509v3_context(Some(&self.cert), None);
        let san = SubjectAlternativeName::new().dns(sni).build(&ctx)?;
        builder.append_extension(san)?;

        let ctx = builder.x509v3_context(Some(&self.cert), None);
        let ski = SubjectKeyIdentifier::new().build(&ctx)?;
        builder.append_extension(ski)?;

        let ctx = builder.x509v3_context(Some(&self.cert), None);
        let aki = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&ctx)?;
        builder.append_extension(aki)?;

        builder.sign(&self.key, MessageDigest::sha256())?;

        Ok(LeafMaterial {
            cert: builder.build(),
            key: leaf_key,
        })
    }
}

fn load_existing(cert_path: &Path, key_path: &Path) -> anyhow::Result<(X509, PKey<Private>)> {
    let cert_pem = fs::read(cert_path)?;
    let cert = X509::from_pem(&cert_pem)?;
    let key_pem = fs::read(key_path)?;
    let key = PKey::private_key_from_pem(&key_pem)?;
    Ok((cert, key))
}

fn persist(
    cert_path: &Path,
    key_path: &Path,
    cert: &X509,
    key: &PKey<Private>,
) -> anyhow::Result<()> {
    fs::write(cert_path, cert.to_pem()?)?;
    fs::write(key_path, key.private_key_to_pem_pkcs8()?)?;
    // Tighten the key permissions where the platform honours them.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(key_path)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(key_path, perm)?;
    }
    Ok(())
}

fn generate_ca(config: &CaConfig) -> anyhow::Result<(X509, PKey<Private>)> {
    let key = ec_p256_key()?;
    let subject = name_builder(&config.common_name, &config.organization)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    builder.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365 * 10)?;
    let serial = random_serial()?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_serial_number(&serial)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    let ctx = builder.x509v3_context(None, None);
    builder.append_extension(SubjectKeyIdentifier::new().build(&ctx)?)?;

    builder.sign(&key, MessageDigest::sha256())?;
    Ok((builder.build(), key))
}

fn ec_p256_key() -> anyhow::Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;
    Ok(PKey::from_ec_key(key)?)
}

fn name_builder(cn: &str, org: &str) -> anyhow::Result<X509Name> {
    let mut builder = X509NameBuilder::new()?;
    builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, org)?;
    Ok(builder.build())
}

fn random_serial() -> anyhow::Result<Asn1Integer> {
    let mut serial = BigNum::new()?;
    // 159 bits keeps the MSB clear so the serial is unambiguously
    // positive once DER-encoded as a two's-complement integer.
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    Ok(serial.to_asn1_integer()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_persistent_ca_material() {
        let tmp = tempdir_path();
        let config = CaConfig::for_dir(&tmp);

        let first = Authority::load_or_generate(config.clone()).expect("first gen");
        assert!(first.cert_path().exists());

        let second = Authority::load_or_generate(config).expect("reload");
        assert_eq!(first.cert.to_pem().unwrap(), second.cert.to_pem().unwrap());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mints_per_host_leaf() {
        let tmp = tempdir_path();
        let authority =
            Authority::load_or_generate(CaConfig::for_dir(&tmp)).expect("init authority");
        let first = authority.leaf_for("example.com").expect("mint 1");
        let second = authority.leaf_for("example.com").expect("mint 2");
        // Cached hit returns the same material.
        assert_eq!(
            first.cert.to_pem().unwrap(),
            second.cert.to_pem().unwrap()
        );

        let other = authority.leaf_for("another.example").expect("mint 3");
        assert_ne!(
            first.cert.to_pem().unwrap(),
            other.cert.to_pem().unwrap()
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn tempdir_path() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "corvex-proxy-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
