//! TLS material for the embedded relay: cert-manager PEM files in production,
//! a generated self-signed certificate for local development.

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow};
use iroh::tls::CaTlsConfig;
use iroh_relay::server::{CertConfig, DEFAULT_CERT_RELOAD_INTERVAL, reloading_resolver};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};

fn server_config_builder()
-> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>> {
    Ok(rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth())
}

/// Certificate + key PEM files, re-read periodically so cert-manager renewals
/// apply without a restart.
pub async fn reloading_cert(cert_path: &Path, key_path: &Path) -> Result<CertConfig> {
    let builder = server_config_builder()?;
    let resolver = reloading_resolver(
        builder.crypto_provider(),
        cert_path.to_path_buf(),
        key_path.to_path_buf(),
        DEFAULT_CERT_RELOAD_INTERVAL,
    )
    .await
    .map_err(|err| anyhow!("loading TLS certificate: {err:?}"))?;
    Ok(CertConfig::Manual {
        server_config: builder.with_cert_resolver(resolver),
    })
}

/// A freshly generated self-signed certificate. Clients must trust
/// [`DevCert::ca`] explicitly.
pub struct DevCert {
    pub cert: CertificateDer<'static>,
    pub cert_pem: String,
    key: PrivateKeyDer<'static>,
}

impl DevCert {
    /// Valid for `localhost`, `127.0.0.1`, `::1` and any extra `hosts`.
    pub fn generate(hosts: &[String]) -> Result<Self> {
        let mut names = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        names.extend(hosts.iter().cloned());
        let generated = rcgen::generate_simple_self_signed(names)?;
        let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        Ok(Self {
            cert: generated.cert.der().clone(),
            cert_pem: generated.cert.pem(),
            key: PrivateKeyDer::from(key),
        })
    }

    pub fn cert_config(&self) -> Result<CertConfig> {
        let server_config = server_config_builder()?
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())?;
        Ok(CertConfig::Manual { server_config })
    }

    pub fn ca(&self) -> CaTlsConfig {
        CaTlsConfig::custom_roots([self.cert.clone()])
    }
}

/// Trust anchors for reaching a relay whose certificate is not publicly
/// trusted, e.g. a `kt-sfu --dev` instance.
pub fn ca_from_pem_file(path: &Path) -> Result<CaTlsConfig> {
    let roots = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(CaTlsConfig::custom_roots(roots))
}
