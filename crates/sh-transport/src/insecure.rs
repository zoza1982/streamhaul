//! **LAN LAB ONLY — NEVER USE IN PRODUCTION.**
//!
//! Helpers that generate self-signed certificates and skip TLS verification.
//! These are intentionally insecure and must never be used outside a controlled
//! loopback / LAN test environment.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::error::TransportError;

/// Witness that the caller has acknowledged the LAN-lab-only, no-TLS-verification posture.
///
/// [`insecure_client_config`] and [`self_signed_server_config`] require one so every use of the
/// insecure path is explicit and greppable at the call site (you cannot reach it by autocomplete
/// alone). It carries no data and exists purely as a speed bump.
#[derive(Debug, Clone, Copy)]
pub struct InsecureLanLab(());

impl InsecureLanLab {
    /// Acknowledge that the resulting config **skips TLS certificate verification** and is for a
    /// controlled LAN lab only — never production.
    #[must_use]
    pub fn i_understand_this_skips_tls_verification() -> Self {
        Self(())
    }
}

/// Returns a [`quinn::TransportConfig`] tuned for LAN-lab loopback testing.
///
/// Settings applied:
/// - `datagram_receive_buffer_size(Some(64 * 1024 * 1024))` — 64 MiB receive buffer.
///   Budget: 120 frames × ~192 fragments × ~1162 bytes ≈ 27 MiB; this is 2× headroom.
/// - `max_idle_timeout(Some(300 s))` — 5 minutes, so a bulk datagram transfer subject
///   to QUIC congestion-window backpressure can complete without triggering idle closure.
/// - `keep_alive_interval(Some(10 s))` — 1/30th of the idle timeout, keeps the connection
///   alive while `send_datagram_wait` holds for congestion-window space.
///
/// **LAN LAB ONLY — NEVER USE IN PRODUCTION.**
pub fn lan_lab_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    // 120 frames × ~192 fragments × ~1162 bytes ≈ 27 MiB; 64 MiB is 2× headroom.
    transport.datagram_receive_buffer_size(Some(64 * 1024 * 1024));
    // 5-minute idle timeout so bulk datagram transfers complete without idle closure.
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(300)) {
        transport.max_idle_timeout(Some(idle));
    }
    // Keep-alive at 1/30th of idle timeout.
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(transport)
}

/// **LAN LAB ONLY — NEVER USE IN PRODUCTION.**
///
/// Generates a self-signed TLS certificate for `localhost` and returns a
/// `quinn::ServerConfig` backed by it. The certificate is generated fresh on
/// every call and is not persisted.
///
// TODO(P4): delete this module (or move to a dev-only `sh-transport-testkit` crate) once the real
// crypto path — Noise/identity (P3) and DTLS fingerprint pinning (P4) — lands.
///
/// # Errors
///
/// Returns [`TransportError::CertGeneration`] if rcgen fails to generate the
/// certificate, or [`TransportError::TlsConfig`] if rustls fails to build the
/// server config from it.
pub fn self_signed_server_config(
    _ack: InsecureLanLab,
) -> Result<quinn::ServerConfig, TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;

    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let server_tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| TransportError::TlsConfig(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let transport = lan_lab_transport_config();
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_cfg.transport_config(transport);
    Ok(server_cfg)
}

/// **LAN LAB ONLY — NEVER USE IN PRODUCTION.**
///
/// Returns a `quinn::ClientConfig` that **completely skips server certificate
/// verification**. Any server, including a MITM, will be accepted.
///
/// This is only suitable for local loopback/LAN testing where certificate
/// management would add friction.
///
/// # Errors
///
/// Returns [`TransportError::TlsConfig`] if the underlying TLS or QUIC
/// configuration cannot be assembled (in practice this should not happen with
/// the ring provider).
pub fn insecure_client_config(_ack: InsecureLanLab) -> Result<quinn::ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(SkipVerification(Arc::clone(&provider)));

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let transport = lan_lab_transport_config();
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_client_config));
    client_cfg.transport_config(transport);
    Ok(client_cfg)
}

/// A `ServerCertVerifier` that accepts every certificate without any checks.
///
/// **LAN LAB ONLY — NEVER USE IN PRODUCTION.**
#[derive(Debug)]
struct SkipVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
