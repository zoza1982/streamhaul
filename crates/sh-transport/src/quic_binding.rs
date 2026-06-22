//! QUIC-to-Noise session-context binding helper.
//!
//! Exports a session-binding label from a [`quinn::Connection`] for use as the
//! `session_context` in the Noise prologue (ADR-0007 §1.4). This channel-binds
//! the Noise handshake to this specific QUIC connection; an attacker cannot lift
//! Noise messages from one QUIC connection to another.
//!
//! # Label
//!
//! The TLS exporter label is `"shp noise binding"` (ADR-0007 §1.4).
//!
//! # Usage
//!
//! ```no_run
//! use sh_transport::quic_binding::export_noise_session_context;
//!
//! # async fn example(conn: quinn::Connection) -> Result<(), sh_transport::TransportError> {
//! let ctx = export_noise_session_context(&conn)?;
//! // Pass `ctx` as `session_context` to NoiseHandshake constructors.
//! # Ok(())
//! # }
//! ```

use crate::error::TransportError;

/// The QUIC TLS exporter label for Noise session binding (ADR-0007 §1.4).
const NOISE_BINDING_LABEL: &str = "shp noise binding";

/// The number of bytes to export from the QUIC TLS session.
const NOISE_CONTEXT_LEN: usize = 32;

/// Exports 32 bytes of session-binding context from a QUIC connection.
///
/// Used to bind the Noise handshake prologue to this specific QUIC connection
/// (ADR-0007 §1.4). Prevents an attacker from lifting Noise messages from one
/// QUIC session to another.
///
/// # Errors
///
/// Returns [`TransportError::NoiseContextExport`] if the QUIC connection's TLS
/// exporter is unavailable (e.g. handshake not yet complete).
///
/// # Panics
///
/// Never panics.
pub fn export_noise_session_context(
    conn: &quinn::Connection,
) -> Result<[u8; NOISE_CONTEXT_LEN], TransportError> {
    let mut out = [0u8; NOISE_CONTEXT_LEN];
    conn.export_keying_material(&mut out, NOISE_BINDING_LABEL.as_bytes(), b"")
        .map_err(|_| TransportError::NoiseContextExport)?;
    Ok(out)
}
