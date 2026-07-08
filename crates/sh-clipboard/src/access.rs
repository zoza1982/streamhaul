//! The `ClipboardAccess` trait.

use crate::ClipboardError;

/// Reads and writes the local machine's clipboard **text**.
///
/// This is the seam between the transport layer (which carries
/// [`ClipboardUpdate`](sh_protocol::ClipboardUpdate)s over the reliable, ordered Clipboard
/// channel) and the OS backend (which owns the real selection). Portable mocks
/// ([`crate::NoopClipboard`], [`crate::RecordingClipboard`]) implement it so the wiring and tests
/// run on any machine without a windowing system -- exactly the seam that `sh-input`'s
/// `InputInjector` is for input.
///
/// # Text only (v1)
///
/// Both methods deal in `String`/`&str`, i.e. **valid UTF-8** by construction. The wire format
/// ([`ClipboardUpdate`](sh_protocol::ClipboardUpdate)) is `text/plain` only in v1 and its `decode`
/// rejects non-UTF-8, so nothing malformed ever reaches this trait. A future non-text format
/// (HTML/image) is a new wire `format` id with its own sanitizer and threat model (ADR-0037), not
/// a widening of this trait.
///
/// # Direction
///
/// The two methods are the local machine's two roles in clipboard sync, described from the local
/// machine's point of view (so the mapping holds whichever peer this trait runs on):
///
/// - [`get_text`](Self::get_text) **reads the local clipboard to offer it outbound** to the peer.
/// - [`set_text`](Self::set_text) **writes content received inbound** from the peer into the local
///   clipboard (this is the paste sink).
///
/// On the host, `get_text` therefore drives the `host->browser` paste (the host is the copy source)
/// and `set_text` drives the `browser->host` paste (the host is the paste sink).
///
/// # Security (the wiring layer's responsibility, not this trait's)
///
/// This trait is a pure OS seam; the host/browser wiring that drives it carries the ADR-0037
/// obligations (fail-closed `CLIPBOARD` capability gate on the receive path in **both** directions;
/// never logging content, §7; control-character normalization before the paste sink). See the
/// crate-root docs and ADR-0037 for the full model.
///
/// # Threading
///
/// Unlike `sh-input`'s `InputInjector` (which mandates a dedicated non-async injection thread), this
/// trait does not fix a threading model -- the wiring PR decides it. Regardless of the calling
/// thread, implementations must complete in bounded time and must not block indefinitely; an OS
/// backend whose primitive can block on IPC (e.g. an X11 selection round-trip to another process)
/// MUST NOT be called directly from the async I/O executor.
///
/// # Object safety
///
/// The trait is object-safe: callers hold a `Box<dyn ClipboardAccess>` and swap backends at run
/// time (OS backend, a capability-denied stub, or a test mock).
pub trait ClipboardAccess: Send {
    /// Read the current clipboard text.
    ///
    /// Returns `Ok(None)` when the clipboard is empty or holds a non-text format (an image, say) --
    /// this is a normal, non-error outcome, not a failure. Returns `Ok(Some(text))` for text.
    ///
    /// This is the **outbound** read: the local machine reads its own clipboard to offer it to the
    /// peer (on the host, the `host->browser` paste -- the host is the copy source). The wiring
    /// gates it behind the `CLIPBOARD` capability and, in the browser, an explicit user gesture
    /// (ADR-0037).
    ///
    /// # Errors
    ///
    /// - [`ClipboardError::Unsupported`] if this backend cannot read (e.g. write-only, or no
    ///   windowing system).
    /// - [`ClipboardError::Backend`] if the OS-level read fails.
    fn get_text(&mut self) -> Result<Option<String>, ClipboardError>;

    /// Write `text` to the clipboard as `text/plain`.
    ///
    /// This is the **inbound** write / paste sink: the local machine writes text the peer sent into
    /// its own clipboard (on the host, the `browser->host` paste -- the host is the paste sink).
    ///
    /// `text` is valid UTF-8 by type. Callers are responsible for bounding its size (the wire bound
    /// is [`MAX_CLIPBOARD_BYTES`](sh_protocol::MAX_CLIPBOARD_BYTES)) and for paste-injection
    /// hardening (control-character normalization) **before** calling this -- this trait writes what
    /// it is given.
    ///
    /// # Errors
    ///
    /// - [`ClipboardError::Unsupported`] if this backend cannot write (e.g. read-only).
    /// - [`ClipboardError::Backend`] if the OS-level write fails.
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError>;
}
