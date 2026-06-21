//! The `InputInjector` trait.

use sh_protocol::InputEvent;

use crate::InputError;

/// Applies a decoded [`InputEvent`] to the local machine.
///
/// # Contract
///
/// Implementations synthesize OS-level input events from the decoded wire event:
///
/// - **Windows** (`sh-platform-win`): `SendInput` / Raw Input.
/// - **Linux** (`sh-platform-linux`): `/dev/uinput`.
/// - **macOS** (`sh-platform-mac`): `CGEvent`.
///
/// This trait is the seam between the transport layer (which delivers events) and the OS
/// backend (which injects them). Portable mocks ([`crate::NoopInjector`],
/// [`crate::RecordingInjector`]) implement it so the pipeline and tests run on any machine
/// without injection hardware.
///
/// # Threading
///
/// [`inject`](Self::inject) is called from a **dedicated injection thread**, not from the async
/// runtime. Implementations must complete in bounded time and must not block indefinitely.
/// Dynamic allocation in the hot path is discouraged — prefer pre-allocated buffers.
///
/// # Object safety
///
/// The trait is object-safe: it can be used as `Box<dyn InputInjector>` so callers can swap
/// backends at run time (e.g. based on OS detection or feature flags).
pub trait InputInjector: Send {
    /// Inject one input event into the local OS.
    ///
    /// The host receives [`InputEvent`]s from the client on the reliable Input channel and feeds
    /// each one to an injector via this method. The injector owns all OS interaction; callers
    /// treat it as a black box.
    ///
    /// Pointer coordinates inside `event` are normalized (`0..=65535`). If the injector needs
    /// absolute pixel coordinates it should apply a [`crate::CoordMapper`] before calling OS APIs.
    ///
    /// # Errors
    ///
    /// - [`InputError::Unsupported`] if this injector does not handle the event's type or fields.
    /// - [`InputError::Backend`] if the OS-level injection call fails.
    /// - [`InputError::ZeroSizeAxis`] if the injector was constructed with an invalid target rect
    ///   (implementations should validate at construction time, not here).
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError>;
}
