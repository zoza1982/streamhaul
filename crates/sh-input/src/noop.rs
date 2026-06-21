//! No-op input injector — accepts and discards every event.

use sh_protocol::InputEvent;

use crate::{InputError, InputInjector};

/// An [`InputInjector`] that silently discards every event.
///
/// Useful as a placeholder when the real platform backend is not yet available
/// (e.g. on headless CI, during testing of the transport pipeline, or as the
/// default before a platform crate is linked in).
///
/// Every call to [`inject`](NoopInjector::inject) returns `Ok(())` immediately
/// without allocating or performing any OS interaction.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopInjector;

impl NoopInjector {
    /// Create a new `NoopInjector`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl InputInjector for NoopInjector {
    /// Accepts `event` and returns `Ok(())` without side effects.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    fn inject(&mut self, _event: &InputEvent) -> Result<(), InputError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sh_protocol::{EventType, InputEvent, Modifiers};

    fn key_event() -> InputEvent {
        InputEvent {
            event_type: EventType::Key,
            modifiers: Modifiers::CTRL,
            pointer_x: 0,
            pointer_y: 0,
            button_mask: 0,
            key_code: 0x0004,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        }
    }

    #[test]
    fn noop_always_returns_ok() {
        let mut inj = NoopInjector::new();
        assert!(inj.inject(&key_event()).is_ok());
    }

    #[test]
    fn noop_is_ok_for_all_event_types() {
        let mut inj = NoopInjector::new();
        for event_type in [
            EventType::PointerMove,
            EventType::Button,
            EventType::Wheel,
            EventType::Key,
            EventType::Touch,
            EventType::Pen,
        ] {
            let event = InputEvent {
                event_type,
                modifiers: Modifiers::empty(),
                pointer_x: 32768,
                pointer_y: 32768,
                button_mask: 0,
                key_code: 0,
                scroll_x: 0,
                scroll_y: 0,
                pressure: 0,
            };
            assert!(inj.inject(&event).is_ok(), "event_type={event_type:?}");
        }
    }

    #[test]
    fn noop_injector_is_dyn_compatible() {
        // Verify object safety: can be boxed as dyn InputInjector.
        let _boxed: Box<dyn InputInjector> = Box::new(NoopInjector::new());
    }
}
