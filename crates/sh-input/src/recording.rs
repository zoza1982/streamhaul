//! Recording input injector — captures every event for test assertions.

use sh_protocol::InputEvent;

use crate::{InputError, InputInjector};

/// An [`InputInjector`] that records every injected [`InputEvent`] in order.
///
/// Intended as a **test double** for the eventual host input loop: feed events in,
/// then assert on [`recorded`](RecordingInjector::recorded) to verify ordering,
/// count, and content.
///
/// # Example
///
/// ```rust
/// use sh_input::RecordingInjector;
/// use sh_input::InputInjector;
/// use sh_protocol::{EventType, InputEvent, Modifiers};
///
/// let mut inj = RecordingInjector::new();
///
/// let event = InputEvent {
///     event_type: EventType::Key,
///     modifiers: Modifiers::empty(),
///     pointer_x: 0,
///     pointer_y: 0,
///     button_mask: 0,
///     key_code: 0x0004,
///     scroll_x: 0,
///     scroll_y: 0,
///     pressure: 0,
/// };
///
/// inj.inject(&event).unwrap();
/// assert_eq!(inj.recorded(), &[event]);
/// ```
#[derive(Debug, Default)]
pub struct RecordingInjector {
    events: Vec<InputEvent>,
}

impl RecordingInjector {
    /// Create a new, empty `RecordingInjector`.
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Return a slice of all events that have been injected, in order.
    #[must_use]
    pub fn recorded(&self) -> &[InputEvent] {
        &self.events
    }

    /// Return the number of events that have been recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if no events have been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear all recorded events, resetting to the initial state.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl InputInjector for RecordingInjector {
    /// Record `event` and return `Ok(())`.
    ///
    /// # Errors
    ///
    /// Never returns an error; the recording always succeeds.
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.events.push(*event);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use sh_protocol::{EventType, InputEvent, Modifiers};

    fn make_event(event_type: EventType, key_code: u16) -> InputEvent {
        InputEvent {
            event_type,
            modifiers: Modifiers::empty(),
            pointer_x: 0,
            pointer_y: 0,
            button_mask: 0,
            key_code,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        }
    }

    #[test]
    fn starts_empty() {
        let inj = RecordingInjector::new();
        assert!(inj.is_empty());
        assert_eq!(inj.len(), 0);
        assert_eq!(inj.recorded(), &[]);
    }

    #[test]
    fn records_single_event() {
        let mut inj = RecordingInjector::new();
        let ev = make_event(EventType::Key, 0x0004);
        inj.inject(&ev).unwrap();
        assert_eq!(inj.len(), 1);
        assert!(!inj.is_empty());
        assert_eq!(inj.recorded(), &[ev]);
    }

    #[test]
    fn preserves_insertion_order() {
        let mut inj = RecordingInjector::new();
        let events: Vec<InputEvent> = [
            EventType::PointerMove,
            EventType::Button,
            EventType::Key,
            EventType::Wheel,
            EventType::Touch,
            EventType::Pen,
        ]
        .iter()
        .enumerate()
        .map(|(i, &et)| make_event(et, i as u16))
        .collect();

        for ev in &events {
            inj.inject(ev).unwrap();
        }

        assert_eq!(inj.len(), events.len());
        assert_eq!(inj.recorded(), events.as_slice());
    }

    #[test]
    fn records_content_faithfully() {
        let mut inj = RecordingInjector::new();
        let ev = InputEvent {
            event_type: EventType::PointerMove,
            modifiers: Modifiers::SHIFT | Modifiers::CTRL,
            pointer_x: 12345,
            pointer_y: 54321,
            button_mask: 0b0000_0011,
            key_code: 0,
            scroll_x: -7,
            scroll_y: 15,
            pressure: 200,
        };
        inj.inject(&ev).unwrap();
        let recorded = inj.recorded();
        assert_eq!(recorded.len(), 1);
        let got = recorded[0];
        assert_eq!(got.event_type, EventType::PointerMove);
        assert_eq!(got.modifiers, Modifiers::SHIFT | Modifiers::CTRL);
        assert_eq!(got.pointer_x, 12345);
        assert_eq!(got.pointer_y, 54321);
        assert_eq!(got.button_mask, 0b0000_0011);
        assert_eq!(got.scroll_x, -7);
        assert_eq!(got.scroll_y, 15);
        assert_eq!(got.pressure, 200);
    }

    #[test]
    fn clear_resets_state() {
        let mut inj = RecordingInjector::new();
        inj.inject(&make_event(EventType::Key, 0x0004)).unwrap();
        inj.inject(&make_event(EventType::Key, 0x0005)).unwrap();
        assert_eq!(inj.len(), 2);
        inj.clear();
        assert!(inj.is_empty());
        assert_eq!(inj.len(), 0);
        assert_eq!(inj.recorded(), &[]);
    }

    #[test]
    fn recording_injector_is_dyn_compatible() {
        let _boxed: Box<dyn InputInjector> = Box::new(RecordingInjector::new());
    }

    #[test]
    fn inject_returns_ok() {
        let mut inj = RecordingInjector::new();
        let result = inj.inject(&make_event(EventType::Key, 0));
        assert!(result.is_ok());
    }

    #[test]
    fn many_events_count_matches() {
        let mut inj = RecordingInjector::new();
        let n = 100usize;
        let ev = make_event(EventType::Button, 0);
        for _ in 0..n {
            inj.inject(&ev).unwrap();
        }
        assert_eq!(inj.len(), n);
    }
}
