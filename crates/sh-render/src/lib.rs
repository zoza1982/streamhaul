//! `sh-render` — client presentation pipeline.
//!
//! Provides frame sink abstractions for the client-side render pipeline.

use sh_media::VideoFrame;

/// Errors that can occur when delivering frames to a sink.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// The sink has reached its maximum capacity and cannot accept more frames.
    #[error("sink is full: capacity {capacity}")]
    SinkFull {
        /// The maximum number of frames the sink can hold.
        capacity: usize,
    },
}

/// A sink that receives decoded video frames for presentation.
///
/// Implementors are responsible for displaying, buffering, or otherwise
/// handling the delivered frames.
pub trait FrameSink: Send {
    /// Deliver a decoded video frame to this sink.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError::SinkFull`] if the sink cannot accept more frames.
    fn deliver(&mut self, frame: VideoFrame) -> Result<(), RenderError>;
}

/// A [`FrameSink`] that collects frames into an in-memory buffer up to a fixed capacity.
///
/// Useful for testing and offline processing where all frames need to be inspected.
pub struct CollectingSink {
    frames: Vec<VideoFrame>,
    capacity: usize,
}

impl CollectingSink {
    /// Create a new `CollectingSink` with the given maximum capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            frames: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Return a slice of all frames collected so far.
    #[must_use]
    pub fn frames(&self) -> &[VideoFrame] {
        &self.frames
    }

    /// Return the number of frames collected so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Return `true` if no frames have been collected yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl FrameSink for CollectingSink {
    /// Deliver a frame to the collecting sink.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError::SinkFull`] when the number of collected frames
    /// equals or exceeds the configured capacity.
    fn deliver(&mut self, frame: VideoFrame) -> Result<(), RenderError> {
        if self.frames.len() >= self.capacity {
            return Err(RenderError::SinkFull {
                capacity: self.capacity,
            });
        }
        self.frames.push(frame);
        Ok(())
    }
}

/// A [`FrameSink`] that silently discards all delivered frames.
///
/// Useful as a no-op sink when frame data is not needed.
pub struct NullSink;

impl FrameSink for NullSink {
    /// Deliver a frame to the null sink (frame is discarded).
    ///
    /// # Errors
    ///
    /// This implementation never returns an error.
    fn deliver(&mut self, _frame: VideoFrame) -> Result<(), RenderError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sh_media::{PixelFormat, Resolution};
    use sh_types::{FrameId, TimestampUs};

    fn make_frame(id: u64) -> VideoFrame {
        VideoFrame {
            data: Bytes::from_static(b"test"),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(4, 1),
            frame_id: FrameId(id),
            capture_ts_us: TimestampUs(0),
        }
    }

    #[test]
    fn collecting_sink_stores_frames() {
        let mut sink = CollectingSink::new(3);
        assert!(sink.is_empty());
        sink.deliver(make_frame(1)).unwrap();
        sink.deliver(make_frame(2)).unwrap();
        assert_eq!(sink.len(), 2);
        assert!(!sink.is_empty());
        let frames = sink.frames();
        assert_eq!(frames[0].frame_id, FrameId(1));
        assert_eq!(frames[1].frame_id, FrameId(2));
    }

    #[test]
    fn collecting_sink_returns_error_when_full() {
        let mut sink = CollectingSink::new(2);
        sink.deliver(make_frame(1)).unwrap();
        sink.deliver(make_frame(2)).unwrap();
        let err = sink.deliver(make_frame(3)).unwrap_err();
        assert!(matches!(err, RenderError::SinkFull { capacity: 2 }));
    }

    #[test]
    fn null_sink_always_succeeds() {
        let mut sink = NullSink;
        sink.deliver(make_frame(1)).unwrap();
        sink.deliver(make_frame(2)).unwrap();
    }
}
