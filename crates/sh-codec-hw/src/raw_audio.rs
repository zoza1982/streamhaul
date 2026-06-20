//! A portable, lossless **raw** audio codec: the "encoded" bitstream is the
//! PCM sample buffer prefixed with a small self-describing header. It exists
//! so the Phase-0 audio pipeline has a real, testable encode/decode path with
//! no hardware or C dependencies. Decoding treats the bitstream as untrusted
//! and never panics.
//!
//! # Wire format
//!
//! ```text
//! Byte  0:    magic    = 0xA0
//! Byte  1:    version  = 1
//! Bytes 2–5:  sample_rate (u32, big-endian)
//! Byte  6:    channels (u8)
//! Byte  7:    reserved = 0x00
//! Bytes 8…:   interleaved i16 LE PCM samples
//! ```
//!
//! Total header length: [`RAW_AUDIO_HEADER_LEN`] = 8 bytes.
//!
//! TODO(deferred): Real Opus encode/decode — blocked on libopus/audiopus requiring cmake.
//! Add AudioCodec::Opus variant and RawOpusEncoder/Decoder when cmake is available.

use bytes::Bytes;
use sh_media::{
    AudioCodec, AudioDecoder, AudioDecoderCaps, AudioEncodedPacket, AudioEncoder, AudioEncoderCaps,
    AudioFrame, MediaError,
};

/// Length of the raw audio bitstream header in bytes.
pub const RAW_AUDIO_HEADER_LEN: usize = 8;

/// Magic byte identifying this as a raw audio bitstream.
const RAW_AUDIO_MAGIC: u8 = 0xA0;

/// Bitstream format version, bumped on any incompatible header change.
const RAW_AUDIO_VERSION: u8 = 1;

/// Lossless raw audio encoder: emits the frame's PCM samples verbatim behind a
/// [`RAW_AUDIO_HEADER_LEN`]-byte self-describing header.
///
/// Every encoded packet can be decoded independently (there is no inter-frame
/// state), so each output is effectively a keyframe.
#[derive(Debug, Clone)]
pub struct RawAudioEncoder {
    sample_rate: u32,
    channels: u8,
}

impl RawAudioEncoder {
    /// Create a new raw audio encoder with the given format parameters.
    ///
    /// These parameters are reported via [`AudioEncoder::caps`] and must match
    /// the [`AudioFrame`]s that will be submitted to [`encode`](Self::encode).
    #[must_use]
    pub fn new(sample_rate: u32, channels: u8) -> Self {
        Self {
            sample_rate,
            channels,
        }
    }
}

impl AudioEncoder for RawAudioEncoder {
    /// Encode one audio frame into a raw audio packet.
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] if the frame's `sample_rate`/`channels` do not match the
    /// format this encoder was constructed with (and advertises via [`caps`](Self::caps)) — a
    /// mismatch means a downstream component negotiating off `caps()` would operate on the wrong
    /// format. Returns [`MediaError::FrameSize`] or [`MediaError::Unsupported`] if the frame's
    /// buffer is inconsistent with its declared format (zero channels, zero sample rate, odd byte
    /// count, or sample count not divisible by channel count for multi-channel frames).
    fn encode(&mut self, frame: &AudioFrame) -> Result<Option<AudioEncodedPacket>, MediaError> {
        if frame.sample_rate != self.sample_rate || frame.channels != self.channels {
            return Err(MediaError::Encode(format!(
                "raw_audio: frame format {}Hz/{}ch does not match encoder caps {}Hz/{}ch",
                frame.sample_rate, frame.channels, self.sample_rate, self.channels
            )));
        }
        frame.validate_len()?;
        let [r0, r1, r2, r3] = frame.sample_rate.to_be_bytes();
        let mut buf = Vec::with_capacity(RAW_AUDIO_HEADER_LEN.saturating_add(frame.samples.len()));
        buf.extend_from_slice(&[
            RAW_AUDIO_MAGIC,
            RAW_AUDIO_VERSION,
            r0,
            r1,
            r2,
            r3,
            frame.channels,
            0x00, // reserved
        ]);
        buf.extend_from_slice(&frame.samples);
        Ok(Some(AudioEncodedPacket {
            data: Bytes::from(buf),
            capture_ts_us: frame.capture_ts_us,
            seq: frame.seq,
            codec: AudioCodec::RawPcm,
        }))
    }

    /// This implementation never buffers; always returns an empty `Vec`.
    ///
    /// # Errors
    /// This implementation never returns an error.
    fn flush(&mut self) -> Result<Vec<AudioEncodedPacket>, MediaError> {
        Ok(Vec::new())
    }

    fn caps(&self) -> AudioEncoderCaps {
        AudioEncoderCaps {
            codec: AudioCodec::RawPcm,
            sample_rate_hz: self.sample_rate,
            channels: self.channels,
        }
    }
}

/// Decoder for [`RawAudioEncoder`] bitstreams.
///
/// Reconstructs the [`AudioFrame`], carrying `capture_ts_us` and `seq` from
/// the [`AudioEncodedPacket`]. On any malformed input this returns
/// [`MediaError::Decode`]; it never panics.
#[derive(Debug, Default, Clone)]
pub struct RawAudioDecoder;

impl RawAudioDecoder {
    /// Create a new raw audio decoder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl AudioDecoder for RawAudioDecoder {
    /// Decode one raw audio packet back into an [`AudioFrame`].
    ///
    /// # Errors
    /// Returns [`MediaError::Decode`] if:
    /// - `packet.codec` is not [`AudioCodec::RawPcm`]
    /// - The header is truncated (fewer than [`RAW_AUDIO_HEADER_LEN`] bytes)
    /// - The magic byte is not `0xA0`
    /// - The version byte is not `1`
    /// - `sample_rate` is zero
    /// - `channels` is zero
    /// - The payload length is odd (not a whole number of i16 samples)
    /// - The total sample count is not divisible by the channel count (multi-channel frames)
    fn decode(&mut self, packet: &AudioEncodedPacket) -> Result<Option<AudioFrame>, MediaError> {
        if packet.codec != AudioCodec::RawPcm {
            return Err(MediaError::Decode(format!(
                "raw_audio: unexpected codec {:?}",
                packet.codec
            )));
        }

        // Parse the header — must be exactly RAW_AUDIO_HEADER_LEN bytes.
        let header: [u8; RAW_AUDIO_HEADER_LEN] = packet
            .data
            .get(..RAW_AUDIO_HEADER_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| MediaError::Decode("raw_audio: truncated header".to_owned()))?;

        let [magic, version, r0, r1, r2, r3, channels, _reserved] = header;

        if magic != RAW_AUDIO_MAGIC {
            return Err(MediaError::Decode(format!(
                "raw_audio: bad magic 0x{magic:02X}"
            )));
        }
        if version != RAW_AUDIO_VERSION {
            return Err(MediaError::Decode(format!(
                "raw_audio: unknown version {version}"
            )));
        }
        let sample_rate = u32::from_be_bytes([r0, r1, r2, r3]);
        if sample_rate == 0 {
            return Err(MediaError::Decode("raw_audio: zero sample_rate".to_owned()));
        }
        if channels == 0 {
            return Err(MediaError::Decode("raw_audio: zero channels".to_owned()));
        }

        // Payload follows the header.
        let samples_bytes = packet.data.slice(RAW_AUDIO_HEADER_LEN..);
        if samples_bytes.len() % 2 != 0 {
            return Err(MediaError::Decode(
                "raw_audio: odd payload length — not a whole number of i16 samples".to_owned(),
            ));
        }
        // For multi-channel frames: total sample count must be divisible by channels.
        let total_samples = samples_bytes.len() / 2;
        let ch_usize = usize::from(channels);
        if ch_usize > 1 {
            // checked_rem avoids the clippy::arithmetic_side_effects lint on `%`. ch_usize is
            // non-zero (channels > 0 checked above) so this is always Some; the unwrap_or(1)
            // fallback is fail-safe — if the guard above were ever removed, a zero divisor would
            // yield a non-zero remainder and reject the frame rather than silently accepting it.
            let rem = total_samples.checked_rem(ch_usize).unwrap_or(1);
            if rem != 0 {
                return Err(MediaError::Decode(format!(
                    "raw_audio: sample count {total_samples} not divisible by channels {channels}"
                )));
            }
        }

        Ok(Some(AudioFrame {
            samples: samples_bytes,
            sample_rate,
            channels,
            capture_ts_us: packet.capture_ts_us,
            seq: packet.seq,
        }))
    }

    /// This implementation never buffers; always returns an empty `Vec`.
    ///
    /// # Errors
    /// This implementation never returns an error.
    fn flush(&mut self) -> Result<Vec<AudioFrame>, MediaError> {
        Ok(Vec::new())
    }

    fn caps(&self) -> AudioDecoderCaps {
        AudioDecoderCaps {
            codec: AudioCodec::RawPcm,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sh_types::TimestampUs;

    fn make_frame(sample_rate: u32, channels: u8, num_samples: usize) -> AudioFrame {
        // num_samples = total i16 samples (all channels combined)
        let byte_len = num_samples * 2;
        let samples: Vec<u8> = (0..byte_len).map(|i| (i % 127) as u8).collect();
        AudioFrame {
            samples: Bytes::from(samples),
            sample_rate,
            channels,
            capture_ts_us: TimestampUs(12_345),
            seq: 7,
        }
    }

    fn make_encoder() -> RawAudioEncoder {
        RawAudioEncoder::new(48_000, 1)
    }

    #[test]
    fn roundtrip_mono() {
        let frame = make_frame(48_000, 1, 960);
        let mut enc = RawAudioEncoder::new(48_000, 1);
        let mut dec = RawAudioDecoder::new();
        let pkt = enc.encode(&frame).unwrap().unwrap();
        assert_eq!(pkt.codec, AudioCodec::RawPcm);
        assert_eq!(pkt.seq, frame.seq);
        assert_eq!(pkt.capture_ts_us, frame.capture_ts_us);
        let decoded = dec.decode(&pkt).unwrap().unwrap();
        assert_eq!(decoded.sample_rate, frame.sample_rate);
        assert_eq!(decoded.channels, frame.channels);
        assert_eq!(decoded.samples, frame.samples);
        assert_eq!(decoded.seq, frame.seq);
        assert_eq!(decoded.capture_ts_us, frame.capture_ts_us);
    }

    #[test]
    fn roundtrip_stereo() {
        let frame = make_frame(44_100, 2, 1764);
        let mut enc = RawAudioEncoder::new(44_100, 2);
        let mut dec = RawAudioDecoder::new();
        let pkt = enc.encode(&frame).unwrap().unwrap();
        let decoded = dec.decode(&pkt).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn flush_returns_empty_vec() {
        let mut enc = make_encoder();
        let mut dec = RawAudioDecoder::new();
        assert_eq!(enc.flush().unwrap(), Vec::<AudioEncodedPacket>::new());
        assert_eq!(dec.flush().unwrap(), Vec::<AudioFrame>::new());
    }

    #[test]
    fn codec_is_raw_pcm() {
        assert_eq!(make_encoder().caps().codec, AudioCodec::RawPcm);
        assert_eq!(RawAudioDecoder::new().caps().codec, AudioCodec::RawPcm);
    }

    #[test]
    fn caps_reports_correct_format() {
        let enc = RawAudioEncoder::new(44_100, 2);
        let caps = enc.caps();
        assert_eq!(caps.codec, AudioCodec::RawPcm);
        assert_eq!(caps.sample_rate_hz, 44_100);
        assert_eq!(caps.channels, 2);
    }

    #[test]
    fn decode_accepts_well_formed_raw_pcm_packet() {
        // Honest happy-path coverage. The decoder's wrong-codec rejection guard
        // (`packet.codec != AudioCodec::RawPcm`) is structurally untestable while
        // `AudioCodec` has only the `RawPcm` variant — see the tracked
        // `decode_rejects_wrong_codec` below.
        let mut dec = RawAudioDecoder::new();
        let frame = make_frame(48_000, 1, 4);
        let mut enc = RawAudioEncoder::new(48_000, 1);
        let pkt = enc.encode(&frame).unwrap().unwrap();
        assert!(dec.decode(&pkt).is_ok());
    }

    #[test]
    #[ignore = "AudioCodec has only RawPcm today; re-enable when Opus lands (tracked: IMPLEMENTATION_PLAN.md R12)"]
    fn decode_rejects_wrong_codec() {
        // When AudioCodec gains a second variant (e.g. Opus), construct a packet
        // carrying it and assert the RawAudioDecoder rejects it:
        //   let pkt = AudioEncodedPacket { codec: AudioCodec::Opus, .. };
        //   assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn encode_rejects_frame_format_mismatch() {
        // Encoder advertises 48kHz/1ch via caps(); a frame with a different
        // format must be rejected so a caps()-negotiating pipeline cannot
        // silently operate on the wrong format.
        let mut enc = RawAudioEncoder::new(48_000, 1);
        let wrong_rate = make_frame(44_100, 1, 4);
        assert!(matches!(
            enc.encode(&wrong_rate),
            Err(MediaError::Encode(_))
        ));
        let wrong_channels = make_frame(48_000, 2, 4);
        assert!(matches!(
            enc.encode(&wrong_channels),
            Err(MediaError::Encode(_))
        ));
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let mut dec = RawAudioDecoder::new();
        let pkt = AudioEncodedPacket {
            data: Bytes::from_static(&[0xA0, 1, 0]),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut dec = RawAudioDecoder::new();
        // Header with bad magic (0xBB instead of 0xA0).
        let pkt = AudioEncodedPacket {
            data: Bytes::from(vec![0xBB, 1, 0, 0, 187, 128, 1, 0]),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut dec = RawAudioDecoder::new();
        let pkt = AudioEncodedPacket {
            data: Bytes::from(vec![0xA0, 99, 0, 0, 187, 128, 1, 0]),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decode_rejects_zero_sample_rate() {
        let mut dec = RawAudioDecoder::new();
        // sample_rate bytes = [0, 0, 0, 0] → zero
        let pkt = AudioEncodedPacket {
            data: Bytes::from(vec![0xA0, 1, 0, 0, 0, 0, 1, 0]),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decode_rejects_zero_channels() {
        let mut dec = RawAudioDecoder::new();
        // channels = 0
        let pkt = AudioEncodedPacket {
            data: Bytes::from(vec![0xA0, 1, 0, 0, 187, 128, 0, 0]),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decode_rejects_odd_payload_length() {
        let mut dec = RawAudioDecoder::new();
        // Valid header (sample_rate=48000=0x0000BB80, channels=1) + 3 bytes payload (odd).
        let mut data = vec![0xA0u8, 1, 0x00, 0x00, 0xBB, 0x80, 1, 0];
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // 3 bytes = odd
        let pkt = AudioEncodedPacket {
            data: Bytes::from(data),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decode_rejects_stereo_frame_with_odd_sample_count() {
        // channels=2, payload=6 bytes = 3 i16 samples → 3 % 2 != 0 → Err
        // Header: magic=0xA0, ver=1, rate=48000=0x0000BB80, channels=2
        let mut dec = RawAudioDecoder::new();
        let mut data = vec![0xA0u8, 1, 0x00, 0x00, 0xBB, 0x80, 2, 0];
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // 6 bytes = 3 samples
        let pkt = AudioEncodedPacket {
            data: Bytes::from(data),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        assert!(
            matches!(dec.decode(&pkt), Err(MediaError::Decode(_))),
            "stereo frame with 3 samples (not divisible by 2) must be rejected"
        );
    }

    #[test]
    fn decode_accepts_empty_payload() {
        // An empty payload is valid for a zero-duration frame (e.g. a flush marker).
        let mut dec = RawAudioDecoder::new();
        // 48000 = 0x0000_BB80
        let pkt = AudioEncodedPacket {
            data: Bytes::from(vec![0xA0, 1, 0x00, 0x00, 0xBB, 0x80, 1, 0]),
            capture_ts_us: TimestampUs(0),
            seq: 0,
            codec: AudioCodec::RawPcm,
        };
        let decoded = dec.decode(&pkt).unwrap().unwrap();
        assert_eq!(decoded.samples.len(), 0);
        assert_eq!(decoded.sample_rate, 48_000);
    }

    /// Property test: arbitrary valid AudioFrames round-trip losslessly.
    #[cfg(test)]
    mod proptest_roundtrip {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn roundtrip_arbitrary(
                sample_rate in 1u32..=192_000,
                channels in 1u8..=8,
                // num_samples: 0..=2000 (per-channel), so total = channels * num_samples
                num_samples_per_channel in 0usize..=2000,
            ) {
                let total_samples = usize::from(channels).saturating_mul(num_samples_per_channel);
                let byte_len = total_samples.saturating_mul(2);
                let samples: Vec<u8> = (0..byte_len).map(|i| (i % 251) as u8).collect();
                let frame = AudioFrame {
                    samples: Bytes::from(samples),
                    sample_rate,
                    channels,
                    capture_ts_us: TimestampUs(12_345_678),
                    seq: 42,
                };

                let mut enc = RawAudioEncoder::new(sample_rate, channels);
                let mut dec = RawAudioDecoder::new();
                let pkt = enc.encode(&frame).unwrap().unwrap();
                let decoded = dec.decode(&pkt).unwrap().unwrap();

                prop_assert_eq!(decoded.sample_rate, frame.sample_rate);
                prop_assert_eq!(decoded.channels, frame.channels);
                prop_assert_eq!(decoded.samples, frame.samples);
                prop_assert_eq!(decoded.seq, frame.seq);
                prop_assert_eq!(decoded.capture_ts_us, frame.capture_ts_us);
            }
        }
    }
}
