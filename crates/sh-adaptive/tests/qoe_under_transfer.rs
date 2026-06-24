//! QoE-under-transfer gate test (Phase 7 / Gate P7 — ADR-0024).
//!
//! Proves the product invariant that **a bulk file transfer consumes only spare bandwidth and does
//! not degrade interactive video** — rigorously and deterministically, the proof the existing
//! `sh-transport` loopback isolation test explicitly deferred (it noted loopback is ~40 Gbps, so it
//! could only smoke-check, and asked for a "rate-limited transport harness at ~10 Mbps").
//!
//! # Model
//!
//! A single shared bottleneck link of fixed capacity drains a **FIFO** byte queue shared by video
//! and file. FIFO (no stream priority) is deliberately the *pessimistic* case: it removes the
//! structural per-stream-priority isolation that QUIC/SCTP also provide, so the **only** thing left
//! to protect video is the budget pacer. If video survives here, it survives a fortiori with stream
//! priority layered on top.
//!
//! - Video is a 60 fps CBR source at the allocator's `video()` budget (frame every 16.67 ms).
//! - File offers bytes two ways:
//!   - **paced** (shipped): a [`TokenBucket`] at the allocator's `file()` *leftover* budget.
//!   - **greedy** (honest control): unpaced — it floods the queue as fast as it can.
//!
//! # What is asserted (non-vacuous)
//!
//! - **Paced:** ≥ 99% of video frames fully drain within a 2-frame (33 ms) deadline — video QoE is
//!   preserved while the transfer runs.
//! - **Greedy control:** far fewer frames meet the deadline — the same harness *does* starve video
//!   when the pacer is removed, proving the paced result is not vacuously true.
//! - **Budget:** the paced file's measured throughput stays at/under its leftover allocation and is
//!   non-zero (it uses spare bandwidth, never more).

#![allow(
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

use std::collections::VecDeque;
use std::time::Duration;

use sh_adaptive::{AllocatorConfig, Bitrate, RateAllocator, TokenBucket};

const LINK: Bitrate = Bitrate(30_000_000); // 30 Mbps shared bottleneck
const FPS: u64 = 60;
const SIM_STEPS: u64 = 2_000; // 2 s at 1 ms resolution
const STEP: Duration = Duration::from_millis(1);
const STEP_US: u64 = 1_000;
const FILE_CHUNK: u64 = 16 * 1024; // 16 KiB application chunk
const FILE_TOTAL: u64 = 8 * 1024 * 1024; // 8 MiB file to push
/// Video frame "on time" deadline: 2 frame intervals (~33 ms).
const FRAME_DEADLINE_US: u64 = 2 * 1_000_000 / FPS;

struct Segment {
    is_video: bool,
    frame_idx: usize,
    remaining: u64,
}

struct SimResult {
    /// Per-frame queueing delay in microseconds (`None` if it never drained within the sim).
    frame_delay_us: Vec<Option<u64>>,
    /// Total file bytes that fully drained across the sim.
    file_drained: u64,
}

/// Run the shared-bottleneck simulation. `paced` selects the shipped token-bucket file pacer vs the
/// greedy (unpaced) honest-control.
fn simulate(paced: bool) -> SimResult {
    let alloc = RateAllocator::new(AllocatorConfig::default()).allocate(LINK);
    let video_bps = alloc.video().0;
    let file_bps = alloc.file().0;
    assert!(video_bps > 0 && file_bps > 0, "both flows must have budget");

    let link_bytes_per_sec = LINK.0 as f64 / 8.0;
    let frame_interval_us = 1_000_000 / FPS;
    let frame_size = (video_bps / 8) / FPS; // bytes per video frame

    // File pacer: leftover budget, 50 ms burst (well above one chunk's worth).
    let mut bucket = TokenBucket::new(Bitrate(file_bps), Duration::from_millis(50));

    let mut queue: VecDeque<Segment> = VecDeque::new();
    let mut frame_enqueue_us: Vec<u64> = Vec::new();
    let mut frame_delay_us: Vec<Option<u64>> = Vec::new();
    let mut next_frame_us = 0u64;
    let mut file_enqueued = 0u64;
    let mut file_drained = 0u64;
    let mut drain_credit = 0.0f64;
    let mut t_us = 0u64;

    for _ in 0..SIM_STEPS {
        // 1. Enqueue any video frames now due.
        while next_frame_us <= t_us {
            let idx = frame_enqueue_us.len();
            frame_enqueue_us.push(t_us);
            frame_delay_us.push(None);
            queue.push_back(Segment {
                is_video: true,
                frame_idx: idx,
                remaining: frame_size,
            });
            next_frame_us += frame_interval_us;
        }

        // 2. Offer file bytes.
        if file_enqueued < FILE_TOTAL {
            if paced {
                bucket.advance(STEP);
                while file_enqueued < FILE_TOTAL && bucket.try_consume(FILE_CHUNK as usize) {
                    queue.push_back(Segment {
                        is_video: false,
                        frame_idx: 0,
                        remaining: FILE_CHUNK,
                    });
                    file_enqueued += FILE_CHUNK;
                }
            } else {
                // Greedy: offer up to 2× the link per step so the queue is always backlogged.
                let offer = (link_bytes_per_sec * STEP.as_secs_f64() * 2.0) as u64;
                let mut offered = 0u64;
                while offered < offer && file_enqueued < FILE_TOTAL {
                    queue.push_back(Segment {
                        is_video: false,
                        frame_idx: 0,
                        remaining: FILE_CHUNK,
                    });
                    file_enqueued += FILE_CHUNK;
                    offered += FILE_CHUNK;
                }
            }
        }

        // 3. Drain the link for one step (FIFO).
        drain_credit += link_bytes_per_sec * STEP.as_secs_f64();
        while drain_credit >= 1.0 {
            let Some(front) = queue.front_mut() else {
                break;
            };
            let take = front.remaining.min(drain_credit as u64);
            if take == 0 {
                break;
            }
            front.remaining -= take;
            drain_credit -= take as f64;
            if front.remaining == 0 {
                let seg = queue.pop_front().unwrap();
                if seg.is_video {
                    // Completed by the end of this step.
                    let done_us = t_us + STEP_US;
                    frame_delay_us[seg.frame_idx] =
                        Some(done_us.saturating_sub(frame_enqueue_us[seg.frame_idx]));
                } else {
                    file_drained += FILE_CHUNK;
                }
            }
        }

        t_us += STEP_US;
    }

    SimResult {
        frame_delay_us,
        file_drained,
    }
}

/// Fraction of frames that fully drained within the on-time deadline.
fn on_time_fraction(r: &SimResult) -> f64 {
    let total = r.frame_delay_us.len();
    assert!(total > 0, "sim must produce video frames");
    let on_time = r
        .frame_delay_us
        .iter()
        .filter(|d| matches!(d, Some(us) if *us <= FRAME_DEADLINE_US))
        .count();
    on_time as f64 / total as f64
}

#[test]
fn paced_file_transfer_preserves_video_qoe_and_greedy_does_not() {
    let paced = simulate(true);
    let greedy = simulate(false);

    let paced_on_time = on_time_fraction(&paced);
    let greedy_on_time = on_time_fraction(&greedy);

    eprintln!(
        "[qoe] paced on-time={:.1}%  greedy on-time={:.1}%  (deadline={} us, {} frames)",
        paced_on_time * 100.0,
        greedy_on_time * 100.0,
        FRAME_DEADLINE_US,
        paced.frame_delay_us.len(),
    );

    // 1. With the shipped pacer, video QoE is preserved: nearly every frame is on time.
    assert!(
        paced_on_time >= 0.99,
        "paced file transfer degraded video: only {:.1}% of frames on time",
        paced_on_time * 100.0
    );

    // 2. Honest control: the SAME harness starves video when the pacer is removed. This proves the
    //    paced result above is not vacuously true (the model can fail).
    assert!(
        greedy_on_time <= 0.50,
        "greedy control did not degrade video ({:.1}% on time) — the test would be vacuous",
        greedy_on_time * 100.0
    );
    assert!(
        paced_on_time > greedy_on_time + 0.40,
        "pacing must be decisively better than greedy (paced {:.1}% vs greedy {:.1}%)",
        paced_on_time * 100.0,
        greedy_on_time * 100.0
    );

    // 3. Budget: the paced file used spare bandwidth — non-zero, and at/under its leftover share
    //    plus the one-time 50 ms burst the bucket starts with (a real, intended allowance). Compute
    //    in f64 so the bound never silently truncates if the allocation changes.
    let alloc = RateAllocator::new(AllocatorConfig::default()).allocate(LINK);
    let file_bytes_per_sec = alloc.file().0 as f64 / 8.0;
    let window_secs = SIM_STEPS as f64 / 1_000.0;
    let file_budget_bytes = file_bytes_per_sec * window_secs; // leftover budget over the window
    let burst_bytes = file_bytes_per_sec * 0.050; // 50 ms burst the pacer is configured with
    let bound = file_budget_bytes + burst_bytes + FILE_CHUNK as f64;
    assert!(paced.file_drained > 0, "paced file made no progress");
    assert!(
        (paced.file_drained as f64) <= bound,
        "paced file exceeded its leftover budget: drained {} > bound {:.0} (budget {:.0} + burst {:.0})",
        paced.file_drained,
        bound,
        file_budget_bytes,
        burst_bytes
    );
    eprintln!(
        "[qoe] paced file drained {} bytes (budget ~{:.0} over {} s)",
        paced.file_drained,
        file_budget_bytes,
        SIM_STEPS / 1_000
    );
}
