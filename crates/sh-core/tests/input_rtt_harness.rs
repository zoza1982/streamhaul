//! Integration test for the Gate P1 input round-trip latency harness.
//!
//! Runs `run_input_rtt_harness` over a loopback QUIC connection with the LAN-lab insecure TLS
//! config (same gate as `loopback_harness.rs`). Asserts exact delivery (reliable channel ⇒
//! zero loss), strict injection order, finite RTT values in correct order, and a generous
//! upper-bound on median RTT (loopback should be well under 50 ms with true per-event RTT).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn input_rtt_200_events() {
        let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
        let server_config = sh_transport::self_signed_server_config(ack).unwrap();
        let client_config = sh_transport::insecure_client_config(ack).unwrap();

        let event_count = 200;
        let params = sh_core::InputRttParams { event_count };

        let report = sh_core::run_input_rtt_harness(server_config, client_config, params)
            .await
            .unwrap();

        // ── Print report for --nocapture visibility ────────────────────────────────
        eprintln!("Input RTT harness report:");
        eprintln!("  Events sent:    {}", report.events_sent);
        eprintln!("  Events echoed:  {}", report.events_echoed);
        eprintln!("  All in order:   {}", report.all_injected_in_order);
        eprintln!("  RTT min:        {} µs", report.rtt_min_us);
        eprintln!("  RTT median:     {} µs", report.rtt_median_us);
        eprintln!("  RTT p95:        {} µs", report.rtt_p95_us);
        eprintln!("  RTT max:        {} µs", report.rtt_max_us);

        // ── Assertions ─────────────────────────────────────────────────────────────

        // Reliable channel: zero loss expected.
        assert_eq!(
            report.events_echoed, event_count,
            "reliable channel must deliver every event; got {}/{}",
            report.events_echoed, event_count
        );

        // Injection order must be preserved (reliable + ordered channel).
        assert!(
            report.all_injected_in_order,
            "events must arrive at the host in send order"
        );

        // RTT values must be finite and in non-decreasing order.
        assert!(
            report.rtt_min_us <= report.rtt_median_us,
            "min ({}) must be ≤ median ({})",
            report.rtt_min_us,
            report.rtt_median_us
        );
        assert!(
            report.rtt_median_us <= report.rtt_p95_us,
            "median ({}) must be ≤ p95 ({})",
            report.rtt_median_us,
            report.rtt_p95_us
        );
        assert!(
            report.rtt_p95_us <= report.rtt_max_us,
            "p95 ({}) must be ≤ max ({})",
            report.rtt_p95_us,
            report.rtt_max_us
        );

        // Loopback RTT budget: tightened to 50 ms because true per-event serialized RTT on
        // loopback is well under 1 ms; 50 ms absorbs extreme CI scheduling jitter.
        assert!(
            report.rtt_median_us < 50_000,
            "median RTT ({} µs) must be < 50 ms on loopback",
            report.rtt_median_us
        );

        // At least one measurement must have been recorded.
        assert!(
            !report.measurements.is_empty(),
            "expected at least one RTT measurement"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn input_rtt_too_many_events_rejected_before_connect() {
        let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
        let server_config = sh_transport::self_signed_server_config(ack).unwrap();
        let client_config = sh_transport::insecure_client_config(ack).unwrap();

        let params = sh_core::InputRttParams {
            event_count: 70_000,
        };
        let err = sh_core::run_input_rtt_harness(server_config, client_config, params)
            .await
            .unwrap_err();

        assert!(
            matches!(err, sh_core::InputRttError::TooManyEvents { count: 70_000 }),
            "expected TooManyEvents, got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn input_rtt_single_event() {
        let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
        let server_config = sh_transport::self_signed_server_config(ack).unwrap();
        let client_config = sh_transport::insecure_client_config(ack).unwrap();

        let params = sh_core::InputRttParams { event_count: 1 };
        let report = sh_core::run_input_rtt_harness(server_config, client_config, params)
            .await
            .unwrap();

        assert_eq!(report.events_echoed, 1);
        assert!(report.all_injected_in_order);
        assert_eq!(
            report.rtt_min_us, report.rtt_max_us,
            "single event: min == max"
        );
        assert_eq!(
            report.rtt_min_us, report.rtt_median_us,
            "single event: min == median"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn input_rtt_zero_events() {
        let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
        let server_config = sh_transport::self_signed_server_config(ack).unwrap();
        let client_config = sh_transport::insecure_client_config(ack).unwrap();

        let params = sh_core::InputRttParams { event_count: 0 };
        let report = sh_core::run_input_rtt_harness(server_config, client_config, params)
            .await
            .unwrap();

        assert_eq!(report.events_echoed, 0);
        assert!(report.all_injected_in_order, "vacuously true for 0 events");
        assert_eq!(report.rtt_min_us, 0);
        assert_eq!(report.rtt_median_us, 0);
        assert_eq!(report.rtt_p95_us, 0);
        assert_eq!(report.rtt_max_us, 0);
    }
}
