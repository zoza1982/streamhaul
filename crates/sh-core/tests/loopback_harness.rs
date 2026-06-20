//! End-to-end loopback harness integration test (P0-10).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn loopback_harness_120_frames() {
        let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
        let server_config = sh_transport::self_signed_server_config(ack).unwrap();
        let client_config = sh_transport::insecure_client_config(ack).unwrap();

        let params = sh_core::HarnessParams {
            resolution: sh_media::Resolution::new(320, 180),
            fps: 30,
            frame_count: 120,
        };

        let report = sh_core::run_loopback_harness(server_config, client_config, params)
            .await
            .unwrap();

        println!("Harness report: {report:#?}");
        println!("  Frames sent:     {}", report.frames_sent);
        println!("  Frames received: {}", report.frames_received);
        println!(
            "  Lossless match:  {}/{}",
            report.lossless_match_count, report.frames_received
        );
        println!("  Latency min:     {} µs", report.latency_min_us);
        println!("  Latency median:  {} µs", report.latency_median_us);
        println!("  Latency p95:     {} µs", report.latency_p95_us);
        println!("  Latency max:     {} µs", report.latency_max_us);

        assert_eq!(report.frames_sent, 120);
        assert_eq!(report.frames_received, 120);
        assert_eq!(
            report.lossless_match_count, 120,
            "all frames must be lossless"
        );
        assert!(
            report.latency_median_us < 100_000,
            "median latency must be < 100ms on loopback"
        );
    }
}
