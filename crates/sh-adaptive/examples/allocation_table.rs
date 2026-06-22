//! Pretty-print channel allocations at several representative total bitrates.
//!
//! Run with:
//!
//! ```text
//! cargo run -p sh-adaptive --example allocation_table
//! ```

use sh_adaptive::allocator::{AllocatorConfig, RateAllocator};
use sh_types::Bitrate;

fn main() {
    let config = AllocatorConfig::default();
    let alloc = RateAllocator::new(config);

    println!();
    println!(
        "{:<14} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Total", "Input", "Control", "Clipboard", "Audio", "Video", "File", "Sum"
    );
    println!("{}", "-".repeat(92));

    for &kbps in &[
        0u64, 1, 32, 96, 192, 200, 300, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 25_000,
    ] {
        let total = Bitrate::from_kbps(kbps);
        let r = alloc.allocate(total);
        println!(
            "{:<14} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            format!("{} kbps", kbps),
            r.input().as_kbps(),
            r.control().as_kbps(),
            r.clipboard().as_kbps(),
            r.audio().as_kbps(),
            r.video().as_kbps(),
            r.file().as_kbps(),
            r.sum().as_kbps(),
        );
    }
    println!();
}
