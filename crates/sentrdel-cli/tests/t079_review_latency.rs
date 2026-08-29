#![forbid(unsafe_code)]

use sentrdel_review::{
    secrets::scan_changed_secrets, structural::StructuralRegistry,
    structural_rules::high_signal_structural_rules, view::NormalizedRepoPath,
};
use serde::Serialize;
use std::{
    env,
    hint::black_box,
    thread::available_parallelism,
    time::{Duration, Instant},
};

const CAPTURED_AT: &str = "2026-08-29T00:00:00Z";
const SMALL_CHANGED_LOC: usize = 1_500;
const BROADER_CHANGED_LOC: usize = 100_000;
const SMALL_TARGET: Duration = Duration::from_secs(5);
const BROADER_TARGET: Duration = Duration::from_secs(30);
const SMALL_SAMPLES: usize = 20;
const BROADER_SAMPLES: usize = 5;

#[derive(Debug, Serialize)]
struct BenchmarkMachine {
    os: &'static str,
    arch: &'static str,
    logical_cpus: usize,
    github_actions: bool,
}

#[derive(Debug, Serialize)]
struct LatencyMeasurement {
    changed_loc: usize,
    samples: usize,
    p95_millis: u128,
    target_millis: u128,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct ReviewLatencyRecord {
    benchmark: &'static str,
    machine: BenchmarkMachine,
    small: LatencyMeasurement,
    broader: LatencyMeasurement,
}

fn benchmark_source(changed_loc: usize) -> Vec<u8> {
    let mut source = String::with_capacity(changed_loc.saturating_mul(24));
    for line in 0..changed_loc {
        use std::fmt::Write as _;
        writeln!(&mut source, "const safe_{line} = {line};").expect("write benchmark source");
    }
    source.into_bytes()
}

fn p95(samples: &mut [Duration]) -> Duration {
    assert!(!samples.is_empty(), "latency benchmark requires samples");
    samples.sort_unstable();
    let rank = samples.len().saturating_mul(95).div_ceil(100).max(1);
    samples[rank - 1]
}

fn measure_warm_review(changed_loc: usize, sample_count: usize) -> Duration {
    let source = benchmark_source(changed_loc);
    let path = NormalizedRepoPath::parse("src/t079-benchmark.js", 512).expect("benchmark path");
    let registry =
        StructuralRegistry::new(high_signal_structural_rules()).expect("structural rules");

    let warm_secret = scan_changed_secrets(&path, &source, CAPTURED_AT).expect("warm secret scan");
    let warm_structural = registry.scan(&path, &source).expect("warm structural scan");
    assert!(warm_secret.is_empty());
    assert!(warm_structural.is_empty());

    let mut samples = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let started = Instant::now();
        let secret = scan_changed_secrets(&path, black_box(&source), CAPTURED_AT)
            .expect("timed secret scan");
        let structural = registry
            .scan(&path, black_box(&source))
            .expect("timed structural scan");
        black_box((&secret, &structural));
        assert!(secret.is_empty());
        assert!(structural.is_empty());
        samples.push(started.elapsed());
    }
    p95(&mut samples)
}

fn measurement(changed_loc: usize, samples: usize, target: Duration) -> LatencyMeasurement {
    let observed = measure_warm_review(changed_loc, samples);
    LatencyMeasurement {
        changed_loc,
        samples,
        p95_millis: observed.as_millis(),
        target_millis: target.as_millis(),
        passed: observed < target,
    }
}

#[test]
fn warm_native_review_latency_targets_are_machine_attributed() {
    let small = measurement(SMALL_CHANGED_LOC, SMALL_SAMPLES, SMALL_TARGET);
    let broader = measurement(BROADER_CHANGED_LOC, BROADER_SAMPLES, BROADER_TARGET);
    let record = ReviewLatencyRecord {
        benchmark: "sentrdelbench-r1/t079-review-latency-v1",
        machine: BenchmarkMachine {
            os: env::consts::OS,
            arch: env::consts::ARCH,
            logical_cpus: available_parallelism().map_or(1, usize::from),
            github_actions: env::var_os("GITHUB_ACTIONS").is_some(),
        },
        small,
        broader,
    };

    println!(
        "{}",
        serde_json::to_string(&record).expect("machine-readable T079 latency record")
    );

    assert!(
        record.small.passed,
        "warm native review p95 for <2k changed LOC must remain below 5 seconds: {record:?}"
    );
    assert!(
        record.broader.passed,
        "broader 100k-LOC warm native review p95 must remain below 30 seconds: {record:?}"
    );
}
