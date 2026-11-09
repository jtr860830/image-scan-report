//! Integration checks for perf behavior.
use image_scan_report::{
    model::Language,
    render::{self, model::RenderOptions, theme},
};
#[allow(dead_code)]
#[path = "support/data.rs"]
mod data;
#[allow(dead_code)]
#[path = "support/pdf.rs"]
mod pdf;

// Linux reports the process high-water mark. macOS ps reports current RSS,
// sampled after rendering, rather than a lifetime high-water mark.
fn peak_rss_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb = status.lines().find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })?;
        Some(kb / 1024)
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let kb = std::str::from_utf8(&output.stdout)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        Some(kb / 1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn budget(minimum: usize, seconds: f64) {
    let base = data::fixture_report(11);
    let mut report = base.clone();
    let mut repetition = 1;
    while report.findings.len() < minimum {
        for image in &base.images {
            let mut image = image.clone();
            image.reference = format!("{}-r{repetition}", image.reference);
            report.images.push(image);
        }
        for finding in &base.findings {
            let mut finding = finding.clone();
            finding.image = format!("{}-r{repetition}", finding.image);
            report.findings.push(finding);
        }
        repetition += 1;
    }
    let opts = RenderOptions {
        min_severity: None,
        image_detail: image_scan_report::model::ImageDetail::Full,
        max_table_rows: None,
        json_artifact: false,
        describe_severities: vec![
            image_scan_report::model::Severity::Critical,
            image_scan_report::model::Severity::High,
        ],
        description_chars: 600,
        remediation_cards: 30,
        customer_logo: None,
        language: Language::ZhTw,
        stale_after_days: 30,
        product_name: "judex".into(),
        product_version: "0.1.0".into(),
        top_images: 10,
        top_findings: 15,
    };
    let start = std::time::Instant::now();
    let bytes = render::render_pdf(&report, &opts, &theme::default_theme()).unwrap();
    let elapsed = start.elapsed().as_secs_f64();
    let pages = pdf::page_count(&bytes);
    println!(
        "{} findings: {elapsed:.3} seconds, {pages} pages",
        report.findings.len()
    );
    match peak_rss_mb() {
        Some(mb) => println!("peak_rss_mb={mb}"),
        None => println!("peak_rss_mb=unknown"),
    }
    assert!(elapsed < seconds, "{elapsed:.3}s exceeds {seconds}s budget");
    assert!(pages > 400, "{pages} pages");
}
#[test]
#[ignore = "release-mode budget"]
fn thirty_thousand_findings_under_budget() {
    budget(30_000, 90.0);
}
#[test]
#[ignore = "release-mode budget"]
fn fifty_thousand_findings_under_budget() {
    budget(50_000, 150.0);
}
