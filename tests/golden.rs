//! Exact protocol bytes must agree across native amd64 and arm64 test runs.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn complete_fixture_corpus_matches_golden_bytes() {
    let binary = env!("CARGO_BIN_EXE_sourcebastion-policy");
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for name in [
        "blocked",
        "warning",
        "malformed",
        "incomplete",
        "conflicting",
    ] {
        let request = fs::read(fixture_dir.join(format!("{name}.request.json"))).unwrap();
        let expected = fs::read(fixture_dir.join(format!("{name}.expected.json"))).unwrap();
        let mut child = Command::new(binary)
            .arg("evaluate")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&request).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.stdout, expected, "{name}: output bytes changed");
        let parsed: Value = serde_json::from_slice(&expected).unwrap();
        let expected_exit = match parsed["status"].as_str().unwrap() {
            "passed" => 0,
            "failed" => 1,
            "error" => 2,
            other => panic!("{name}: unsupported fixture status {other}"),
        };
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{name}: exit mismatch"
        );
        assert!(output.stderr.is_empty(), "{name}: unexpected stderr output");
    }
}
