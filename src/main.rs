use sourcebastion_policy_engine::{evaluate_bytes, ResultRecord, MAX_INPUT_BYTES};
use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const WALL_LIMIT: Duration = Duration::from_secs(5);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut input = Vec::new();
    let read_result = io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input);
    if read_result.is_err() {
        emit_and_exit(&ResultRecord::error("INVALID_REQUEST"));
    }
    match arguments.as_slice() {
        [] => {
            if input.len() > MAX_INPUT_BYTES {
                emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
            }
            supervised_evaluate(&input, false);
        }
        [command] if command == "evaluate" => {
            if input.len() > MAX_INPUT_BYTES {
                emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
            }
            supervised_evaluate(&input, false);
        }
        [command] if command == "evaluate-rule-sets" => {
            if input.len() > MAX_INPUT_BYTES {
                emit_failure("RESOURCE_LIMIT", true);
            }
            supervised_evaluate(&input, true);
        }
        [command] if command == "__rule_sets_worker" => {
            if !apply_worker_limits() {
                emit_failure("RESOURCE_LIMIT", true);
            }
            let result = sourcebastion_policy_engine::rule_set_evaluation::evaluate_bytes(&input);
            emit_json_and_exit(&result, result.exit_code());
        }
        [command] if command == "__worker" => {
            if !apply_worker_limits() {
                emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
            }
            emit_and_exit(&evaluate_bytes(&input));
        }
        [command] if command == "convert-plan09" => {
            match sourcebastion_policy_engine::migration::convert_bytes(&input) {
                Ok(conversion) => emit_json_and_exit(&conversion, 0),
                Err(error) => {
                    emit_json_and_exit(&serde_json::json!({"error_code": error.code()}), 2)
                }
            }
        }
        [command] if command == "compile-gate" => {
            match sourcebastion_policy_engine::gate_settings::compile_bytes(&input) {
                Ok(bundle) => emit_json_and_exit(&serde_json::json!({"bundles": [bundle]}), 0),
                Err(error) => {
                    emit_json_and_exit(&serde_json::json!({"error_code": error.code()}), 2)
                }
            }
        }
        [command] if command == "compile-rule-sets-preview" => {
            match sourcebastion_policy_engine::rule_sets::compile_bytes(
                &input,
                &sourcebastion_policy_engine::SEVERITIES,
            ) {
                Ok(rules) => emit_json_and_exit(
                    &serde_json::json!({
                        "compiler_profile": "rule-sets.preview.v1", "schema_version": 2,
                        "engine_version": env!("CARGO_PKG_VERSION"),
                        "supported_kinds": ["finding_count"],
                        "supported_severities": sourcebastion_policy_engine::SEVERITIES,
                        "rules": rules,
                    }),
                    0,
                ),
                Err(error) => emit_json_and_exit(
                    &serde_json::json!({
                        "error_code": match error {
                            sourcebastion_policy_engine::rule_sets::Error::ResourceLimit => "RESOURCE_LIMIT",
                            sourcebastion_policy_engine::rule_sets::Error::UnsupportedSeverity => "UNSUPPORTED_SEVERITY",
                            sourcebastion_policy_engine::rule_sets::Error::InvalidDocument => "INVALID_RULE_SETS",
                        }
                    }),
                    2,
                ),
            }
        }
        _ => emit_json_and_exit(&serde_json::json!({"error_code": "INVALID_COMMAND"}), 2),
    }
}

fn emit_failure(code: &'static str, rule_sets: bool) -> ! {
    if rule_sets {
        let result = sourcebastion_policy_engine::rule_set_evaluation::Result::error(code);
        emit_json_and_exit(&result, 2);
    }
    emit_and_exit(&ResultRecord::error(code))
}

fn supervised_evaluate(input: &[u8], rule_sets: bool) -> ! {
    let start = Instant::now();
    let max_output = if rule_sets {
        4 * 1024 * 1024
    } else {
        MAX_OUTPUT_BYTES
    };
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => emit_failure("INTERNAL_ERROR", rule_sets),
    };
    let mut child = match Command::new(executable)
        .arg(if rule_sets {
            "__rule_sets_worker"
        } else {
            "__worker"
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => emit_failure("INTERNAL_ERROR", rule_sets),
    };
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        emit_failure("INTERNAL_ERROR", rule_sets);
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        emit_failure("INTERNAL_ERROR", rule_sets);
    };
    let input_bytes = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input_bytes));
    // Drain output while the worker runs; a full pipe would otherwise prevent
    // the worker from exiting, even for a valid bounded result.
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let read_result = stdout
            .take((max_output + 1) as u64)
            .read_to_end(&mut output);
        read_result.map(|_| output)
    });
    let status = match wait_for_worker(&mut child, start, WALL_LIMIT) {
        Ok(status) => status,
        Err(_) => emit_failure("RESOURCE_LIMIT", rule_sets),
    };
    if !writer.join().is_ok_and(|write_result| write_result.is_ok()) {
        emit_failure("RESOURCE_LIMIT", rule_sets);
    }
    let output = match reader.join() {
        Ok(Ok(output)) if output.len() <= max_output => output,
        _ => emit_failure("RESOURCE_LIMIT", rule_sets),
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&output) {
        Ok(value) => value,
        Err(_) => emit_failure("RESOURCE_LIMIT", rule_sets),
    };
    let expected_code = match parsed.get("status").and_then(|value| value.as_str()) {
        Some("passed") => 0,
        Some("failed") if !rule_sets => 1,
        Some("error") if !rule_sets => 2,
        Some("passed_with_warnings" | "gating_disabled") if rule_sets => 0,
        Some("blocked") if rule_sets => 1,
        Some("unevaluable") if rule_sets => 2,
        _ => emit_failure("INTERNAL_ERROR", rule_sets),
    };
    if status.code() != Some(expected_code) {
        emit_failure("RESOURCE_LIMIT", rule_sets);
    }
    let mut out = io::stdout().lock();
    if out.write_all(&output).is_err() {
        std::process::exit(2);
    }
    std::process::exit(expected_code);
}

fn wait_for_worker(
    child: &mut Child,
    start: Instant,
    limit: Duration,
) -> Result<ExitStatus, Box<ResultRecord>> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Box::new(ResultRecord::error("RESOURCE_LIMIT")));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_worker_limits() -> bool {
    let address_space = libc::rlimit {
        rlim_cur: 512 * 1024 * 1024,
        rlim_max: 512 * 1024 * 1024,
    };
    let cpu = libc::rlimit {
        rlim_cur: 3,
        rlim_max: 3,
    };
    // SAFETY: these are valid Linux resource constants and initialized limits.
    unsafe {
        libc::setrlimit(libc::RLIMIT_AS, &address_space) == 0
            && libc::setrlimit(libc::RLIMIT_CPU, &cpu) == 0
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_worker_limits() -> bool {
    false
}

fn emit_and_exit(result: &ResultRecord) -> ! {
    emit_json_and_exit(result, result.exit_code())
}

fn emit_json_and_exit<T: serde::Serialize>(value: &T, exit_code: i32) -> ! {
    let mut out = io::stdout().lock();
    if serde_json::to_writer(&mut out, value).is_err() || out.write_all(b"\n").is_err() {
        std::process::exit(2);
    }
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_out_worker_is_unevaluable() {
        let mut child = Command::new("sleep").arg("1").spawn().unwrap();
        let result = wait_for_worker(&mut child, Instant::now(), Duration::from_millis(20));
        let error = result.unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.diagnostic_codes, ["RESOURCE_LIMIT"]);
        assert!(child.try_wait().unwrap().is_some());
    }
}
