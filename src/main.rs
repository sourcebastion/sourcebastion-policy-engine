use sourcebastion_policy_engine::{evaluate_bytes, ResultRecord, MAX_INPUT_BYTES};
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
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
            supervised_evaluate(&input);
        }
        [command] if command == "evaluate" => {
            if input.len() > MAX_INPUT_BYTES {
                emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
            }
            supervised_evaluate(&input);
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
        _ => emit_json_and_exit(&serde_json::json!({"error_code": "INVALID_COMMAND"}), 2),
    }
}

fn supervised_evaluate(input: &[u8]) -> ! {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => emit_and_exit(&ResultRecord::error("INTERNAL_ERROR")),
    };
    let mut child = match Command::new(executable)
        .arg("__worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => emit_and_exit(&ResultRecord::error("INTERNAL_ERROR")),
    };
    if child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(input).is_err())
    {
        let _ = child.kill();
        let _ = child.wait();
        emit_and_exit(&ResultRecord::error("INTERNAL_ERROR"));
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut output = Vec::new();
                let read_result = child.stdout.take().map(|stdout| {
                    stdout
                        .take((MAX_OUTPUT_BYTES + 1) as u64)
                        .read_to_end(&mut output)
                });
                if !matches!(read_result, Some(Ok(_))) || output.len() > MAX_OUTPUT_BYTES {
                    emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
                }
                let parsed: serde_json::Value = match serde_json::from_slice(&output) {
                    Ok(value) => value,
                    Err(_) => emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT")),
                };
                let expected_code = match parsed.get("status").and_then(|value| value.as_str()) {
                    Some("passed") => 0,
                    Some("failed") => 1,
                    Some("error") => 2,
                    _ => emit_and_exit(&ResultRecord::error("INTERNAL_ERROR")),
                };
                if status.code() != Some(expected_code) {
                    emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
                }
                let mut out = io::stdout().lock();
                if out.write_all(&output).is_err() {
                    std::process::exit(2);
                }
                std::process::exit(expected_code);
            }
            Ok(None) if start.elapsed() < WALL_LIMIT => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                emit_and_exit(&ResultRecord::error("RESOURCE_LIMIT"));
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
