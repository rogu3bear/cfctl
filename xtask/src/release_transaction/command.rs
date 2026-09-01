use std::{path::Path, process::Command};

use crate::{TaskError, io_error};

const MAX_DIAGNOSTIC_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandOutput {
    pub(super) code: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

pub(super) trait CommandRunner {
    fn output(&mut self, program: &str, arguments: &[&str]) -> Result<CommandOutput, TaskError>;
}

#[derive(Default)]
pub(super) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn output(&mut self, program: &str, arguments: &[&str]) -> Result<CommandOutput, TaskError> {
        let result = Command::new(program)
            .args(arguments)
            .output()
            .map_err(|source| io_error(Path::new(program), source))?;
        Ok(CommandOutput {
            code: result.status.code(),
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }
}

pub(super) fn checked_output(
    runner: &mut impl CommandRunner,
    program: &str,
    arguments: &[&str],
    public_label: &str,
) -> Result<String, TaskError> {
    let output = runner.output(program, arguments)?;
    if output.code == Some(0) {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    let diagnostics = bounded_redacted_diagnostics(&output);
    let suffix = if diagnostics.is_empty() {
        "no safe diagnostics were emitted".to_owned()
    } else {
        diagnostics
    };
    Err(TaskError::Command(format!(
        "{public_label} exited {:?}: {suffix}",
        output.code
    )))
}

pub(super) fn bounded_redacted_diagnostics(output: &CommandOutput) -> String {
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    if !combined.is_empty() && !output.stderr.is_empty() {
        combined.push('\n');
    }
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    let mut redacted = combined
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "authorization",
                "bearer ",
                "password",
                "secret",
                "token",
                "credential",
                "private key",
                "apple-id",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                "[REDACTED]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    redacted = redacted.trim().to_owned();
    if redacted.len() > MAX_DIAGNOSTIC_BYTES {
        let mut boundary = MAX_DIAGNOSTIC_BYTES.saturating_sub("\n[TRUNCATED]".len());
        while !redacted.is_char_boundary(boundary) {
            boundary -= 1;
        }
        redacted.truncate(boundary);
        redacted.push_str("\n[TRUNCATED]");
    }
    redacted
}
