use std::{env, io::Write, process::ExitCode};

use cfctl_cli::{Cli, InvocationMode, classify_invocation, runtime};
use cfctl_core::ResultEnvelopeV2;
use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    let mode = classify_invocation(arguments.clone());
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let result = match mode {
        InvocationMode::NaturalLanguage(intent) => runtime::execute_natural_language(&intent).await,
        InvocationMode::Deterministic => match Cli::try_parse_from(arguments) {
            Ok(cli) => runtime::execute(cli).await,
            Err(error) => {
                let exit_code = u8::try_from(error.exit_code()).unwrap_or(2);
                if json_requested && exit_code == 2 {
                    let envelope = ResultEnvelopeV2::failure(
                        "cfctl",
                        "CFCTL_USAGE",
                        &error.to_string(),
                        Some("Run `cfctl --help` and correct the rejected arguments."),
                    );
                    let Ok(output) = runtime::render(&envelope, true) else {
                        return ExitCode::from(1);
                    };
                    if std::io::stderr().write_all(output.as_bytes()).is_err() {
                        return ExitCode::from(1);
                    }
                    return ExitCode::from(exit_code);
                }
                let _ignored = error.print();
                return ExitCode::from(exit_code);
            }
        },
    };
    let (envelope, success) = match result {
        Ok(envelope) => {
            let success = envelope.ok;
            (envelope, success)
        }
        Err(error) => (
            ResultEnvelopeV2::failure(
                "cfctl",
                "CFCTL_ERROR",
                &error.to_string(),
                Some("Run `cfctl doctor --json` and inspect the exact blocker."),
            ),
            false,
        ),
    };
    match runtime::render(&envelope, json_requested) {
        Ok(output) => {
            let target: &mut dyn Write = if success {
                &mut std::io::stdout()
            } else {
                &mut std::io::stderr()
            };
            if target.write_all(output.as_bytes()).is_err() {
                return ExitCode::from(1);
            }
        }
        Err(_) => return ExitCode::from(1),
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
