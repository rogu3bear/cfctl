use std::{env, io::Write, process::ExitCode};

use cfctl_cli::{Cli, Command, InvocationMode, PlansCommand, classify_invocation, runtime};
use cfctl_core::ResultEnvelopeV2;
use clap::Parser;

struct FailureEnvelopeContext {
    command: &'static str,
    operation_id: Option<String>,
}

impl FailureEnvelopeContext {
    fn generic() -> Self {
        Self {
            command: "cfctl",
            operation_id: None,
        }
    }

    fn deterministic(cli: &Cli) -> Self {
        let Some(Command::Plans(arguments)) = &cli.command else {
            return Self::generic();
        };
        let (command, operation_id) = match &arguments.command {
            PlansCommand::Show(selector) => ("plans show", &selector.operation_id),
            PlansCommand::Approve(arguments) => ("plans approve", &arguments.operation_id),
            PlansCommand::Run(selector) => ("plans run", &selector.operation_id),
            PlansCommand::Status(selector) => ("plans status", &selector.operation_id),
            PlansCommand::Resume(selector) => ("plans resume", &selector.operation_id),
            PlansCommand::Rectify(selector) => ("plans rectify", &selector.operation_id),
            PlansCommand::Cancel(selector) => ("plans cancel", &selector.operation_id),
            PlansCommand::Bundle(_) => return Self::generic(),
        };
        Self {
            command,
            operation_id: Some(operation_id.clone()),
        }
    }
}

fn failure_envelope(
    context: &FailureEnvelopeContext,
    error: &runtime::CliError,
) -> ResultEnvelopeV2 {
    let next_step = error
        .next_step()
        .unwrap_or_else(|| "Run `cfctl doctor --json` and inspect the exact blocker.".to_owned());
    let mut envelope = ResultEnvelopeV2::failure(
        context.command,
        error.code(),
        &error.to_string(),
        Some(next_step.as_str()),
    );
    envelope.operation_id.clone_from(&context.operation_id);
    envelope
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    let mode = classify_invocation(arguments.clone());
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let (result, failure_context) = match mode {
        InvocationMode::NaturalLanguage(intent) => (
            runtime::execute_natural_language(&intent).await,
            FailureEnvelopeContext::generic(),
        ),
        InvocationMode::Deterministic => match Cli::try_parse_from(arguments) {
            Ok(cli) => {
                let context = FailureEnvelopeContext::deterministic(&cli);
                (runtime::execute(cli).await, context)
            }
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
        Err(error) => (failure_envelope(&failure_context, &error), false),
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

#[cfg(test)]
mod tests {
    use cfctl_cli::runtime::CliError;
    use cfctl_core::{CoreError, PlanStatus};
    use clap::Parser as _;

    use super::{Cli, FailureEnvelopeContext, failure_envelope};

    #[test]
    fn duplicate_plan_approval_failure_keeps_command_and_operation_context() {
        let operation_id = "ab2c8ee6-8d88-4d3a-a015-2329b65bf6d3";
        let cli = match Cli::try_parse_from([
            "cfctl",
            "plans",
            "approve",
            operation_id,
            "--yes",
            "--json",
        ]) {
            Ok(cli) => cli,
            Err(error) => panic!("valid duplicate approval command: {error}"),
        };
        let context = FailureEnvelopeContext::deterministic(&cli);
        let error = CliError::from(CoreError::InvalidPlanState {
            operation_id: operation_id.to_owned(),
            actual: PlanStatus::Approved,
            expected: "draft",
        });

        let envelope = failure_envelope(&context, &error);

        assert!(!envelope.ok);
        assert!(!envelope.performed);
        assert_eq!(envelope.command, "plans approve");
        assert_eq!(envelope.operation_id.as_deref(), Some(operation_id));
        let Some(error) = envelope.error else {
            panic!("failure envelope must include failure details");
        };
        assert_eq!(error.code, "CFCTL_PLAN_LIFECYCLE");
        assert!(error.message.contains("Approved; expected draft"));
        assert_eq!(
            error.next_step.as_deref(),
            Some(
                "The plan is already approved; run it: `cfctl plans run ab2c8ee6-8d88-4d3a-a015-2329b65bf6d3`."
            )
        );
    }
}
