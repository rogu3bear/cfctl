use cfctl_cli::Cli;
use clap::Parser as _;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one parser contract enumerates the complete evidence-key lifecycle and exact confirmations"
)]
fn evidence_key_lifecycle_surface_is_explicit_and_retirement_requires_confirmation() {
    use cfctl_cli::{AuthCommand, Command, EvidenceKeyCommand};

    for action in [
        "private-preview",
        "private-history",
        "adopt-preview",
        "init-preview",
        "init",
        "status",
        "rotate",
        "recover-preview",
    ] {
        let cli = Cli::try_parse_from(["cfctl", "auth", "evidence-key", action])
            .expect("evidence-key lifecycle action parses");
        let Some(Command::Auth(arguments)) = cli.command else {
            panic!("auth command");
        };
        let AuthCommand::EvidenceKey(group) = arguments.command else {
            panic!("evidence-key command");
        };
        let parsed = match group.command {
            EvidenceKeyCommand::PrivatePreview => "private-preview",
            EvidenceKeyCommand::PrivateActivate(_) => "private-activate",
            EvidenceKeyCommand::PrivateHistory => "private-history",
            EvidenceKeyCommand::AdoptPreview => "adopt-preview",
            EvidenceKeyCommand::AdoptPlan(_) => "adopt-plan",
            EvidenceKeyCommand::Adopt(_) => "adopt",
            EvidenceKeyCommand::InitPreview => "init-preview",
            EvidenceKeyCommand::Init => "init",
            EvidenceKeyCommand::Status => "status",
            EvidenceKeyCommand::Rotate => "rotate",
            EvidenceKeyCommand::Retire(_) => "retire",
            EvidenceKeyCommand::RecoverPreview => "recover-preview",
            EvidenceKeyCommand::RecoverPlan(_) => "recover-plan",
            EvidenceKeyCommand::Recover(_) => "recover",
            EvidenceKeyCommand::Reset(_) => "reset",
        };
        assert_eq!(parsed, action);
    }

    let cli = Cli::try_parse_from([
        "cfctl",
        "auth",
        "evidence-key",
        "retire",
        "7ff2b63e-f412-4a73-978a-e88b86ef5327",
        "--yes",
    ])
    .expect("evidence-key retire parses");
    let Some(Command::Auth(arguments)) = cli.command else {
        panic!("auth command");
    };
    let AuthCommand::EvidenceKey(group) = arguments.command else {
        panic!("evidence-key command");
    };
    let EvidenceKeyCommand::Retire(retire) = group.command else {
        panic!("retire command");
    };
    assert!(retire.yes);

    // Reset discards an authority, so confirmation is part of its parser contract and
    // must never default to true.
    for (arguments, expected) in [
        (vec!["cfctl", "auth", "evidence-key", "reset"], false),
        (
            vec!["cfctl", "auth", "evidence-key", "reset", "--yes"],
            true,
        ),
    ] {
        let cli = Cli::try_parse_from(arguments).expect("evidence-key reset parses");
        let Some(Command::Auth(arguments)) = cli.command else {
            panic!("auth command");
        };
        let AuthCommand::EvidenceKey(group) = arguments.command else {
            panic!("evidence-key command");
        };
        let EvidenceKeyCommand::Reset(reset) = group.command else {
            panic!("reset command");
        };
        assert_eq!(reset.yes, expected);
    }

    let plan_id = "7ff2b63e-f412-4a73-978a-e88b86ef5327";
    for action in ["status", "revoke"] {
        let arguments = vec![
            "cfctl",
            "auth",
            "evidence-key",
            "recover-plan",
            action,
            plan_id,
        ];
        Cli::try_parse_from(arguments).expect("recovery-plan lifecycle action parses");
    }
    Cli::try_parse_from(["cfctl", "auth", "evidence-key", "recover-plan", "create"])
        .expect("recovery-plan creation parses");

    let cli = Cli::try_parse_from(["cfctl", "auth", "evidence-key", "recover", plan_id, "--yes"])
        .expect("evidence-key recover parses");
    let Some(Command::Auth(arguments)) = cli.command else {
        panic!("auth command");
    };
    let AuthCommand::EvidenceKey(group) = arguments.command else {
        panic!("evidence-key command");
    };
    let EvidenceKeyCommand::Recover(recover) = group.command else {
        panic!("recover command");
    };
    assert!(recover.yes);

    for action in ["current", "status", "revoke"] {
        if action == "current" {
            Cli::try_parse_from(["cfctl", "auth", "evidence-key", "adopt-plan", action])
                .expect("current adoption plan parses without an ID");
            continue;
        }
        Cli::try_parse_from([
            "cfctl",
            "auth",
            "evidence-key",
            "adopt-plan",
            action,
            plan_id,
        ])
        .expect("adoption-plan lifecycle action parses");
    }
    Cli::try_parse_from(["cfctl", "auth", "evidence-key", "adopt-plan", "create"])
        .expect("disabled adoption-plan creation remains an explicit command surface");
    assert!(
        Cli::try_parse_from([
            "cfctl",
            "auth",
            "evidence-key",
            "adopt-plan",
            "create",
            "--source-candidate-identity",
            "git:0123456789abcdef0123456789abcdef01234567",
        ])
        .is_err(),
        "raw caller identity claims are not accepted as adoption authority"
    );
    let cli = Cli::try_parse_from(["cfctl", "auth", "evidence-key", "adopt", plan_id, "--yes"])
        .expect("evidence-key adopt parses");
    let Some(Command::Auth(arguments)) = cli.command else {
        panic!("auth command");
    };
    let AuthCommand::EvidenceKey(group) = arguments.command else {
        panic!("evidence-key command");
    };
    let EvidenceKeyCommand::Adopt(adopt) = group.command else {
        panic!("adopt command");
    };
    assert!(adopt.yes);
}

#[test]
fn private_activation_requires_a_plan_and_explicit_confirmation() {
    use cfctl_cli::{AuthCommand, Command, EvidenceKeyCommand};
    let plan_id = "7ff2b63e-f412-4a73-978a-e88b86ef5327";
    assert!(Cli::try_parse_from(["cfctl", "auth", "evidence-key", "private-activate"]).is_err());
    for confirmed in [false, true] {
        let mut arguments = vec!["cfctl", "auth", "evidence-key", "private-activate", plan_id];
        if confirmed {
            arguments.push("--yes");
        }
        let cli = Cli::try_parse_from(arguments).expect("private activation parses");
        let Some(Command::Auth(arguments)) = cli.command else {
            panic!("auth command");
        };
        let AuthCommand::EvidenceKey(group) = arguments.command else {
            panic!("evidence-key command");
        };
        let EvidenceKeyCommand::PrivateActivate(activation) = group.command else {
            panic!("private activation");
        };
        assert_eq!(activation.plan_id, plan_id);
        assert_eq!(activation.yes, confirmed);
    }
}
