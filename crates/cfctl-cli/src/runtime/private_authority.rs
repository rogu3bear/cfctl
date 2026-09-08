use super::prelude::{CliError, Result, ResultEnvelopeV2, StateStore};
use crate::{EvidenceKeyPrivateRebindArgs, EvidenceKeyPrivateRebindPreviewArgs};

pub(super) fn preview(
    store: &StateStore,
    arguments: &EvidenceKeyPrivateRebindPreviewArgs,
) -> Result<ResultEnvelopeV2> {
    let preview = store.private_authority_rebind_preview(arguments.previous_device)?;
    Ok(ResultEnvelopeV2::success(
        "auth evidence-key private-rebind-preview",
        serde_json::to_value(preview)?,
    ))
}

pub(super) fn rebind(
    store: &StateStore,
    arguments: &EvidenceKeyPrivateRebindArgs,
) -> Result<ResultEnvelopeV2> {
    if !arguments.yes {
        return Err(CliError::Input("private authority rebinding requires the exact reviewed digest and --yes; run private-rebind-preview first".to_owned()));
    }
    let result =
        store.rebind_private_authority(arguments.previous_device, &arguments.expected_review)?;
    let performed = !result.already_bound;
    let mut envelope = ResultEnvelopeV2::success(
        "auth evidence-key private-rebind",
        serde_json::to_value(result)?,
    );
    envelope.performed = performed;
    Ok(envelope)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{EvidenceKeyPrivateRebindArgs, rebind};
    use cfctl_storage::{RuntimePaths, StateStore};

    #[test]
    fn private_rebind_requires_confirmation_before_touching_authority() {
        let root = tempfile::tempdir().expect("test root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("test store");
        let arguments = EvidenceKeyPrivateRebindArgs {
            previous_device: 17,
            expected_review: "sha256:review".to_owned(),
            yes: false,
        };
        assert!(
            rebind(&store, &arguments)
                .expect_err("confirmation required")
                .to_string()
                .contains("--yes")
        );
        assert!(store.evidence_root_identity().expect("marker").is_none());
        assert!(!store.paths().data_dir.join("private-authority").exists());
    }
}
