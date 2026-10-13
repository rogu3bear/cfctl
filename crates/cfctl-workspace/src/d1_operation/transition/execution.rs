//! Deterministic ledger placement. No provider call or execution admission.
use cfctl_core::workspace_d1::transition::{
    EXECUTION_COMPILER_ID, ExecutionManifest, MAX_ENVELOPE_BYTES, Segment, Target,
};

use super::{Result, invariant, sha256};

pub(super) fn materialize(
    source: &[u8],
    compiled: &cfctl_core::workspace_d1::transition::Compiled,
) -> Result<Vec<u8>> {
    let expected = compile(source, &compiled.segments, &compiled.declaration.target)?;
    if expected != compiled.execution {
        return Err(invariant("native execution manifest changed"));
    }
    let mut bytes = Vec::with_capacity(expected.execution_length);
    bytes.extend_from_slice(&source[..expected.ledger_offset]);
    bytes.extend_from_slice(&ledger_sql(&compiled.declaration.target)?);
    bytes.extend_from_slice(&source[expected.ledger_offset..]);
    if bytes.len() != expected.execution_length || sha256(&bytes) != expected.execution_sha256 {
        return Err(invariant(
            "native execution bytes differ from their manifest",
        ));
    }
    Ok(bytes)
}

/// The installed ledger must independently qualify this exact table/column/default
/// contract. No ledger bootstrap or inferred predecessor entries are generated.
fn ledger_sql(target: &Target) -> Result<Vec<u8>> {
    if target.file.is_empty() || target.file.contains(['\0', '\n', '\r']) {
        return Err(invariant("V3 target ledger filename is invalid"));
    }
    Ok(format!(
        "INSERT INTO \"d1_migrations\" (\"name\") VALUES ('{}');\n",
        target.file.replace('\'', "''")
    )
    .into_bytes())
}

pub(super) fn compile(
    source: &[u8],
    segments: &[Segment],
    target: &Target,
) -> Result<ExecutionManifest> {
    if segments.len() != 5 || segments[2].source != target.source {
        return Err(invariant(
            "V3 execution requires the exact five source segments",
        ));
    }
    let mut offset = 0_usize;
    for segment in segments {
        let end = offset
            .checked_add(segment.length)
            .ok_or_else(|| invariant("V3 execution segment offset overflow"))?;
        if segment.offset != offset
            || segment.length == 0
            || source.get(offset..end).is_none_or(|bytes| {
                !bytes.ends_with(b"\n") || sha256(bytes) != segment.source.sha256
            })
        {
            return Err(invariant(
                "V3 execution source segment bytes or offsets differ",
            ));
        }
        offset = end;
    }
    if offset != source.len() {
        return Err(invariant("V3 execution has unbound source bytes"));
    }
    let ledger = ledger_sql(target)?;
    let length = source
        .len()
        .checked_add(ledger.len())
        .filter(|length| *length <= MAX_ENVELOPE_BYTES)
        .ok_or_else(|| invariant("V3 execution including ledger exceeds its byte bound"))?;
    let ledger_offset = segments[4].offset;
    let mut execution = Vec::with_capacity(length);
    execution.extend_from_slice(&source[..ledger_offset]);
    execution.extend_from_slice(&ledger);
    execution.extend_from_slice(&source[ledger_offset..]);
    Ok(ExecutionManifest {
        compiler_id: EXECUTION_COMPILER_ID.to_owned(),
        source_envelope_sha256: sha256(source),
        ledger_name: target.file.clone(),
        ledger_offset,
        ledger_length: ledger.len(),
        ledger_sha256: sha256(&ledger),
        execution_length: length,
        execution_sha256: sha256(&execution),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use cfctl_core::workspace_d1::transition::Source;

    fn specimen() -> (Vec<u8>, Vec<Segment>, Target) {
        let mut bytes = Vec::new();
        let mut segments = Vec::new();
        for (index, sql) in [
            "-- preconditions\nSELECT 1;\n",
            "-- capture\nSELECT 2;\n",
            "-- immutable original\nPRAGMA foreign_keys=ON;\nSELECT 3;\n",
            "-- preservation\nSELECT 4;\n",
            "-- cleanup\nSELECT 5;\n",
        ]
        .iter()
        .enumerate()
        {
            segments.push(Segment {
                source: Source {
                    path: format!("{index}.sql"),
                    sha256: sha256(sql.as_bytes()),
                    git_blob_oid: "a".repeat(40),
                },
                offset: bytes.len(),
                length: sql.len(),
            });
            bytes.extend_from_slice(sql.as_bytes());
        }
        let target = Target {
            sequence: 176,
            file: "0177_party_identity_contract.sql".to_owned(),
            source: segments[2].source.clone(),
        };
        (bytes, segments, target)
    }

    #[test]
    fn execution_binds_ledger_after_preservation_before_cleanup_without_rewriting_original() {
        let (source, segments, target) = specimen();
        let manifest = compile(&source, &segments, &target).unwrap();
        let ledger = ledger_sql(&target).unwrap();
        let cut = segments[4].offset;
        let execution = [
            source[..cut].to_vec(),
            ledger.clone(),
            source[cut..].to_vec(),
        ]
        .concat();
        assert_eq!(manifest.execution_sha256, sha256(&execution));
        assert_eq!(manifest.source_envelope_sha256, sha256(&source));
        assert_ne!(manifest.execution_sha256, manifest.source_envelope_sha256);
        assert_eq!(manifest.ledger_name, target.file);
        assert_eq!(manifest.ledger_offset, cut);
        assert_eq!(manifest.ledger_sha256, sha256(&ledger));
        assert_eq!(manifest.execution_length, source.len() + ledger.len());
        let original = &segments[2];
        assert_eq!(
            &execution[original.offset..original.offset + original.length],
            &source[original.offset..original.offset + original.length]
        );
    }

    #[test]
    fn execution_rejects_source_offset_target_and_unbound_byte_drift() {
        let (source, segments, target) = specimen();
        let mut wrong = source.clone();
        wrong[0] = b' ';
        assert!(compile(&wrong, &segments, &target).is_err());
        let mut wrong = segments.clone();
        wrong[4].offset -= 1;
        assert!(compile(&source, &wrong, &target).is_err());
        let mut wrong = target.clone();
        wrong.source.sha256 = sha256(b"different\n");
        assert!(compile(&source, &segments, &wrong).is_err());
        let mut wrong = source.clone();
        wrong.extend_from_slice(b"SELECT 6;\n");
        assert!(compile(&wrong, &segments, &target).is_err());
    }

    #[test]
    fn execution_escapes_manifest_filename_and_digest_tracks_ledger_identity() {
        let (source, segments, target) = specimen();
        let before = compile(&source, &segments, &target).unwrap();
        let mut changed = target;
        changed.file = "0177_'quoted.sql".to_owned();
        let after = compile(&source, &segments, &changed).unwrap();
        assert_eq!(after.source_envelope_sha256, before.source_envelope_sha256);
        assert_ne!(after.execution_sha256, before.execution_sha256);
        assert!(
            String::from_utf8(ledger_sql(&changed).unwrap())
                .unwrap()
                .contains("0177_''quoted.sql")
        );
        changed.file.push('\n');
        assert!(compile(&source, &segments, &changed).is_err());
    }

    #[test]
    fn execution_ceiling_includes_compiler_owned_ledger_bytes() {
        let (mut source, mut segments, target) = specimen();
        let padding = MAX_ENVELOPE_BYTES - source.len();
        source.splice(0..0, std::iter::repeat_n(b' ', padding));
        segments[0].length += padding;
        segments[0].source.sha256 = sha256(&source[..segments[0].length]);
        for segment in &mut segments[1..] {
            segment.offset += padding;
        }
        assert_eq!(source.len(), MAX_ENVELOPE_BYTES);
        assert!(compile(&source, &segments, &target).is_err());
    }
}
