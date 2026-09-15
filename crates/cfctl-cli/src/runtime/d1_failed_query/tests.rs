#![allow(clippy::expect_used)]
use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn named_private_sink_must_retain_the_exact_response() {
    let root = tempfile::tempdir().expect("private directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("directory mode");
    let directory = PrivateDirectory::open(root.path()).expect("private directory");
    let mut sink = directory
        .create_new_file("response.json")
        .expect("private sink");
    assert!(retain_response(
        &directory,
        "response.json",
        &mut sink,
        b"provider response"
    ));
    assert_eq!(
        directory.read("response.json", 65_536).expect("read"),
        Some(b"provider response".to_vec())
    );
}

#[test]
fn vanished_replaced_or_nonprivate_output_is_incomplete_after_fd_write() {
    for change in ["unlink", "replace", "public-mode", "hardlink"] {
        let root = tempfile::tempdir().expect("private directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("directory mode");
        let directory = PrivateDirectory::open(root.path()).expect("private directory");
        let path = root.path().join("response.json");
        let mut sink = directory
            .create_new_file("response.json")
            .expect("private sink");
        match change {
            "unlink" => fs::remove_file(&path).expect("unlink during request"),
            "replace" => {
                fs::remove_file(&path).expect("unlink during request");
                let mut replacement = directory
                    .create_new_file("response.json")
                    .expect("replacement");
                replacement
                    .write_all(b"different bytes")
                    .expect("replacement body");
            }
            "public-mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode drift")
            }
            "hardlink" => fs::hard_link(&path, root.path().join("alias.json")).expect("link drift"),
            _ => unreachable!(),
        }
        assert!(
            !retain_response(&directory, "response.json", &mut sink, b"provider response"),
            "{change}"
        );
        // Retention failure does not remove or replace residue and never retries
        // the provider. The caller maps false to performed=true/incomplete.
        assert_eq!(path.exists(), change != "unlink");
    }
}
