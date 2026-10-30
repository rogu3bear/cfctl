//! Disposable package layout shared by the actual producer consumers' tests.
#![allow(clippy::expect_used, clippy::wildcard_imports)]
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

pub(crate) struct BinFixture {
    pub _root: tempfile::TempDir,
    pub package: PathBuf,
    pub dependency: PathBuf,
    pub executable: PathBuf,
    pub alias: PathBuf,
}

impl BinFixture {
    pub fn new(with_alias: bool) -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        let package = root
            .path()
            .canonicalize()
            .expect("canonical fixture")
            .join("node_modules/wrangler");
        let dependency = package.join("node_modules/miniflare");
        fs::create_dir_all(package.join("bin")).expect("launcher directory");
        fs::create_dir_all(package.join("wrangler-dist")).expect("distribution");
        fs::create_dir_all(package.join("node_modules/.bin")).expect("bin directory");
        fs::create_dir_all(&dependency).expect("dependency");
        fs::write(package.join("package.json"), r#"{"name":"wrangler","version":"4.100.0","dependencies":{"miniflare":"4.20260611.0"}}"#).expect("package metadata");
        fs::write(package.join("wrangler-dist/cli.js"), "require('miniflare')")
            .expect("distribution");
        fs::write(
            dependency.join("package.json"),
            r#"{"name":"miniflare","version":"4.20260611.0","bin":{"miniflare":"bootstrap.js"}}"#,
        )
        .expect("dependency metadata");
        fs::write(
            dependency.join("bootstrap.js"),
            "export const fixture = true;",
        )
        .expect("bin target");
        let executable = package.join("bin/wrangler.js");
        fs::write(&executable, "#!/bin/sh\nprintf '4.100.0\\n'\n").expect("launcher");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("launcher mode");
        let alias = package.join("node_modules/.bin/miniflare");
        if with_alias {
            symlink("../miniflare/bootstrap.js", &alias).expect("bin alias");
        }
        Self {
            _root: root,
            package,
            dependency,
            executable,
            alias,
        }
    }

    pub fn retarget(&self, target: &str) {
        fs::remove_file(&self.alias).expect("remove fixture alias");
        symlink(target, &self.alias).expect("retarget fixture alias");
    }

    pub fn drift(&self, kind: &str) {
        match kind {
            "link" => self.retarget("../miniflare/./bootstrap.js"),
            "bytes" => fs::write(self.dependency.join("bootstrap.js"), "changed target bytes")
                .expect("target drift"),
            "declaration" => fs::write(
                self.dependency.join("package.json"),
                r#"{"name":"miniflare","version":"4.20260611.0","bin":{"miniflare":"other.js"}}"#,
            )
            .expect("declaration drift"),
            _ => panic!("unknown test drift"),
        }
    }

    pub fn capability(operation: &str) -> CapabilityV1 {
        let mut capability = CapabilityV1::new("fixture", "Fixture", "CLI", "wrangler");
        capability.source = format!("wrangler 4.100.0 {operation} help");
        capability
    }
}
