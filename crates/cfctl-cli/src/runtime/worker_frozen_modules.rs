//! Bounded local parsing with Wrangler's exact admitted esbuild dependency.
use std::os::unix::process::CommandExt as _;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use super::{
    CliError,
    worker_frozen_config::Projection,
    worker_frozen_files::{CapturedArtifact, failure, write_private},
    wrangler_producer,
};

struct ParserChild(Child);

impl Drop for ParserChild {
    fn drop(&mut self) {
        // The Node helper and esbuild service share a fresh process group.
        // Reap on every return, including timeout and parse failure.
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.wait();
    }
}

pub(super) fn inspect(
    artifact: &CapturedArtifact,
    projection: &Projection,
    producer: &Value,
    document: &Value,
) -> Result<Value, CliError> {
    let main = &projection.main;
    let module_root = &projection.module_root;
    let esbuild = wrangler_producer::component_root(producer, "esbuild")?.join("lib/main.js");
    let interpreter = producer
        .pointer("/interpreter/path")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("module parsing requires the bound JavaScript interpreter"))?;
    let scratch = tempfile::Builder::new()
        .prefix("cfctl-frozen-parser-")
        .tempdir()
        .map_err(|_| failure("cannot create private module parser directory"))?;
    let script = scratch.path().join("check.cjs");
    let input = scratch.path().join("input.json");
    let output = scratch.path().join("output.json");
    write_private(&script, include_bytes!("worker_frozen_modules.cjs"))?;
    let files = artifact
        .bytes
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path, "content": STANDARD.encode(bytes),
            })
        })
        .collect::<Vec<_>>();
    write_private(
        &input,
        &serde_json::to_vec(&json!({
            "main": main, "module_root": module_root, "files": files, "esbuild": esbuild,
            "find_additional_modules": document.get("find_additional_modules").and_then(Value::as_bool).unwrap_or(true),
            "rules": document.get("rules").cloned().unwrap_or_else(|| json!([])),
            "upload_source_maps": document.get("upload_source_maps").and_then(Value::as_bool).unwrap_or(false),
        }))?,
    )?;
    write_private(&output, b"")?;
    let stdin = fs::File::open(&input).map_err(|_| failure("cannot bind parser input"))?;
    let stdout = fs::OpenOptions::new()
        .write(true)
        .open(&output)
        .map_err(|_| failure("cannot bind parser output"))?;
    let child = Command::new(Path::new(interpreter))
        .arg(&script)
        .current_dir(scratch.path())
        .env_clear()
        .env("HOME", scratch.path())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| failure("module parser did not start"))?;
    let mut child = ParserChild(child);
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        match child
            .0
            .try_wait()
            .map_err(|_| failure("module parser status unavailable"))?
        {
            Some(status) if status.success() => break,
            Some(_) => {
                return Err(failure(
                    "module imports or source maps are not closed over admitted bytes",
                ));
            }
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => return Err(failure("module closure parsing timed out")),
        }
    }
    let bytes = fs::read(&output).map_err(|_| failure("module parser receipt unavailable"))?;
    serde_json::from_slice(&bytes).map_err(|_| failure("module parser receipt malformed"))
}
