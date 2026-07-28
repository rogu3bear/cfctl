// probe-then-test: connectivity fan-out first, cargo tests only if wiring holds.
// Args (all optional):
//   crates: array of package names (e.g. ["cfctl-cli","cfctl-core"]) — default = full workspace
//   test_filter: cargo -p filter string (e.g. "cfctl-cli") — default = --workspace
//   skip_tests: bool — probe-only when true

let meta = #{
    name: "probe-then-test",
    description: "Fan out crate connectivity probes, then run cargo tests only if wiring holds",
    when_to_use: "Before trusting a dirty tree or after wiring changes: probe function connections across crates, then test",
    phases: [
        #{ title: "Probe", detail: "trace public surfaces and cross-crate wiring per package" },
        #{ title: "Gate", detail: "fail closed on blocking disconnects" },
        #{ title: "Test", detail: "cargo test only after probe is clean" },
        #{ title: "Report", detail: "scratch summary with probe + test evidence" },
    ],
};

let probe_schema = #{
    "type": "object",
    "required": ["pkg", "connected", "disconnects", "summary"],
    "properties": #{
        "pkg": #{ "type": "string" },
        "connected": #{ "type": "boolean" },
        "entrypoints": #{
            "type": "array",
            "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["symbol", "file"],
                "properties": #{
                    "symbol": #{ "type": "string" },
                    "file": #{ "type": "string" },
                    "role": #{ "type": "string" },
                },
            },
        },
        "edges": #{
            "type": "array",
            "maxItems": 20,
            "items": #{
                "type": "object",
                "required": ["from", "to", "kind"],
                "properties": #{
                    "from": #{ "type": "string" },
                    "to": #{ "type": "string" },
                    "kind": #{ "type": "string" },
                },
            },
        },
        "disconnects": #{
            "type": "array",
            "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["severity", "target", "issue", "evidence"],
                "properties": #{
                    "severity": #{ "type": "string" },
                    "target": #{ "type": "string" },
                    "issue": #{ "type": "string" },
                    "evidence": #{ "type": "string" },
                },
            },
        },
        "summary": #{ "type": "string" },
    },
};

let test_schema = #{
    "type": "object",
    "required": ["ok", "command", "exit_code", "summary"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "command": #{ "type": "string" },
        "exit_code": #{ "type": "integer" },
        "failed_tests": #{
            "type": "array",
            "maxItems": 30,
            "items": #{ "type": "string" },
        },
        "summary": #{ "type": "string" },
    },
};

// --- resolve package list (script-owned work-list, not agent discovery) ---
let default_packages = [
    "cfctl-core",
    "cfctl-auth",
    "cfctl-catalog",
    "cfctl-cloudflare",
    "cfctl-planner",
    "cfctl-registry",
    "cfctl-workspace",
    "cfctl-agent",
    "cfctl-storage",
    "cfctl-cli",
    "xtask",
];

let packages = default_packages;
let skip_tests = false;
let test_filter = ();

if args != () {
    if args.crates != () {
        packages = args.crates;
    }
    if args.skip_tests != () && args.skip_tests == true {
        skip_tests = true;
    }
    if args.test_filter != () {
        test_filter = args.test_filter;
    }
}

if packages.len() == 0 {
    pause("verification", "Pass args.crates as a non-empty array of package names, or omit args for the full workspace.");
}

// Cap fan-out so a mis-sized args.crates cannot exhaust the budget before Test.
const MAX_PROBE = 12;
if packages.len() > MAX_PROBE {
    log("Truncating packages from " + packages.len().to_string() + " to " + MAX_PROBE.to_string());
    let trimmed = [];
    let pi = 0;
    while pi < MAX_PROBE {
        trimmed.push(packages[pi]);
        pi += 1;
    }
    packages = trimmed;
}

log("Probing " + packages.len().to_string() + " package(s); skip_tests=" + skip_tests.to_string());

// --- Phase 1: Probe connectivity (read-only, parallel) ---
phase("Probe");

let probe_jobs = [];
for pkg in packages {
    let pkg_path = "crates/" + pkg;
    if pkg == "xtask" {
        pkg_path = "xtask";
    }

    let prompt = "";
    prompt += "You are a connectivity probe for the cfctl Rust workspace at the repo root.\n";
    prompt += "Package under probe: " + pkg + " (path: " + pkg_path + ").\n\n";
    prompt += "MANDATORY method — use tools, do not answer from memory:\n";
    prompt += "1. Read " + pkg_path + "/Cargo.toml and the package entry (src/lib.rs and/or src/main.rs).\n";
    prompt += "2. List public modules and key pub fn/struct/enum surfaces (entrypoints).\n";
    prompt += "3. Trace how this package is wired: workspace deps in Cargo.toml, use/imports of other cfctl-* crates, ";
    prompt += "and (for cfctl-cli) how commands call into other crates.\n";
    prompt += "4. Grep the workspace for consumers of this package's public symbols (use grep/read_file).\n";
    prompt += "5. Flag DISCONNECTS only with file:line evidence: dead public API with no callers, declared deps unused, ";
    prompt += "commands registered but not dispatched, modules that never re-export, broken ownership vs ANCHOR.md, ";
    prompt += "or call paths that cannot reach a real implementation.\n\n";
    prompt += "Severity: use \"blocking\" when tests would be misleading (unwired path, missing dispatch, broken link); ";
    prompt += "\"advisory\" for style, unused-but-intentional, or incomplete docs.\n";
    prompt += "Set connected=true only when the package's main surfaces you inspected actually link to real implementations ";
    prompt += "or real consumers. Empty disconnects is valid ONLY after tool-backed inspection.\n";
    prompt += "Return at most 12 disconnects and 20 edges. Prefer concrete symbol/file paths over prose.\n";
    prompt += "Schema field pkg must equal \"" + pkg + "\".";

    probe_jobs.push(#{
        prompt: prompt,
        label: "probe:" + pkg,
        capability_mode: "read-only",
        output_schema: probe_schema,
    });
}

let probe_results = parallel(probe_jobs);

// --- Phase 2: Gate (script-owned; agents do not decide whether to test) ---
phase("Gate");

let probe_reports = [];
let blocking = [];
let advisory = [];
let failed_probes = [];
let connected_packages = [];
let i = 0;

for r in probe_results {
    let pkg = packages[i];
    if r == () || !r.success || r.output == () {
        failed_probes.push(pkg);
        blocking.push(#{
            pkg: pkg,
            severity: "blocking",
            target: pkg,
            issue: "probe agent failed or returned unusable output",
            evidence: "parallel slot empty or success=false",
        });
    } else {
        let out = r.output;
        probe_reports.push(out);

        let pkg_connected = out.connected == true;
        if pkg_connected {
            connected_packages.push(pkg);
        } else {
            // Treat connected=false as blocking even if disconnects array is empty.
            blocking.push(#{
                pkg: pkg,
                severity: "blocking",
                target: pkg,
                issue: "probe reported connected=false",
                evidence: if out.summary != () { out.summary } else { "no summary" },
            });
        }

        if out.disconnects != () {
            for d in out.disconnects {
                let sev = if d.severity != () { d.severity } else { "advisory" };
                // Normalize to lowercase-ish match without regex.
                let is_blocking = sev == "blocking" || sev == "Blocking" || sev == "BLOCKING";
                let row = #{
                    pkg: pkg,
                    severity: sev,
                    target: if d.target != () { d.target } else { pkg },
                    issue: if d.issue != () { d.issue } else { "unspecified" },
                    evidence: if d.evidence != () { d.evidence } else { "" },
                };
                if is_blocking {
                    blocking.push(row);
                } else {
                    advisory.push(row);
                }
            }
        }
    }
    i += 1;
}

log("Probe done: connected=" + connected_packages.len().to_string()
    + "/" + packages.len().to_string()
    + " blocking=" + blocking.len().to_string()
    + " advisory=" + advisory.len().to_string()
    + " failed_probes=" + failed_probes.len().to_string());

let probe_clean = blocking.len() == 0 && failed_probes.len() == 0;

// --- Phase 3: Test only if probe is clean ---
phase("Test");

let test_ran = false;
let test_ok = false;
let test_output = ();

if !probe_clean {
    log("Skipping tests: probe gate failed closed on blocking disconnects or failed probes.");
} else if skip_tests {
    log("Skipping tests: args.skip_tests=true (probe-only run).");
    test_ok = true;
} else {
    let cmd = "cargo test --workspace -- --nocapture";
    if test_filter != () {
        cmd = "cargo test -p " + test_filter + " -- --nocapture";
    }

    let tprompt = "";
    tprompt += "Run the workspace test gate for cfctl. Working directory is the repo root.\n";
    tprompt += "Probe already passed: all requested packages reported connected with zero blocking disconnects.\n";
    tprompt += "Execute EXACTLY this command via your shell tool and capture exit code + failure names:\n";
    tprompt += "  " + cmd + "\n\n";
    tprompt += "Do not change code. Do not re-run a different filter unless the exact command fails to start ";
    tprompt += "(missing toolchain) — then report that as ok=false.\n";
    tprompt += "Set ok=true only when the command exits 0. List failed test names in failed_tests (empty if all pass).\n";
    tprompt += "summary must include pass/fail counts or the primary failure reason.";

    let tr = agent(tprompt, #{
        label: "test:cargo",
        capability_mode: "execute",
        output_schema: test_schema,
    });

    test_ran = true;
    if tr != () && tr.success && tr.output != () {
        test_output = tr.output;
        test_ok = tr.output.ok == true;
    } else {
        test_ok = false;
        test_output = #{
            ok: false,
            command: cmd,
            exit_code: -1,
            failed_tests: [],
            summary: "test agent failed or returned unusable output",
        };
    }
}

// --- Phase 4: Report ---
phase("Report");

let status = "probe_failed";
if probe_clean && skip_tests {
    status = "probe_ok_tests_skipped";
} else if probe_clean && test_ran && test_ok {
    status = "probe_ok_tests_ok";
} else if probe_clean && test_ran && !test_ok {
    status = "probe_ok_tests_failed";
}

let report = "";
report += "# probe-then-test\n\n";
report += "Status: **" + status + "**\n\n";
report += "## Scope\n\n";
report += "- packages: " + packages.len().to_string() + "\n";
report += "- connected: " + connected_packages.len().to_string() + "\n";
report += "- blocking disconnects: " + blocking.len().to_string() + "\n";
report += "- advisory: " + advisory.len().to_string() + "\n";
report += "- failed probes: " + failed_probes.len().to_string() + "\n";
report += "- tests ran: " + test_ran.to_string() + "\n\n";

report += "## Blocking disconnects\n\n";
if blocking.len() == 0 {
    report += "_None._\n\n";
} else {
    for b in blocking {
        report += "- **" + b.pkg + "** `" + b.target + "`: " + b.issue + "\n";
        report += "  - evidence: " + b.evidence + "\n";
    }
    report += "\n";
}

report += "## Advisory\n\n";
if advisory.len() == 0 {
    report += "_None._\n\n";
} else {
    let ai = 0;
    for a in advisory {
        if ai < 20 {
            report += "- **" + a.pkg + "** `" + a.target + "`: " + a.issue + "\n";
        }
        ai += 1;
    }
    if advisory.len() > 20 {
        report += "- _… " + (advisory.len() - 20).to_string() + " more omitted_\n";
    }
    report += "\n";
}

report += "## Per-package probe summaries\n\n";
for pr in probe_reports {
    let pname = if pr.pkg != () { pr.pkg } else { "?" };
    let pconn = if pr.connected == true { "connected" } else { "NOT connected" };
    let psum = if pr.summary != () { pr.summary } else { "" };
    report += "### " + pname + " (" + pconn + ")\n\n";
    report += psum + "\n\n";
}

report += "## Tests\n\n";
if !test_ran {
    if skip_tests {
        report += "Skipped by request (`skip_tests`).\n";
    } else {
        report += "Skipped: probe gate failed closed.\n";
    }
} else if test_output != () {
    let tsum = if test_output.summary != () { test_output.summary } else { "" };
    let tcmd = if test_output.command != () { test_output.command } else { "" };
    let texit = if test_output.exit_code != () { test_output.exit_code.to_string() } else { "?" };
    report += "- command: `" + tcmd + "`\n";
    report += "- exit_code: " + texit + "\n";
    report += "- ok: " + test_ok.to_string() + "\n";
    report += "- summary: " + tsum + "\n";
    if test_output.failed_tests != () && test_output.failed_tests.len() > 0 {
        report += "- failed_tests:\n";
        for ft in test_output.failed_tests {
            report += "  - " + ft + "\n";
        }
    }
} else {
    report += "Test agent returned no structured output.\n";
}

let path = write_scratch_file("probe-then-test-report.md", report);
log("Wrote " + path + " status=" + status);

complete(#{
    status: status,
    path: path,
    packages: packages,
    connected_packages: connected_packages,
    blocking_count: blocking.len(),
    advisory_count: advisory.len(),
    failed_probes: failed_probes,
    probe_clean: probe_clean,
    test_ran: test_ran,
    test_ok: test_ok,
    blocking: blocking,
    test: test_output,
});
