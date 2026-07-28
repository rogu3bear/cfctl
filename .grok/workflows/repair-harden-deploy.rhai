// repair-harden-deploy: take probe/test findings → repair → harden → local ship proof.
//
// Args (optional unless noted):
//   findings: array of { pkg, target, issue, evidence, severity?, source? }
//             Prefer output from probe-then-test (blocking + advisory, or test failures).
//   max_repairs: int (default 6, hard cap 8) — highest-priority items only
//   include_advisory: bool (default true) — when collecting via re-scan, keep advisory too
//   re_scan: bool (default false) — if findings empty/absent, re-probe listed crates for disconnects
//   crates: array of package names for re_scan (default full workspace subset)
//   skip_deploy: bool (default false) — stop after harden + cargo test; skip xtask verify
//   dry_run: bool (default false) — plan repairs only; no write agents
//
// "Deploy" here means local ship-readiness proof (cargo xtask verify), NOT live Cloudflare
// mutation. Production Cloudflare changes stay on cfctl plan/approve/run.

let meta = #{
    name: "repair-harden-deploy",
    description: "Repair probe/test findings, harden the fix surface, then prove local ship readiness",
    when_to_use: "After probe-then-test (or failed cargo): fix confirmed findings, harden tests/policy, run local verify before ship",
    phases: [
        #{ title: "Collect", detail: "ingest args.findings or re-scan crates for disconnects" },
        #{ title: "Triage", detail: "cap, scope-filter, and prioritize repair work" },
        #{ title: "Repair", detail: "one writer per package for selected findings" },
        #{ title: "Harden", detail: "tests, fail-closed edges, and proof that the fix sticks" },
        #{ title: "Deploy", detail: "local ship-readiness: cargo test then cargo xtask verify" },
        #{ title: "Report", detail: "scratch summary of repairs, harden, and proof" },
    ],
};

let finding_item_schema = #{
    "type": "object",
    "required": ["pkg", "target", "issue", "evidence"],
    "properties": #{
        "pkg": #{ "type": "string" },
        "target": #{ "type": "string" },
        "issue": #{ "type": "string" },
        "evidence": #{ "type": "string" },
        "severity": #{ "type": "string" },
        "source": #{ "type": "string" },
    },
};

let collect_schema = #{
    "type": "object",
    "required": ["pkg", "findings"],
    "properties": #{
        "pkg": #{ "type": "string" },
        "findings": #{
            "type": "array",
            "maxItems": 10,
            "items": finding_item_schema,
        },
    },
};

let repair_schema = #{
    "type": "object",
    "required": ["pkg", "attempted", "changed_files", "summary", "ok"],
    "properties": #{
        "pkg": #{ "type": "string" },
        "attempted": #{ "type": "integer" },
        "fixed": #{ "type": "integer" },
        "skipped": #{ "type": "integer" },
        "changed_files": #{
            "type": "array",
            "maxItems": 20,
            "items": #{ "type": "string" },
        },
        "notes": #{
            "type": "array",
            "maxItems": 12,
            "items": #{ "type": "string" },
        },
        "ok": #{ "type": "boolean" },
        "summary": #{ "type": "string" },
    },
};

let harden_schema = #{
    "type": "object",
    "required": ["ok", "actions", "summary"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "actions": #{
            "type": "array",
            "maxItems": 16,
            "items": #{ "type": "string" },
        },
        "changed_files": #{
            "type": "array",
            "maxItems": 20,
            "items": #{ "type": "string" },
        },
        "summary": #{ "type": "string" },
    },
};

let proof_schema = #{
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

// --- resolve args ---
let findings = [];
let max_repairs = 6;
let include_advisory = true;
let re_scan = false;
let skip_deploy = false;
let dry_run = false;
let scan_crates = [
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

if args != () {
    if args.findings != () {
        findings = args.findings;
    }
    if args.max_repairs != () {
        max_repairs = args.max_repairs;
    }
    if args.include_advisory != () && args.include_advisory == false {
        include_advisory = false;
    }
    if args.re_scan != () && args.re_scan == true {
        re_scan = true;
    }
    if args.crates != () {
        scan_crates = args.crates;
    }
    if args.skip_deploy != () && args.skip_deploy == true {
        skip_deploy = true;
    }
    if args.dry_run != () && args.dry_run == true {
        dry_run = true;
    }
}

if max_repairs < 1 {
    max_repairs = 1;
}
if max_repairs > 8 {
    log("Clamping max_repairs from " + max_repairs.to_string() + " to 8");
    max_repairs = 8;
}

const MAX_SCAN = 12;
if scan_crates.len() > MAX_SCAN {
    log("Truncating scan crates from " + scan_crates.len().to_string() + " to " + MAX_SCAN.to_string());
    let trimmed_scan = [];
    let si = 0;
    while si < MAX_SCAN {
        trimmed_scan.push(scan_crates[si]);
        si += 1;
    }
    scan_crates = trimmed_scan;
}

// --- Phase 1: Collect ---
phase("Collect");

if findings.len() == 0 && !re_scan {
    pause(
        "verification",
        "Pass args.findings (from probe-then-test) or set args.re_scan=true to re-probe crates for repair work.",
    );
}

if findings.len() == 0 && re_scan {
    log("Re-scanning " + scan_crates.len().to_string() + " crate(s) for repair candidates");
    let cjobs = [];
    for cname in scan_crates {
        let cpath = "crates/" + cname;
        if cname == "xtask" {
            cpath = "xtask";
        }
        let cprompt = "";
        cprompt += "You collect fixable connectivity/quality findings for the cfctl workspace.\n";
        cprompt += "Package: " + cname + " path: " + cpath + "\n\n";
        cprompt += "MANDATORY: use read_file/grep on real sources — do not invent issues from memory.\n";
        cprompt += "Find disconnects, dead dispatch, missing tests for public mutation paths, ";
        cprompt += "broken wiring vs ANCHOR.md ownership, or clear fail-open gaps that a small repair can fix.\n";
        cprompt += "Each finding needs pkg=\"" + cname + "\", target (symbol or path), issue, evidence (file:line), ";
        cprompt += "severity (\"blocking\" or \"advisory\"), source=\"re_scan\".\n";
        cprompt += "At most 10 findings. Empty list is valid ONLY after tool-backed inspection found nothing actionable.\n";
        cprompt += "Prefer actionable repairs over style nits.";

        cjobs.push(#{
            prompt: cprompt,
            label: "collect:" + cname,
            capability_mode: "read-only",
            output_schema: collect_schema,
        });
    }
    let cresults = parallel(cjobs);
    let ci = 0;
    for cr in cresults {
        if cr != () && cr.success && cr.output != () && cr.output.findings != () {
            for f in cr.output.findings {
                // Script-owned scope filter: pkg must be in scan list / match crate under probe.
                let fpkg = if f.pkg != () { f.pkg } else { scan_crates[ci] };
                let in_scope = false;
                for allowed in scan_crates {
                    if fpkg == allowed {
                        in_scope = true;
                    }
                }
                if in_scope {
                    findings.push(#{
                        pkg: fpkg,
                        target: if f.target != () { f.target } else { fpkg },
                        issue: if f.issue != () { f.issue } else { "unspecified" },
                        evidence: if f.evidence != () { f.evidence } else { "" },
                        severity: if f.severity != () { f.severity } else { "advisory" },
                        source: "re_scan",
                    });
                } else {
                    log("Dropped out-of-scope finding pkg=" + fpkg);
                }
            }
        }
        ci += 1;
    }
}

// Normalize caller-supplied findings (guard fields)
let normalized = [];
for f in findings {
    if f == () {
        continue;
    }
    let fpkg = if f.pkg != () { f.pkg } else { "unknown" };
    let fsev = if f.severity != () { f.severity } else { "advisory" };
    if !include_advisory {
        let is_block = fsev == "blocking" || fsev == "Blocking" || fsev == "BLOCKING";
        if !is_block {
            continue;
        }
    }
    // Paths must look local — reject absolute home escapes in target/evidence strings later in prompts via encode.
    normalized.push(#{
        pkg: fpkg,
        target: if f.target != () { f.target } else { fpkg },
        issue: if f.issue != () { f.issue } else { "unspecified" },
        evidence: if f.evidence != () { f.evidence } else { "" },
        severity: fsev,
        source: if f.source != () { f.source } else { "args" },
    });
}
findings = normalized;

log("Collected " + findings.len().to_string() + " finding(s) before triage");

// --- Phase 2: Triage (script-owned prioritization) ---
phase("Triage");

// Priority: blocking first, then advisory; stable within severity by original order.
let blocking_items = [];
let advisory_items = [];
for f in findings {
    let sev = f.severity;
    if sev == "blocking" || sev == "Blocking" || sev == "BLOCKING" {
        blocking_items.push(f);
    } else {
        advisory_items.push(f);
    }
}

let selected = [];
for f in blocking_items {
    if selected.len() < max_repairs {
        selected.push(f);
    }
}
for f in advisory_items {
    if selected.len() < max_repairs {
        selected.push(f);
    }
}

let dropped = findings.len() - selected.len();
if dropped > 0 {
    log("Triage dropped " + dropped.to_string() + " finding(s) over max_repairs=" + max_repairs.to_string());
}

if selected.len() == 0 {
    let empty_path = write_scratch_file(
        "repair-harden-deploy-report.md",
        "# repair-harden-deploy\n\nNo findings to repair. Nothing to harden or deploy.\n",
    );
    complete(#{
        status: "nothing_to_do",
        path: empty_path,
        selected_count: 0,
        repaired: [],
        harden_ok: true,
        deploy_ok: true,
    });
}

// Group selected findings by pkg for one writer per package (avoids multi-writer conflicts).
let pkg_keys = [];
let groups = #{};
for f in selected {
    let key = f.pkg;
    let known = false;
    for k in pkg_keys {
        if k == key {
            known = true;
        }
    }
    if !known {
        pkg_keys.push(key);
        // Store findings in a side map via parallel arrays (Rhai maps of arrays).
        groups[key] = [f];
    } else {
        let cur = groups[key];
        cur.push(f);
        groups[key] = cur;
    }
}

log("Triage selected " + selected.len().to_string() + " finding(s) across " + pkg_keys.len().to_string() + " package(s); dry_run=" + dry_run.to_string());

// --- Phase 3: Repair ---
phase("Repair");

let repair_reports = [];
let all_changed = [];
let repair_ok = true;

if dry_run {
    log("dry_run: skipping write repairs; recording plan only");
    for key in pkg_keys {
        let g = groups[key];
        let notes = [];
        for item in g {
            notes.push("would_fix: " + item.target + " — " + item.issue);
        }
        repair_reports.push(#{
            pkg: key,
            attempted: g.len(),
            fixed: 0,
            skipped: g.len(),
            changed_files: [],
            notes: notes,
            ok: true,
            summary: "dry_run plan for " + key,
        });
    }
} else {
    let rjobs = [];
    for key in pkg_keys {
        let g = groups[key];
        let encoded = json_encode(g);
        let rprompt = "";
        rprompt += "You are a surgical repair agent for the cfctl Rust workspace (repo root).\n";
        rprompt += "Package scope: " + key + "\n";
        rprompt += "Repair ONLY these findings (JSON). Do not expand scope to drive-by refactors:\n";
        rprompt += encoded + "\n\n";
        rprompt += "Rules:\n";
        rprompt += "1. Read the cited evidence files with tools before editing.\n";
        rprompt += "2. Prefer the smallest correct fix that restores wiring or fail-closed behavior.\n";
        rprompt += "3. Stay inside crates/" + key + " (or xtask/ if pkg is xtask) unless a one-line consumer fix is required ";
        rprompt += "to reconnect a public surface — note any cross-crate touch in notes.\n";
        rprompt += "4. Do not touch credentials, live Cloudflare, or commit/push.\n";
        rprompt += "5. Do not weaken tests or approval gates to make green.\n";
        rprompt += "6. After edits, run a scoped check if useful: cargo test -p " + key + " --lib (or cargo check -p " + key + ").\n";
        rprompt += "7. Set ok=true only if attempted repairs either landed correctly or were justifiably skipped with notes.\n";
        rprompt += "8. List every changed_files path relative to repo root.\n";
        rprompt += "Return structured repair_schema fields: pkg, attempted, fixed, skipped, changed_files, notes, ok, summary.";

        rjobs.push(#{
            prompt: rprompt,
            label: "repair:" + key,
            capability_mode: "read-write",
            output_schema: repair_schema,
        });
    }

    let rresults = parallel(rjobs);
    let ri = 0;
    for rr in rresults {
        let key = pkg_keys[ri];
        if rr == () || !rr.success || rr.output == () {
            repair_ok = false;
            repair_reports.push(#{
                pkg: key,
                attempted: groups[key].len(),
                fixed: 0,
                skipped: groups[key].len(),
                changed_files: [],
                notes: ["repair agent failed or unusable output"],
                ok: false,
                summary: "repair failed for " + key,
            });
        } else {
            let out = rr.output;
            if out.ok != true {
                repair_ok = false;
            }
            if out.changed_files != () {
                for p in out.changed_files {
                    all_changed.push(p);
                }
            }
            repair_reports.push(out);
        }
        ri += 1;
    }
}

log("Repair phase done ok=" + repair_ok.to_string() + " changed_files≈" + all_changed.len().to_string());

// --- Phase 4: Harden ---
phase("Harden");

let harden_ok = false;
let harden_out = ();

if dry_run {
    harden_ok = true;
    harden_out = #{
        ok: true,
        actions: ["dry_run: would add/adjust regression tests for repaired surfaces"],
        changed_files: [],
        summary: "dry_run skipped harden writes",
    };
} else {
    let hprompt = "";
    hprompt += "You harden the cfctl workspace AFTER repairs. Repo root is the working directory.\n";
    hprompt += "Selected findings that were repaired (JSON):\n";
    hprompt += json_encode(selected) + "\n\n";
    hprompt += "Repair reports (JSON):\n";
    hprompt += json_encode(repair_reports) + "\n\n";
    hprompt += "Changed files so far (may be incomplete):\n";
    hprompt += json_encode(all_changed) + "\n\n";
    hprompt += "MANDATORY harden steps (use tools; edit only as needed):\n";
    hprompt += "1. Read the repaired regions; ensure a regression test or contract assertion covers the failure mode.\n";
    hprompt += "2. Prefer fail-closed behavior; do not add silent defaults that hide missing wiring.\n";
    hprompt += "3. Run cargo test for the touched packages (or --workspace if few changes).\n";
    hprompt += "4. Do not commit, push, or call live Cloudflare.\n";
    hprompt += "5. If repairs did nothing useful, still verify tests pass and say so in summary.\n";
    hprompt += "Set ok=true only when tests you ran passed (or no code needed change AND existing tests still pass).\n";
    hprompt += "List actions taken and changed_files.";

    let hr = agent(hprompt, #{
        label: "harden",
        capability_mode: "read-write",
        output_schema: harden_schema,
    });

    if hr != () && hr.success && hr.output != () {
        harden_out = hr.output;
        harden_ok = hr.output.ok == true;
        if hr.output.changed_files != () {
            for p in hr.output.changed_files {
                all_changed.push(p);
            }
        }
    } else {
        harden_ok = false;
        harden_out = #{
            ok: false,
            actions: [],
            changed_files: [],
            summary: "harden agent failed or returned unusable output",
        };
    }
}

log("Harden ok=" + harden_ok.to_string());

// --- Phase 5: Deploy (local ship-readiness only) ---
phase("Deploy");

let deploy_ok = false;
let test_proof = ();
let verify_proof = ();
let deploy_ran = false;

if dry_run {
    deploy_ok = true;
    test_proof = #{
        ok: true,
        command: "(dry_run)",
        exit_code: 0,
        failed_tests: [],
        summary: "dry_run skipped deploy proof",
    };
} else if !harden_ok {
    log("Skipping deploy proof: harden gate failed closed");
    deploy_ok = false;
} else {
    deploy_ran = true;

    let tprompt = "";
    tprompt += "Run workspace tests as the first deploy gate for cfctl.\n";
    tprompt += "Execute EXACTLY:\n  cargo test --workspace -- --nocapture\n";
    tprompt += "Do not edit code. ok=true only if exit code 0. List failed_tests if any.\n";

    let tr = agent(tprompt, #{
        label: "deploy:test",
        capability_mode: "execute",
        output_schema: proof_schema,
    });

    if tr != () && tr.success && tr.output != () {
        test_proof = tr.output;
        deploy_ok = tr.output.ok == true;
    } else {
        test_proof = #{
            ok: false,
            command: "cargo test --workspace -- --nocapture",
            exit_code: -1,
            failed_tests: [],
            summary: "test proof agent failed",
        };
        deploy_ok = false;
    }

    if deploy_ok && !skip_deploy {
        let vprompt = "";
        vprompt += "Run the local ship-readiness proof for cfctl (NOT live Cloudflare deploy).\n";
        vprompt += "Execute EXACTLY:\n  cargo xtask verify\n";
        vprompt += "This is format + clippy(-D warnings) + tests assembly per repo contract.\n";
        vprompt += "Do not edit code, do not release, do not push, do not call Cloudflare APIs.\n";
        vprompt += "ok=true only if exit code 0. Summarize the failing stage if any.\n";

        let vr = agent(vprompt, #{
            label: "deploy:verify",
            capability_mode: "execute",
            output_schema: proof_schema,
        });

        if vr != () && vr.success && vr.output != () {
            verify_proof = vr.output;
            deploy_ok = vr.output.ok == true;
        } else {
            verify_proof = #{
                ok: false,
                command: "cargo xtask verify",
                exit_code: -1,
                failed_tests: [],
                summary: "verify proof agent failed",
            };
            deploy_ok = false;
        }
    } else if deploy_ok && skip_deploy {
        log("skip_deploy=true: cargo test only; xtask verify skipped");
        verify_proof = #{
            ok: true,
            command: "(skipped)",
            exit_code: 0,
            failed_tests: [],
            summary: "xtask verify skipped by args.skip_deploy",
        };
    }
}

log("Deploy proof ok=" + deploy_ok.to_string() + " ran=" + deploy_ran.to_string());

// --- Phase 6: Report ---
phase("Report");

let status = "failed";
if dry_run {
    status = "dry_run_plan";
} else if repair_ok && harden_ok && deploy_ok {
    status = "repaired_hardened_deploy_ok";
} else if repair_ok && harden_ok && !deploy_ok {
    status = "repaired_hardened_deploy_failed";
} else if repair_ok && !harden_ok {
    status = "repaired_harden_failed";
} else {
    status = "repair_failed";
}

let report = "";
report += "# repair-harden-deploy\n\n";
report += "Status: **" + status + "**\n\n";
report += "## Inputs\n\n";
report += "- selected findings: " + selected.len().to_string() + "\n";
report += "- packages: " + pkg_keys.len().to_string() + "\n";
report += "- dry_run: " + dry_run.to_string() + "\n";
report += "- skip_deploy: " + skip_deploy.to_string() + "\n";
report += "- max_repairs: " + max_repairs.to_string() + "\n\n";

report += "## Selected findings\n\n";
for f in selected {
    report += "- **" + f.pkg + "** `" + f.target + "` [" + f.severity + "]: " + f.issue + "\n";
    report += "  - evidence: " + f.evidence + "\n";
}
report += "\n";

report += "## Repair\n\n";
for rr in repair_reports {
    let rpkg = if rr.pkg != () { rr.pkg } else { "?" };
    let rok = if rr.ok == true { "ok" } else { "FAILED" };
    let rsum = if rr.summary != () { rr.summary } else { "" };
    report += "### " + rpkg + " (" + rok + ")\n\n";
    report += rsum + "\n\n";
    if rr.changed_files != () && rr.changed_files.len() > 0 {
        report += "Changed:\n";
        for p in rr.changed_files {
            report += "- `" + p + "`\n";
        }
        report += "\n";
    }
    if rr.notes != () {
        for n in rr.notes {
            report += "- note: " + n + "\n";
        }
        report += "\n";
    }
}

report += "## Harden\n\n";
if harden_out != () {
    let hsum = if harden_out.summary != () { harden_out.summary } else { "" };
    report += "- ok: " + harden_ok.to_string() + "\n";
    report += "- summary: " + hsum + "\n";
    if harden_out.actions != () {
        for a in harden_out.actions {
            report += "- action: " + a + "\n";
        }
    }
    report += "\n";
} else {
    report += "_No harden output._\n\n";
}

report += "## Deploy (local ship-readiness)\n\n";
report += "_Not live Cloudflare. Production edge changes require cfctl plan/approve/run._\n\n";
if test_proof != () {
    let tsum = if test_proof.summary != () { test_proof.summary } else { "" };
    let tcmd = if test_proof.command != () { test_proof.command } else { "" };
    report += "### cargo test\n\n";
    report += "- command: `" + tcmd + "`\n";
    report += "- ok: " + (test_proof.ok == true).to_string() + "\n";
    report += "- summary: " + tsum + "\n\n";
}
if verify_proof != () {
    let vsum = if verify_proof.summary != () { verify_proof.summary } else { "" };
    let vcmd = if verify_proof.command != () { verify_proof.command } else { "" };
    report += "### cargo xtask verify\n\n";
    report += "- command: `" + vcmd + "`\n";
    report += "- ok: " + (verify_proof.ok == true).to_string() + "\n";
    report += "- summary: " + vsum + "\n\n";
}
if !deploy_ran && !dry_run {
    report += "Deploy proof did not run (harden failed or skipped).\n\n";
}

report += "## Changed files (union)\n\n";
if all_changed.len() == 0 {
    report += "_None recorded._\n";
} else {
    // Dedupe-ish by naive scan
    let seen = [];
    for p in all_changed {
        let already = false;
        for s in seen {
            if s == p {
                already = true;
            }
        }
        if !already {
            seen.push(p);
            report += "- `" + p + "`\n";
        }
    }
}

let path = write_scratch_file("repair-harden-deploy-report.md", report);
log("Wrote " + path + " status=" + status);

complete(#{
    status: status,
    path: path,
    selected_count: selected.len(),
    selected: selected,
    packages: pkg_keys,
    repair_ok: repair_ok,
    harden_ok: harden_ok,
    deploy_ok: deploy_ok,
    dry_run: dry_run,
    repairs: repair_reports,
    harden: harden_out,
    test_proof: test_proof,
    verify_proof: verify_proof,
    changed_files: all_changed,
});
