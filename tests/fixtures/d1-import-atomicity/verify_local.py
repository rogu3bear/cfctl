#!/usr/bin/env python3
"""Check synthetic SQL inputs locally; never claim provider atomicity."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

sys.dont_write_bytecode = True
HEAD = "749167e0401d00864cd691db66d95470bf74597c"
TREE = "71ef426194ff005b97c08bf0afce904bf2f53ad6"
FIXTURE_SOURCE = "eeaad2f4d4529401acb7fe5a4ad37e21bca11b5caf303bd2220323cc2a79fab5"
BOOTSTRAP = "a611a61461a0e9fef9a1bcea332391507d37b2301c4dfaf4ac2593c30b965f00"
OPEN = "378a164cf562c2f867d65c1a4f76fb0d9f79ca325699698441d97cc3a55d5d50"
SEED_HEADER = (
    "-- Synthetic Sign original-state fixture for isolated native-import qualification.\n"
    "-- Never a production repair or an inferred migration ledger.\n"
)
FAULT_HEADER = (
    "-- Deliberate failure after the actual initial-open UPDATE, isolated qualification only.\n"
)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def checked_bytes(path, digest):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, str(path)
    return data


def dump(db):
    return "\n".join(db.iterdump())


def rejected_atomic(module, db, sql):
    before = dump(db)
    try:
        module.atomic(db, sql)
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("deliberate or stale CHECK failure was accepted")
    assert dump(db) == before
    assert db.execute(
        "SELECT count(*) FROM sqlite_schema WHERE name='sign_recovery_command_assert'"
    ).fetchone() == (0,)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sign-source", required=True, type=Path)
    args = parser.parse_args()
    root = args.sign_source.resolve(strict=True)
    assert git(root, "rev-parse", "--show-toplevel") == str(root)
    assert git(root, "rev-parse", "HEAD") == HEAD
    assert git(root, "rev-parse", "HEAD^{tree}") == TREE
    assert not git(root, "status", "--porcelain=v1", "--untracked-files=all")
    helper = root / "scripts/test_sign_writer_protocol.py"
    checked_bytes(helper, FIXTURE_SOURCE)
    spec = importlib.util.spec_from_file_location("frozen_sign_sql_fixture", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture_root = Path(__file__).resolve().parent
    seed = (fixture_root / "seed.sql").read_text()
    original = module.original_fixture()
    try:
        expected_seed = SEED_HEADER + "\n".join(
            line for line in original.iterdump()
            if line not in ("BEGIN TRANSACTION;", "COMMIT;")
        ) + "\n"
        assert seed == expected_seed
    finally:
        original.close()
    sql_root = root / "cloudflare/sign-worker/sql"
    bootstrap = checked_bytes(sql_root / "bootstrap_v7.sql", BOOTSTRAP).decode()
    opening = checked_bytes(sql_root / "open_admission.sql", OPEN).decode()
    marker = "INSERT INTO sign_recovery_command_assert VALUES(changes()=1);"
    assert opening.count(marker) == 1
    failure = (fixture_root / "fail-after-update.sql").read_text()
    assert failure == FAULT_HEADER + opening.replace(
        marker, "INSERT INTO sign_recovery_command_assert VALUES(0);\n" + marker
    )
    with sqlite3.connect(":memory:") as db:
        module.atomic(db, seed)
        module.atomic(db, bootstrap)
        assert db.execute(
            "SELECT protocol,epoch,revision,mode FROM sign_recovery_control"
        ).fetchall() == [(7, 1, 1, "closed")]
        before = list(db.iterdump())
        rejected_atomic(module, db, failure)
        module.atomic(db, opening)
        assert db.execute(
            "SELECT protocol,epoch,revision,mode FROM sign_recovery_control"
        ).fetchall() == [(7, 2, 2, "open")]
        # The exact program may change only the control row and remove its scratch table.
        without_control = lambda rows: [
            row for row in rows
            if not row.startswith('INSERT INTO "sign_recovery_control"')
        ]
        assert without_control(before) == without_control(list(db.iterdump()))
        rejected_atomic(module, db, opening)
    # Negative control: per-statement autocommit exposes the partial UPDATE and scratch table.
    with sqlite3.connect(":memory:", isolation_level=None) as db:
        module.atomic(db, seed)
        module.atomic(db, bootstrap)
        before = dump(db)
        try:
            for statement in module.statements(failure):
                db.execute(statement)
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("negative control did not reach its CHECK failure")
        assert dump(db) != before
        assert db.execute("SELECT mode,epoch,revision FROM sign_recovery_control").fetchone() == (
            "open", 2, 2
        )
        assert db.execute(
            "SELECT count(*) FROM sqlite_schema WHERE name='sign_recovery_command_assert'"
        ).fetchone() == (1,)
    assert not git(root, "status", "--porcelain=v1", "--untracked-files=all")
    print(json.dumps({
        "state": "LOCAL_FIXTURE_CHECKS_PASS", "source": HEAD, "tree": TREE,
        "checks": ["exact_source_and_seed", "failure_after_update_full_rollback",
                   "initial_open_only_control_delta", "stale_open_full_rollback",
                   "non_atomic_negative_control_detected"],
        "provider_atomicity": "UNQUALIFIED", "provider_effects": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
