# v2 stacked review, merge, and rollback runbook

This runbook records the local review stack for the Rust v2 cutover. It is a
sequencing artifact, not evidence that any branch was pushed, pull request was
opened, commit was merged, Cloudflare resource was changed, or release was
published.

The branch is a clean-break implementation, not a collection of independent
late patches. The first viable Rust checkpoint is the audited cutover at
`10dd6b6`: a proposed pre-cutover boundary at `688f511` failed two planner
policy tests in a fresh detached worktree. Do not split there or cherry-pick a
later layer directly onto `origin/main`.

## Local stack

Each Rust checkpoint below passed `cargo xtask verify` from a detached
worktree with a fresh `CARGO_TARGET_DIR`. The source-config root has a narrower
proof lane because that historical commit predates the Rust workspace.

| Order | Local head | Base | Checkpoint | Commits | Exact diff | Local proof |
| --- | --- | --- | --- | ---: | --- | --- |
| 0 | `codex/cfctl-v2-00-access-state` | `origin/main` | `763d8ff` | 1 | 2 files, 54 insertions | both JSON documents parse; `git diff --check` passes |
| 1 | `codex/cfctl-v2-01-cutover` | order 0 | `10dd6b6` | 10 | 226 files, 19,038 insertions, 34,119 deletions | fresh full proof passed |
| 2 | `codex/cfctl-v2-02-lifecycle` | order 1 | `7920ede` | 12 | 15 files, 4,605 insertions, 137 deletions | fresh full proof passed |
| 3 | `codex/cfctl-v2-03-supply-chain` | order 2 | `92d4da6` | 3 | 18 files, 444 insertions, 167 deletions | fresh full proof passed |
| 4 | `codex/cfctl-v2-04-readback` | order 3 | `b7bdcd2` | 8 | 9 files, 4,558 insertions, 319 deletions | fresh full proof passed |
| 5 | `codex/cfctl-v2-05-request-contracts` | order 4 | `f964021` | 14 | 10 files, 3,361 insertions, 192 deletions | fresh full proof passed |
| 6 | `codex/cfctl-v2-hardening` | order 5 | `4be1e79` code checkpoint | 4 code commits plus review docs | code checkpoint: 11 files, 1,294 insertions, 209 deletions | full proof passed at the code checkpoint; rerun after review-only changes |

Order 0 is deliberately isolated. It records desired state for the OSINT
Research Center Access application and exact-email policy. The two files are
source configuration, not live Cloudflare evidence. The local cfctl data
directory had no configured profiles during this audit, so the available
`access-applications-get-an-access-application` and
`access-policies-get-an-access-policy` readbacks could not be executed. Merge
the state commit as its own change if that desired state belongs on `main`, or
remove it from the v2 ancestry before publishing the stack. Do not hide it in
the cutover PR.

## Review preparation

Before publishing a head, prove that its exact base is an ancestor and inspect
only the ordered delta:

```bash
git merge-base --is-ancestor <base> <head>
git log --reverse --oneline <base>..<head>
git diff --check <base>..<head>
git diff --stat <base>..<head>
```

For every Rust head, use a detached worktree and a target directory that has
not been reused for another historical checkout:

```bash
git worktree add --detach /tmp/cfctl-review-<order> <checkpoint>
(
  cd /tmp/cfctl-review-<order>
  CARGO_TARGET_DIR=/tmp/cfctl-target-<order> cargo xtask verify
)
```

Remove the detached worktree and clean its explicit target after retaining the
result. A failure is a blocked checkpoint, not permission to delete or weaken
the failing test.

```bash
CARGO_TARGET_DIR=/tmp/cfctl-target-<order> cargo clean
git worktree remove /tmp/cfctl-review-<order>
```

## Pull request and merge order

No branch in this runbook is authorized for push merely because it exists
locally. Once an operator authorizes publication, push each named head without
rewriting it and open stacked pull requests with the base shown above. Keep
them draft until their base is settled and their exact delta is reviewed.

Merge one order at a time. Prefer merge commits so the hash-proven checkpoint
remains an ancestor of `main`. After each merge:

1. Confirm the pull request state is `MERGED` and record its merge commit.
2. Fetch `origin` and prove the checkpoint is an ancestor of `origin/main`.
3. Retarget the next pull request to `main`.
4. Recheck its commit list and exact diff against the updated remote base.
5. Run `cargo xtask verify` in a fresh worktree at the next head.

If repository policy requires squash or rebase merging, the checkpoint hash
will not survive. Reconstruct the resulting `origin/main` in a clean worktree
and rerun the full proof lane before treating the layer as merged and proven.

## Rollback and repair

- Before merge, add the repair to the affected stack head and merge that repair
  forward into later heads without rewriting a reviewed or published commit.
- After merge, revert the merge commit through a new reviewed pull request. Do
  not reset shared `main` or bypass a failing gate.
- Reverting order 0 changes repository desired state only. It does not undo a
  live Access application or policy; any live reversal requires a fresh read,
  a separately reviewed hash-bound plan, explicit approval, execution, and
  post-change verification.
- A catalog compensation action is a new plan with independent authority. An
  apply receipt or the presence of rollback metadata is not proof that
  compensation ran.
- Public release, site deployment, domain verification, permanent OAuth
  promotion, paid actions, and account-backed smoke mutations remain separate
  operator-authorized lanes after the entire merged tree is re-proven.
