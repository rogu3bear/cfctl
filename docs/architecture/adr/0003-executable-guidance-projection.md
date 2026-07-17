# ADR 0003: Project guidance from executable contracts

- Status: accepted
- Date: 2026-07-16

## Context

The control plane already enforced its safety and lifecycle rules in code, but
explained them independently across CLI JSON, help text, repository documents,
and generated agent instructions. Phrase-presence checks could detect missing
headings without proving that the underlying claims still matched. That made
the system harder to learn and allowed a core behavioral change to leave a
plausible but stale explanation behind.

## Decision

`cfctl-core` owns typed capability guides and versioned system-topic documents.
The existing `cfctl guide <capability-id>` JSON shape remains unchanged. The
additive `cfctl guide --topic system|standing-authority` interface answers the
operator questions that govern execution: what is happening, why, what changes
locally and remotely, what can block progress, and what to do next.

System topics are deterministic and available without a catalog or network.
Human documentation embeds Markdown rendered from the topic documents, managed
agent guidance links to the same CLI topics, and `cargo xtask verify` requires
the checked-in generated sections to match the renderer exactly. Narrative and
rationale remain hand-written around those factual projections.

## Consequences

- There is one executable source for lifecycle guidance and several checked
  projections, rather than a second documentation authority.
- Existing capability-guide consumers keep their command and JSON contracts.
- Guidance changes that affect public behavior require an intentional model,
  projection, test, and documentation update in one change set.
- The exact projection gate prevents silent drift but does not replace tests of
  the runtime behavior described by each topic.
