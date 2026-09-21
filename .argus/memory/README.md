# Argus Memory

Argus loads everything in this folder into every review. It's how the reviewer
learns your codebase instead of reviewing it cold each time. Memory is plain
Markdown, lives in your repo, and is edited by pull request — so it's reviewable,
diff-able, and fully under your control. Nothing is hidden in a model.

## Files

| File | Purpose | Authority |
|---|---|---|
| `conventions.md` | How this repo does things: patterns to enforce, idioms, "the way we do X here." | A violation is a finding (severity per the convention). |
| `accepted-patterns.md` | "Yes, we know — this is intentional here." Kills repeat false-positives. | **Authoritative.** Argus must not re-flag these. |
| `knowledge/*.md` | Durable, curated notes about subsystems, past incidents, gotchas. | Context Argus pulls in when the relevant area is touched. |

## How memory grows

1. **Argus proposes.** When Argus sees the team repeatedly accept a pattern it
   flagged, or spots a convention worth recording, it adds a **📝 Memory suggestion**
   to the review.
2. **A human curates.** Someone opens (or approves) a PR editing these files. Memory
   only changes through normal review — Argus never writes to it directly.
3. **Reviews get sharper.** Next run, Argus honors the new entry: fewer false
   positives, tighter enforcement of what you actually care about.

## Guidelines

- Keep entries short and specific, with a *why*. "We allow raw SQL in
  `analytics/` because the ORM can't express the window functions — reviewed
  2026-06, see #1234."
- Prune stale entries. Wrong memory is worse than none.
- Security carve-outs belong in `accepted-patterns.md` with an explicit rationale
  and a link — never a silent exception.

See [`../docs/memory.md`](../docs/memory.md) for the full model.
