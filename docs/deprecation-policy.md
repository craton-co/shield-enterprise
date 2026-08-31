# Deprecation Policy

Last reviewed: **2026-05-10**.

This document is the binding policy for how Craton Shield Enterprise
removes public API items. It complements
[docs/api-stability.md](api-stability.md), which defines the
stability tiers that govern *whether* an item is allowed to break at
all.

## 1. SemVer commitment

Craton Shield Enterprise follows
[Semantic Versioning 2.0.0](https://semver.org/). While the project is
at 0.x, breaking changes may land in a minor release; once 1.0 ships,
breaking changes require a major bump. The deprecation timeline below
applies inside whichever cadence is current.

## 2. Timeline

For any item in the **Stable** or **Beta** tier:

1. **Minor N** — the item is marked `#[deprecated(since = "...", note = "use X")]`
   and a CHANGELOG entry under `### Deprecated` is added in the same
   release.
2. **Minor N** (and any patch releases of N) — the item remains
   functional. Calls compile with a warning that names the
   replacement.
3. **Minor N+1 (or next major)** — the item may be removed. A
   CHANGELOG entry under `### Removed` documents the exact item,
   replacement, and the deprecation release that announced the
   removal.

The minimum grace period is therefore **one minor release**. Crates
are free to keep an item deprecated for longer; the policy is a floor,
not a ceiling.

**Experimental** items (see api-stability.md §Stability Tiers) are
excluded from this timeline. They may be removed in the next release
of any cadence, with or without a `#[deprecated]` cycle.

## 3. How items are marked

A deprecated item carries all three of:

- A `#[deprecated(since = "X.Y.0", note = "use `replacement` instead — see <link>")]`
  attribute. The `note` must name the replacement and link to a
  doc or CHANGELOG entry explaining the rationale.
- A rustdoc paragraph at the top of the item beginning with
  `**Deprecated since X.Y.0.**` so the warning is visible in rendered
  docs.
- A CHANGELOG entry in the release that introduces the deprecation
  and again in the release that removes it.

CI enforces the attribute via `cargo doc --no-deps -- -D warnings`;
missing rustdoc or CHANGELOG entries are caught in code review.

## 4. Security-critical exception

A deprecation tied to an unpatched security vulnerability may bypass
the one-minor grace period when continued use of the deprecated path
poses an exploitable risk. In that case:

1. The deprecation lands together with the security fix in the same
   patch release.
2. A security advisory is published per [SECURITY.md](../SECURITY.md)
   naming the deprecated item.
3. Removal may follow in the very next minor release (rather than the
   one after).

The exception is recorded in the CHANGELOG entry with the advisory
identifier. The current example is `TelemetryUplink::new_with_counter`,
which is deprecated in 0.7 and will be removed in 0.8 — see
[docs/migration-0.6-to-0.7.md §2](migration-0.6-to-0.7.md).

## 5. Cross-references

- [docs/api-stability.md](api-stability.md) — stability tiers and
  what each tier promises.
- [SECURITY.md](../SECURITY.md) — disclosure SLA and the security
  advisory process referenced by §4.
- [docs/release-process.md](release-process.md) — how CHANGELOG
  entries flow through the release.
