## Summary

Brief description of the change and motivation.

Fixes # (issue number)

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Refactor (no functional change)
- [ ] Documentation
- [ ] CI / tooling

## Crate(s) Modified

-

## Checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo audit` shows no new advisories
- [ ] `cargo doc --workspace --no-deps` builds without warnings
- [ ] `#![no_std]` compatibility maintained
- [ ] No new heap allocations introduced
- [ ] Public types use `#[repr(C)]` and derive appropriate traits
- [ ] Every new `unsafe` block has a `// SAFETY:` comment
- [ ] CHANGELOG.md updated (if user-facing change)

## Testing

Describe the tests added or modified, and how to verify the change.

## ABI Impact

- [ ] No changes to `vs-ffi` or `include/cratonshield.h`
- [ ] ABI-compatible changes (fields added at end, no removals)
- [ ] ABI-breaking changes (documented in CHANGELOG, version bumped)
