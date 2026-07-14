---
change: CHG-0002-replace-the-incomplete-no-spec-rationale-with-a-stable-full-library-algochat-con
artifact: testing
---

# Testing

Run `bun run tsc` and `bun test` through the existing Fledge verification
lane. Run strict SpecSync with forced measurement and a 100% threshold. Confirm
all four agent integrations and Trust doctor. After acceptance, use released
SpecSync 5.0.1 and immutable Trust 1.0.0 as the authoritative consumer checks.
Inspect the final diff to prove no `src/`, package, lockfile, or test bytes
changed.
