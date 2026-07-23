---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: research
---

# Research

## Research

- ARC-4 ABI: dynamic `byte[]` app args are encoded `uint16_be(length) ‖ bytes`; static arrays are passed raw.
- AVM resource availability: an inner payment receiver must be in the outer transaction's foreign accounts unless it is the sender.
- Failure reproduced on LocalNet against RavenRouter app 1002 before the fix; round-trip passes after.
