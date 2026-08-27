---
change: default-new-chataccounts-to-falcon-1024-pqsig-while-mnemonic-import-stays-ed25519
artifact: testing
---

# Testing

```
fledge lanes run verify
```

New mnemonic tests cover Falcon default, explicit Falcon recover, import
without scheme staying Ed25519, and shared X25519 keys across schemes.
No live network mutation. Mailbox tests still use `algosdk.generateAccount()`.
