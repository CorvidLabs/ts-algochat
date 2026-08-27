---
change: default-new-chataccounts-to-falcon-1024-pqsig-while-mnemonic-import-stays-ed25519
artifact: requirements
---

# Requirements

Adds REQ-algochat-024 to the algochat spec: Falcon-1024 default for new
accounts, Ed25519 default for mnemonic import, mnemonic-entropy encryption
keys, 3× minFee on Falcon payments, `txnSigner` as the send path.
