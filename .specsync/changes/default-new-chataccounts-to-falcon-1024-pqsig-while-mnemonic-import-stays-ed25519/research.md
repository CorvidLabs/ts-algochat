---
change: default-new-chataccounts-to-falcon-1024-pqsig-while-mnemonic-import-stays-ed25519
artifact: research
---

# Research

Official js-algorand-sdk 3.7 example (`examples/falcon.ts`) derives the
Falcon seed with `pq25WordMnemonicToSeed(mnemonic, FALCON_1024_SCHEME)` and
signs via `addressWithSignersFromRawFalcon1024Signer`. LocalNet and TestNet
(algod 5.0.0) accepted a Falcon-signed 0-amount note at 3,000 µAlgo.
