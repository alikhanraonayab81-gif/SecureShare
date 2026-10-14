# SecureShare — Encrypted Prototype (Fingerprint Confirmation)

A student demo for peer-to-peer file transfer with receiver approval and browser-based encryption.

## Run it
1. Extract this folder on both devices.
2. Open the folder in VS Code and use Live Server to serve `index.html` on each device (or host it on HTTPS).
3. Keep both devices online because PeerJS uses a signalling service.
4. On one device choose **Start as sender** and share the generated Peer ID with the other device.
5. On the other choose **Start as receiver**, enter the sender Peer ID, and connect.
6. Wait for the AES-GCM fingerprint to appear on both devices. Compare the full fingerprint through a separate trusted channel (for example, a voice call where you know who you are speaking to).
7. Tick the fingerprint confirmation checkbox on **both devices**. File sending/acceptance remains disabled until the local device confirms.
8. Select a small non-sensitive test file, request transfer, accept on the receiver, and check the downloaded content.

## Current prototype behaviour
- ECDH P-256 key agreement and AES-256-GCM file encryption/decryption using Web Crypto API.
- Receiver approval via Accept/Reject.
- Fingerprint comparison prompt; each device must manually confirm before it can send/accept a file.
- Demo file size cap: 20 MB.
- Encrypted data is sent in chunks after encryption.

## Important security limitations
- This is a learning prototype, not a production-ready or independently audited security product.
- The ECDH public-key exchange is not authenticated by a trusted identity provider. Manual fingerprint comparison is intended to help detect key substitution only when users compare it through a trusted, separate channel.
- The confirmation checkbox is a local user gate; it cannot prove that the remote user has checked their own box.
- Do not use for sensitive or valuable files. Further work is needed on protocol design, robust transfer state handling, replay/session binding, denial-of-service controls, and independent security review.
\n\n## GitHub Pages root upload\nUpload `index.html`, `style.css`, and `app.js` together to the repository root. This build includes the fingerprint confirmation checkbox and a separate receiver confirmation checkbox before Accept.\n