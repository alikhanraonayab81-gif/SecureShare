# SecureShare — HTTPS-ready GitHub Pages build

This is the static web build of the SecureShare student prototype. It includes the HTML, CSS and JavaScript files needed to host it on GitHub Pages over HTTPS.

## Publish online with HTTPS (one-time setup)

1. Sign in to GitHub: https://github.com/new
2. Create a repository named **SecureShare**. Set it to **Public** (GitHub Free supports Pages for public repositories). Do not add a README, license or `.gitignore` because this ZIP already includes its own README.
3. Open the new repository and choose **Add file → Upload files**.
4. Extract this ZIP on your computer, open the extracted `SecureShare_GitHubPages` folder, and upload these items from inside it to the repository's top/root level: `index.html`, `style.css`, the `js` folder, `.nojekyll`, and `README.md`. Do not upload the enclosing folder itself.
5. Commit the upload to the `main` branch.
6. Open **Settings → Pages**. Under **Build and deployment**, choose **Deploy from a branch**, select branch **main** and folder **/(root)**, then click **Save**.
7. Wait for the Pages deployment to finish. Your site URL will be `https://YOUR-GITHUB-USERNAME.github.io/SecureShare/` (replace `YOUR-GITHUB-USERNAME` with your actual GitHub username).
8. In **Settings → Pages**, enable **Enforce HTTPS** if the option is shown. GitHub Pages `github.io` sites are served over HTTPS automatically.
9. Open the exact `https://...github.io/SecureShare/` URL on both devices. Do not use the laptop's `http://192.168...` Live Server URL for the final test.

## Test checklist

- Open the hosted HTTPS URL on two devices with internet access.
- Device 1: choose **Start as sender** and share its Peer ID/QR.
- Device 2: choose **Start as receiver**, scan the QR (allow camera permission) or enter the Peer ID manually, then connect.
- Wait for the encryption status and compare the fingerprint on both screens using a separate trusted channel.
- Send a small, non-sensitive test file. Confirm the receiver gets the request, accepts it, downloads the file and that its contents match.
- If camera scanning fails, manually enter the Peer ID; camera permission/browser support can vary.

## Important limitations

- I cannot publish directly into your GitHub account from this chat without authorized access. This ZIP is prepared for upload; the repository creation and Pages enablement above require your GitHub login.
- Hosting over HTTPS makes browser Web Crypto and camera APIs available in a secure context, but it does not itself prove the app is secure or guarantee every device/browser works. Test on your actual phone and laptop.
- This is an educational prototype, not a security-audited product. Compare the session fingerprint out-of-band before sending files. Do not use sensitive/irreplaceable files.
- The source code in a public repository is visible to everyone. Do not commit secrets or private files.
- The app relies on third-party CDN libraries and PeerJS signalling; internet access is required. File metadata is not encrypted by the app-level file encryption, and a fingerprint comparison is needed to reduce man-in-the-middle risk.
