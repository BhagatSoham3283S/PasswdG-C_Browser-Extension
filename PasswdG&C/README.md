# PassGuard browser extension

PassGuard is a Manifest V3 browser extension for Chromium browsers such as Chrome, Brave and Edge. It generates a unique password, checks its strength and known breach status, then offers to fill and save it only after the user accepts.

## User flow

1. Open PassGuard on the website where you are creating an account. The extension generates a 20-character password by default; adjust its length or regenerate it as needed.
2. PassGuard estimates strength locally and checks the Have I Been Pwned password corpus. It hashes the password locally, requests only the first five characters of the SHA-1 hash, and compares the returned suffixes on the device. A failed breach lookup prevents acceptance.
3. Create or unlock the local vault, then select **Accept & save**. PassGuard fills the visible new-password field and its confirm-password field on the current page (it never touches a "current password" field) and stores the password encrypted in extension local storage. It captures the page hostname and, when available, the associated username or email field.

The extension does not submit forms. The user reviews and submits the website form themselves.

## Install locally

1. Open `chrome://extensions` in Chrome, `brave://extensions` in Brave, or `edge://extensions` in Edge. (In Brave, if the breach check fails only with Shields up, set Shields to Down for that site.)
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select this project folder.
4. Pin PassGuard, open a sign-up page, and click the extension icon.

The extension needs `activeTab` and `scripting` to fill a password field only after the user clicks **Accept & save**. It needs `storage` for the encrypted vault and access to `api.pwnedpasswords.com` for breach checks. It does not run a content script on every website.

## Vault security

Vault entries are encrypted with AES-GCM using a key derived from the user's vault password with PBKDF2-SHA-256 (600,000 iterations for new vaults; vaults created by v1.0.0 keep their original 310,000). The salt and ciphertext are stored in `chrome.storage.local`; the derived key stays in popup memory and is discarded when the popup closes or the user locks the vault. Use a unique, strong vault password and keep a separate recovery method: PassGuard cannot recover a forgotten vault password. Saved passwords can be shown or copied from the vault panel after unlocking. Removing the extension or clearing its data may delete saved entries.

This is a local encrypted vault prototype, not a replacement for a mature, independently audited password manager. A compromised browser profile or device can expose passwords while the vault is unlocked or after they are filled into a website.

## Project files

- `manifest.json` — Manifest V3 permissions, popup registration and icons.
- `index.html`, `style.css` — extension popup UI.
- `app.js` — generation checks, HIBP lookup, page fill, and encrypted vault.
- `generator.js` — secure random generation using `crypto.getRandomValues()` and rejection sampling.
- `icons/` — PNG toolbar icons (16, 32, 48, 128).

To publish the extension, package this folder for the target browser's extension store and review the store-specific listing and privacy requirements.
