(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const ui = {
    site: $('site-name'), siteStatus: $('site-status'), output: $('password-output'), regenerate: $('regenerate'), copy: $('copy-password'),
    length: $('length'), lengthValue: $('length-value'), fill: $('meter-fill'), strength: $('strength-label'),
    check: $('check-status'), accept: $('accept-password'), action: $('action-status'), vaultState: $('vault-state'),
    master: $('master-password'), vaultToggle: $('vault-toggle'), vaultHelp: $('vault-help'), lock: $('lock-vault'), saved: $('saved-list')
  };
  // Vaults created by v1.0.0 used 310,000 PBKDF2 iterations and did not store the count, so that is the fallback.
  const LEGACY_ITERATIONS = 310000;
  const VAULT_ITERATIONS = 600000;
  const VERIFY_TEXT = 'PassGuard vault verification';
  let tab = null, generated = '', healthPassed = false, vaultKey = null, vaultSalt = null, vaultVerifier = null,
    vaultIterations = LEGACY_ITERATIONS, savedEntries = [], generationId = 0, debounceTimer = null;

  function bytesToHex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
  function hexToBytes(hex) { return new Uint8Array((hex.match(/.{2}/g) || []).map(x => parseInt(x, 16))); }
  async function hash(password, algorithm) {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest(algorithm, new TextEncoder().encode(password))));
  }
  async function checkBreach(password) {
    const sha1 = await hash(password, 'SHA-1');
    const response = await fetch('https://api.pwnedpasswords.com/range/' + sha1.slice(0, 5), {
      headers: { 'Add-Padding': 'true' }, cache: 'no-store', credentials: 'omit'
    });
    if (!response.ok) throw new Error('Breach lookup is unavailable.');
    const suffix = sha1.slice(5).toUpperCase();
    for (const line of (await response.text()).split(/\r?\n/)) {
      const parts = line.split(':');
      if (parts[0] === suffix) return Number(parts[1]) || 1;
    }
    return 0;
  }
  function score(password) {
    let points = Math.min(password.length, 24) * 2.5;
    points += [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(re => re.test(password)).length * 8;
    if (password.length >= 16) points += 8;
    if (/(.)\1{2,}|123|abc|qwe|password|admin/i.test(password)) points -= 18;
    return Math.max(0, Math.min(100, Math.round(points)));
  }
  function scoreLabel(n) { return n >= 85 ? 'Excellent' : n >= 70 ? 'Strong' : n >= 55 ? 'Good' : 'Fair'; }
  function setHealth(state, text) { ui.check.dataset.state = state; ui.check.textContent = text; }
  function isWebTab() {
    try { return !!tab && /^https?:$/.test(new URL(tab.url).protocol); } catch (_) { return false; }
  }
  function canAccept() { return healthPassed && !!vaultKey && !!generated && isWebTab(); }
  function setVaultLabel() {
    ui.vaultState.textContent = vaultKey ? 'Unlocked' : vaultSalt ? 'Locked' : 'Not set up';
    ui.vaultState.classList.toggle('unlocked', !!vaultKey);
    ui.vaultToggle.textContent = vaultKey ? 'Vault ready' : vaultSalt ? 'Unlock vault' : 'Create vault';
    ui.vaultToggle.disabled = !!vaultKey;
    ui.lock.hidden = !vaultKey;
    ui.vaultHelp.textContent = vaultSalt ? 'Unlock your encrypted passwords using your vault password.' : 'Create a vault password. Passwords are encrypted on this device using AES-GCM.';
  }
  async function deriveKey(password, salt, iterations) {
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function loadVault() {
    const values = await chrome.storage.local.get(['vaultSalt', 'vaultEntries', 'vaultVerifier', 'vaultIter']);
    vaultSalt = values.vaultSalt || null;
    savedEntries = values.vaultEntries || [];
    vaultVerifier = values.vaultVerifier || null;
    vaultIterations = values.vaultIter || LEGACY_ITERATIONS;
    setVaultLabel();
  }
  async function copyText(text, button, doneLabel, idleLabel) {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = doneLabel;
    } catch (_) { button.textContent = 'Failed'; }
    setTimeout(() => { button.textContent = idleLabel; }, 1200);
  }
  function makeButton(label, className) {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = label; if (className) b.className = className;
    return b;
  }
  async function renderSaved() {
    ui.saved.replaceChildren();
    if (!vaultKey) return;
    const decrypted = [];
    for (let i = 0; i < savedEntries.length; i++) {
      try {
        const item = savedEntries[i];
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(item.iv) }, vaultKey, hexToBytes(item.data));
        decrypted.push({ index: i, ...JSON.parse(new TextDecoder().decode(plain)) });
      } catch (_) { /* An unreadable entry is skipped without exposing stored data. */ }
    }
    if (!decrypted.length) {
      const empty = document.createElement('p'); empty.className = 'saved-empty'; empty.textContent = 'No saved passwords yet.';
      ui.saved.append(empty); return;
    }
    for (const entry of decrypted) {
      const row = document.createElement('div'); row.className = 'saved-row';
      const info = document.createElement('div'); info.className = 'saved-info';
      const label = document.createElement('strong'); label.textContent = entry.site;
      info.append(label);
      if (entry.username) { const user = document.createElement('span'); user.className = 'saved-user'; user.textContent = entry.username; info.append(user); }
      const actions = document.createElement('div'); actions.className = 'saved-actions';
      const secret = document.createElement('code'); secret.className = 'saved-secret'; secret.hidden = true;
      const copy = makeButton('Copy'); const show = makeButton('Show'); const remove = makeButton('Remove', 'danger');
      copy.addEventListener('click', () => copyText(entry.password, copy, 'Copied', 'Copy'));
      show.addEventListener('click', () => {
        const reveal = secret.hidden;
        secret.hidden = !reveal;
        secret.textContent = reveal ? entry.password : ''; // the password is only in the DOM while visible
        show.textContent = reveal ? 'Hide' : 'Show';
      });
      remove.addEventListener('click', async () => {
        savedEntries.splice(entry.index, 1);
        await chrome.storage.local.set({ vaultEntries: savedEntries });
        await renderSaved();
      });
      actions.append(copy, show, remove);
      row.append(info, actions, secret); ui.saved.append(row);
    }
  }
  async function generate() {
    const requestId = ++generationId;
    healthPassed = false; ui.accept.disabled = true; ui.action.textContent = '';
    try {
      const result = PassGenerator.generate({ length: Number(ui.length.value), upper: true, lower: true, digits: true, symbols: true, avoidConfusing: true });
      generated = result.password; ui.output.textContent = generated;
      const value = score(generated); ui.fill.style.width = value + '%'; ui.strength.textContent = scoreLabel(value);
      setHealth('pending', 'Checking strength and breach history…');
      const count = await checkBreach(generated);
      if (requestId !== generationId) return;
      if (count > 0) { setHealth('bad', 'This password appears in known breaches. Generate another.'); return; }
      healthPassed = true;
      setHealth('ok', 'Strong and not found in known breaches.');
      ui.accept.disabled = !canAccept();
      if (!vaultKey) ui.action.textContent = 'Unlock the vault to accept and save.';
      else if (!isWebTab()) ui.action.textContent = 'Open a regular website (http/https) to fill a password.';
    } catch (error) { if (requestId === generationId) setHealth('warn', 'Breach check failed. Try again before using this password.'); }
  }
  async function accept() {
    if (!canAccept()) return;
    ui.accept.disabled = true; ui.action.textContent = 'Filling the page and encrypting…';
    try {
      const result = await chrome.scripting.executeScript({ target: { tabId: tab.id }, args: [generated], func: (password) => {
        // getClientRects() also covers position:fixed fields (modals), which have no offsetParent.
        const visible = (x) => !x.disabled && (x.offsetParent !== null || x.getClientRects().length > 0);
        const inputs = Array.from(document.querySelectorAll('input[type="password"]')).filter(visible);
        if (!inputs.length) return { ok: false, reason: 'No visible password field was found.' };
        const isCurrent = (x) => x.autocomplete === 'current-password' || /current|old|existing/i.test(x.name + ' ' + x.id);
        const isConfirm = (x) => /confirm|repeat|retype|again|verify/i.test([x.name, x.id, x.placeholder, x.getAttribute('aria-label')].join(' '));
        const target = inputs.find(x => x.autocomplete === 'new-password') || inputs.find(x => !isCurrent(x)) || inputs[0];
        const scope = target.form || target.closest('form');
        // Fill the confirm-password field too, but never a "current password" field.
        const others = inputs.filter(x => x !== target && !isCurrent(x) && (scope ? (x.form === scope || scope.contains(x)) : isConfirm(x)));
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        const fillField = (el) => {
          setter.call(el, password);
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        };
        [target, ...others].forEach(fillField);
        const candidates = scope ? Array.from(scope.querySelectorAll('input')) : Array.from(document.querySelectorAll('input'));
        const user = candidates.find(x => x !== target && visible(x) && (/^(email|username|user)$/i.test(x.autocomplete) || /user|email|login/i.test(x.name + ' ' + x.id)));
        return { ok: true, username: user ? user.value : '', site: location.hostname, filled: 1 + others.length };
      }});
      const outcome = result[0]?.result;
      if (!outcome?.ok) throw new Error(outcome?.reason || 'Could not fill the password field.');
      const record = { site: outcome.site, username: outcome.username, password: generated, savedAt: Date.now() };
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, new TextEncoder().encode(JSON.stringify(record)));
      savedEntries.push({ iv: bytesToHex(iv), data: bytesToHex(new Uint8Array(encrypted)) });
      await chrome.storage.local.set({ vaultEntries: savedEntries });
      await renderSaved();
      ui.action.textContent = 'Filled ' + outcome.filled + (outcome.filled === 1 ? ' field' : ' fields') + ' on ' + outcome.site + ' and saved in your encrypted vault.';
    } catch (error) { ui.action.textContent = error.message || 'Could not fill and save this password.'; }
    ui.accept.disabled = !canAccept();
  }
  ui.length.addEventListener('input', () => {
    ui.lengthValue.value = ui.length.value;
    healthPassed = false; ui.accept.disabled = true; // the old password is no longer the one on screen
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(generate, 250);       // avoid one breach lookup per slider tick
  });
  ui.regenerate.addEventListener('click', generate);
  ui.copy.addEventListener('click', () => copyText(generated, ui.copy, 'Copied', 'Copy'));
  ui.accept.addEventListener('click', accept);
  ui.vaultToggle.addEventListener('click', async () => {
    const password = ui.master.value;
    if (vaultKey || password.length < 10) { ui.vaultHelp.textContent = 'Use a vault password with at least 10 characters.'; return; }
    ui.vaultToggle.disabled = true;
    try {
      if (!vaultSalt) {
        const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
        const key = await deriveKey(password, hexToBytes(salt), VAULT_ITERATIONS);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(VERIFY_TEXT));
        const verifier = { iv: bytesToHex(iv), data: bytesToHex(new Uint8Array(data)) };
        await chrome.storage.local.set({ vaultSalt: salt, vaultEntries: [], vaultVerifier: verifier, vaultIter: VAULT_ITERATIONS });
        vaultSalt = salt; vaultVerifier = verifier; vaultIterations = VAULT_ITERATIONS; savedEntries = []; vaultKey = key;
      } else {
        if (!vaultVerifier) throw new Error('Vault verification data is missing. Existing vault cannot be unlocked safely.');
        const key = await deriveKey(password, hexToBytes(vaultSalt), vaultIterations);
        let proof;
        try {
          proof = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(vaultVerifier.iv) }, key, hexToBytes(vaultVerifier.data));
        } catch (_) {
          // AES-GCM authentication fails with a generic browser error when the key is wrong.
          throw new Error('Vault password is incorrect.');
        }
        if (new TextDecoder().decode(proof) !== VERIFY_TEXT) throw new Error('Vault password is incorrect.');
        vaultKey = key;
      }
      ui.master.value = ''; setVaultLabel(); await renderSaved(); await generate();
    } catch (error) {
      ui.vaultHelp.textContent = error.message || 'Could not open the vault.';
      ui.vaultToggle.disabled = false;
    }
  });
  ui.lock.addEventListener('click', () => { vaultKey = null; ui.saved.replaceChildren(); setVaultLabel(); ui.accept.disabled = true; });
  (async function init() {
    ui.vaultToggle.disabled = true; // do not allow "Create vault" until the stored vault has been read
    try { await loadVault(); } catch (_) { ui.vaultHelp.textContent = 'Could not read the vault from extension storage.'; }
    try {
      [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const url = new URL(tab.url);
        ui.site.textContent = url.hostname || 'Current website';
        ui.siteStatus.textContent = isWebTab() ? 'Ready' : 'Not a web page';
      } else { ui.site.textContent = 'Unavailable on this page'; ui.siteStatus.textContent = 'Unavailable'; }
      await generate();
    } catch (_) { setHealth('warn', 'Open a regular website to use PassGuard.'); }
  })();
})();
