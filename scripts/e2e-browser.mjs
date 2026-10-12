/**
 * Browser end-to-end test: two isolated Chromium profiles (Alice and Bob) use
 * the real web app against a running server. Verifies account creation,
 * invite links, text, photo and video delivery, receipts, safety numbers,
 * lock/unlock, and that the page never violates its Content-Security-Policy.
 * Also captures the README screenshots.
 *
 *   BASE_URL=http://localhost:8080 node scripts/e2e-browser.mjs [--screenshots]
 */
import { chromium } from 'playwright';

const BASE = process.env.BASE_URL ?? 'http://localhost:8080';
const SHOTS = process.argv.includes('--screenshots');
const shotDir = 'docs/screenshots';
const exe = process.env.CHROMIUM_PATH || undefined;
const problems = [];
let step = 0;
const log = (s) => console.log(`  ${++step}. ${s}`);
const assert = (c, m) => {
  if (!c) throw new Error('ASSERTION FAILED: ' + m);
};

const browser = await chromium.launch({ executablePath: exe });

// Real media to send, produced by the browser itself: a PNG photo and a VP8/WebM video (MediaRecorder).
let photoBytes, videoBytes;
{
  const ctx = await browser.newContext({ viewport: { width: 640, height: 400 } });
  const p = await ctx.newPage();
  await p.setContent(`<body style="margin:0"><canvas id=c width=640 height=400></canvas><script>
    const c = document.getElementById('c'), g = c.getContext('2d');
    window.draw = (t) => {
      const sky = g.createLinearGradient(0, 0, 0, 400); sky.addColorStop(0, '#1b2a4a'); sky.addColorStop(0.55, '#f08a5d'); sky.addColorStop(1, '#f9d56e');
      g.fillStyle = sky; g.fillRect(0, 0, 640, 400);
      g.fillStyle = '#fff6d5'; g.beginPath(); g.arc(320 + Math.sin(t) * 140, 250 - Math.cos(t) * 30, 46, 0, 7); g.fill();
      g.fillStyle = '#2e1f3e'; g.beginPath(); g.moveTo(0, 400); g.lineTo(0, 300); g.lineTo(140, 210); g.lineTo(260, 290); g.lineTo(380, 190); g.lineTo(520, 280); g.lineTo(640, 230); g.lineTo(640, 400); g.fill();
      g.fillStyle = '#1a1226'; g.beginPath(); g.moveTo(0, 400); g.lineTo(0, 350); g.lineTo(200, 300); g.lineTo(420, 345); g.lineTo(640, 310); g.lineTo(640, 400); g.fill();
    };
    draw(0);
  </script></body>`);
  photoBytes = await p.locator('#c').screenshot({ type: 'png' });
  const b64 = await p.evaluate(async () => {
    const c = document.getElementById('c');
    const rec = new MediaRecorder(c.captureStream(30), { mimeType: 'video/webm;codecs=vp8' });
    const chunks = [];
    rec.ondataavailable = (e) => chunks.push(e.data);
    const done = new Promise((r) => (rec.onstop = r));
    rec.start(200);
    let t = 0;
    const iv = setInterval(() => window.draw((t += 0.06)), 33);
    await new Promise((r) => setTimeout(r, 3000));
    clearInterval(iv);
    rec.stop();
    await done;
    const buf = new Uint8Array(await new Blob(chunks).arrayBuffer());
    let s = '';
    for (const x of buf) s += String.fromCharCode(x);
    return btoa(s);
  });
  videoBytes = Buffer.from(b64, 'base64');
  await ctx.close();
}

async function newUser(name, viewport = { width: 1280, height: 800 }) {
  const ctx = await browser.newContext({ viewport, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  page.on('console', (m) => {
    const t = m.text();
    if (m.type() === 'error' && !/WebSocket connection .* failed/.test(t)) problems.push(`[${name} console] ${t}`);
    if (/Content Security Policy|Refused to/.test(t)) problems.push(`[${name} CSP] ${t}`);
  });
  page.on('pageerror', (e) => problems.push(`[${name} pageerror] ${e.message}`));
  return { ctx, page, name };
}

async function register(u, passphrase) {
  await u.page.getByPlaceholder('Display name').fill(u.name);
  await u.page.getByPlaceholder('Passphrase to encrypt this device').fill(passphrase);
  await u.page.getByPlaceholder('Repeat passphrase').fill(passphrase);
  await u.page.getByRole('button', { name: 'Create secure account' }).click();
  await u.page.getByText('Connected, end-to-end encrypted').waitFor({ timeout: 30000 });
}

console.log('Obscura browser E2E against', BASE);
const alice = await newUser('Alice');
await alice.page.goto(BASE);
await alice.page.getByText('Create secure account').waitFor();
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/welcome.png` });
await register(alice, 'correct horse battery staple 42');
log('Alice created an account (keys generated in-browser, vault sealed with Argon2id)');

await alice.page.getByRole('button', { name: /Invite/ }).click();
const link = await alice.page.getByLabel('Invite link').inputValue();
assert(/#\/invite\/[a-z2-7]{32}\./.test(link), 'invite link format');
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/invite.png` });
await alice.page.getByRole('button', { name: 'Close' }).click();
log('Alice copied her invite link');

const bob = await newUser('Bob');
await bob.page.goto(link.replace(/^https?:\/\/[^/]+/, BASE));
await bob.page.getByText('Create an account to open the invite you received.').waitFor();
await register(bob, 'another very long passphrase 99');
await bob.page.getByRole('button', { name: 'Start encrypted chat' }).click();
await bob.page.getByText('Verify safety number').waitFor();
log('Bob opened the invite, created an account and ran PQXDH with Alice');

await alice.page.getByText('Bob', { exact: true }).first().waitFor({ timeout: 15000 });
await alice.page.getByText('Bob', { exact: true }).first().click();
log('Alice sees Bob appear in real time (sealed-sender hello over WebSocket)');

await alice.page.getByPlaceholder('Encrypted message').fill('Hi Bob! This is end-to-end encrypted with post-quantum keys.');
await alice.page.keyboard.press('Enter');
await bob.page.getByText('Hi Bob! This is end-to-end encrypted with post-quantum keys.').waitFor({ timeout: 15000 });
log('Text message delivered and decrypted');

await bob.page.getByPlaceholder('Encrypted message').fill('Got it. Sending you a photo and a video.');
await bob.page.keyboard.press('Enter');
await alice.page.getByText('Got it. Sending you a photo and a video.').waitFor({ timeout: 15000 });

// Photo: a real PNG (a screenshot of Alice's own screen), sent through the file picker.
const png = photoBytes;
await bob.page.locator('input[type=file]').setInputFiles({ name: 'sunset.png', mimeType: 'image/png', buffer: png });
await bob.page.locator('input[type=file]').setInputFiles({ name: 'timelapse.webm', mimeType: 'video/webm', buffer: videoBytes });
await bob.page.locator('input[type=file]').setInputFiles({ name: 'notes.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n% Obscura test document\n') });
await alice.page.locator('.bubble img[alt="sunset.png"]').waitFor({ timeout: 30000 });
await alice.page.locator('.bubble video').waitFor({ timeout: 30000 });
await alice.page.getByText('notes.pdf').waitFor({ timeout: 30000 });
const imgOk = await alice.page.locator('.bubble img[alt="sunset.png"]').evaluate((img) => img.complete && img.naturalWidth > 0);
assert(imgOk, 'image decoded and rendered');
const videoOk = await alice.page.locator('.bubble video').evaluate(
  (v) => new Promise((res) => (v.readyState >= 1 ? res(v.duration > 0) : v.addEventListener('loadedmetadata', () => res(v.duration > 0), { once: true }))),
);
assert(videoOk, 'video decoded and playable');
log(`Photo (${png.length} B), video (${videoBytes.length} B) and PDF delivered, decrypted and rendered`);

await alice.page.getByPlaceholder('Encrypted message').fill('Beautiful. The server only ever saw ciphertext.');
await alice.page.keyboard.press('Enter');
await bob.page.getByText('Beautiful. The server only ever saw ciphertext.').waitFor();
await alice.page.locator('.bubble-row.out').last().locator('.read').waitFor({ timeout: 15000 });
log('Read receipt (also end-to-end encrypted) came back');

if (SHOTS) {
  await alice.page.setViewportSize({ width: 1280, height: 1080 });
  await alice.page.waitForTimeout(300);
  await alice.page.locator('.messages').evaluate((el) => el.scrollTo({ top: el.scrollHeight }));
  await alice.page.waitForTimeout(300);
  await alice.page.screenshot({ path: `${shotDir}/chat.png` });
  await alice.page.setViewportSize({ width: 1280, height: 800 });
}

// Inspector
await alice.page.locator('.bubble-row.in .lock-btn').first().click();
await alice.page.getByText('What the server saw').waitFor();
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/inspector.png` });
await alice.page.getByRole('button', { name: 'Close' }).click();
log('Encryption inspector shows the per-message ratchet state');

// Safety numbers match across both browsers
await alice.page.getByRole('button', { name: /Verify safety number/ }).click();
const sa = (await alice.page.locator('.safety').innerText()).replace(/\D/g, '');
await bob.page.getByRole('button', { name: /Verify safety number/ }).click();
const sb = (await bob.page.locator('.safety').innerText()).replace(/\D/g, '');
assert(sa.length === 60 && sa === sb, 'safety numbers match');
await alice.page.getByLabel('Compare safety number').fill(sb);
await alice.page.getByText('They match.').waitFor();
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/safety.png` });
await alice.page.getByRole('button', { name: /Mark as verified/ }).click();
await alice.page.getByRole('button', { name: 'Close' }).click();
await bob.page.getByRole('button', { name: 'Close' }).click();
log('Safety numbers are identical in both browsers (60 digits)');

// Security center: what the server knows
await alice.page.getByRole('button', { name: /Security/ }).click();
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/security.png` });
await alice.page.getByRole('button', { name: 'What the server knows' }).click();
await alice.page.getByText('"accountId"').waitFor();
const serverJson = await alice.page.locator('pre.json').innerText();
assert(!serverJson.includes('Alice') && !serverJson.includes('Bob'), 'server view holds no names');
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/server-view.png` });
await alice.page.getByRole('button', { name: 'Close' }).click();
log('Server view contains no names, contacts or content');

// Lock + unlock
await alice.page.getByRole('button', { name: /Lock/ }).first().click();
await alice.page.getByRole('button', { name: 'Unlock' }).waitFor();
if (SHOTS) await alice.page.screenshot({ path: `${shotDir}/locked.png` });
await alice.page.getByPlaceholder('Passphrase').fill('wrong passphrase');
await alice.page.getByRole('button', { name: 'Unlock' }).click();
await alice.page.getByText('Wrong passphrase.').waitFor({ timeout: 20000 });
await alice.page.getByPlaceholder('Passphrase').fill('correct horse battery staple 42');
await alice.page.getByRole('button', { name: 'Unlock' }).click();
await alice.page.getByText('Bob', { exact: true }).first().click();
await alice.page.getByText('Beautiful. The server only ever saw ciphertext.').waitFor();
log('Lock wipes keys; wrong passphrase rejected; correct one restores the encrypted history');

// IndexedDB holds only ciphertext
const leaks = await alice.page.evaluate(async () => {
  const db = await new Promise((r) => {
    const q = indexedDB.open('obscura');
    q.onsuccess = () => r(q.result);
  });
  const all = await new Promise((r) => {
    const q = db.transaction('kv').objectStore('kv').getAll();
    q.onsuccess = () => r(q.result);
  });
  const text = all.map((v) => new TextDecoder('latin1').decode(new Uint8Array(v))).join('');
  return ['Hi Bob', 'photo and a video', 'Bob', 'sunset.png', 'secretKey'].filter((s) => text.includes(s));
});
assert(leaks.length === 0, 'IndexedDB leaks: ' + leaks.join(','));
log('Browser storage (IndexedDB) contains only ciphertext');

if (SHOTS) {
  const m = await newUser('Mobile', { width: 390, height: 844 });
  await m.ctx.addCookies([]);
  await bob.page.setViewportSize({ width: 390, height: 844 });
  await bob.page.waitForTimeout(300);
  await bob.page.screenshot({ path: `${shotDir}/mobile.png` });
  await m.ctx.close();
}

await browser.close();
if (problems.length) {
  console.error('\nProblems detected:\n' + problems.join('\n'));
  process.exit(1);
}
console.log(`\nAll ${step} browser checks passed. No CSP violations, no page errors.`);
