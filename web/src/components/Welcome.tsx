import { FormEvent, useState } from 'react';
import { KV, ObscuraClient } from '@obscura/core';
import { Shield } from './Icons';

function strength(p: string): { score: number; label: string } {
  let s = 0;
  if (p.length >= 10) s++;
  if (p.length >= 14) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
  if (/\d/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p) || p.split(/\s+/).length >= 4) s++;
  return { score: s, label: ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'][s] };
}

export function Welcome(props: { kv: KV; hasAccount: boolean; invitePending: boolean; onReady: (c: ObscuraClient) => void; onErased: () => void }) {
  const [name, setName] = useState('');
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const st = strength(pass);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (pass.length < 10) return setError('Use at least 10 characters. A few random words work well.');
    if (pass !== pass2) return setError('The passphrases do not match.');
    try {
      setBusy('Generating identity keys (Ed25519, X25519, ML-KEM-768) and hardening your vault with Argon2id…');
      const c = await ObscuraClient.create({ kv: props.kv, server: location.origin, name, passphrase: pass });
      await c.connect();
      props.onReady(c);
    } catch (err) {
      setError((err as Error).message);
      setBusy(null);
    }
  }

  async function unlock(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      setBusy('Deriving your vault key with Argon2id (64 MiB)…');
      const c = await ObscuraClient.unlock({ kv: props.kv, passphrase: pass });
      await c.connect();
      props.onReady(c);
    } catch (err) {
      setError((err as Error).message === 'wrong passphrase' ? 'Wrong passphrase.' : (err as Error).message);
      setBusy(null);
    }
  }

  async function erase() {
    if (!confirm('Erase the encrypted vault on this device? Without your passphrase this cannot be recovered.')) return;
    await props.kv.clear();
    props.onErased();
  }

  return (
    <div className="welcome">
      <div className="welcome-card">
        <div className="brand">
          <Shield size={40} />
          <div>
            <h1>Obscura</h1>
            <p className="muted">Post-quantum end-to-end encrypted messenger</p>
          </div>
        </div>

        {props.hasAccount ? (
          <form onSubmit={unlock}>
            <p>Your messages and keys on this device are locked. Enter your passphrase to decrypt them.</p>
            <input type="password" autoFocus placeholder="Passphrase" value={pass} onChange={(e) => setPass(e.target.value)} aria-label="Passphrase" />
            <button className="primary" disabled={!!busy || !pass}>
              Unlock
            </button>
            <button type="button" className="link danger" onClick={erase}>
              Forgot passphrase? Erase this device
            </button>
          </form>
        ) : (
          <form onSubmit={create}>
            {props.invitePending && <p className="notice">Create an account to open the invite you received.</p>}
            <p>
              No phone number, no email. Your account is a key pair generated right here. The server never learns who you
              are or what you say, and never sees who a message is from.
            </p>
            <input placeholder="Display name (only your contacts see it)" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} aria-label="Display name" />
            <input type="password" placeholder="Passphrase to encrypt this device" value={pass} onChange={(e) => setPass(e.target.value)} aria-label="Passphrase" />
            {pass && (
              <div className={`meter s${st.score}`}>
                <span />
                <em>{st.label}</em>
              </div>
            )}
            <input type="password" placeholder="Repeat passphrase" value={pass2} onChange={(e) => setPass2(e.target.value)} aria-label="Repeat passphrase" />
            <button className="primary" disabled={!!busy || !name.trim()}>
              Create secure account
            </button>
            <p className="fine">
              Your passphrase never leaves this device and cannot be reset. If you forget it, your local history is gone for
              good, by design.
            </p>
          </form>
        )}
        {busy && <p className="busy">{busy}</p>}
        {error && <p className="error">{error}</p>}
        <ul className="features">
          <li>PQXDH key agreement: X25519 + ML-KEM-768</li>
          <li>Hybrid post-quantum Double Ratchet</li>
          <li>Sealed sender: the server can't see who's messaging</li>
          <li>Encrypted photos, videos and files up to 100 MB</li>
        </ul>
      </div>
    </div>
  );
}
