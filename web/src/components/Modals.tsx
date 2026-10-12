import { ReactNode, useEffect, useMemo, useState } from 'react';
import qrcode from 'qrcode-generator';
import type { Contact, Message, ObscuraClient, ServerView } from '@obscura/core';
import { DEFAULT_KDF, fromB64, toHex } from '@obscura/core';
import { ShieldCheck } from './Icons';
import { formatBytes } from './Messenger';

function Modal(props: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && props.onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [props]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className={`modal ${props.wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={props.title}>
        <header>
          <h3>{props.title}</h3>
          <button className="icon" onClick={props.onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="modal-body">{props.children}</div>
      </div>
    </div>
  );
}

/** QR rendered as SVG markup we generate ourselves (no third-party network calls, CSP-safe). */
function QrCode({ text }: { text: string }) {
  const svg = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    return qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  }, [text]);
  const src = useMemo(() => URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' })), [svg]);
  useEffect(() => () => URL.revokeObjectURL(src), [src]);
  return <img className="qr" src={src} alt="QR code" />;
}

export function InviteModal(props: { client: ObscuraClient; onClose: () => void }) {
  const [link, setLink] = useState(() => props.client.inviteLink(location.origin));
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  return (
    <Modal title="Your invite" onClose={props.onClose}>
      <p>
        Anyone with this link can start an encrypted chat with you. Nobody else can even deliver a message to you: the
        server requires the secret access key inside the link.
      </p>
      <QrCode text={link} />
      <div className="copy-row">
        <input readOnly value={link} onFocus={(e) => e.target.select()} aria-label="Invite link" />
        <button
          className="primary"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(link);
              setCopied(true);
            } catch {
              // Clipboard API needs HTTPS; fall back to selecting the text.
              (document.querySelector('input[aria-label="Invite link"]') as HTMLInputElement | null)?.select();
            }
          }}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <p className="fine">
        The secret part comes after <code>#</code>, which browsers never send to any server. Your ID is a hash of your
        identity key, so the link also pins your key: the server cannot swap it.
      </p>
      <button
        className="link danger"
        disabled={busy}
        onClick={async () => {
          if (!confirm('Revoke this link? Existing contacts automatically receive your new key. Anyone who only has the old link will no longer reach you.')) return;
          setBusy(true);
          await props.client.rotateAccessKey();
          setLink(props.client.inviteLink(location.origin));
          setBusy(false);
          setCopied(false);
        }}
      >
        Revoke this link and make a new one
      </button>
    </Modal>
  );
}

export function AddContactModal(props: { client: ObscuraClient; initialLink?: string; onClose: () => void; onAdded: (c: Contact) => void }) {
  const [link, setLink] = useState(props.initialLink ?? '');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title="Add a contact" onClose={props.onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            props.onAdded(await props.client.addContact(link.trim(), name.trim() || undefined));
          } catch (err) {
            setError((err as Error).message);
            setBusy(false);
          }
        }}
      >
        <p>Paste the invite link they shared with you.</p>
        <input placeholder="https://…/#/invite/…" value={link} onChange={(e) => setLink(e.target.value)} autoFocus aria-label="Invite link" />
        <input placeholder="Nickname (optional, stays on this device)" value={name} onChange={(e) => setName(e.target.value)} aria-label="Nickname" />
        <button className="primary" disabled={busy || !link.trim()}>
          {busy ? 'Running PQXDH key agreement…' : 'Start encrypted chat'}
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </Modal>
  );
}

export function SafetyModal(props: { client: ObscuraClient; contact: Contact; onClose: () => void }) {
  const [sn, setSn] = useState<{ digits: string; groups: string[] } | null>(null);
  const [verified, setVerified] = useState(props.contact.verified);
  const [compare, setCompare] = useState('');
  useEffect(() => {
    void props.client.safetyNumber(props.contact.id).then(setSn);
  }, [props.client, props.contact.id]);
  const cleaned = compare.replace(/\D/g, '');
  return (
    <Modal title={`Verify ${props.contact.name}`} onClose={props.onClose}>
      {!sn ? (
        <p>Send a message first so your devices can exchange keys.</p>
      ) : (
        <>
          <p>
            Compare these numbers with {props.contact.name} in person or on a call. If they match, nobody (not even the
            server operator) is intercepting your conversation.
          </p>
          <div className="safety">
            {sn.groups.map((g, i) => (
              <span key={i}>{g}</span>
            ))}
          </div>
          <QrCode text={`obscura-safety:${sn.digits}`} />
          <input placeholder="Or paste the number they sent you to compare" value={compare} onChange={(e) => setCompare(e.target.value)} aria-label="Compare safety number" />
          {cleaned.length === 60 && (cleaned === sn.digits ? <p className="ok">They match.</p> : <p className="error">They do NOT match. Do not trust this conversation.</p>)}
          <button
            className={verified ? '' : 'primary'}
            onClick={async () => {
              await props.client.setVerified(props.contact.id, !verified);
              setVerified(!verified);
            }}
          >
            {verified ? 'Clear verification' : (
              <>
                <ShieldCheck size={16} /> Mark as verified
              </>
            )}
          </button>
        </>
      )}
    </Modal>
  );
}

export function InspectorModal(props: { client: ObscuraClient; message: Message; contact: Contact; onClose: () => void }) {
  const c = props.message.crypto!;
  const head = toHex(fromB64(c.envelopeHead)).replace(/(.{2})/g, '$1 ').trim();
  const rows: [string, ReactNode][] = [
    ['Direction', props.message.dir === 'out' ? `You → ${props.contact.name}` : `${props.contact.name} → You`],
    ['Message type', c.kind === 'prekey' ? 'PQXDH session setup + first ratchet message' : 'Double Ratchet message'],
    ['Key agreement', c.kind === 'prekey' ? 'X25519 ×4 + ML-KEM-768 encapsulation (PQXDH)' : 'Established session'],
    ['Ratchet step', `#${c.ratchetStep}${c.pqRatchet ? ' (X25519 + ML-KEM-768 hybrid step)' : ' (initial chain, PQ-seeded by PQXDH)'}`],
    ['Message number in chain', String(c.counter)],
    ['Message key', 'Single-use, derived by HMAC-SHA256 chain, deleted after use'],
    ['Cipher', 'XChaCha20-Poly1305 (header bound as associated data)'],
    ['Padding', 'ISO 7816-4 to 256-byte blocks (length hidden)'],
    ['Envelope', `Sealed sender, ${formatBytes(c.envelopeBytes)} on the wire`],
  ];
  return (
    <Modal title="Encryption details" onClose={props.onClose} wide>
      <table className="kv">
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k}>
              <th>{k}</th>
              <td>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>What the server saw</h4>
      <ul className="seen">
        <li>
          Recipient: <code>{props.message.dir === 'out' ? props.contact.id : props.client.accountId}</code>
        </li>
        <li>Sender: unknown (sealed sender: the sender's identity is inside the encryption)</li>
        <li>Content: {formatBytes(c.envelopeBytes)} of random-looking bytes, starting with:</li>
      </ul>
      <pre className="hex">{head} …</pre>
    </Modal>
  );
}

export function SecurityModal(props: { client: ObscuraClient; onClose: () => void; onDestroyed: () => void }) {
  const [tab, setTab] = useState<'protocol' | 'server' | 'device'>('protocol');
  const [view, setView] = useState<ServerView | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (tab === 'server' && !view) props.client.serverView().then(setView, (e) => setErr(e.message));
  }, [tab, view, props.client]);
  return (
    <Modal title="Security center" onClose={props.onClose} wide>
      <nav className="tabs">
        <button className={tab === 'protocol' ? 'on' : ''} onClick={() => setTab('protocol')}>
          Protocol
        </button>
        <button className={tab === 'server' ? 'on' : ''} onClick={() => setTab('server')}>
          What the server knows
        </button>
        <button className={tab === 'device' ? 'on' : ''} onClick={() => setTab('device')}>
          This device
        </button>
      </nav>
      {tab === 'protocol' && (
        <ul className="proto">
          <li>
            <b>PQXDH key agreement.</b> X25519 (4 Diffie-Hellman operations) combined with ML-KEM-768 (NIST FIPS 203).
            Breaking a session requires breaking both, so traffic recorded today stays safe from future quantum computers.
          </li>
          <li>
            <b>Hybrid post-quantum Double Ratchet.</b> Every reply mixes a fresh X25519 and a fresh ML-KEM-768 secret into
            the root key. Each message has its own key that is deleted after use (forward secrecy), and a stolen key heals
            after one round trip (post-compromise security).
          </li>
          <li>
            <b>Sealed sender.</b> Envelopes are encrypted to the recipient's identity key with the sender hidden inside.
            The server knows who a message is for, never who it is from.
          </li>
          <li>
            <b>Encrypted media.</b> Photos, videos and files are encrypted in 64 KiB chunks (XChaCha20-Poly1305 STREAM)
            with a fresh key per file, padded with Padmé to hide size, and deleted from the server once downloaded.
          </li>
          <li>
            <b>Self-authenticating IDs.</b> Your ID is the hash of your identity key, so a malicious server cannot
            substitute keys for a contact you added by link. Safety numbers let you verify in person.
          </li>
          <li>
            <b>Invite-only reachability.</b> Delivering a message requires your secret access key. Blocking someone
            rotates it.
          </li>
          <li>
            <b>Encrypted at rest.</b> Keys, messages and media on this device are encrypted under a key derived from your
            passphrase with Argon2id. The app locks itself after 10 minutes of inactivity.
          </li>
          <li>
            <b>No identifiers.</b> No phone number, email, or password. Requests are signed with your Ed25519 key, and
            the server does not log IP addresses.
          </li>
        </ul>
      )}
      {tab === 'server' && (
        <>
          <p>This is the complete record the server holds for your account, fetched live:</p>
          {err && <p className="error">{err}</p>}
          <pre className="json">{view ? JSON.stringify(view, null, 2) : 'Loading…'}</pre>
        </>
      )}
      {tab === 'device' && (
        <div className="device">
          <table className="kv">
            <tbody>
              <tr>
                <th>Your ID</th>
                <td className="mono">{props.client.accountId}</td>
              </tr>
              <tr>
                <th>Vault</th>
                <td>
                  Argon2id, {DEFAULT_KDF.memoryKiB / 1024} MiB, {DEFAULT_KDF.iterations} passes → XChaCha20-Poly1305
                </td>
              </tr>
              <tr>
                <th>Auto-lock</th>
                <td>After 10 minutes of inactivity</td>
              </tr>
            </tbody>
          </table>
          <button
            className="danger-btn"
            onClick={async () => {
              if (!confirm('Permanently delete your account from the server and erase everything on this device? This cannot be undone.')) return;
              try {
                await props.client.destroyEverything();
              } catch {
                /* local wipe still happened */
              }
              props.onDestroyed();
            }}
          >
            Delete account and erase this device
          </button>
        </div>
      )}
    </Modal>
  );
}
