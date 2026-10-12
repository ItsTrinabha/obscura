import { useCallback, useEffect, useRef, useState } from 'react';
import type { ClientEvent, Contact, Message, ObscuraClient } from '@obscura/core';
import { formatDuration, MAX_FILE_BYTES } from '@obscura/core';
import { Alert, Back, Check, CheckCheck, Clock, File as FileIcon, Lock, Paperclip, Plus, QR, Send, Server, Shield, ShieldCheck, Timer } from './Icons';
import { AddContactModal, InspectorModal, InviteModal, SafetyModal, SecurityModal } from './Modals';

type ModalState =
  | { kind: 'invite' }
  | { kind: 'add'; link?: string }
  | { kind: 'security' }
  | { kind: 'safety'; contact: Contact }
  | { kind: 'inspect'; message: Message; contact: Contact }
  | null;

const TIMERS = [0, 30, 300, 3600, 86400, 604800];

export function Messenger(props: { client: ObscuraClient; pendingInvite: string | null; clearInvite: () => void; onLock: () => void; onDestroyed: () => void }) {
  const { client } = props;
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [online, setOnline] = useState(client.online);
  const [modal, setModal] = useState<ModalState>(null);
  const [toast, setToast] = useState<string | null>(null);
  const activeRef = useRef<string | null>(null);
  activeRef.current = activeId;

  const refreshContacts = useCallback(async () => setContacts(await client.contacts()), [client]);
  const refreshMessages = useCallback(async () => {
    const id = activeRef.current;
    setMessages(id ? await client.messages(id) : []);
  }, [client]);

  useEffect(() => {
    void refreshContacts();
    const off = client.on((e: ClientEvent) => {
      if (e.type === 'connection') setOnline(e.state === 'online');
      if (e.type === 'contact') void refreshContacts();
      if (e.type === 'error') setToast(e.error);
      if ((e.type === 'message' || e.type === 'message-updated' || e.type === 'messages-removed') && e.contactId === activeRef.current) {
        void refreshMessages();
        if (e.type === 'message' && e.message.dir === 'in' && document.visibilityState === 'visible') void client.markRead(e.contactId);
      }
    });
    return () => {
      off();
    };
  }, [client, refreshContacts, refreshMessages]);

  useEffect(() => {
    if (props.pendingInvite) {
      setModal({ kind: 'add', link: props.pendingInvite });
      props.clearInvite();
    }
  }, [props.pendingInvite]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    void refreshMessages();
    if (activeId) void client.markRead(activeId);
  }, [activeId, client, refreshMessages]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(t);
  }, [toast]);

  const active = contacts.find((c) => c.id === activeId) ?? null;

  return (
    <div className={`app ${active ? 'has-chat' : ''}`}>
      <aside className="sidebar">
        <header className="me">
          <div className="avatar">{initials(client.name)}</div>
          <div className="me-text">
            <strong>{client.name}</strong>
            <span className={`status ${online ? 'on' : ''}`}>{online ? 'Connected, end-to-end encrypted' : 'Connecting…'}</span>
          </div>
        </header>
        <div className="actions">
          <button onClick={() => setModal({ kind: 'invite' })} title="Share your invite">
            <QR /> Invite
          </button>
          <button onClick={() => setModal({ kind: 'add' })} title="Add a contact">
            <Plus /> Add
          </button>
          <button onClick={() => setModal({ kind: 'security' })} title="Security center">
            <Server /> Security
          </button>
          <button onClick={props.onLock} title="Lock now (wipes keys from memory)">
            <Lock size={18} /> Lock
          </button>
        </div>
        <ul className="contacts">
          {contacts.length === 0 && (
            <li className="empty">
              No conversations yet. Share your <b>invite</b> link or QR code with someone, or <b>add</b> theirs.
            </li>
          )}
          {contacts.map((c) => (
            <li key={c.id} className={c.id === activeId ? 'active' : ''} onClick={() => setActiveId(c.id)}>
              <div className="avatar">{initials(c.name)}</div>
              <div className="c-text">
                <strong>
                  {c.name} {c.verified && <span className="verified" title="Safety number verified"><ShieldCheck size={14} /></span>}
                  {c.blocked && <span className="tag">blocked</span>}
                </strong>
                <span className="muted mono">{c.id.slice(0, 8)}…</span>
              </div>
              {c.unread > 0 && c.id !== activeId && <span className="badge">{c.unread}</span>}
            </li>
          ))}
        </ul>
        <footer className="sidebar-foot">
          <Shield size={14} /> PQXDH · ML-KEM-768 · Double Ratchet
        </footer>
      </aside>

      <main className="chat">
        {active ? (
          <Chat
            key={active.id}
            client={client}
            contact={active}
            messages={messages}
            onBack={() => setActiveId(null)}
            onSafety={() => setModal({ kind: 'safety', contact: active })}
            onInspect={(m) => setModal({ kind: 'inspect', message: m, contact: active })}
            onToast={setToast}
          />
        ) : (
          <div className="placeholder">
            <Shield size={56} />
            <h2>Private by design</h2>
            <p>
              Every message, photo, video and file is encrypted on this device before it leaves. Keys are agreed with a
              hybrid of X25519 and the post-quantum ML-KEM-768, and replaced after every reply.
            </p>
          </div>
        )}
      </main>

      {modal?.kind === 'invite' && <InviteModal client={client} onClose={() => setModal(null)} />}
      {modal?.kind === 'add' && (
        <AddContactModal
          client={client}
          initialLink={modal.link}
          onClose={() => setModal(null)}
          onAdded={(c) => {
            setModal(null);
            void refreshContacts();
            setActiveId(c.id);
          }}
        />
      )}
      {modal?.kind === 'security' && <SecurityModal client={client} onClose={() => setModal(null)} onDestroyed={props.onDestroyed} />}
      {modal?.kind === 'safety' && (
        <SafetyModal
          client={client}
          contact={modal.contact}
          onClose={() => {
            setModal(null);
            void refreshContacts();
          }}
        />
      )}
      {modal?.kind === 'inspect' && <InspectorModal client={client} message={modal.message} contact={modal.contact} onClose={() => setModal(null)} />}
      {toast && (
        <div className="toast" role="status" onClick={() => setToast(null)}>
          {toast}
        </div>
      )}
    </div>
  );
}

function Chat(props: {
  client: ObscuraClient;
  contact: Contact;
  messages: Message[];
  onBack: () => void;
  onSafety: () => void;
  onInspect: (m: Message) => void;
  onToast: (s: string) => void;
}) {
  const { client, contact, messages } = props;
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [drag, setDrag] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight });
  }, [messages.length]);

  async function send() {
    const t = text.trim();
    if (!t) return;
    setText('');
    setSending(true);
    try {
      await client.sendText(contact.id, t);
    } catch (e) {
      props.onToast((e as Error).message);
    } finally {
      setSending(false);
    }
  }

  async function sendFiles(files: FileList | File[]) {
    for (const f of Array.from(files)) {
      if (f.size > MAX_FILE_BYTES) {
        props.onToast(`${f.name} is larger than 100 MB`);
        continue;
      }
      setSending(true);
      try {
        await client.sendFile(contact.id, new Uint8Array(await f.arrayBuffer()), f.name, f.type);
      } catch (e) {
        props.onToast((e as Error).message);
      } finally {
        setSending(false);
      }
    }
  }

  return (
    <div
      className={`chat-inner ${drag ? 'drag' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDrag(false);
        if (e.dataTransfer.files.length) void sendFiles(e.dataTransfer.files);
      }}
    >
      <header className="chat-head">
        <button className="icon back" onClick={props.onBack} aria-label="Back">
          <Back />
        </button>
        <div className="avatar">{initials(contact.name)}</div>
        <div className="chat-title">
          <strong>{contact.name}</strong>
          <button className={`verify ${contact.verified ? 'ok' : ''}`} onClick={props.onSafety}>
            {contact.verified ? (
              <>
                <ShieldCheck size={14} /> Verified
              </>
            ) : (
              <>
                <Shield size={14} /> Verify safety number
              </>
            )}
          </button>
        </div>
        <label className="timer" title="Disappearing messages">
          <Timer />
          <select
            value={contact.timer}
            onChange={(e) => void client.setTimer(contact.id, Number(e.target.value)).catch((err) => props.onToast(err.message))}
            aria-label="Disappearing messages"
          >
            {TIMERS.map((t) => (
              <option key={t} value={t}>
                {t ? formatDuration(t) : 'Off'}
              </option>
            ))}
          </select>
        </label>
        <ChatMenu client={client} contact={contact} onToast={props.onToast} />
      </header>

      <div className="messages" ref={scroller}>
        <div className="e2ee-banner">
          <Lock /> Messages, photos, videos and files are end-to-end encrypted with post-quantum keys. Not even the server can read them.
          {!contact.verified && (
            <button className="link" onClick={props.onSafety}>
              Verify {contact.name}
            </button>
          )}
        </div>
        {messages.map((m) =>
          m.dir === 'system' ? (
            <div key={m.id} className="system-msg">
              <Timer size={14} /> {m.text}
            </div>
          ) : (
            <Bubble key={m.id} client={client} message={m} onInspect={() => props.onInspect(m)} />
          ),
        )}
      </div>

      <footer className="composer">
        <input ref={fileInput} type="file" multiple hidden onChange={(e) => e.target.files && void sendFiles(e.target.files).then(() => (e.target.value = ''))} />
        <button className="icon" onClick={() => fileInput.current?.click()} aria-label="Attach photo, video or file" disabled={contact.blocked}>
          <Paperclip />
        </button>
        <textarea
          rows={1}
          placeholder={contact.blocked ? 'You blocked this contact' : contact.accessKey ? 'Encrypted message' : 'Waiting for this contact to share their invite…'}
          value={text}
          disabled={contact.blocked || !contact.accessKey}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void send();
            }
          }}
        />
        <button className="icon send" onClick={send} disabled={!text.trim() || sending} aria-label="Send">
          <Send />
        </button>
      </footer>
    </div>
  );
}

function ChatMenu(props: { client: ObscuraClient; contact: Contact; onToast: (s: string) => void }) {
  const [open, setOpen] = useState(false);
  const { client, contact } = props;
  return (
    <div className="menu">
      <button className="icon" onClick={() => setOpen(!open)} aria-label="Conversation menu">
        ⋯
      </button>
      {open && (
        <ul onMouseLeave={() => setOpen(false)}>
          <li
            onClick={async () => {
              setOpen(false);
              const name = prompt('Rename contact', contact.name);
              if (name?.trim()) await client.renameContact(contact.id, name.trim());
            }}
          >
            Rename
          </li>
          {!contact.blocked && (
            <li
              className="danger"
              onClick={async () => {
                setOpen(false);
                if (!confirm(`Block ${contact.name}? Your access key is rotated, so they can no longer deliver anything to you.`)) return;
                try {
                  await client.blockContact(contact.id);
                  props.onToast(`${contact.name} is blocked and their access is revoked.`);
                } catch (e) {
                  props.onToast((e as Error).message);
                }
              }}
            >
              Block and revoke access
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

const INLINE_IMAGE = /^image\/(png|jpeg|gif|webp|avif)$/;
const INLINE_VIDEO = /^video\/(mp4|webm|ogg|quicktime)$/;
const INLINE_AUDIO = /^audio\/(mpeg|ogg|wav|webm|mp4|aac|x-m4a)$/;

function Bubble(props: { client: ObscuraClient; message: Message; onInspect: () => void }) {
  const { message: m } = props;
  const [url, setUrl] = useState<string | null>(null);
  const fileId = m.file?.state === 'ready' ? m.file.fileId : null;
  const mime = m.file?.mime ?? '';

  useEffect(() => {
    if (!fileId) return;
    let u: string | null = null;
    let cancelled = false;
    void props.client.getFile(fileId).then((data) => {
      if (!data || cancelled) return;
      // Decrypted bytes live only in memory as a blob: URL; revoked when the bubble unmounts.
      u = URL.createObjectURL(new Blob([data.slice().buffer], { type: INLINE_IMAGE.test(mime) || INLINE_VIDEO.test(mime) || INLINE_AUDIO.test(mime) ? mime : 'application/octet-stream' }));
      setUrl(u);
    });
    return () => {
      cancelled = true;
      if (u) URL.revokeObjectURL(u);
    };
  }, [fileId, mime, props.client]);

  return (
    <div className={`bubble-row ${m.dir}`}>
      <div className="bubble">
        {m.file && (
          <div className="attachment">
            {m.file.state === 'downloading' && <div className="dl">Downloading and decrypting {m.file.name}…</div>}
            {m.file.state === 'error' && <div className="dl error">Could not download or verify {m.file.name}</div>}
            {url && INLINE_IMAGE.test(mime) && <img src={url} alt={m.file.name} />}
            {url && INLINE_VIDEO.test(mime) && <video src={url} controls playsInline />}
            {url && INLINE_AUDIO.test(mime) && <audio src={url} controls />}
            {url && (
              <a className="file" href={url} download={m.file.name}>
                <FileIcon /> <span>{m.file.name}</span> <em>{formatBytes(m.file.size)}</em>
              </a>
            )}
          </div>
        )}
        {m.text && <div className="text">{m.text}</div>}
        <div className="meta">
          {m.expiresAt && <Timer size={12} />}
          <span>{new Date(m.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          {m.crypto && (
            <button className="lock-btn" onClick={props.onInspect} title="Inspect encryption">
              <Lock size={12} />
              {m.crypto.pqRatchet ? 'PQ' : 'PQXDH'}
            </button>
          )}
          {m.dir === 'out' && <StatusIcon status={m.status} />}
        </div>
      </div>
    </div>
  );
}

function StatusIcon({ status }: { status?: Message['status'] }) {
  if (status === 'sending') return <span title="Encrypting and sending"><Clock size={12} /></span>;
  if (status === 'failed') return <span className="error" title="Failed to send"><Alert size={12} /></span>;
  if (status === 'sent') return <span title="Sent"><Check size={12} /></span>;
  if (status === 'delivered') return <span title="Delivered"><CheckCheck size={12} /></span>;
  if (status === 'read') return <span className="read" title="Read"><CheckCheck size={12} /></span>;
  return null;
}

export function initials(name: string): string {
  return (
    name
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => [...w][0]?.toUpperCase() ?? '')
      .join('') || '?'
  );
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
