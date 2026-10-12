import { useCallback, useEffect, useRef, useState } from 'react';
import { ObscuraClient } from '@obscura/core';
import { IdbKV } from './idb';
import { Welcome } from './components/Welcome';
import { Messenger } from './components/Messenger';

const kv = new IdbKV();
const AUTO_LOCK_MS = 10 * 60_000;

function readInviteFromHash(): string | null {
  return location.hash.startsWith('#/invite/') ? location.href : null;
}

export function App() {
  const [client, setClient] = useState<ObscuraClient | null>(null);
  const [hasAccount, setHasAccount] = useState<boolean | null>(null);
  const [pendingInvite, setPendingInvite] = useState<string | null>(readInviteFromHash);
  const lastActivity = useRef(Date.now());

  useEffect(() => {
    ObscuraClient.hasAccount(kv).then(setHasAccount);
    const onHash = () => {
      const inv = readInviteFromHash();
      if (inv) setPendingInvite(inv);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // The invite secret lives only in the fragment; clear it from the address bar once captured.
  useEffect(() => {
    if (pendingInvite && location.hash) history.replaceState(null, '', location.pathname);
  }, [pendingInvite]);

  const lock = useCallback(() => {
    setClient((c) => {
      c?.lock();
      return null;
    });
  }, []);

  // Auto-lock after inactivity: keys are wiped from memory, the vault needs the passphrase again.
  useEffect(() => {
    if (!client) return;
    const bump = () => (lastActivity.current = Date.now());
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    const t = setInterval(() => {
      if (Date.now() - lastActivity.current > AUTO_LOCK_MS) lock();
    }, 15_000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, bump));
      clearInterval(t);
    };
  }, [client, lock]);

  if (hasAccount === null) return <div className="splash" />;

  if (!client) {
    return (
      <Welcome
        kv={kv}
        hasAccount={hasAccount}
        invitePending={!!pendingInvite}
        onReady={(c) => {
          lastActivity.current = Date.now();
          setHasAccount(true);
          setClient(c);
        }}
        onErased={() => setHasAccount(false)}
      />
    );
  }

  return (
    <Messenger
      client={client}
      pendingInvite={pendingInvite}
      clearInvite={() => setPendingInvite(null)}
      onLock={lock}
      onDestroyed={() => {
        setClient(null);
        setHasAccount(false);
      }}
    />
  );
}
