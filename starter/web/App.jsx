// Session, sign-in, invite redemption, and the shell (org switcher + nav).
//
// Every permission-gated element reads the server's resolved set — `me.permissions` from
// /auth/me for nav, each row's own `permissions` for row actions. There is no role-to-
// permission table in web/. An element is rendered with data-state="unlocked" or not at all.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api, auth, setAccessToken, clearAccessToken, setStaleHandler } from './api.js';
import { Gate, ErrorNote, themeStyle, allowed } from './ui.jsx';
import { DevicesCard, PeopleCard, GrantsCard, SessionsCard, AuditCard, AdminCard } from './cards.jsx';

// The org lives in the URL (/o/<orgId>), which is the one place it can survive a reload
// without web storage. The server still decides whether the caller may be there.
const orgFromUrl = () => /^\/o\/([^/]+)/.exec(window.location.pathname)?.[1] ?? null;
const inviteFromUrl = () => /^\/invite\/([^/]+)/.exec(window.location.pathname)?.[1] ?? null;

export function App() {
  const [phase, setPhase] = useState('loading'); // loading | login | app | invite
  const [me, setMe] = useState(null);
  const [notice, setNotice] = useState(null);
  const orgRef = useRef(null);

  // Load /auth/me for the token we now hold, and point the URL at its org.
  const enter = useCallback(async (token) => {
    setAccessToken(token);
    const next = await auth.me();
    orgRef.current = next.orgId;
    window.history.replaceState(null, '', `/o/${next.orgId}`);
    setMe(next);
    setPhase('app');
  }, []);

  const toLogin = useCallback((message = null) => {
    clearAccessToken();
    orgRef.current = null;
    setMe(null);
    setNotice(message);
    window.history.replaceState(null, '', '/');
    setPhase('login');
  }, []);

  // A stale token means our authority changed: get a fresh token for the same org and
  // re-read what the server now says we may do.
  useEffect(() => {
    setStaleHandler(async () => {
      try {
        const r = await auth.refresh(orgRef.current);
        if (!r.token) throw new Error('no org');
        await enter(r.token);
      } catch {
        toLogin('Your session ended. Sign in again.');
        throw new Error('session ended');
      }
    });
  }, [enter, toLogin]);

  // First load: an invite link, or try to resume from the refresh cookie.
  useEffect(() => {
    if (inviteFromUrl()) { setPhase('invite'); return; }
    (async () => {
      const wanted = orgFromUrl();
      try {
        let r;
        try { r = await auth.refresh(wanted); } catch (err) {
          // The org in the URL is not one we can open any more: fall back to the default.
          if (wanted && err.status === 404) r = await auth.refresh(null); else throw err;
        }
        if (r.token) await enter(r.token); else toLogin();
      } catch {
        toLogin();
      }
    })();
  }, [enter, toLogin]);

  const signOut = useCallback(async () => {
    try { await auth.logout(); } catch { /* signing out locally regardless */ }
    toLogin();
  }, [toLogin]);

  if (phase === 'loading') return <main className="centered" aria-busy="true">Loading…</main>;
  if (phase === 'invite') {
    return <InvitePage token={inviteFromUrl()} onDone={(msg) => toLogin(msg)} />;
  }
  if (phase === 'login') {
    return <LoginPage notice={notice} onSignedIn={async (r) => {
      if (!r.token) { toLogin('You are not a member of any organization yet.'); return; }
      await enter(r.token);
    }} />;
  }
  return <Shell me={me} enter={enter} onSignOut={signOut} />;
}

// --- sign-in -------------------------------------------------------------------------

function LoginPage({ notice, onSignedIn }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    // Say what is missing rather than sending a request we know will fail.
    if (!email.trim() || !password) {
      const missing = [!email.trim() && 'email', !password && 'password'].filter(Boolean).join(' and ');
      setError({ code: 'VALIDATION', message: `Enter your ${missing}.` });
      return;
    }
    setBusy(true);
    try {
      await onSignedIn(await auth.login(email.trim(), password));
    } catch (err) {
      // The server's words, unimproved: a wrong password and an unknown account read the same.
      setError({ code: err.code, message: err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="centered">
      <form className="card login" data-testid="login-form" onSubmit={submit} noValidate>
        <h1>RemoteOps</h1>
        {notice && <p className="notice" role="status">{notice}</p>}
        <label>Email
          <input data-testid="login-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label>Password
          <input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="error" data-testid="login-error" data-error-code={error.code} role="alert" aria-live="assertive">
            {error.message}
          </p>
        )}
        <button data-testid="login-submit" type="submit" disabled={busy}>Sign in</button>
      </form>
    </main>
  );
}

// --- invite redemption ----------------------------------------------------------------

function InvitePage({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // Only what the public endpoint returns is shown. A bad token shows the refusal and
    // nothing else — no org name, because we never learned one.
    auth.peekInvite(token).then(setInvite, (err) => setError(err));
  }, [token]);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await auth.acceptInvite(token, { name, password });
      onDone(`Welcome to ${invite.orgName}. Sign in to continue.`);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (!invite) {
    return (
      <main className="centered">
        <div className="card">
          <h1>Invitation</h1>
          {error
            ? <p className="error" data-testid="invite-error" data-error-code={error.code} role="alert">{inviteMessage(error)}</p>
            : <p aria-busy="true">Checking your invitation…</p>}
        </div>
      </main>
    );
  }

  return (
    <main className="centered">
      <form className="card login" onSubmit={submit}>
        <h1>Join {invite.orgName}</h1>
        <p>You've been invited as <strong data-testid="invite-role">{invite.role}</strong>.</p>
        <label>Email<input data-testid="invite-email" value={invite.email} readOnly /></label>
        <label>Your name<input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label>Password
          <input data-testid="invite-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <p className="hint">Already have an account with this email? Enter its current password.</p>
        {error && <p className="error" data-testid="invite-error" data-error-code={error.code} role="alert">{error.message}</p>}
        <button data-testid="invite-submit" type="submit" disabled={busy}>Accept invitation</button>
      </form>
    </main>
  );
}

function inviteMessage(err) {
  if (err.status === 404) return 'This invitation link is not valid.';
  if (err.status === 410) return 'This invitation has expired or was cancelled. Ask for a new one.';
  if (err.status === 409) return 'This invitation has already been used.';
  return err.message;
}

// --- the shell ------------------------------------------------------------------------

// Card key, test id suffix, and the permission(s) that make it appear.
const CARDS = [
  { key: 'devices', label: 'Devices', any: ['device:list'] },
  { key: 'people', label: 'People', any: ['user:read'] },
  { key: 'grants', label: 'Grants', any: ['user:read'] },
  { key: 'sessions', label: 'Sessions', any: ['session:view'] },
  { key: 'audit', label: 'Audit', any: ['audit:read'] },
  { key: 'admin', label: 'Admin', any: ['org:update', 'org:delete'] },
];

function Shell({ me, enter, onSignOut }) {
  const visible = CARDS.filter((c) => c.any.some((p) => allowed(me.permissions, p)));
  const [view, setView] = useState(visible[0]?.key ?? null);
  const [error, setError] = useState(null);
  const current = visible.find((c) => c.key === view) ? view : visible[0]?.key ?? null;

  // Switching mints a token for the other org. If ours has gone stale meanwhile, the
  // refresh cookie can mint one for the target org directly.
  const switchOrg = async (orgId) => {
    setError(null);
    try {
      let r;
      try { r = await auth.switchOrg(orgId); } catch (err) {
        if (err.code !== 'TOKEN_STALE') throw err;
        r = await auth.refresh(orgId);
      }
      await enter(r.token);
      setView(null);
    } catch (err) { setError(err); }
  };

  const createOrg = async () => {
    const name = window.prompt('Name for the new organization');
    if (!name) return;
    setError(null);
    try {
      const org = await api('POST', '/orgs', { name });
      await switchOrg(org.id);
    } catch (err) { setError(err); }
  };

  // After an action that changes our own authority or the org itself.
  const reloadMe = async () => {
    try {
      const r = await auth.refresh(me.orgId);
      await enter(r.token);
    } catch (err) { setError(err); }
  };

  const props = { me, reloadMe };
  return (
    <div className="shell" data-testid="app-shell" data-org-id={me.orgId} data-org-theme={me.orgs.find((o) => o.id === me.orgId)?.theme ?? ''}
      style={themeStyle(me.orgs.find((o) => o.id === me.orgId)?.theme)}>
      <header className="topbar">
        <div className="org-title">
          <strong>{me.orgs.find((o) => o.id === me.orgId)?.name}</strong>
          <span className="role">as <span data-testid="active-role">{me.role}</span></span>
        </div>
        <nav className="orgs" aria-label="Organizations">
          {me.orgs.map((o) => (
            <button key={o.id} data-testid="org-option" data-org-id={o.id}
              aria-current={o.id === me.orgId ? 'true' : undefined}
              className={o.id === me.orgId ? 'org active' : 'org'} onClick={() => switchOrg(o.id)}>
              {o.name}
            </button>
          ))}
          <button data-testid="create-org" onClick={createOrg}>+ New org</button>
        </nav>
        <span className="who">{me.user.email}</span>
        <button data-testid="sign-out" onClick={onSignOut}>Sign out</button>
      </header>

      <ErrorNote error={error} />

      <div className="body">
        <nav className="cards" aria-label="Sections">
          {visible.map((c) => (
            <Gate key={c.key} set={me.permissions} permission={c.any.find((p) => allowed(me.permissions, p))}>
              <button data-testid={`nav-${c.key}`} className={c.key === current ? 'active' : ''} onClick={() => setView(c.key)}>
                {c.label}
              </button>
            </Gate>
          ))}
        </nav>
        {/* key: remount on org or card change, so each visit fetches fresh from the server */}
        <section className="content" key={`${me.orgId}:${current}`}>
          {current === 'devices' && <DevicesCard {...props} />}
          {current === 'people' && <PeopleCard {...props} />}
          {current === 'grants' && <GrantsCard {...props} />}
          {current === 'sessions' && <SessionsCard {...props} />}
          {current === 'audit' && <AuditCard {...props} />}
          {current === 'admin' && <AdminCard {...props} onOrgGone={async () => {
            const other = me.orgs.find((o) => o.id !== me.orgId);
            if (other) await switchOrg(other.id); else await onSignOut();
          }} />}
          {!current && <p className="empty">You have no sections available in this organization.</p>}
        </section>
      </div>
    </div>
  );
}
