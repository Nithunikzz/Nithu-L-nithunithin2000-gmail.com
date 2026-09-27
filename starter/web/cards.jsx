// The six cards. Each fetches on mount (the shell remounts a card on every visit), so what
// is on screen is what the server said on this visit — never a cached earlier answer.
//
// Gates: nav-level entries use `me.permissions` (the org-level set from /auth/me); row
// entries use the row's own resolved `permissions`, so a device-scoped grant shows up on
// exactly one row. "Add device" uses `me.orgWidePermissions`: creating a device is not an
// action on any existing device, so a grant on one device must not unlock it.

import React, { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';
import { Gate, ErrorNote, allowed, fmtTime } from './ui.jsx';

const KINDS = ['linux', 'macos', 'windows', 'android', 'ios'];

// Fetch on mount; expose the result, the error, and a reload.
function useLoad(load, deps) {
  const [state, setState] = useState({ data: null, error: null });
  const reload = useCallback(() => {
    load().then((data) => setState({ data, error: null }), (error) => setState({ data: null, error }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { ...state, reload };
}

// Run an action, show its failure, reload on success.
function useAction(after) {
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const run = async (fn, ok) => {
    setError(null);
    setMessage(null);
    try {
      const result = await fn();
      if (ok) setMessage(typeof ok === 'function' ? ok(result) : ok);
      await after?.();
      return result;
    } catch (err) {
      setError(err);
      return null;
    }
  };
  return { run, error, message };
}

const Status = ({ action }) => (
  <>
    <ErrorNote error={action.error} />
    {action.message && <p className="notice" role="status" data-testid="action-message">{action.message}</p>}
  </>
);

const Loading = ({ what }) => <p aria-busy="true">Loading {what}…</p>;

// --- Devices ---------------------------------------------------------------------------

export function DevicesCard({ me }) {
  const list = useLoad(() => api('GET', `/orgs/${me.orgId}/devices`), [me.orgId]);
  const action = useAction(list.reload);
  const [adding, setAdding] = useState(false);

  const start = (d, mode) => action.run(
    () => api('POST', `/orgs/${me.orgId}/sessions`, { deviceId: d.id, mode }),
    (s) => `Started a ${mode} session on ${d.name} (${s.id}).`,
  );
  const rename = (d) => {
    const name = window.prompt('New name for the device', d.name);
    if (name && name !== d.name) action.run(() => api('PATCH', `/orgs/${me.orgId}/devices/${d.id}`, { name }), 'Device renamed.');
  };
  const decommission = (d) => {
    if (window.confirm(`Decommission ${d.name}? Its sessions will end.`)) {
      action.run(() => api('DELETE', `/orgs/${me.orgId}/devices/${d.id}`), `${d.name} decommissioned.`);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <h2>Devices</h2>
        <Gate set={me.orgWidePermissions} permission="device:provision">
          <button data-testid="add-device" onClick={() => setAdding((v) => !v)}>Add device</button>
        </Gate>
      </div>
      {adding && <AddDevice me={me} onDone={() => { setAdding(false); list.reload(); }} />}
      <Status action={action} />
      <ErrorNote error={list.error} testId="load-error" />
      {!list.data && !list.error && <Loading what="devices" />}
      {list.data && list.data.devices.length === 0 && (
        <p className="empty" data-testid="devices-empty">No devices yet.</p>
      )}
      {list.data && list.data.devices.length > 0 && (
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {list.data.devices.map((d) => (
              <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                <td>{d.name}</td>
                <td>{d.kind}</td>
                <td>{d.online ? 'online' : 'offline'}</td>
                <td className="actions">
                  <Gate set={d.permissions} permission="device:view">
                    <button data-testid="start-view" onClick={() => start(d, 'view')}>View</button>
                  </Gate>
                  <Gate set={d.permissions} permission="device:control">
                    <button data-testid="start-control" onClick={() => start(d, 'control')}>Control</button>
                  </Gate>
                  <Gate set={d.permissions} permission="device:terminal">
                    <button data-testid="start-terminal" onClick={() => start(d, 'terminal')}>Terminal</button>
                  </Gate>
                  <Gate set={d.permissions} permission="device:file_transfer">
                    <button data-testid="transfer-files" onClick={() => action.run(async () => null,
                      'File transfer is not part of this console: sessions are records, not remote access.')}>Files</button>
                  </Gate>
                  <Gate set={d.permissions} permission="device:update">
                    <button data-testid="rename-device" onClick={() => rename(d)}>Rename</button>
                  </Gate>
                  <Gate set={d.permissions} permission="device:provision">
                    <button data-testid="decommission-device" className="danger" onClick={() => decommission(d)}>Decommission</button>
                  </Gate>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function AddDevice({ me, onDone }) {
  const [name, setName] = useState('');
  const [kind, setKind] = useState('linux');
  const action = useAction();
  const submit = async (e) => {
    e.preventDefault();
    if (await action.run(() => api('POST', `/orgs/${me.orgId}/devices`, { name, kind }))) onDone();
  };
  return (
    <form className="inline-form" onSubmit={submit}>
      <label>Name<input data-testid="device-name" value={name} onChange={(e) => setName(e.target.value)} /></label>
      <label>Kind
        <select data-testid="device-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
      </label>
      <button data-testid="device-submit" type="submit">Add</button>
      <Status action={action} />
    </form>
  );
}

// --- People ----------------------------------------------------------------------------

export function PeopleCard({ me, reloadMe }) {
  const list = useLoad(() => api('GET', `/orgs/${me.orgId}/members`), [me.orgId]);
  const action = useAction(list.reload);
  const [inviting, setInviting] = useState(false);
  const base = `/orgs/${me.orgId}/members`;

  const changeRole = (m, role) => action.run(() => api('PATCH', `${base}/${m.userId}`, { role }), `${m.name} is now ${role}.`);
  const toggleSuspend = (m) => m.status === 'suspended'
    ? action.run(() => api('DELETE', `${base}/${m.userId}/suspend`), `${m.name} reinstated.`)
    : action.run(() => api('POST', `${base}/${m.userId}/suspend`), `${m.name} suspended; their sessions ended.`);
  const remove = (m) => {
    if (window.confirm(`Remove ${m.name} from this organization?`)) {
      action.run(() => api('DELETE', `${base}/${m.userId}`), `${m.name} removed.`);
    }
  };
  const leave = () => {
    if (window.confirm('Leave this organization?')) {
      action.run(() => api('DELETE', `${base}/me`)).then((r) => r && reloadMe());
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <h2>People</h2>
        <Gate set={me.permissions} permission="user:invite">
          <button data-testid="invite-user" onClick={() => setInviting((v) => !v)}>Invite</button>
        </Gate>
        <button data-testid="leave-org" className="subtle" onClick={leave}>Leave org</button>
      </div>
      {inviting && <InviteForm me={me} />}
      <Status action={action} />
      <ErrorNote error={list.error} testId="load-error" />
      {!list.data && !list.error && <Loading what="people" />}
      {list.data && (
        <table>
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {list.data.members.map((m) => {
              const self = m.userId === me.user.id;
              return (
                <tr key={m.userId} data-testid="user-row" data-user-id={m.userId}>
                  <td>{m.name}{self && ' (you)'}</td>
                  <td>{m.email}</td>
                  <td>
                    {!self && allowed(me.permissions, 'user:role:update') ? (
                      <Gate set={me.permissions} permission="user:role:update">
                        <select data-testid="role-select" value={m.role} onChange={(e) => changeRole(m, e.target.value)}>
                          {me.roles.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
                        </select>
                      </Gate>
                    ) : m.role}
                  </td>
                  <td>{m.status}</td>
                  <td className="actions">
                    {!self && (
                      <>
                        <Gate set={me.permissions} permission="user:remove">
                          <button data-testid="suspend-user" onClick={() => toggleSuspend(m)}>
                            {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                          </button>
                        </Gate>
                        <Gate set={me.permissions} permission="user:remove">
                          <button data-testid="remove-user" className="danger" onClick={() => remove(m)}>Remove</button>
                        </Gate>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function InviteForm({ me }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState(me.roles[0]?.key ?? '');
  const [link, setLink] = useState(null);
  const action = useAction();
  const submit = async (e) => {
    e.preventDefault();
    setLink(null);
    const r = await action.run(() => api('POST', `/orgs/${me.orgId}/invites`, { email, role }));
    // Shown once: the server returns the raw token only in this response.
    if (r) setLink(`${window.location.origin}/invite/${r.inviteToken}`);
  };
  return (
    <form className="inline-form" onSubmit={submit}>
      <label>Email<input data-testid="invite-user-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
      <label>Role
        <select data-testid="invite-user-role" value={role} onChange={(e) => setRole(e.target.value)}>
          {me.roles.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
        </select>
      </label>
      <button data-testid="invite-user-submit" type="submit">Send invite</button>
      <Status action={action} />
      {link && (
        <p className="notice" role="status">
          Invite link (shown once): <code data-testid="invite-link">{link}</code>
        </p>
      )}
    </form>
  );
}

// --- Grants ----------------------------------------------------------------------------

export function GrantsCard({ me }) {
  const grants = useLoad(() => api('GET', `/orgs/${me.orgId}/grants`), [me.orgId]);
  const members = useLoad(() => api('GET', `/orgs/${me.orgId}/members`), [me.orgId]);
  // Device names are a nicety: a caller without device:list still sees the grants.
  const devices = useLoad(() => api('GET', `/orgs/${me.orgId}/devices`).catch(() => ({ devices: [] })), [me.orgId]);
  const action = useAction(grants.reload);
  const [creating, setCreating] = useState(false);

  const who = (id) => members.data?.members.find((m) => m.userId === id)?.email ?? id;
  const where = (id) => (id ? devices.data?.devices.find((d) => d.id === id)?.name ?? id : 'org-wide');
  // Revoked grants are history, not current authority: they are not listed.
  const live = grants.data?.grants.filter((g) => !g.revokedAt) ?? [];

  return (
    <div className="card">
      <div className="card-head">
        <h2>Grants</h2>
        <Gate set={me.permissions} permission="grant:create">
          <button data-testid="new-grant" onClick={() => setCreating((v) => !v)}>New grant</button>
        </Gate>
      </div>
      {creating && (
        <NewGrant me={me} members={members.data?.members ?? []} devices={devices.data?.devices ?? []}
          onDone={() => { setCreating(false); grants.reload(); }} />
      )}
      <Status action={action} />
      <ErrorNote error={grants.error} testId="load-error" />
      {!grants.data && !grants.error && <Loading what="grants" />}
      {grants.data && live.length === 0 && <p className="empty" data-testid="grants-empty">No grants.</p>}
      {live.length > 0 && (
        <table>
          <thead><tr><th>Effect</th><th>User</th><th>Scope</th><th>Permissions</th><th>Window</th><th>Actions</th></tr></thead>
          <tbody>
            {live.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                <td><span className={`pill ${g.effect}`}>{g.effect}</span></td>
                <td>{who(g.userId)}</td>
                <td>{where(g.deviceId)}</td>
                <td><code>{g.permissions.join(', ')}</code></td>
                <td>{g.startsAt || g.expiresAt ? `${fmtTime(g.startsAt)} → ${fmtTime(g.expiresAt)}` : 'always'}</td>
                <td className="actions">
                  <Gate set={me.permissions} permission="grant:revoke">
                    <button data-testid="revoke-grant" className="danger"
                      onClick={() => action.run(() => api('DELETE', `/orgs/${me.orgId}/grants/${g.id}`), 'Grant revoked.')}>
                      Revoke
                    </button>
                  </Gate>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function NewGrant({ me, members, devices, onDone }) {
  const others = members.filter((m) => m.userId !== me.user.id && m.status === 'active');
  const catalogue = Object.keys(me.permissions).sort();
  const [userId, setUserId] = useState(others[0]?.userId ?? '');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [expiresAt, setExpiresAt] = useState('');
  const [picked, setPicked] = useState(new Set());
  const action = useAction();

  const toggle = (p) => setPicked((s) => { const n = new Set(s); if (n.has(p)) n.delete(p); else n.add(p); return n; });
  const submit = async (e) => {
    e.preventDefault();
    const body = { userId, effect, permissions: [...picked], deviceId: deviceId || null };
    if (expiresAt) body.expiresAt = new Date(expiresAt).toISOString();
    if (await action.run(() => api('POST', `/orgs/${me.orgId}/grants`, body))) onDone();
  };

  return (
    <form className="inline-form grant-form" onSubmit={submit}>
      <label>User
        <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
          {others.map((m) => <option key={m.userId} value={m.userId}>{m.email}</option>)}
        </select>
      </label>
      <label>Scope
        <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">Whole org</option>
          {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
      </label>
      <label>Effect
        <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)}>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </label>
      <label>Expires
        <input data-testid="grant-expires" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
      </label>
      <fieldset>
        <legend>Permissions</legend>
        {catalogue.map((p) => (
          <label key={p} className="check">
            <input type="checkbox" data-permission-key={p} checked={picked.has(p)} onChange={() => toggle(p)} /> {p}
          </label>
        ))}
      </fieldset>
      <button data-testid="grant-submit" type="submit">Create grant</button>
      <Status action={action} />
    </form>
  );
}

// --- Sessions --------------------------------------------------------------------------

export function SessionsCard({ me }) {
  const list = useLoad(() => api('GET', `/orgs/${me.orgId}/sessions`), [me.orgId]);
  const devices = useLoad(() => api('GET', `/orgs/${me.orgId}/devices`).catch(() => ({ devices: [] })), [me.orgId]);
  const action = useAction(list.reload);
  const [starting, setStarting] = useState(false);
  const name = (id) => devices.data?.devices.find((d) => d.id === id)?.name ?? id;

  return (
    <div className="card">
      <div className="card-head">
        <h2>Sessions</h2>
        <Gate set={me.permissions} permission="session:start">
          <button data-testid="new-session" onClick={() => setStarting((v) => !v)}>Start a session</button>
        </Gate>
      </div>
      {starting && <NewSession me={me} devices={devices.data?.devices ?? []} onDone={() => { setStarting(false); list.reload(); }} />}
      <Status action={action} />
      <ErrorNote error={list.error} testId="load-error" />
      {!list.data && !list.error && <Loading what="sessions" />}
      {list.data && list.data.sessions.length === 0 && <p className="empty" data-testid="sessions-empty">No sessions.</p>}
      {list.data && list.data.sessions.length > 0 && (
        <table>
          <thead><tr><th>Device</th><th>Mode</th><th>State</th><th>Started</th><th>Ends</th><th>Actions</th></tr></thead>
          <tbody>
            {list.data.sessions.map((s) => {
              const own = s.user_id === me.user.id;
              const stop = (
                <button data-testid="stop-session" onClick={() => action.run(() => api('DELETE', `/sessions/${s.id}`), 'Session stopped.')}>
                  Stop
                </button>
              );
              return (
                <tr key={s.id} data-testid="session-row" data-session-id={s.id} data-state-value={s.state}>
                  <td>{name(s.device_id)}</td>
                  <td>{s.mode}</td>
                  <td>{s.state}{s.end_reason ? ` (${s.end_reason})` : ''}</td>
                  <td>{fmtTime(s.started_at)}</td>
                  <td>{fmtTime(s.ended_at ?? s.expires_at)}</td>
                  <td className="actions">
                    {s.state !== 'ended' && (own
                      ? React.cloneElement(stop, { 'data-state': 'unlocked' })
                      : <Gate set={me.permissions} permission="session:terminate">{stop}</Gate>)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function NewSession({ me, devices, onDone }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id ?? '');
  const [mode, setMode] = useState('view');
  const action = useAction();
  const submit = async (e) => {
    e.preventDefault();
    if (await action.run(() => api('POST', `/orgs/${me.orgId}/sessions`, { deviceId, mode }))) onDone();
  };
  return (
    <form className="inline-form" onSubmit={submit}>
      <label>Device
        <select data-testid="session-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
      </label>
      <label>Mode
        <select data-testid="session-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="view">view</option><option value="control">control</option><option value="terminal">terminal</option>
        </select>
      </label>
      <button data-testid="session-submit" type="submit">Start</button>
      <Status action={action} />
    </form>
  );
}

// --- Audit -----------------------------------------------------------------------------

const PAGE = 50;

export function AuditCard({ me }) {
  const [offset, setOffset] = useState(0);
  const list = useLoad(() => api('GET', `/orgs/${me.orgId}/audit?limit=${PAGE}&offset=${offset}`), [me.orgId, offset]);
  return (
    <div className="card">
      <div className="card-head"><h2>Audit</h2></div>
      <ErrorNote error={list.error} testId="load-error" />
      {!list.data && !list.error && <Loading what="audit events" />}
      {list.data && (
        <>
          <table>
            <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th></tr></thead>
            <tbody>
              {list.data.events.map((e) => (
                <tr key={e.id} data-testid="audit-row" data-result={e.result}>
                  <td>{fmtTime(e.at)}</td>
                  <td>{e.actor_id ?? '—'}</td>
                  <td>{e.action}</td>
                  <td>{e.target_type ? `${e.target_type} ${e.target_id ?? ''}` : '—'}</td>
                  <td><span className={`pill ${e.result}`}>{e.result}</span>{e.reason_code ? ` ${e.reason_code}` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="pager">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
            <span>{list.data.total === 0 ? 'No events' : `${offset + 1}–${Math.min(offset + PAGE, list.data.total)} of ${list.data.total}`}</span>
            <button disabled={offset + PAGE >= list.data.total} onClick={() => setOffset(offset + PAGE)}>Older</button>
          </div>
        </>
      )}
    </div>
  );
}

// --- Admin -----------------------------------------------------------------------------

export function AdminCard({ me, reloadMe, onOrgGone }) {
  const action = useAction();
  const org = me.orgs.find((o) => o.id === me.orgId);

  const rename = async () => {
    const name = window.prompt('New name for the organization', org?.name);
    if (!name || name === org?.name) return;
    if (await action.run(() => api('PATCH', `/orgs/${me.orgId}`, { name }))) await reloadMe();
  };
  const remove = async () => {
    const typed = window.prompt(`Type the organization's name to delete it: ${org?.name}`);
    if (typed !== org?.name) return;
    if (await action.run(() => api('DELETE', `/orgs/${me.orgId}`))) await onOrgGone();
  };

  return (
    <div className="card">
      <div className="card-head"><h2>Admin</h2></div>
      <p>{org?.name} <span className="muted">({me.orgId})</span></p>
      <div className="actions">
        <Gate set={me.permissions} permission="org:update">
          <button data-testid="rename-org" onClick={rename}>Rename organization</button>
        </Gate>
        <Gate set={me.permissions} permission="org:delete">
          <button data-testid="delete-org" className="danger" onClick={remove}>Delete organization</button>
        </Gate>
      </div>
      <Status action={action} />
    </div>
  );
}
