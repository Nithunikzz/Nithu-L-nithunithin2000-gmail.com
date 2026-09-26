// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { nowIso } from './db.js';
import { resolve, MODE_PERMISSION } from './permissions.js';

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/lifecycle.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export function roleRanks(db) { throw todo('roleRanks'); }
export function assertRoleExists(db, role) { throw todo('assertRoleExists'); }
export function assertCanModify(db, callerRole, targetRole) { throw todo('assertCanModify'); }
export function assertNotLastOwner(db, orgId, userId) { throw todo('assertNotLastOwner'); }
// The one implementation of "these sessions are over". Filters are ANDed; omit one to not
// filter on it. Returns the number of sessions ended.
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const where = ["state <> 'ended'", 'org_id = ?'];
  const args = [orgId];
  if (userId) { where.push('user_id = ?'); args.push(userId); }
  if (deviceId) { where.push('device_id = ?'); args.push(deviceId); }
  if (exceptSessionId) { where.push('id <> ?'); args.push(exceptSessionId); }
  const now = nowIso();
  return db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE ${where.join(' AND ')}`
  ).run(reason, now, ...args).changes;
}
// A session past its TTL still says 'active' until something writes otherwise, and while it
// does it still holds one_exclusive_session_per_device. Nothing runs in the background, so
// every path that reads or claims sessions calls this first. ended_at is the moment it
// actually expired, not the moment we noticed. Filters as in endActiveSessions.
export function expireSessions(db, { orgId, deviceId, sessionId } = {}) {
  const where = ["state <> 'ended'", 'expires_at <= ?'];
  const args = [nowIso()];
  if (orgId) { where.push('org_id = ?'); args.push(orgId); }
  if (deviceId) { where.push('device_id = ?'); args.push(deviceId); }
  if (sessionId) { where.push('id = ?'); args.push(sessionId); }
  return db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = expires_at WHERE ${where.join(' AND ')}`
  ).run(...args).changes;
}

// What authorised this session, frozen at start. Sessions are grandfathered: this snapshot,
// not the live permission set, is the session's authority until it ends (PERMISSIONS.md §7).
export function snapshotAuthority(db, { userId, orgId, deviceId, mode }) {
  const { role, permissions } = resolve(db, { userId, orgId, deviceId });
  const used = ['session:start', MODE_PERMISSION[mode]].map((p) => [p, permissions[p]]);
  return {
    role,
    permissions: Object.fromEntries(used),
    grantIds: [...new Set(used.map(([, d]) => d.source).filter((s) => s?.startsWith('grant:')).map((s) => s.slice(6)))],
    snapshotAt: nowIso(),
  };
}

// started_at + org.max_session_minutes: the TTL that bounds grandfathered authority.
export function sessionExpiry(db, orgId) {
  const { max_session_minutes } = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  return new Date(Date.now() + max_session_minutes * 60_000).toISOString();
}
