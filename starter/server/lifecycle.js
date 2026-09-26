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

import { nowIso, bumpPermVersion } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';
import { resolve, MODE_PERMISSION } from './permissions.js';

// --- modification authority (D8) -------------------------------------------------
//
// Ranks are read from `roles`, never from a list in code: the personalised DB has a role
// (`reviewer`, rank 35) that no document mentions, and it has to slot in by its rank.

const OWNER = 'owner';

export function roleRanks(db) {
  return new Map(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !roleRanks(db).has(role)) throw badRequest('unknown role', 'unknown_role');
}

// Acting on a member (role change, suspend, reinstate, remove) needs a strictly higher rank.
// The one exception is owner -> owner: `check-api.js` expects one owner to demote another,
// while PERMISSIONS.md §6 says equal rank is a 403. See DECISIONS.md.
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === OWNER && targetRole === OWNER) return;
  const ranks = roleRanks(db);
  if (!(ranks.get(callerRole) > ranks.get(targetRole))) {
    throw forbidden('you cannot modify a member of equal or higher role', 'rank');
  }
}

// Conferring a role (role change or invite): strictly below your own, except that only an
// owner may confer owner.
export function assertCanAssign(db, callerRole, newRole) {
  if (newRole === OWNER) {
    if (callerRole !== OWNER) throw forbidden('only an owner can confer owner', 'rank');
    return;
  }
  const ranks = roleRanks(db);
  if (!(ranks.get(callerRole) > ranks.get(newRole))) {
    throw forbidden('you cannot confer a role equal to or above your own', 'rank');
  }
}

// Throws LAST_OWNER if taking userId out of active ownership would leave the org with none.
// Callers run this inside the same transaction as the change, so the count and the write
// can't be separated by another request.
export function assertNotLastOwner(db, orgId, userId) {
  const target = db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (!target || target.role !== OWNER || target.status !== 'active') return;
  const others = db.prepare(
    "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active' AND user_id <> ?"
  ).get(orgId, userId).n;
  if (others === 0) throw lastOwner();
}

// Take a member out of the org: removal or leaving. Tenancy event, so it cascades: status,
// pv (their tokens die), sessions, and — my own policy, not in the docs — their live grants,
// so a later re-invite does not bring old authority back with it.
export function removeMembership(db, { orgId, userId }) {
  db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(orgId, userId);
  bumpPermVersion(db, { orgId, userId });
  endActiveSessions(db, { orgId, userId, reason: 'membership_removed' });
  db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL')
    .run(nowIso(), orgId, userId);
}
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
