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
export function snapshotAuthority(db, { userId, orgId, deviceId }) { throw todo('snapshotAuthority'); }
export function sessionExpiry(db, orgId) { throw todo('sessionExpiry'); }
