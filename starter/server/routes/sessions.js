// Sessions. Records only — nothing here touches a real device (BRIEF.md §4).
//
// Start is the compound check: session:start AND the mode permission, on the same device.
// control/terminal are exclusive per device; the partial unique index
// one_exclusive_session_per_device enforces that, and this file only translates its error.

import { send, badRequest, notFound, conflict, deviceBusy } from '../http.js';
import { newId, nowIso } from '../db.js';
import { resolve, assertCan, assertCanStartSession, MODE_PERMISSION } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { snapshotAuthority, sessionExpiry, expireSessions } from '../lifecycle.js';

const sessionJson = (s) => ({ ...s, authorized_by: JSON.parse(s.authorized_by) });

export function registerSessionRoutes(router, { db }) {
  const byId = db.prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?');

  // A session in the caller's org that the caller may see: their own, or session:view on its
  // device. Anything else reads as absent.
  function visibleSession(ctx, sessionId) {
    expireSessions(db, { orgId: ctx.orgId, sessionId });
    const s = byId.get(sessionId, ctx.orgId);
    if (!s) throw notFound();
    if (s.user_id !== ctx.userId) {
      const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: s.device_id });
      if (permissions['session:view'].effect !== 'allow') throw notFound();
    }
    return s;
  }

  router.post('/v1/orgs/:orgId/sessions', (ctx, _p, res) => {
    const { deviceId, mode } = ctx.body;
    if (!MODE_PERMISSION[mode]) throw badRequest('mode must be view, control or terminal');
    if (typeof deviceId !== 'string') throw badRequest('deviceId is required');

    const device = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId);
    if (!device) throw notFound();
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
    // Same visibility rule as the device routes: a device you can't view is absent.
    if (permissions['device:view'].effect !== 'allow') throw notFound();

    auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId },
      () => assertCanStartSession(db, ctx, mode, deviceId));

    const id = newId('ses');
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId, mode });
    try {
      db.transaction(() => {
        // Release the device from any session whose TTL has passed, or it stays "busy" forever.
        expireSessions(db, { deviceId });
        // Inserted straight as 'active': the exclusivity index only covers state = 'active'.
        db.prepare(
          `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
           VALUES (?,?,?,?,?, 'active', ?, ?, ?)`
        ).run(id, ctx.orgId, ctx.userId, deviceId, mode, JSON.stringify(authorizedBy), nowIso(), sessionExpiry(db, ctx.orgId));
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.start', targetType: 'session', targetId: id, result: 'allow', requestId: ctx.requestId });
      })();
    } catch (err) {
      if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        const holder = db.prepare(
          "SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')"
        ).get(deviceId);
        throw deviceBusy(`device already has an exclusive session: ${holder?.id ?? 'unknown'}`);
      }
      throw err;
    }
    send(res, 201, sessionJson(byId.get(id, ctx.orgId)));
  });

  router.get('/v1/orgs/:orgId/sessions', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'session.list', targetType: 'org', targetId: ctx.orgId },
      () => assertCan(db, ctx, 'session:view'));
    expireSessions(db, { orgId: ctx.orgId });
    const rows = db.prepare('SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC, id').all(ctx.orgId);
    send(res, 200, { sessions: rows.map(sessionJson) });
  });

  router.get('/v1/sessions/:sessionId', (ctx, p, res) => {
    send(res, 200, sessionJson(visibleSession(ctx, p.sessionId)));
  });

  // Your own -> user_stopped. Someone else's needs session:terminate -> admin_terminated.
  router.delete('/v1/sessions/:sessionId', (ctx, p, res) => {
    const s = visibleSession(ctx, p.sessionId);
    if (s.state === 'ended') throw conflict('session has already ended');

    const own = s.user_id === ctx.userId;
    if (!own) {
      auditDenials(db, ctx, { action: 'session.terminate', targetType: 'session', targetId: s.id },
        () => assertCan(db, ctx, 'session:terminate', s.device_id));
    }
    const reason = own ? 'user_stopped' : 'admin_terminated';
    db.transaction(() => {
      db.prepare("UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ? AND state <> 'ended'")
        .run(reason, nowIso(), s.id);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: own ? 'session.stop' : 'session.terminate', targetType: 'session', targetId: s.id, result: 'allow', requestId: ctx.requestId });
    })();
    send(res, 200, sessionJson(byId.get(s.id, ctx.orgId)));
  });
}
