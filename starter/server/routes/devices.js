// Devices and grants.
//
// Every route here is under /v1/orgs/:orgId, so context.js has already refused any org that is
// not the token's. What is left per route: is the target in THIS org (else 404), may the
// caller see it (device:view, else 404 — it is absent from their list too), and may they do
// this to it (else 403, audited).

import { send, badRequest, notFound, conflict, forbidden, normalizeTs, HttpError } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { resolve, resolveDevices, resolveOrgWide, assertCan, assertCanOrgWide, assertMayGrant } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';

const KINDS = new Set(['macos', 'windows', 'linux', 'android', 'ios']);
const MAX_NAME = 100;

const deviceJson = (d, permissions) => ({
  id: d.id, name: d.name, kind: d.kind, online: d.online === 1, permissions,
});

function validName(name) {
  if (typeof name !== 'string' || !name.trim()) throw badRequest('name is required');
  if (name.trim().length > MAX_NAME) throw badRequest(`name is longer than ${MAX_NAME} characters`);
  return name.trim();
}

export function registerDeviceRoutes(router, { db }) {
  const deviceIn = db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL');
  const nameTaken = db.prepare(
    'SELECT 1 FROM devices WHERE org_id = ? AND lower(name) = lower(?) AND deleted_at IS NULL AND id <> ?'
  );

  // A device in the caller's org that the caller may see, with their resolved set for it.
  // Not in this org, deleted, or device:view denied -> 404: all three read the same.
  function visibleDevice(ctx, deviceId) {
    const device = deviceIn.get(deviceId, ctx.orgId);
    if (!device) throw notFound();
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
    if (permissions['device:view'].effect !== 'allow') throw notFound();
    return { device, permissions };
  }

  const denyAudited = (ctx, action, targetType, targetId, fn) =>
    auditDenials(db, ctx, { action, targetType, targetId }, fn);

  // --- devices ---------------------------------------------------------------

  router.get('/v1/orgs/:orgId/devices', (ctx, _p, res) => {
    denyAudited(ctx, 'device.list', 'org', ctx.orgId, () => assertCan(db, ctx, 'device:list'));

    const rows = db.prepare(
      'SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name, id'
    ).all(ctx.orgId);
    // One resolution for the whole list, however many rows (no per-row queries).
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: rows.map((d) => d.id) });

    // device:view decides row inclusion: a denied row is absent, never redacted.
    const devices = rows
      .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
      .map((d) => deviceJson(d, byDevice[d.id]));
    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:orgId/devices/:deviceId', (ctx, p, res) => {
    const { device, permissions } = visibleDevice(ctx, p.deviceId);
    send(res, 200, deviceJson(device, permissions));
  });

  router.post('/v1/orgs/:orgId/devices', (ctx, _p, res) => {
    denyAudited(ctx, 'device.create', 'org', ctx.orgId, () => assertCanOrgWide(db, ctx, 'device:provision'));
    const name = validName(ctx.body.name);
    const kind = ctx.body.kind;
    if (!KINDS.has(kind)) throw badRequest(`kind must be one of ${[...KINDS].join(', ')}`);
    if (nameTaken.get(ctx.orgId, name, '')) throw conflict('a device with that name already exists');

    const id = newId('dev');
    db.transaction(() => {
      db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?,?,?,?,0)').run(id, ctx.orgId, name, kind);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.create', targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });
    })();
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: id });
    send(res, 201, deviceJson(deviceIn.get(id, ctx.orgId), permissions));
  });

  router.patch('/v1/orgs/:orgId/devices/:deviceId', (ctx, p, res) => {
    visibleDevice(ctx, p.deviceId);
    denyAudited(ctx, 'device.update', 'device', p.deviceId, () => assertCan(db, ctx, 'device:update', p.deviceId));
    const name = validName(ctx.body.name);
    if (nameTaken.get(ctx.orgId, name, p.deviceId)) throw conflict('a device with that name already exists');

    db.transaction(() => {
      db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name, p.deviceId);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: p.deviceId, result: 'allow', requestId: ctx.requestId });
    })();
    const { device, permissions } = visibleDevice(ctx, p.deviceId);
    send(res, 200, deviceJson(device, permissions));
  });

  // Decommission: soft delete. Sessions on it end — a tenancy event, not a permission tweak.
  router.delete('/v1/orgs/:orgId/devices/:deviceId', (ctx, p, res) => {
    visibleDevice(ctx, p.deviceId);
    denyAudited(ctx, 'device.delete', 'device', p.deviceId, () => assertCan(db, ctx, 'device:provision', p.deviceId));

    db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), p.deviceId);
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: p.deviceId, reason: 'device_transferred' });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.delete', targetType: 'device', targetId: p.deviceId, result: 'allow', requestId: ctx.requestId });
    })();
    send(res, 200, { id: p.deviceId, deleted: true });
  });

  // Transfer needs device:provision on this device here AND device:provision in the target
  // org. A target org the caller is not an active member of is a 404, like any other org.
  router.post('/v1/orgs/:orgId/devices/:deviceId/transfer', (ctx, p, res) => {
    visibleDevice(ctx, p.deviceId);
    const toOrgId = ctx.body.toOrgId ?? ctx.body.orgId;
    if (typeof toOrgId !== 'string') throw badRequest('toOrgId is required');
    if (toOrgId === ctx.orgId) throw badRequest('the device is already in that org');

    // Receiving a device is an org-wide act in the target org: a device-scoped grant there
    // (on some other device) is not authority to bring a new one in.
    const there = resolveOrgWide(db, { userId: ctx.userId, orgId: toOrgId });
    if (there.role === null) throw notFound();

    denyAudited(ctx, 'device.transfer', 'device', p.deviceId, () => {
      assertCan(db, ctx, 'device:provision', p.deviceId);
      const d = there.permissions['device:provision'];
      if (d.effect !== 'allow') throw forbidden('missing device:provision in the target org', d.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission');
    });

    db.transaction(() => {
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: p.deviceId, reason: 'device_transferred' });
      // Device-scoped grants in the old org would otherwise name a device of another org.
      const affected = db.prepare(
        'SELECT DISTINCT user_id FROM grants WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL'
      ).all(ctx.orgId, p.deviceId);
      db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL')
        .run(nowIso(), ctx.orgId, p.deviceId);
      for (const { user_id } of affected) bumpPermVersion(db, { orgId: ctx.orgId, userId: user_id });
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(toOrgId, p.deviceId);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer_out', targetType: 'device', targetId: p.deviceId, result: 'allow', requestId: ctx.requestId });
      audit(db, { orgId: toOrgId, actorId: ctx.userId, action: 'device.transfer_in', targetType: 'device', targetId: p.deviceId, result: 'allow', requestId: ctx.requestId });
    })();
    send(res, 200, { id: p.deviceId, orgId: toOrgId });
  });

  // --- grants ----------------------------------------------------------------

  const grantJson = (g) => ({
    id: g.id, userId: g.user_id, deviceId: g.device_id, effect: g.effect,
    permissions: db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ? ORDER BY permission').all(g.id).map((r) => r.permission),
    startsAt: g.starts_at, expiresAt: g.expires_at, revokedAt: g.revoked_at,
    createdBy: g.created_by, createdAt: g.created_at,
  });

  router.post('/v1/orgs/:orgId/grants', (ctx, _p, res) => {
    const { userId, deviceId = null, effect, permissions } = ctx.body;

    // 400s: shape of the request.
    if (typeof userId !== 'string') throw badRequest('userId is required');
    if (effect !== 'allow' && effect !== 'deny') throw badRequest('effect must be allow or deny');
    if (!Array.isArray(permissions) || permissions.length === 0 || !permissions.every((x) => typeof x === 'string')) {
      throw badRequest('permissions must be a non-empty array of strings');
    }
    if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string');
    const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
    const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
    if (expiresAt && expiresAt <= nowIso()) throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt must be in the future', 'expired_grant');
    if (startsAt && expiresAt && expiresAt <= startsAt) throw badRequest('expiresAt must be after startsAt');

    // 404s: targets that are not in this org.
    const member = db.prepare("SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'").get(ctx.orgId, userId);
    if (!member) throw notFound();
    if (deviceId !== null && !deviceIn.get(deviceId, ctx.orgId)) throw notFound();

    // 403s: no self-grants, no laundering. Audited.
    denyAudited(ctx, 'grant.create', 'user', userId, () => {
      if (deviceId === null) assertCanOrgWide(db, ctx, 'grant:create');
      else assertCan(db, ctx, 'grant:create', deviceId);
      if (userId === ctx.userId) throw forbidden('you cannot grant to yourself', 'self_grant');
      assertMayGrant(db, ctx, permissions, deviceId);
    });

    // An unknown permission string is refused by the FK on grant_permissions, not by a list
    // kept in code (D19). Translate that one failure into a 400.
    const id = newId('grt');
    try {
      db.transaction(() => {
        db.prepare(
          'INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?)'
        ).run(id, ctx.orgId, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
        const add = db.prepare('INSERT OR IGNORE INTO grant_permissions (grant_id, permission) VALUES (?,?)');
        for (const perm of permissions) add.run(id, perm);
        bumpPermVersion(db, { orgId: ctx.orgId, userId });
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: id, result: 'allow', requestId: ctx.requestId });
      })();
    } catch (err) {
      if (err?.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') throw badRequest('unknown permission', 'unknown_permission');
      throw err;
    }
    send(res, 201, grantJson(db.prepare('SELECT * FROM grants WHERE id = ?').get(id)));
  });

  router.get('/v1/orgs/:orgId/grants', (ctx, _p, res) => {
    denyAudited(ctx, 'grant.list', 'org', ctx.orgId, () => assertCan(db, ctx, 'user:read'));
    const userId = ctx.query.get('userId');
    const rows = userId
      ? db.prepare('SELECT * FROM grants WHERE org_id = ? AND user_id = ? ORDER BY created_at, id').all(ctx.orgId, userId)
      : db.prepare('SELECT * FROM grants WHERE org_id = ? ORDER BY created_at, id').all(ctx.orgId);
    send(res, 200, { grants: rows.map(grantJson) });
  });

  // Revoking an already-revoked grant is a 404: it is no longer visible.
  router.delete('/v1/orgs/:orgId/grants/:grantId', (ctx, p, res) => {
    const grant = db.prepare('SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(p.grantId, ctx.orgId);
    if (!grant) throw notFound();
    denyAudited(ctx, 'grant.revoke', 'grant', grant.id, () =>
      grant.device_id === null
        ? assertCanOrgWide(db, ctx, 'grant:revoke')
        : assertCan(db, ctx, 'grant:revoke', grant.device_id));

    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grant.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId });
    })();
    send(res, 200, grantJson(db.prepare('SELECT * FROM grants WHERE id = ?').get(grant.id)));
  });
}
