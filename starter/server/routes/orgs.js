// Orgs, members, and effective permissions.
//
// Membership changes are either permission tweaks or tenancy events (PERMISSIONS.md §7):
//   role change          -> bump pv; running sessions are grandfathered
//   suspend / remove     -> bump pv AND end that user's sessions in this org
// Rank rules and last-owner protection live in lifecycle.js, so every route asks the same way.

import { send, badRequest, notFound, conflict, forbidden, selfRoleChange } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { resolve, assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import {
  assertRoleExists, assertCanModify, assertCanAssign, assertNotLastOwner,
  endActiveSessions, removeMembership,
} from '../lifecycle.js';
import { orgsOf, publicOrgs } from './auth.js';

const MAX_NAME = 100;
const THEMES = ['cobalt', 'amber', 'emerald', 'rose', 'violet', 'slate'];
const THEME = /^[a-z][a-z0-9-]{0,31}$/;

function validName(name) {
  if (typeof name !== 'string' || !name.trim()) throw badRequest('name is required');
  if (name.trim().length > MAX_NAME) throw badRequest(`name is longer than ${MAX_NAME} characters`);
  return name.trim();
}

const memberJson = (m) => ({
  userId: m.user_id, email: m.email, name: m.name, role: m.role, status: m.status, joinedAt: m.joined_at,
});

export function registerOrgRoutes(router, { db }) {
  const memberOf = db.prepare(
    `SELECT m.*, u.email, u.name FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.user_id = ?`
  );
  const orgById = db.prepare('SELECT id, name, theme, max_session_minutes FROM organizations WHERE id = ? AND deleted_at IS NULL');

  const logAllow = (ctx, action, targetType, targetId, orgId = ctx.orgId) =>
    audit(db, { orgId, actorId: ctx.userId, action, targetType, targetId, result: 'allow', requestId: ctx.requestId });
  const guarded = (ctx, action, targetType, targetId, fn) =>
    auditDenials(db, ctx, { action, targetType, targetId }, fn);

  // A member of this org other than someone who has left or been removed. Else 404.
  function targetMember(ctx, userId) {
    const m = memberOf.get(ctx.orgId, userId);
    if (!m || m.status === 'removed' || m.status === 'invited') throw notFound();
    return m;
  }

  // --- orgs ------------------------------------------------------------------

  // Discovery: every org the user is an active member of. Lists orgs; acts in none of them.
  router.get('/v1/orgs', (ctx, _p, res) => {
    send(res, 200, { orgs: publicOrgs(orgsOf(db, ctx.userId)) });
  });

  router.post('/v1/orgs', (ctx, _p, res) => {
    const name = validName(ctx.body.name);
    let theme = ctx.body.theme;
    if (theme !== undefined && (typeof theme !== 'string' || !THEME.test(theme))) throw badRequest('theme is invalid');
    if (theme === undefined) {
      // Pick a theme the creator isn't already using, so the new org is visibly distinct.
      const used = new Set(orgsOf(db, ctx.userId).map((o) => o.theme));
      theme = THEMES.find((t) => !used.has(t)) ?? THEMES[0];
    }

    const id = newId('org');
    db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?,?,?)').run(id, name, theme);
      db.prepare(
        "INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?,?,?,'owner','active',?)"
      ).run(newId('mem'), id, ctx.userId, nowIso());
      logAllow(ctx, 'org.create', 'org', id, id);
    })();
    send(res, 201, { id, name, theme, role: 'owner' });
  });

  router.patch('/v1/orgs/:orgId', (ctx, _p, res) => {
    guarded(ctx, 'org.update', 'org', ctx.orgId, () => assertCan(db, ctx, 'org:update'));
    const { name, theme, maxSessionMinutes } = ctx.body;
    const sets = [], args = [];
    if (name !== undefined) { sets.push('name = ?'); args.push(validName(name)); }
    if (theme !== undefined) {
      if (typeof theme !== 'string' || !THEME.test(theme)) throw badRequest('theme is invalid');
      sets.push('theme = ?'); args.push(theme);
    }
    if (maxSessionMinutes !== undefined) {
      if (!Number.isInteger(maxSessionMinutes) || maxSessionMinutes < 1 || maxSessionMinutes > 24 * 60) {
        throw badRequest('maxSessionMinutes must be an integer between 1 and 1440');
      }
      sets.push('max_session_minutes = ?'); args.push(maxSessionMinutes);
    }
    if (!sets.length) throw badRequest('nothing to update');

    db.transaction(() => {
      db.prepare(`UPDATE organizations SET ${sets.join(', ')} WHERE id = ?`).run(...args, ctx.orgId);
      logAllow(ctx, 'org.update', 'org', ctx.orgId);
    })();
    const o = orgById.get(ctx.orgId);
    send(res, 200, { id: o.id, name: o.name, theme: o.theme, maxSessionMinutes: o.max_session_minutes });
  });

  // Soft delete. Every token for the org stops working (context.js skips deleted orgs), live
  // sessions end, and pending invites die.
  router.delete('/v1/orgs/:orgId', (ctx, _p, res) => {
    guarded(ctx, 'org.delete', 'org', ctx.orgId, () => assertCan(db, ctx, 'org:delete'));
    db.transaction(() => {
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
      endActiveSessions(db, { orgId: ctx.orgId, reason: 'membership_removed' });
      db.prepare('UPDATE invites SET revoked_at = ? WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL')
        .run(nowIso(), ctx.orgId);
      logAllow(ctx, 'org.delete', 'org', ctx.orgId);
    })();
    send(res, 200, { id: ctx.orgId, deleted: true });
  });

  // --- members ---------------------------------------------------------------

  router.get('/v1/orgs/:orgId/members', (ctx, _p, res) => {
    guarded(ctx, 'member.list', 'org', ctx.orgId, () => assertCan(db, ctx, 'user:read'));
    const rows = db.prepare(
      `SELECT m.*, u.email, u.name FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status IN ('active', 'suspended') ORDER BY u.name, u.id`
    ).all(ctx.orgId);
    send(res, 200, { members: rows.map(memberJson) });
  });

  // Registered before /members/:userId, or the router reads 'me' as a user id.
  router.delete('/v1/orgs/:orgId/members/me', (ctx, _p, res) => {
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, ctx.userId);
      removeMembership(db, { orgId: ctx.orgId, userId: ctx.userId });
      logAllow(ctx, 'member.leave', 'user', ctx.userId);
    })();
    send(res, 200, { userId: ctx.userId, status: 'removed' });
  });

  router.patch('/v1/orgs/:orgId/members/:userId', (ctx, p, res) => {
    const target = targetMember(ctx, p.userId);
    const { role } = ctx.body;
    assertRoleExists(db, role);
    if (p.userId === ctx.userId) {
      guarded(ctx, 'member.role', 'user', p.userId, () => { throw selfRoleChange(); });
    }
    guarded(ctx, 'member.role', 'user', p.userId, () => {
      assertCan(db, ctx, 'user:role:update');
      assertCanModify(db, ctx.role, target.role);
      assertCanAssign(db, ctx.role, role);
    });
    if (role === target.role) return send(res, 200, memberJson(target));

    db.transaction(() => {
      if (role !== 'owner') assertNotLastOwner(db, ctx.orgId, p.userId);
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(role, ctx.orgId, p.userId);
      // A permission tweak: their tokens go stale, their running sessions are grandfathered.
      bumpPermVersion(db, { orgId: ctx.orgId, userId: p.userId });
      logAllow(ctx, 'member.role', 'user', p.userId);
    })();
    send(res, 200, memberJson(memberOf.get(ctx.orgId, p.userId)));
  });

  router.post('/v1/orgs/:orgId/members/:userId/suspend', (ctx, p, res) => {
    const target = targetMember(ctx, p.userId);
    if (p.userId === ctx.userId) throw forbidden('you cannot suspend yourself', 'self');
    guarded(ctx, 'member.suspend', 'user', p.userId, () => {
      assertCan(db, ctx, 'user:remove');
      assertCanModify(db, ctx.role, target.role);
    });
    if (target.status === 'suspended') throw conflict('member is already suspended');

    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, p.userId);
      db.prepare("UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, p.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: p.userId });
      endActiveSessions(db, { orgId: ctx.orgId, userId: p.userId, reason: 'user_suspended' });
      logAllow(ctx, 'member.suspend', 'user', p.userId);
    })();
    send(res, 200, memberJson(memberOf.get(ctx.orgId, p.userId)));
  });

  // Reinstate. Sessions that suspension ended stay ended.
  router.delete('/v1/orgs/:orgId/members/:userId/suspend', (ctx, p, res) => {
    const target = targetMember(ctx, p.userId);
    guarded(ctx, 'member.reinstate', 'user', p.userId, () => {
      assertCan(db, ctx, 'user:remove');
      assertCanModify(db, ctx.role, target.role);
    });
    if (target.status !== 'suspended') throw conflict('member is not suspended');

    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, p.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: p.userId });
      logAllow(ctx, 'member.reinstate', 'user', p.userId);
    })();
    send(res, 200, memberJson(memberOf.get(ctx.orgId, p.userId)));
  });

  // Remove from this org. The user row, their other orgs and the audit trail are untouched.
  router.delete('/v1/orgs/:orgId/members/:userId', (ctx, p, res) => {
    const target = targetMember(ctx, p.userId);
    if (p.userId === ctx.userId) throw forbidden('use DELETE /members/me to leave', 'self');
    guarded(ctx, 'member.remove', 'user', p.userId, () => {
      assertCan(db, ctx, 'user:remove');
      assertCanModify(db, ctx.role, target.role);
    });

    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, p.userId);
      removeMembership(db, { orgId: ctx.orgId, userId: p.userId });
      logAllow(ctx, 'member.remove', 'user', p.userId);
    })();
    send(res, 200, { userId: p.userId, status: 'removed' });
  });

  // --- effective permissions -------------------------------------------------

  // user:read, or yourself. Resolved in the token's org, so the same user id gives a
  // different set under a different org.
  router.get('/v1/orgs/:orgId/users/:userId/effective', (ctx, p, res) => {
    if (p.userId !== ctx.userId) {
      guarded(ctx, 'member.effective', 'user', p.userId, () => assertCan(db, ctx, 'user:read'));
      targetMember(ctx, p.userId);
    }
    const deviceId = ctx.query.get('deviceId');
    if (deviceId && !db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId)) {
      throw notFound();
    }
    const { role, permissions } = resolve(db, { userId: p.userId, orgId: ctx.orgId, deviceId: deviceId || null });
    send(res, 200, { role, permissions });
  });
}
