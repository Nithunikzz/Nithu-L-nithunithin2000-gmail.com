// Invites: the only way a person joins an org (AUTH-DATA-MODEL.md §6).
//
// The raw token is a bearer credential: stored only as a hash, returned once at creation,
// never logged. States: pending -> accepted | revoked | expired.
//   GET/accept on an expired or revoked token -> 410 GONE
//   accept on an already-accepted token        -> 409

import {
  issueAccessToken, newInviteToken, hashInviteToken, hashPassword, verifyPassword,
} from '../auth.js';
import { send, badRequest, notFound, conflict, gone, unauthenticated } from '../http.js';
import { newId, nowIso } from '../db.js';
import { assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { assertRoleExists, assertCanAssign } from '../lifecycle.js';
import { orgsOf, publicOrgs, issueRefresh, setRefreshCookie } from './auth.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD = 8;

const normalEmail = (e) => (typeof e === 'string' ? e.trim().toLowerCase() : '');

function stateOf(inv, now = nowIso()) {
  if (inv.accepted_at) return 'accepted';
  if (inv.revoked_at) return 'revoked';
  if (inv.expires_at <= now) return 'expired';
  return 'pending';
}

const inviteJson = (inv) => ({
  id: inv.id, email: inv.email, role: inv.role, state: stateOf(inv),
  expiresAt: inv.expires_at, invitedBy: inv.invited_by, createdAt: inv.created_at,
});

export function registerInviteRoutes(router, { db, secret }) {
  const byHash = db.prepare(
    `SELECT i.*, o.name AS org_name, o.deleted_at AS org_deleted_at
       FROM invites i JOIN organizations o ON o.id = i.org_id WHERE i.token_hash = ?`
  );

  // Look a raw token up and refuse anything that is not a live, pending invite.
  function liveInvite(raw) {
    const inv = byHash.get(hashInviteToken(String(raw)));
    if (!inv) throw notFound();
    const state = stateOf(inv);
    if (state === 'accepted') throw conflict('invite has already been used');
    if (state !== 'pending' || inv.org_deleted_at) throw gone();
    return inv;
  }

  // --- org-side (authenticated, user:invite) ---------------------------------

  router.post('/v1/orgs/:orgId/invites', (ctx, _p, res) => {
    const email = normalEmail(ctx.body.email);
    if (!EMAIL.test(email)) throw badRequest('a valid email is required');
    const { role } = ctx.body;
    assertRoleExists(db, role);

    auditDenials(db, ctx, { action: 'invite.create', targetType: 'org', targetId: ctx.orgId }, () => {
      assertCan(db, ctx, 'user:invite');
      assertCanAssign(db, ctx.role, role);
    });

    const member = db.prepare(
      `SELECT m.status FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active', 'suspended')`
    ).get(ctx.orgId, email);
    if (member) throw conflict('that person is already a member of this org');

    const raw = newInviteToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    try {
      db.transaction(() => {
        // An expired-but-never-cancelled invite still counts as "live" to the partial unique
        // index, so retire it first or it blocks re-inviting that email forever.
        db.prepare(
          'UPDATE invites SET revoked_at = ? WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= ?'
        ).run(nowIso(), ctx.orgId, email, nowIso());
        db.prepare(
          'INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?,?,?,?,?,?,?)'
        ).run(id, ctx.orgId, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: id, result: 'allow', requestId: ctx.requestId });
      })();
    } catch (err) {
      // one_live_invite_per_email: the database, not a prior SELECT, refuses the duplicate.
      if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('that email already has a live invite');
      throw err;
    }
    // The only time the raw token ever leaves the server.
    send(res, 201, { ...inviteJson(db.prepare('SELECT * FROM invites WHERE id = ?').get(id)), inviteToken: raw });
  });

  router.get('/v1/orgs/:orgId/invites', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'invite.list', targetType: 'org', targetId: ctx.orgId },
      () => assertCan(db, ctx, 'user:invite'));
    const rows = db.prepare('SELECT * FROM invites WHERE org_id = ? ORDER BY created_at DESC, id').all(ctx.orgId);
    send(res, 200, { invites: rows.map(inviteJson) });
  });

  // Cancel. Only a pending invite is visible to cancel; anything else is 404.
  router.delete('/v1/orgs/:orgId/invites/:inviteId', (ctx, p, res) => {
    const inv = db.prepare('SELECT * FROM invites WHERE id = ? AND org_id = ?').get(p.inviteId, ctx.orgId);
    if (!inv || stateOf(inv) !== 'pending') throw notFound();
    auditDenials(db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: inv.id },
      () => assertCan(db, ctx, 'user:invite'));
    db.transaction(() => {
      db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), inv.id);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: inv.id, result: 'allow', requestId: ctx.requestId });
    })();
    send(res, 200, inviteJson(db.prepare('SELECT * FROM invites WHERE id = ?').get(inv.id)));
  });

  // --- token-side (public: the token is the credential) ----------------------

  // Just enough to render "You've been invited to Acme Robotics as operator." No org id,
  // no members, no devices: the holder is not a member yet.
  router.get('/v1/invites/:token', (_ctx, p, res) => {
    const inv = liveInvite(p.token);
    send(res, 200, { orgName: inv.org_name, role: inv.role, email: inv.email, expiresAt: inv.expires_at });
  });

  // Accept, in one transaction: user, membership, invite, audit, then tokens.
  //
  // An email that already has an account must prove it owns that account with its current
  // password. Otherwise the invite token alone would sign its holder in as an existing user.
  // Their password and name are never changed here. (BUILD-LOG phase 3, prediction 7.)
  router.post('/v1/invites/:token/accept', (ctx, p, res) => {
    const { name, password } = ctx.body;
    if (typeof password !== 'string') throw badRequest('password is required');

    const accepted = db.transaction(() => {
      const inv = liveInvite(p.token);
      let user = db.prepare('SELECT id, email, name, password_hash FROM users WHERE email = ?').get(inv.email);

      if (user) {
        if (!verifyPassword(password, user.password_hash)) {
          throw unauthenticated('this email already has an account: sign in with its password to accept');
        }
      } else {
        if (typeof name !== 'string' || !name.trim() || name.trim().length > 100) throw badRequest('name is required');
        if (password.length < MIN_PASSWORD) throw badRequest(`password must be at least ${MIN_PASSWORD} characters`);
        const id = newId('usr');
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?,?,?,?)')
          .run(id, inv.email, name.trim(), hashPassword(password));
        user = { id, email: inv.email, name: name.trim() };
      }

      // memberships is UNIQUE(org_id, user_id): a previously removed member gets their old row
      // back, flipped to active, rather than a second row.
      const existing = db.prepare('SELECT status FROM memberships WHERE org_id = ? AND user_id = ?').get(inv.org_id, user.id);
      if (existing && (existing.status === 'active' || existing.status === 'suspended')) {
        throw conflict('already a member of this org');
      }
      if (existing) {
        db.prepare(
          "UPDATE memberships SET role = ?, status = 'active', joined_at = ?, invited_by = ?, perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?"
        ).run(inv.role, nowIso(), inv.invited_by, inv.org_id, user.id);
      } else {
        db.prepare(
          "INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?,?,?,?,'active',?,?)"
        ).run(newId('mem'), inv.org_id, user.id, inv.role, inv.invited_by, nowIso());
      }

      // Single use: the conditional update is what makes two concurrent accepts produce one winner.
      const won = db.prepare(
        'UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL'
      ).run(nowIso(), user.id, inv.id).changes;
      if (!won) throw conflict('invite has already been used');

      audit(db, { orgId: inv.org_id, actorId: user.id, action: 'invite.accept', targetType: 'invite', targetId: inv.id, result: 'allow', requestId: ctx.requestId });
      return { inv, user };
    })();

    const { inv, user } = accepted;
    const m = db.prepare('SELECT role, perm_version FROM memberships WHERE org_id = ? AND user_id = ?').get(inv.org_id, user.id);
    setRefreshCookie(res, issueRefresh(db, user.id));
    send(res, 200, {
      token: issueAccessToken({ userId: user.id, orgId: inv.org_id, role: m.role, permVersion: m.perm_version }, secret),
      orgId: inv.org_id,
      role: m.role,
      user: { id: user.id, email: user.email, name: user.name },
      orgs: publicOrgs(orgsOf(db, user.id)),
    });
  });
}
