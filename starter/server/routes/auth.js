// Auth routes: login, refresh, org switch, and "who am I".
//
// Access token: JWT, 15 min, memory only on the client, one org per token.
// Refresh token: opaque, stored hashed, httpOnly cookie, rotated on every use; replaying a
// rotated token revokes its whole family (AUTH-DATA-MODEL.md §2).

import {
  issueAccessToken, newRefreshToken, hashRefreshToken, hashPassword, verifyPassword,
  REFRESH_TTL_SECONDS,
} from '../auth.js';
import { send, unauthenticated, notFound, badRequest } from '../http.js';
import { newId, nowIso } from '../db.js';
import { resolve } from '../permissions.js';

const COOKIE = 'rt';

// Run scrypt even for an unknown email, so "no such user" and "wrong password" take the
// same time as well as returning the same body — no account enumeration either way.
const DUMMY_HASH = hashPassword('not-a-real-password');

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function setRefreshCookie(res, raw) {
  res.setHeader(
    'set-cookie',
    `${COOKIE}=${raw}; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth; Max-Age=${REFRESH_TTL_SECONDS}`
  );
}

function issueRefresh(db, userId, familyId = newId('fam')) {
  const raw = newRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
  db.prepare(
    'INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)'
  ).run(newId('rt'), userId, hashRefreshToken(raw), familyId, expiresAt);
  return raw;
}

// Every org the user is an active member of. Oldest membership first, so the default org on
// login is stable.
function orgsOf(db, userId) {
  return db.prepare(
    `SELECT o.id, o.name, o.theme, m.role, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY COALESCE(m.joined_at, m.created_at), o.id`
  ).all(userId);
}

// Mint an access token for one org, or null if the user has no active membership there.
function tokenFor(db, secret, userId, orgs, orgId) {
  const org = orgId ? orgs.find((o) => o.id === orgId) : orgs[0];
  if (!org) return null;
  return {
    token: issueAccessToken({ userId, orgId: org.id, role: org.role, permVersion: org.perm_version }, secret),
    orgId: org.id,
    role: org.role,
  };
}

const publicOrgs = (orgs) => orgs.map(({ id, name, theme, role }) => ({ id, name, theme, role }));

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
      throw badRequest('email and password are required');
    }

    const user = db.prepare('SELECT id, email, name, password_hash FROM users WHERE email = ?')
      .get(email.trim().toLowerCase());
    const ok = verifyPassword(password, user?.password_hash ?? DUMMY_HASH);
    if (!user || !ok) throw unauthenticated('invalid email or password');

    const orgs = orgsOf(db, user.id);
    const scoped = tokenFor(db, secret, user.id, orgs, orgId);
    if (orgId && !scoped) throw notFound();

    setRefreshCookie(res, issueRefresh(db, user.id));
    send(res, 200, {
      token: scoped?.token ?? null,
      orgId: scoped?.orgId ?? null,
      role: scoped?.role ?? null,
      user: { id: user.id, email: user.email, name: user.name },
      orgs: publicOrgs(orgs),
    });
  });

  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    if (!raw) throw unauthenticated();

    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) throw unauthenticated();

    // Reuse of a rotated token means it leaked: kill the whole lineage.
    if (row.revoked_at) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(nowIso(), row.family_id);
      throw unauthenticated();
    }
    if (row.expires_at <= nowIso()) throw unauthenticated();

    const rotate = db.transaction(() => {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), row.id);
      return issueRefresh(db, row.user_id, row.family_id);
    });
    const next = rotate();

    const orgs = orgsOf(db, row.user_id);
    const scoped = tokenFor(db, secret, row.user_id, orgs, ctx.body.orgId);
    if (ctx.body.orgId && !scoped) throw notFound();

    setRefreshCookie(res, next);
    send(res, 200, {
      token: scoped?.token ?? null,
      orgId: scoped?.orgId ?? null,
      role: scoped?.role ?? null,
      orgs: publicOrgs(orgs),
    });
  });

  // Switch org: a new token scoped to another org the caller is an active member of.
  // Not a member there -> 404, the same answer as an org that does not exist.
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (typeof orgId !== 'string') throw badRequest('orgId is required');

    const scoped = tokenFor(db, secret, ctx.userId, orgsOf(db, ctx.userId), orgId);
    if (!scoped) throw notFound();
    send(res, 200, scoped);
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(ctx.userId);
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId });
    send(res, 200, {
      user,
      orgId: ctx.orgId,
      role: ctx.role,
      orgs: publicOrgs(orgsOf(db, ctx.userId)),
      permissions,
    });
  });
}
