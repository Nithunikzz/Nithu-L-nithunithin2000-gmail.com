// Per-request context: turn a bearer token into an authenticated caller.
//
// The order of the checks is the design (BUILD-LOG, phase 2b prediction):
//
//   1. a bearer token that verifies                      -> else 401 UNAUTHENTICATED
//   2. a live membership in the token's org              -> else 401 (org deleted, removed)
//   3. the token's pv matches the membership's            -> else 401 TOKEN_STALE
//   4. the membership is not suspended                   -> else 403 FORBIDDEN / suspended
//   5. an org named in the URL IS the token's org         -> else 404 NOT_FOUND
//
// 1–4 are facts about the caller's own token and membership. 5 is a plain string compare
// with the URL: it never looks the named org up, so its answer is the same whether that org
// exists, belongs to someone else, or is one the caller is also a member of. Isolation is
// structural — the caller cannot name another org — not a filter applied afterwards.
//
// authenticate(db, secret) returns (req, params) => caller.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, forbidden, notFound } from './http.js';

const BEARER = /^Bearer\s+(\S+)$/i;

export function authenticate(db, secret) {
  const membershipOf = db.prepare(
    `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
  );

  return function buildContext(req, params = {}) {
    const match = BEARER.exec(req.headers.authorization ?? '');
    if (!match) throw unauthenticated();

    const claims = verifyAccessToken(match[1], secret);

    const membership = membershipOf.get(claims.org, claims.sub);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this org');
    }

    assertFresh(claims, membership);

    if (membership.status === 'suspended') throw forbidden('membership suspended', 'suspended');

    if (params.orgId !== undefined && params.orgId !== claims.org) throw notFound();

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
