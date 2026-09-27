// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

const decision = (effect, source, reason) => ({ effect, source, reason });

// A grant names an exact permission or a wildcard ('*', 'device:*', ...). Expand it
// against the catalogue as read from the table, so an undocumented permission such as
// the personalised one is covered by 'device:*' without being listed anywhere in code.
function expand(pattern, catalogue) {
  if (pattern === '*') return catalogue;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // 'device:*' -> 'device:'
    return catalogue.filter((p) => p.startsWith(prefix));
  }
  return catalogue.includes(pattern) ? [pattern] : [];
}

// Everything one user's answers in one org depend on, read once per call.
function loadInputs(db, { userId, orgId, now }) {
  const catalogue = db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);

  const membership = db.prepare(
    `SELECT m.role, m.status
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
  ).get(orgId, userId);

  if (!membership || membership.status !== 'active') return { catalogue, membership };

  const baseline = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(membership.role).map((r) => r.permission)
  );

  // Live grants only: not revoked, inside the half-open window starts_at <= now < expires_at.
  // Timestamps are canonical ISO-8601 'Z' strings, so string comparison is time comparison.
  // A device-scoped grant on a soft-deleted device no longer applies anywhere.
  const nowIso = now.toISOString();
  const rows = db.prepare(
    `SELECT g.id, g.effect, g.device_id, gp.permission AS pattern
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       LEFT JOIN devices d ON d.id = g.device_id
      WHERE g.org_id = ? AND g.user_id = ?
        AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)
        AND (g.device_id IS NULL OR d.deleted_at IS NULL)
      ORDER BY g.id`
  ).all(orgId, userId, nowIso, nowIso);

  const grants = rows.map((r) => ({
    id: r.id,
    effect: r.effect,
    deviceId: r.device_id,
    covers: new Set(expand(r.pattern, catalogue)),
  }));

  return { catalogue, membership, baseline, grants, index: indexGrants(grants) };
}

// Index the live grants once per resolution, so a decision is a lookup rather than a scan of
// every grant. Measured before this existed (BUILD-LOG phase 8): a caller with 1,000 grants
// took 1.28 s for GET /devices on 2,005 devices, all of it in scans, none in queries.
//
//   byPerm:    permission -> { deny, allow } -> { orgWide, byDevice: deviceId -> grant }
//   devicePos: deviceId -> position of the first grant naming it
//
// Only the FIRST grant (in `grants` order, i.e. ORDER BY g.id) is kept per slot, with its
// position, because that is the one a scan would have found — so the reported source is
// unchanged, not just the effect.
function indexGrants(grants) {
  const byPerm = new Map();
  const devicePos = new Map();
  const slot = () => ({ orgWide: null, byDevice: new Map() });

  grants.forEach((g, i) => {
    if (g.deviceId !== null && !devicePos.has(g.deviceId)) devicePos.set(g.deviceId, i);
    const entry = { g, i };
    for (const p of g.covers) {
      let e = byPerm.get(p);
      if (!e) byPerm.set(p, (e = { deny: slot(), allow: slot() }));
      const s = e[g.effect];
      if (g.deviceId === null) s.orgWide ??= entry;
      else if (!s.byDevice.has(g.deviceId)) s.byDevice.set(g.deviceId, entry);
    }
  });
  return { byPerm, devicePos };
}

// The first grant in a slot that applies at `scope`: an org-wide one, or one on that device.
function firstApplying(s, scope) {
  const a = s.orgWide;
  const b = scope === null ? undefined : s.byDevice.get(scope);
  if (a && b) return (a.i < b.i ? a : b).g;
  return (a ?? b)?.g ?? null;
}

// The one decision, for one permission at one scope. scope === null means "a device
// with no device-scoped grants of its own": only org-wide grants apply.
function decide(inputs, permission, scope) {
  const { membership, baseline, index } = inputs;
  const e = index.byPerm.get(permission);

  // D1: deny first, regardless of scope — an org-wide deny is never carved out.
  const deny = e && firstApplying(e.deny, scope);
  if (deny) return decision('deny', `grant:${deny.id}`, 'explicit_deny');

  if (baseline.has(permission)) return decision('allow', `role:${membership.role}`, null);

  const allow = e && firstApplying(e.allow, scope);
  if (allow) return decision('allow', `grant:${allow.id}`, null);

  return decision('deny', null, 'implicit'); // D4
}

// Org level is the union across devices (PERMISSIONS.md §3): allowed if the answer is
// allow on at least one device. When the plain org-wide answer is not allow, the only
// devices that can turn it into allow are those with a device-scoped ALLOW for this
// permission (a baseline allow would already have made the plain answer allow; an org-wide
// deny applies to every device). They are tried in first-appearance order, the same order
// as evaluating every device with a grant, so the same device and source win.
function decideOrgLevel(inputs, permission) {
  const plain = decide(inputs, permission, null);
  if (plain.effect === 'allow') return plain;
  const e = inputs.index.byPerm.get(permission);
  if (!e) return plain;
  const { devicePos } = inputs.index;
  const candidates = [...e.allow.byDevice.keys()].sort((a, b) => devicePos.get(a) - devicePos.get(b));
  for (const deviceId of candidates) {
    const d = decide(inputs, permission, deviceId);
    if (d.effect === 'allow') return d;
  }
  return plain;
}

function permissionSet(inputs, scope, orgLevel) {
  const { catalogue, membership } = inputs;
  const out = {};

  // Identity and membership come before any grant: no membership, or a suspended one,
  // means nothing at all — not even the role baseline.
  if (!membership || membership.status !== 'active') {
    const reason = membership?.status === 'suspended' ? 'suspended' : 'not_a_member';
    for (const p of catalogue) out[p] = decision('deny', null, reason);
    return out;
  }

  for (const p of catalogue) out[p] = orgLevel ? decideOrgLevel(inputs, p) : decide(inputs, p, scope);
  return out;
}

const roleOf = (inputs) =>
  inputs.membership && inputs.membership.status !== 'removed' && inputs.membership.status !== 'invited'
    ? inputs.membership.role
    : null;

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const inputs = loadInputs(db, { userId, orgId, now });
  return { role: roleOf(inputs), permissions: permissionSet(inputs, deviceId, deviceId === null) };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
// One read of the inputs for the whole list, however many rows.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const inputs = loadInputs(db, { userId, orgId, now });
  const byDevice = {};
  for (const id of deviceIds) byDevice[id] = permissionSet(inputs, id, false);
  return { role: roleOf(inputs), byDevice };
}

function lookup(db, ctx, permission, deviceId = null) {
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const d = permissions[permission];
  if (!d) throw badRequest(`unknown permission ${permission}`);
  return d;
}

export function can(db, ctx, permission, deviceId = null) {
  return lookup(db, ctx, permission, deviceId).effect === 'allow';
}

const refusalReason = (d) => (d.reason === 'implicit' || d.reason === 'not_a_member' ? 'missing_permission' : d.reason);

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId = null) {
  const d = lookup(db, ctx, permission, deviceId);
  if (d.effect !== 'allow') throw forbidden(`missing ${permission}`, refusalReason(d));
  return d;
}

// The org-WIDE set: baseline plus org-wide grants only. Device-scoped grants never count.
// This is the question for actions that name no existing device — creating a device,
// receiving a transfer, creating or revoking an org-wide grant. The org-LEVEL union above
// answers "allowed on at least one device", which is right for showing a nav card but would
// let a grant on one device authorise an org-wide action. (BUILD-LOG phase 7, prediction 1.)
export function resolveOrgWide(db, { userId, orgId, now = new Date() }) {
  const inputs = loadInputs(db, { userId, orgId, now });
  return { role: roleOf(inputs), permissions: permissionSet(inputs, null, false) };
}

export function assertCanOrgWide(db, ctx, permission) {
  const d = resolveOrgWide(db, { userId: ctx.userId, orgId: ctx.orgId }).permissions[permission];
  if (!d) throw badRequest(`unknown permission ${permission}`);
  if (d.effect !== 'allow') throw forbidden(`missing ${permission} across the org`, refusalReason(d));
  return d;
}

// No privilege laundering: you may only grant authority you hold at that scope.
//
// Device-scoped grant: you must hold each permission on that device.
// Org-wide grant: you must hold it on EVERY device — the org-level union is not enough,
// or a caller allowed on one device (or denied on one) could hand it out org-wide.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const inputs = loadInputs(db, { userId: ctx.userId, orgId: ctx.orgId, now: new Date() });
  const held = permissionSet(inputs, deviceId, false);

  for (const pattern of patterns) {
    for (const p of expand(pattern, inputs.catalogue)) {
      const d = held[p];
      if (d.effect !== 'allow') throw forbidden(`you do not hold ${p} at this scope`, refusalReason(d));
      if (deviceId === null) {
        const deniedSomewhere = inputs.grants.find((g) => g.effect === 'deny' && g.covers.has(p));
        if (deniedSomewhere) throw forbidden(`you do not hold ${p} on every device`, 'scope_mismatch');
      }
    }
  }
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest('mode must be view, control or terminal');

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  if (permissions['session:start'].effect !== 'allow') {
    throw forbidden('you cannot start sessions', 'missing_permission');
  }
  if (permissions[modePermission].effect !== 'allow') {
    throw forbidden(`missing ${modePermission} on this device`, 'missing_device_permission');
  }
  return permissions;
}
