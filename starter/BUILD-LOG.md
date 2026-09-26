# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.


## Phase 0 — orientation
### 2026-09-26

Reset the database successfully and confirmed the personalized fixture was loaded, including the
extra `reviewer` role and `device:reboot` permission.

Ran the untouched skeleton checks before making implementation changes.
`check-permissions.js` stopped because `permissions.js::resolve()` is still the provided TODO stub.
`check-jwt.js` reported 0 passed and 43 failed because `verifyAccessToken()` is still a stub.
`check-api.js` could not get through login: Dana's login returned 404 and the suite aborted afterward.

The starting point is therefore multiple intentional server-side stubs rather than isolated test
failures. I will inspect the token contract first before implementing authentication.
## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

### 2026-09-26

Implemented `verifyAccessToken()` in `server/auth.js` in the order the stub's TODO lists the rules:
shape (3 base64url segments) -> JSON objects -> pinned `alg`/`typ` -> HMAC compared with
`timingSafeEqual` -> `exp <= now` rejected -> `iss`/`aud` -> non-empty `jti`. Every failure throws
`unauthenticated()` from `http.js`, because `check-jwt.js` asserts the rejection *shape*
(`401 UNAUTHENTICATED`), not just that something threw.

`node scripts/check-jwt.js`: 0/43 on the stub -> 43/43 on the first run. No failures to chase.

The one line that is not obvious: signature length is checked before `timingSafeEqual`, because
that function throws a `RangeError` on buffers of different lengths. Without the check, "signature
truncated" would only become a 401 by accident, via the outer `catch`.

Open: the outer `try/catch` maps *any* error to 401, including a missing/undefined secret. That
hides a server misconfiguration as "every token is invalid". Leaving it for now; to revisit.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-26 — initial model (prediction, before writing `resolve()`)

Worked this out with an AI assistant after reading PERMISSIONS.md §3–§4 and querying `app.db`
(roles, role_permissions, permissions, permission_patterns, grants). Committed before any engine
code so the tests can prove it wrong. I have not read `check-permissions.js` yet.

1. Org-wide deny vs device-scoped allow: deny wins, whatever the scope (§4 D1).
2. Scope: an org-wide grant (`device_id` NULL) applies to every device question; a grant on
   device Y does not apply to a question about device X.
3. Org-level with allow on one device and deny on another (my personalised user: `allow
   device:reboot` on `dev_p_bb3398_a`, `deny` on `dev_p_bb3398_b`): I predict **allow**, because
   §3 calls org level "the union across all devices" — resolve each device, allowed if any device
   allows. Only ~65% sure: the same section says deny wins, and that could mean any deny anywhere
   kills the org-level answer. This is the one I expect might break.
4. Wildcards: `device:*` should expand to every row in `permissions` starting `device:`. §4 says
   "the seven device permissions" and `*` is "all nineteen", but my DB has 8 device permissions
   and 20 total — the personalised fixture adds `device:reboot`. So expand from the table at
   runtime, never from a hardcoded list. (Docs vs DB disagreement — note for "Where this repo
   argues with itself".)
5. Time windows are half-open, `starts_at <= now < expires_at`: NULL `starts_at` = already
   active, NULL `expires_at` = no end, `expires_at == now` = expired.
6. A revoked grant counts for nothing (allow or deny). A suspended member has no permissions at
   all, not even the role baseline (§3 step 1).
7. No implication: `device:control` does not give `device:view` (§4 D5).

Only 3 is a real guess; 1, 2, 5, 6, 7 are read from the docs, not discovered.

### 2026-09-26 — engine written, what the tests said

Wrote `server/permissions.js` from the model above (with AI help; I went through each function
before committing): `expand()` reads wildcards against the `permissions` table, `loadInputs()`
does 3 queries (membership, baseline, live grants — revoked/out-of-window/deleted-device grants
are dropped in SQL), `decide()` is deny grant -> role -> allow grant -> implicit.

`check-permissions.js` 35/35, `check-personalisation.js` 18/18, first run. Nothing in the
public suites contradicted the model — so this is "not disproved yet", not "confirmed".

Q3 is still open. I expected the personalisation suite to settle it, but it only *computes*
`orgWide = resolve(db, ctx)` (line 48) and never asserts on it. My engine gives
`device:reboot` = allow on `dev_p_bb3398_a`, deny/explicit_deny on `_b`, and **allow** at org
level (source `grant:grt_p_bb3398_allow`). Sam's `device:terminal` at org level is still
deny/explicit_deny — the org-wide deny applies to every device, so the union is empty. Kept
the union reading; it is probably in the hidden tier.

Choice I made while writing it: `assertMayGrant` does NOT use the org-level union. For an
org-wide grant the caller must hold the permission with no deny on any device. See DECISIONS.md.

Unsettled: a device-scoped grant of a non-device permission (e.g. `audit:read` on one device)
currently counts at org level through the union. No document says what that should mean.

### 2026-09-26 — caller context: prediction before writing `context.js`

Proposed with an AI assistant; I reviewed each answer before committing. Committed before any
`context.js` code.

1. Token for Acme, URL names Globex -> **404**, and still 404 if I am also a Globex member. The
   access token is scoped to exactly one org; switching means minting a new token
   (`POST /v1/auth/token`).
2. Stale token AND wrong org -> **401 TOKEN_STALE**: freshness first, isolation second. Neither
   answer leaks anything about the other org, as long as the isolation step is a plain compare
   of `claims.org` with the URL and never looks the URL's org up. A stale token gets no answer at
   all; after refreshing, the retry gets the 404.
3. Suspended member, fresh token -> **403 FORBIDDEN, reason `suspended`**, refused in the context
   layer, not left to `resolve()`, or routes that need no permission (`/auth/me`, leaving the
   org) would keep working for a suspended user. Not a clean prediction: early on I saw a line
   in the organiser README naming suspension on ungated routes as a test area.
4. No org in the URL: `/sessions/:id` acts in the token's org (another org's session -> 404);
   `GET /v1/orgs` lists every org I'm an active member of (discovery, not acting in them);
   `/auth/me` reports the token's org.
5. Token valid but org soft-deleted -> **401**: the membership lookup skips deleted orgs, so
   I'm "not a member". Docs don't say; a real guess.

### 2026-09-26 — caller context: what happened (commit 74ddaef)

Wrote `context.js` + auth routes (login/refresh/token/me) with AI help. Tested the five
predictions by calling `buildContext` directly on a copy of `app.db`: all five held — wrong org
404 (also for an org I *am* a member of, and for one that doesn't exist, same body), stale +
wrong org 401 TOKEN_STALE, suspended 403/`suspended` (tested *without* bumping pv, so context
catches it even if a suspend route forgets the bump), no org in URL -> token's org, deleted org 401.

The interesting part was `check-api.js`, not my predictions. With only auth routes registered,
"Acme token against Globex -> 404" **passed** and "no token -> 401" **failed with 404**. Both for
the same reason: `server/index.js` matches the route before it authenticates, and there was no
devices route yet, so the router said 404 before `context.js` ever ran. The pass was a false
positive. It only meant something once `/orgs/:orgId/devices` existed (next commit), when it
still passed and "no token" flipped to 401.

Smoke test of refresh: rotation works; replaying the old cookie -> 401 and kills the family, so
the newest cookie is dead too. Unknown email and wrong password give the identical body and
both run scrypt.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

### 2026-09-26 — devices + grants routes

Wrote `routes/devices.js`, `audit.js`, and `endActiveSessions` in `lifecycle.js` with AI help.
`check-api.js`: every devices check passes (kiosk-lobby-01 absent for the viewer, Dana's
one-device control grant). It aborts later at sessions, which don't exist yet, so the grant
checks never ran. Probed grants by hand against a throwaway server: teleport -> 400
`unknown_permission` (the FK refuses it, the route only translates the error), self-grant 403,
past expiry 400 GRANT_EXPIRED, other org's device 404, revoke twice -> 404.

Surprise: an admin granting `device:*` on one device was refused with `missing_permission`, not
the `explicit_deny` I expected from the org-wide terminal deny I'd just given them. The first
permission it failed on was `device:reboot`. `device:*` expands (from the table) to 8
permissions, no role baseline holds the personalised one, and `assertMayGrant` requires the
caller to hold every expanded permission. So in this DB **nobody, not even an owner, can grant
`device:*` or `*`**. No-laundering is doing what it says, but no document mentions this
consequence. Recording it as an observation; I haven't changed anything.

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._

- **Duplicate device names are a check-then-insert race.** `routes/devices.js` checks
  `nameTaken` and then inserts, and there is no unique index behind it (I can't edit
  `schema.sql`). Two concurrent creates with the same name can both succeed. Not fixed.
- **Login with no active orgs** returns 200 with `token: null`. The user can't call anything
  org-scoped. Not decided whether that is right.
- **`*` / `device:*` can't be granted** in an org with an undocumented permission (Phase 4).
