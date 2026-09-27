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

### 2026-09-26 — prediction before writing org/member/invite routes

Proposed with an AI assistant after reading AUTH-DATA-MODEL.md §6–§7, PERMISSIONS.md §6 and §9,
and the `check-api.js` member/invite checks; I reviewed each before committing. No code yet.

1. Owner demoting another owner: PERMISSIONS.md §6 says equal role -> 403, but `check-api.js`
   expects Dana (owner) demoting `owner@acme.test` -> 200. Predict owners are the exception:
   equal rank -> 403 except owner -> owner. (Doc vs test disagreement.)
2. Rank comes from `roles.rank`, not the documented 5-level order. My DB has `reviewer` at 35.
   Reviewer holds `user:remove`, so predict reviewer can suspend an operator (30) but not an
   admin (40).
3. "A role the inviter could assign": predict strictly below your own rank, except owner can
   assign owner. An admin cannot invite an admin.
4. Suspending the last owner -> 409 LAST_OWNER, although §7 only lists it for remove/demote/
   leave. Otherwise the org's only owner can be suspended and it has no active owner.
5. Remove member -> `removed`, bump pv, end sessions (`membership_removed`), AND revoke their
   live grants in that org, so a later re-invite doesn't bring old grants back. Not in the docs.
6. Re-inviting a removed member: `memberships` is UNIQUE(org_id, user_id), so accept must flip
   the old row back to active, not insert. Inviting someone active or suspended -> 409.
7. Invite for an email that already has a user: accept "issues tokens", so whoever holds the
   invite token would be signed in as that person, and could set their password. Predict
   accept must never change an existing user's password and must require their current
   password before issuing tokens. The docs don't cover this.
8. `DELETE /members/me` must be registered before `/members/:userId`, or `me` is read as an id.

Real guesses: 1, 4, 5, 6, 7.

### 2026-09-26 — orgs/members/invites: what happened

Wrote `routes/orgs.js`, `routes/invites.js` and the rank/last-owner/removal rules in
`lifecycle.js` with AI help. For 7 I chose "require the existing user's current password"
over following the doc literally or attaching without tokens.

`check-api.js` now passes everything up to `/audit` (Phase 6, not written). That includes
grandfathering and the suspension cascade, so **Phase 5 predictions 5 and 6 finally ran and
held**: Sam's session survived his demotion, his next request was 401 TOKEN_STALE, suspension
ended it with `user_suspended`, and reinstating did not bring it back.

Probed the eight predictions on a throwaway server:
- 1: admin -> admin 403 `rank`, owner -> owner 200. The doc says equal rank is 403; the test
  wants owner -> owner allowed. Built what the test expects (DECISIONS.md).
- 2, 3: ranks come from the table. Reviewer (35) can invite and suspend an operator (30) but
  gets 403 for an admin (40). Admin can't invite admin or owner; owner can invite owner.
- 4 was **wrong about what's reachable**. The last-owner guard on suspend/demote can never fire
  through the API: only an owner can modify an owner, and nobody can suspend or demote
  themselves, so whoever does it is always another active owner. LAST_OWNER is only reachable
  by the last owner leaving (`DELETE /members/me` -> 409). Kept the guard as defence in depth.
- 5: removal ended the viewer's session (`membership_removed`), revoked their grant, and their
  old token got 401.
- 6: re-inviting the removed viewer reused their single membership row (still 1 row, now
  operator); the old grant stayed revoked.
- 7: wrong password -> 401 and the invite is still usable; right password -> 200; Sam's name
  and password unchanged; still one user row with his email.
- 8: `/members/me` works; the sole owner leaving gets LAST_OWNER.
- Two parallel accepts of one invite -> 200 + 409.

Not test-first, unlike the session bug: while writing invite creation I noticed that an
expired-but-never-cancelled invite is still "live" to `one_live_invite_per_email`
(`WHERE accepted_at IS NULL AND revoked_at IS NULL`, no expiry), so that email could never be
invited again. I wrote the fix (retire expired invites before inserting) first, and only
afterwards confirmed the bug with raw SQL: a second insert with the expired one present ->
`UNIQUE constraint failed: invites.org_id, invites.email`. Through the API, re-invite after
expiry -> 201.

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

### 2026-09-26 — prediction before writing the session routes

Proposed with an AI assistant after reading PERMISSIONS.md §7, AUTH-DATA-MODEL.md §9 and the
`sessions` schema; I reviewed each before committing. No session code exists yet.

1. `POST /sessions` order: device visible (404) -> `session:start` (403 `missing_permission`)
   -> mode permission (403 `missing_device_permission`) -> exclusivity (409 DEVICE_BUSY). Both
   missing -> `missing_permission`: "you can't open sessions at all" outranks "not here".
2. Race: I predict a check-then-insert would NOT actually race in this server. better-sqlite3 is
   synchronous and the handler never awaits between check and insert, so Node can't interleave
   two requests there. Relying on the unique index anyway (it also holds across processes) and
   translating its error to 409.
3. The index `one_exclusive_session_per_device` only covers `state = 'active'`, so a session
   inserted as `connecting` would not be protected. Insert straight as `active`.
4. A session past `expires_at` still says `active` until something changes it, so it still
   holds the unique index. Predict a real bug: an abandoned control session keeps the device
   busy forever, unless expired sessions are marked `session_expired` before inserting.
5. After Sam is demoted, his running session stays active, and his next request is 401
   TOKEN_STALE (the demotion bumps pv), not 403.
6. Suspension ends his session (`user_suspended`); reinstating does not bring it back.
7. Reading someone else's session without `session:view` -> 404, same reasoning as devices.
8. Stopping an already-ended session -> 409 CONFLICT, not 404: unlike a revoked grant, an
   ended session is still visible via GET.

Real guesses: 2, 3, 4, 8. The rest are mostly read from the docs.

### 2026-09-26 — sessions: #4 was a real bug (commit 420a5fd)

Wrote `routes/sessions.js` with AI help, deliberately *without* any expiry handling first, to
test prediction 4 before fixing it. Probe on a throwaway DB: owner starts `control` on
`dev_lab_win_01` (201), I set that session's `expires_at` to 2020, then admin starts `control`
on the same device -> **409 DEVICE_BUSY**, held by the expired session, whose row still said
`state: active`. So an abandoned session keeps the device busy forever. Nothing in the
server ever writes the expiry.

Fix: `expireSessions()` in `lifecycle.js` marks sessions past `expires_at` as ended /
`session_expired`, with `ended_at = expires_at` (when it expired, not when we noticed). It
runs before a start (for that device), a list (the org), and a get/stop (that session).
Same probe after: old row ended/`session_expired`, admin gets 201.

The rest:
- 1 confirmed: viewer asking for `control` on qa-android (neither permission) ->
  `missing_permission`. Device with `device:view` denied -> 404 for any mode.
- 2: 20 rounds of two parallel control requests -> 201+409 all 20 times. That establishes the
  required outcome (exactly one wins) but **not the mechanism**. The test can't tell
  synchronous request handling from the unique index. Not claiming either.
- 3 is a design choice, not a result: sessions are inserted straight as `active` because the
  index only covers `state = 'active'`.
- 7 confirmed: someone else's session with `session:view` denied -> 404, same body as a made-up
  id and as another org's session.
- 8 confirmed: stop own -> 200 `user_stopped`; stop again -> 409; admin stopping someone else's
  -> `admin_terminated`.
- 5 and 6 are untested: `check-api.js` fails "owner demotes Sam" with 404 (no member routes yet).

My own mistake in the probe: "viewer terminates Sam's session" came back 401 TOKEN_STALE,
because I bumped the viewer's pv mid-script and kept using the old token. It's a test bug,
not a code bug.

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

### 2026-09-26 — prediction before writing `GET /audit`

Proposed with an AI assistant; I reviewed each before committing. The docs say almost nothing
about audit reads: pagination is only pinned by `check-api.js` (limit 0/-1/99999 -> 400,
offset -1 -> 400, offset 99999 -> 200, limit 1 and 200 -> 200).

1. `limit` is an integer 1..200, default 50. 0, negative, >200, `abc`, `1.5`, empty -> 400
   (the tests only pin some of these). `offset` past the end -> 200 with an empty list.
2. Newest first, ties by id. Offset paging can skip or repeat rows if events arrive between
   pages. Accepting that rather than building cursors.
3. Audited: every successful change (one row, in the same transaction as the change) and every
   403. Not 404s (Phase 4 decision), not 401s, not successful reads.
4. Failed logins can't be audited: `audit_events.org_id` is NOT NULL and a failed login has no
   org. The schema rules it out.
5. A denial row written inside a `db.transaction` that then throws would roll back with it.
   Predict my routes are safe because every `auditDenials` call runs before the transaction
   starts. Will test, not assume.
6. Rows come back with their column names (`result`, `reason_code`), only this org's.

Real guesses: 1 beyond what the tests pin, 4, 5.

### 2026-09-26 — audit and pagination: what happened (commit 6f621ea)

Wrote `GET /v1/orgs/:orgId/audit` in `routes/orgs.js` with AI help: needs `audit:read`,
validates `limit` (1..200, default 50) and `offset`, newest first with `id` as tie-breaker,
returns `{ events, limit, offset, total }`. `check-api.js` now runs to the end: 66/66.

Predictions:
- 1 held. Beyond what the tests pin: `abc`, `1.5`, empty, `201`, `+5`, `1e2` -> 400; `200` and
  `01` -> 200; `offset=99999` -> 200 with `events: []`. Raw SQLite on the same table:
  `LIMIT 0` returns 0 rows, and `LIMIT -1` returns all 4. Handing the query string straight to
  SQLite would have turned `limit=-1` into "the whole log", so the range check sits before the
  query.
- 5 held. Operator reading the log -> 403 and deny rows went 1 -> 2; viewer changing a role ->
  403 and 2 -> 3. A scan of every route file found no audit-denial call inside a
  `db.transaction` block, so no denial row can be rolled back.
- 6 held. The Globex log has 0 rows from other orgs; a Globex token on the Acme audit URL -> 404.
- 3 and 4 are decisions, not results. 4 stands: failed logins can't be audited because
  `org_id` is NOT NULL.

**The unexpected part came from the ordering probe (prediction 2).** Two pages with `limit=2`:
three ISO timestamps, then an event whose `at` was the literal string `-2h30m`. It was 2.5
hours old but sorted last, because `-` sorts before `2`. Not my route: `resolveTime()` in
the provided `scripts/load-db.js` matched only single-unit offsets (`^([+-])(\d+)([dhm])$`).
The fixture also uses compound ones, which fell through as "already absolute ISO" and were
stored raw: `aud_003.at = "-2h30m"` and `ses_ended_view.ended_at = "-2h55m"`. Fixed the pattern to
accept a run of units. Fresh load: 0 malformed timestamps, audit order correct, and
`ses_ended_view` ends between its start and its expiry. Re-ran all four suites (66/43/35/18)
and reset `app.db`.

I did not anticipate this from the API side. It surfaced only because I looked at the order
the rows actually came back in, rather than just the status code.

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

### 2026-09-26 — prediction before writing any console code

Proposed with an AI assistant after reading UI-INVENTORY.md and all 25 tests in
`tests/ui.spec.js`; I reviewed each before committing. `web/` is still the placeholder.
Setup facts: Playwright runs the server in production mode, which serves `dist/`, but `dist/`
doesn't exist and the `test` script doesn't build it (the config comment says "`npm test`
builds the SPA first"). Chromium for Playwright isn't installed yet.

1. Existing server bug suspected: nav and "Add device" use the org-level union. A user whose
   only `device:provision` is a grant on one device gets org-level allow, so the button would
   appear. `POST /devices` uses the same org-level `assertCan`, so the API would let them create
   devices on the strength of a one-device grant. Test before fixing.
2. The first Playwright run fails everything until `npm run build`.
3. A reload goes back to the default (oldest-membership) org, because nothing may be stored
   client-side. The test only reloads on Acme, so it passes regardless. An org in the URL
   would survive a reload without storage.
4. `GET /grants` returns revoked grants too, so the console must list only live ones, or row
   counts break after any revoke.
5. The "server withdraws the permission" test means no caching of the device list across
   navigation: each visit refetches.
6. Invite page: after my Phase 3 decision, an existing account needs its password, so the page
   must show the server's 401 reason. The test only covers a new account.
7. Theme colours are keyed by theme name in CSS. That's presentation, not a permission table.
   A new org's theme needs a colour too, or "switching orgs changes the background" fails.

Real guesses: 1, 3, 4, 6.

### 2026-09-27 — console: what happened (commits 77be3b1, b9f0b7e)

**1 was a real server bug, found before any UI code.** Probe on a throwaway server: owner
grants Sam `device:provision` on `dev_lab_mac_01` only. Sam's org-level `device:provision`
came back allow (the union), and `POST /devices` for a brand-new device returned **201**.
Decommissioning a *different* device was already 403, so only actions that name no existing
device leaked. Same pattern in three more places: receiving a transfer (target org), and
creating or revoking an org-wide grant. Added `resolveOrgWide()`/`assertCanOrgWide()`
(baseline + org-wide grants only) for those four; `/auth/me` also returns
`orgWidePermissions` so the console can gate "Add device" on it. After: 403 for Sam, 201 for
the owner, all API suites green. The Phase 2 union isn't wrong. It answers "allowed on at least
one device", which is the right question for a nav card and the wrong one for an org-wide act.
The engine now answers three questions, not two (DECISIONS.md).

2 held, and was worse than predicted: with no `dist/` every test waits out the full 30 s
timeout on the login field. I first wrote that `dist/` wasn't gitignored. Wrong: it is
(`.gitignore` line 9), my check had looked at a path that didn't exist yet. The real repo issue
was the `test` script not building, although the config says it does. Changed it to
`vite build && playwright test`.

Wrote the console (`web/`) with AI help. First full Playwright run after building: **25/25**.

Checked the rest with a throwaway spec outside `tests/`:
- 3: the org is in the URL (`/o/<orgId>`), so a reload on Globex stays on Globex. The shipped test
  only reloads on Acme and would pass either way.
- 4: revoking a grant takes the list from 3 rows to 2. My first version of this probe
  "failed" with expected -1: it counted rows before the list had loaded (0). The page was right;
  I fixed the probe, not the app.
- 5: each card refetches on every visit (it is remounted by key), which is why the "server
  withdraws the permission" test passes.
- 6: an existing-account invite with the wrong password shows the server's own words ("this
  email already has an account: sign in with its password to accept", UNAUTHENTICATED).
- 7: an unknown theme gets a colour derived from its name.
- Extra: sign-out now revokes the refresh cookie (`POST /auth/logout`). Without it, a reload
  right after "sign out" would have signed the user straight back in from the cookie.

Final: Playwright 25/25, API 66/66, JWT 43/43, permissions 35/35, personalisation 18/18.

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

### 2026-09-27 — prediction before measuring anything

Proposed with an AI assistant after reading how every route touches the DB; I reviewed each
before committing. No hardening code yet. What the code shows: one shared connection; most
routes call `db.prepare()` inside the handler (recompiled per request); each permission
resolution (`loadInputs`) is 4 queries, plus 1 in `context.js`.

1. `GET /devices` has no per-row queries: `resolveDevices` loads inputs once, so the count is
   flat (~10) whether the org has 5 devices or 5,000.
2. `GET /grants` is N+1: `grantJson()` runs one `grant_permissions` query per grant row.
3. Permissions are resolved more than once per request: `POST /sessions` 3 times (visibility,
   `assertCanStartSession`, `snapshotAuthority`), `PATCH /devices/:id` 3 times.
4. At scale the cost is in memory, not queries: `decide()` scans every grant for every
   permission for every device, so `GET /devices` is roughly devices x 20 x grants. Fine at seed
   size; predict noticeably slow around 1,000 devices x 1,000 grants, with a flat query count.
5. `/auth/me` grows with the number of devices that have their own grants (the org-level union
   evaluates each one).
6. Re-preparing statements per request is measurable but small next to 2 and 4.

Real guesses: 4, 5, 6 (they need numbers). 2 is the concrete bug-shaped one.

### 2026-09-27 — baseline measurements (no code changed)

Tool, kept outside the repo: a `node --import` preload that wraps better-sqlite3 to count
statement executions and `prepare()` calls per HTTP request, plus a driver that hits each
endpoint 7 times and takes the median. Seed DB vs a scaled copy: 2,005 devices, 305 Acme
members, 2,003 grants, 1,000+ of them on `usr_acme_viewer`.

| endpoint (caller)            | queries seed -> scaled | median ms seed -> scaled |
|------------------------------|------------------------|--------------------------|
| GET /auth/me (dana)          | 12 -> 12               | 1.3 -> 1.2               |
| GET /auth/me (viewer)        | 12 -> 12               | 1.3 -> **376**           |
| GET /devices (dana)          | 10 -> 10               | 0.9 -> 26                |
| GET /devices (viewer)        | 10 -> 10               | 0.8 -> **1,279**         |
| GET /grants (dana)           | 9 -> **2,009**         | 0.5 -> 26                |
| GET /members, /sessions, /audit | 6-7 -> 6-7          | <= 1.6                   |
| PATCH /devices/:id           | 18 -> 18               | 0.8 -> 1.4               |
| POST /sessions               | 19 -> 19               | 0.9 -> 1.0               |

- 1 confirmed: `GET /devices` stays at 10 queries at 2,005 devices.
- 2 confirmed: `GET /grants` is 5 + 1 per grant. But only 26 ms: SQLite in-process is cheap
  per query. Real, but not the biggest problem.
- 3: repeated resolution is visible in the counts (18-19 queries), but costs about 1 ms.
- 4 confirmed, and it's the real cost: same 10 queries, 1.28 s for a caller with 1,000
  grants vs 26 ms for Dana. Time follows the *caller's* grant count x devices x permissions,
  not the database.
- 5 confirmed: `/auth/me` 376 ms for the grant-heavy viewer vs 1.2 ms for Dana.
- 6: statement preparation is 0.1-0.5 ms per request, except 9 of the 26 ms in `GET /grants`
  (the N+1 re-prepares each time).

Plan from the numbers: fix 4/5 (index grants per resolution) first, then the 2 N+1, each
re-measured. Leave 3 and 6 alone: about 1 ms and <= 0.5 ms don't justify caching or
request-scoped state.

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._

- **Duplicate device names are a check-then-insert race.** `routes/devices.js` checks
  `nameTaken` and then inserts, and there is no unique index behind it (I can't edit
  `schema.sql`). Two concurrent creates with the same name can both succeed. Not fixed.
- **Login with no active orgs** returns 200 with `token: null`. The user can't call anything
  org-scoped. Not decided whether that is right.
- **`*` / `device:*` can't be granted** in an org with an undocumented permission (Phase 4).
- **No `invited` membership rows.** AUTH-DATA-MODEL.md §6 says accept flips the membership "from
  `invited` to `active`", but for a brand-new email there is no user row for an `invited`
  membership to point at (`memberships.user_id` is NOT NULL, FK to users). Accept creates the
  membership, or reactivates a removed one, instead. Nothing ever writes status `invited`.
