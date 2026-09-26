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

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

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
