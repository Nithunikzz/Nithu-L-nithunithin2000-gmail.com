# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### An org-wide grant needs the permission on every device, not just one

**What I chose:** `assertMayGrant` (`server/permissions.js`) with `deviceId === null` requires the
caller to hold each permission at the plain org-wide scope AND to have no deny grant for it on any
device. It deliberately does not reuse the org-level union that `resolve()` uses.
**Why:** the org-level union answers "can they do this *somewhere*?". That's right for showing a
nav item, but wrong for handing out authority *everywhere*. With the union, my personalised user
(allow `device:reboot` on `dev_p_bb3398_a`, deny on `_b`) resolves to org-level allow, so they
could create an org-wide `device:reboot` grant for someone else and give away reboot on `_b`, the
exact device they were denied on. That is the laundering D9 forbids.
**What I rejected:** calling `can(db, ctx, p)` at org level. It's shorter and reuses one path, but
fails on the case above.
**What would change my mind:** a hidden-tier or spec statement that "at that scope" for an
org-wide grant means the org-level view. Then a device-scoped allow would be enough to grant
org-wide, and I'd want to see that written down.

---

### Org-level resolution is a union over devices: allow on one device is allow

**What I chose:** `decideOrgLevel()` returns allow if the permission resolves to allow on at
least one device (the plain org-wide answer, or any device with its own grants). Deny still wins
*on the device it applies to*. An org-wide deny applies to every device, so it still gives deny.
**Why:** PERMISSIONS.md §3 defines org-level as "the union across all devices in the org". Logged
as a 65% prediction in commit 54c6dc6 before writing the engine. `check-personalisation.js`
computes the org-level result but does not assert it (line 48), so no public test settles this.
**What I rejected:** "any deny anywhere makes the org-level answer deny". It hides a nav entry
from a user who genuinely can act on another device.
**What would change my mind:** a test expecting org-level deny for allow-on-A + deny-on-B.

---

### A device the caller can't view is a 404 on direct access, not a 403

**What I chose:** `visibleDevice()` in `routes/devices.js` returns 404 when `device:view` resolves
to deny, the same as for a device that is deleted or in another org.
**Why:** `GET /devices` drops that row entirely. Probed as `viewer@acme.test`:
`kiosk-lobby-01` is absent from the list and `GET /devices/dev_kiosk_lobby_01` is 404. If direct
access returned 403, the caller could confirm by id that a device they were never shown exists.
**What I rejected:** 403 on the grounds that the device is "in your org, you just lack the
permission". That is the PERMISSIONS.md §5 rule for most resources, but for a device
`device:view` *is* the visibility question.
**What would change my mind:** a test expecting 403 for a device denied by `device:view`.

---

### Transferring a device revokes the old org's grants on it

**What I chose:** `POST .../devices/:id/transfer` ends active sessions (`device_transferred`), sets
`revoked_at` on every live grant in the old org whose `device_id` is this device, and bumps those
users' `perm_version`, all in one transaction with the move.
**Why:** after the move those grants name a device that belongs to another org. `resolve()`
filters grants by `org_id`, so today they would be inert. But they would come back to life if
the device were ever transferred back. No document says what happens to them.
**What I rejected:** leaving them in place because they're harmless now. That's harmless only
until the device returns.
**What would change my mind:** a spec line or test saying grants survive a round-trip transfer.

---

### Only 403s are audited as denials, not 404s

**What I chose:** `auditDenials()` in `audit.js` writes a `result='deny'` row for an `HttpError`
with status 403 and ignores everything else.
**Why:** a 403 is a refused action on a target the caller could see. A 404 means they couldn't
see it: another org's device, a revoked grant. Writing that target id into this org's log
would record an id the caller was never entitled to learn. Hand probe: 4 refused grant/transfer
attempts produced 4 deny rows with reasons (`self_grant`, `missing_permission`, `explicit_deny`).
**What I rejected:** auditing every non-2xx. It's noisier, and it logs cross-org probing into
the wrong org's audit trail.
**What would change my mind:** a requirement to detect cross-org probing. That belongs in a
separate security log, not in the org's own audit trail.

---

### Accepting an invite for an existing account requires that account's password

**What I chose:** in `POST /invites/{token}/accept` (`routes/invites.js`), if the invite's email
already has a user, the request must carry that user's current password (`verifyPassword`)
before a membership is attached or tokens are issued. Their name and password are never
changed. Wrong password -> 401, and the invite stays usable.
**Why:** this is my resolution of a gap, not a documented rule. AUTH-DATA-MODEL.md §6 says accept
"upserts the user … and issues tokens". Taken literally, whoever holds the invite token is signed
in as the existing person, and could set their password. Probe: accepting an invite for
`sam@example.test` with `attackerpass` -> 401; with Sam's real password -> 200; Sam's name and
login unchanged, still one user row.
**What I rejected:** (a) the literal reading, which is account takeover by invite link;
(b) attaching the membership without issuing tokens. That's safe, but it drops the documented
"issue tokens", and it still lets a token holder add someone to an org without their consent.
**What would change my mind:** a spec statement that invite emails are verified out of band and
the token is meant to authenticate. Even then I'd keep "never overwrite an existing password".

---

### Removing a member also revokes their grants in that org

**What I chose:** `removeMembership()` in `lifecycle.js` sets `revoked_at` on the user's live grants
in that org, alongside the documented status change, pv bump and session end.
**Why:** a removed member can be re-invited, and accept reuses the same membership row
(UNIQUE(org_id, user_id)). Without the revoke, their old grants would silently apply again.
Probe: removed viewer with a `device:control` grant, re-invited as operator: the grant stayed
revoked.
**What I rejected:** leaving grants in place because `resolve()` ignores non-active members. True
while they're removed, wrong the moment they come back.
**What would change my mind:** a requirement that rehiring restores prior access. Then it should
be an explicit restore, not a side effect.

---

### Audit pagination is validated at the API boundary, never passed through to SQLite

**What I chose:** `pageParam()` in `routes/orgs.js` accepts only whole numbers written as digits:
`limit` 1..200 (default 50), `offset` >= 0. Anything else is 400 `invalid_pagination`, checked
before the query runs. Out-of-range values are rejected, not clamped. Order is `at DESC, id DESC`.
**Why:** raw SQLite on `audit_events`: `LIMIT -1` returned all 4 Acme rows and `LIMIT 0`
returned none. So the API's meaning of `limit` would silently be SQLite's. `check-api.js`
(section "pagination boundaries are defined, not clamped") wants 400 for 0, -1 and 99999, and
my probe adds `abc`, `1.5`, `+5` and `1e2` -> 400. The `id` tie-break keeps page boundaries
stable when two events share a timestamp.
**What I rejected:** passing `limit`/`offset` straight into `LIMIT ? OFFSET ?` (-1 means
"everything"), and clamping 99999 down to 200, which the test explicitly calls wrong.
**What would change my mind:** a contract that wants clamping, or cursor pagination. Offset
paging can skip or repeat rows when events arrive between pages, and I've accepted that.

---

## Where this repo argues with itself

### The seed loader and the fixture disagree about relative timestamps

- `scripts/load-db.js` `resolveTime()`: "Timestamps in the fixture are RELATIVE ('-2h', '+7d',
  'now')", parsed with `^([+-])(\d+)([dhm])$`, one unit only.
- `seed/orgs.json`: `"at": "-2h30m"` (aud_003) and `"endedAt": "-2h55m"` (ses_ended_view).

The loader stored those two raw, and the audit ordering probe found `-2h30m` sorted after every
real date. I fixed the loader (it's plumbing, not a file the brief forbids editing) to accept a
run of units, rather than compensating in the audit query. The fixture is the data, and a
reader shouldn't have to know which rows are malformed. What would change my mind: a rule that
fixture offsets must be single-unit. Then the fixture is the bug, and the loader should reject
the value instead of storing it.

### Can an owner modify another owner?

- PERMISSIONS.md §6: "modify a user of equal role (admin -> admin) | `403`".
- `check-api.js`: "demoting a NON-last owner is allowed": Dana (owner) demotes `owner@acme.test`
  (owner) -> expects 200.

Built against the test: `assertCanModify` in `lifecycle.js` requires a strictly higher rank, with
one exception, owner -> owner. Probe: admin -> admin 403, owner -> owner 200. The reason to side
with the test: owner is the top rank, so under the strict rule nobody could ever demote or
remove an owner, and a second owner could never be taken out of the org.

### The size of the wildcards

- PERMISSIONS.md §4: "`device:*` collapses to the seven device permissions; `*` to all nineteen."
- My `app.db` (`SELECT key FROM permissions`): 8 `device:` permissions and 20 in total. The
  personalised fixture adds `device:reboot`.

Built against the database: `expand()` filters the `permissions` table by prefix at runtime, so
`device:*` covers `device:reboot`. A hardcoded list of 7 would pass `check-permissions.js` and
fail `check-personalisation.js`, and grading uses a different nonce anyway.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
