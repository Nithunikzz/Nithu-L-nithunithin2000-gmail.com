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

## Where this repo argues with itself

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
