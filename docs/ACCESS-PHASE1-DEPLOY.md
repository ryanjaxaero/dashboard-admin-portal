# Access control phase 1 - deploy procedure

Status: BUILT AND LINTED, NOT DEPLOYED. Deploys happen from the
workstation over Novamira, per docs/DEPLOY.md. This file covers only
what is new about deploying snippet 11 the first time.

What ships: wp/jaxaero-access.php (snippet 11, prefix jaxauth_) plus
the one-time setup payload scripts/php/access-setup.php.

What it does: real WordPress accounts (email + password), a single
sign-in page at /signin, self-service password change, and an
/access-admin panel that turns widgets on and off per user. It gates
the existing dashboards through pre_do_shortcode_tag and
post_password_required WITHOUT editing snippets 5-10. Page passwords
keep working for anyone not signed in. Deactivating snippet 11
restores the old behavior completely.


## 0. Before anything

- scripts/php/export-wp-state.php - snapshot the hand-entered state.
- Confirm with Ryan. Show him this file and the diff.


## 1. Local gates (all four PASSED in the web sandbox on Aug 19)

    php -l wp/jaxaero-access.php
    php -r 'wrap the body in a function and lint THAT'   (eval scope)
    node scripts/check-srcdoc.mjs wp/jaxaero-access.php  (raw + stripped)
    offline browser harness: login, home, admin render and their JS
      runs with zero errors, raw AND newline-stripped

Re-run the first three on the workstation before deploying anyway.


## 2. Install snippet 11

Create a NEW row in wp_snippets (do not touch snippets 5-10):

    name   JAXAERO Access Control
    scope  global
    active 1
    code   = bytes of wp/jaxaero-access.php WITHOUT the "<?php\n"
             header (tail -c +7), same convention as every snippet

Verify sha256 of the stored code against tail -c +7 of the repo file.
Then clear the snippet caches - once per scope, global / admin /
front-end (the ArgumentCountError gotcha in CLAUDE.md).


## 3. Run the setup payload

scripts/php/access-setup.php via the sandbox-file execute-php path.

THE PASSWORD: the payload contains the placeholder
<<REPLACE_AT_RUN_TIME>>. Substitute Ben's starting password into the
PAYLOAD YOU EXECUTE, at run time. Ryan supplies it. It must never be
committed to this repo (CLAUDE.md hard rule 4) and the script aborts
if the placeholder is still present.

The script is idempotent. It creates the /signin and /access-admin
pages (Elementor Canvas, NOT password protected - /signin must be
reachable logged out, /access-admin is gated in code to admins),
writes the jaxauth_pages map, and creates Ben Gabriel
(ben@flyjaxaero.com, member role) with grants: rev, auto, pay,
pay.rates, sales, tax, requests. Deliberately not granted: access
(admin panel - Ryan administers via his WordPress admin account,
which passes jaxauth_is_admin through manage_options) and invoice
(Ben Gabriel is not a CFI; nothing to bind).


## 4. Verify in a real browser before telling anyone

Logged OUT (fresh private window):
  - /signin shows the sign-in form, no data
  - every dashboard page still shows its password form; the password
    still works (dual access unchanged)
  - wrong email or wrong password at /signin: the same generic
    message; sixth try inside 15 minutes says locked

Ben's account (Ryan does this himself first):
  - sign in at /signin -> welcome page with six cards
  - every card opens without a page password prompt
  - AUTO page shows the payroll widget (grant: pay)
  - change password: mismatch rejected, short rejected, good one
    works, sign out, old password fails, new password works

Ryan's WP admin account:
  - /access-admin loads; Ben listed with seven grants
  - toggle one widget off, save, reload Ben view: that widget shows
    the "not enabled" card in place; audit log recorded the save
  - toggle it back on

WordPress option caching note from CLAUDE.md applies: verify reads
in a FRESH request, not the same one that wrote.


## 5. Rollback

Deactivate snippet 11. Every gate disappears; page passwords are
untouched throughout. The pages /signin and /access-admin render
their raw shortcode text until reactivation - harmless.


## Phase 2 (not in this deploy)

Sub-widget keys (rev.mom, auto.tax and so on) need guards inside
snippets 5-9; instructor accounts with invoice bindings replace the
16 page passwords; the punch list L1 entry tracks it.
