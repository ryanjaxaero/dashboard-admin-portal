# Per-user login and widget access control - DESIGN

Status: DESIGN ONLY. Nothing in this document is built or deployed.
Branch: claude/admin-widget-controls-10o9o4
Written: Aug 15, 2026, in the claude.ai/code web sandbox (no deploy access).
Companion mockup: docs/mockups/access-admin.html (open in any browser).

Ryan's request, verbatim (Aug 15, 2026, this session):

  "designing an admin interface that allows an admin to turn different
   dashboard widgets on and off for different users. User need to be
   able to login with their email address and password using a single
   login url. The admin should be able to switch different
   widgets/modules on and off for different users."

Open questions for Ryan are at the end. Several change the build, none
change the architecture.


## 1. What exists today, and why this is a real change

Access control today is WordPress page passwords, nothing else:

  - Each dashboard page has one shared password (post_password).
  - The 16 instructor invoice pages each have a UNIQUE password so no
    instructor can open a colleague's pay page.
  - REST writes are gated by secrets (jaxpay_save_token, jaxreq_token)
    rendered only into password-protected pages.
  - There are no user accounts, no identity, and no record of who
    viewed what. A password identifies a page, not a person.

This request replaces "a password per page" with "an account per
person plus an entitlement list per account". That is the correct
direction: it collapses 17+ passwords into one login URL, gives every
action a name, and makes "what can Ben see" a setting instead of a
password-distribution problem.

Referenced sessions (pulled from the account Aug 15): the long-running
"JAXAERO Dashboards" workstation session (session_01NdgLwtvbnexKuxfd38dkU3,
last active Aug 15 morning) holds the deploy connection and build
memory; the archived "Fsp hourly refresh" / "Fsp keepalive" sessions
are the office PC automation. Nothing in them conflicts with this
design; the workstation session is where this eventually deploys from.


## 2. Hard constraints this design honors

1. NEVER any FSP credential. These are WordPress accounts only. No FSP
   login, no FSP password field, anywhere. (CLAUDE.md rule 1.)
2. The dev site CANNOT send email (punch list K12: Postmark token dead
   since Jul 21). Therefore NO email-based password reset at launch.
   Admin sets and resets passwords; a temporary password is shown once
   to the admin, who hands it over out of band. If the Postmark token
   is ever restored, self-service reset can be added.
3. No credentials in this repo. Accounts are created on the site;
   temporary passwords are generated server-side and never written to
   a file here.
4. srcdoc rules apply to all new UI (zero // comments, semicolons
   everywhere, no unescaped apostrophes, check-srcdoc raw and
   stripped).
5. Deploys happen from the workstation over Novamira, per DEPLOY.md.
   This sandbox drafts only.
6. Aug 16 pay date: B12 (distribute the 16 URL+password pairs) must
   NOT wait for this build. Passwords go out as planned; this system
   replaces them afterward. See section 9.


## 3. Architecture overview

One new snippet owns identity and entitlements. Existing snippets gain
only small render-time checks.

  Snippet 11 (proposed)   wp/jaxaero-access.php   prefix jaxauth_
    - [jaxaero_login]         the single login page
    - [jaxaero_home]          post-login landing: cards for allowed pages
    - [jaxaero_access_admin]  the admin matrix (users x widgets)
    - access-check helpers used by snippets 5-10
    - REST routes for admin actions
    - login rate limiting and the audit log

Identity is NATIVE WordPress users, not a custom credential table:

  - Email address is the login name. WordPress supports signing in by
    email natively (wp_authenticate handles it).
  - Custom role `jaxaero_member` with NO wp-admin capabilities. Members
    never see wp-admin; the admin bar is hidden for the role.
  - Admins of THIS system are marked by a capability `jaxauth_admin`
    granted to their user. Being a WordPress Administrator is neither
    necessary nor sufficient - the dashboard admin list is its own
    thing, so Ben can be a dashboard admin without site admin rights.

Why native users instead of rolling our own: password hashing, session
cookies, logout, brute-force surface, and "remember me" are all solved,
audited WordPress core code. A hand-rolled credential store in an
option would repeat work and get the security details wrong first.

Entitlements live in user_meta, validated against a central registry:

  user_meta jaxauth_grants      array of widget keys (section 4)
  user_meta jaxauth_instructor  instructor slug binding, or empty
  option    jaxauth_registry    NOT stored - the registry is code, a
                                constant in snippet 11. Grants that
                                reference unknown keys are ignored.
  option    jaxauth_log         append-only audit trail of admin
                                actions (who, when, what changed).
                                No delete, same philosophy as the
                                requests board.


## 4. The widget registry

Two levels: PAGE keys gate whole pages, CHILD keys gate sections
inside a page. Granting a child without its page does nothing; the
admin UI enforces that visually (children indent under their page).

  Key                  What it unlocks
  -------------------  ------------------------------------------------
  rev                  Revenue dashboard page (5785)
  rev.mom              month-over-month table + popup
  rev.category         revenue by category table
  rev.daily            daily chart + popup
  auto                 AUTO dashboard page (5787)
  auto.tax             per-aircraft DOR tax widget + popup
  auto.payroll         the payroll widget iframe on that page
  sales                Revenue + sales pipeline page (5788)
  sales.pipeline       pipeline table
  sales.meta           Meta/ads panel
  sales.starts         new starts panel
  sales.studentload    student load panel
  tax                  standalone sales tax page (5789)
  pay                  payroll widget wherever it renders
  pay.rates            "Edit rates" button + rate editor page (5795)
  pay.events           "Checkrides & reviews" editor
  pay.pdf              invoice PDF buttons (single + combined) + CSV
  invoice              the logged-in user's OWN instructor invoice page
  requests             punch list + requests board (5816)
  access               the access admin page itself (implies admin)

Notes:

  - KPI rows, notes and headline cards are NOT separately toggleable.
    A dashboard with its headline stripped is not a dashboard. Only
    sections that are meaningfully optional get child keys. More can
    be added later; the registry is one constant.
  - `invoice` is deliberately NOT parameterized. It always renders the
    instructor bound to the logged-in account (jaxauth_instructor).
    An admin toggle can never point one instructor at another's pay.
    Admins with `pay` see everyone via the payroll widget instead.
  - Role templates in the admin UI are conveniences that pre-check
    boxes, not stored roles: Owner (everything), Instructor
    (invoice only), Finance/tax (tax only). Saving always stores the
    explicit key list.


## 5. Enforcement - where the checks run

Page level. On template_redirect, if the requested page ID is in the
registered map and the visitor lacks the page key: logged out ->
redirect to the login URL with ?next=; logged in -> a plain "you do
not have access to this page" note with a link back to their home.
Gated pages send nocache_headers(). WP Rocket does not serve cached
pages to logged-in users, and the anonymous-visitor variant is the
login redirect, so nothing entitled ever enters the page cache. This
mirrors the already-verified behavior for password-protected pages.

Widget level. Server side, inside each snippet's render function,
BEFORE the srcdoc is assembled: a disabled section is simply not
built, so it is absent from the HTML, not hidden by CSS. Nothing
sensitive rides to the browser to be un-hidden. This is the same
reason [jaxaero_requests punch="0"] sends an empty array rather than
hiding the mirror (punch list K9).

Existing snippets change minimally: each optional section gains one
`if (jaxauth_can('key'))` guard around code that already exists.
Snippet 11 defines jaxauth_can(); if snippet 11 is ever deactivated,
a function_exists fallback keeps current behavior (everything renders
for anyone past the page gate), so a bad deploy of the new snippet
cannot blank the dashboards.

Transition rule. During rollout, pages accept EITHER a valid login
with the right key OR the existing page password (a filter on
post_password_required short-circuits for entitled users). Passwords
are removed page by page only after logins are proven. The tax page
(5789) may keep its password permanently - the tax attorneys are
external and two credentials for them may be simpler than accounts.
Open question 6.


## 6. The login page

  - One URL, e.g. /signin (NOT /login - WordPress canonically
    redirects /login to wp-login.php, which would fight us).
  - Elementor Canvas page, NOT password protected, [jaxaero_login].
  - Email + password + "keep me signed in" (14 days), JAXAERO look
    (navy #1F2F54, red #C10F1B, tan #C0A788 - the existing palette).
  - POSTs to a REST route that calls wp_signon and redirects to
    ?next= (validated same-site) or the member's home page.
  - Failures: one generic message, "That email and password
    combination did not work." Same message for unknown email and
    wrong password - no user enumeration.
  - Rate limiting: 5 failures per email and per IP in 15 minutes
    locks that email/IP pair out for 15 minutes (transient counter).
    The lockout message says when to retry and never confirms the
    account exists.
  - wp-login.php stays functional for Ryan's real WordPress admin
    account. Members are pointed at /signin; if a member lands on
    wp-login.php anyway, logging in there works too and drops them at
    their home page. No security by obscurity claims either way.
  - Logged-in visits to /signin bounce straight to home.

Post-login home: a page with [jaxaero_home] showing one card per page
key the member holds (name, one-line description, link). A member
with a single grant skips the card page and lands directly on that
page. Header of every gated page shows "Signed in as <name> - sign
out" inside the page chrome (parent page, not the srcdoc, so the
iframes stay untouched).


## 7. The admin interface

Page: /access-admin (Elementor Canvas, gated by the `access` key -
page password optional during transition). Shortcode
[jaxaero_access_admin]. Same srcdoc iframe pattern as everything else.

Layout (see docs/mockups/access-admin.html):

  LEFT: user list. Name, email, role template chip, enabled/disabled
  state, last sign-in. Disabled users sort to the bottom. "Add user"
  button on top.

  RIGHT: detail panel for the selected user.
    - Identity block: name, email, instructor binding dropdown
      (roster slugs from jaxpay_instructors, or "none"), admin
      checkbox, enable/disable, "Reset password".
    - Access matrix: page keys as section rows with children indented
      under them, one toggle each. Toggling a page off greys its
      children. Role template buttons (Owner / Instructor / Finance)
      pre-check the boxes; nothing saves until "Save access".
    - Save is one click per user, not per toggle - matches the rate
      editor pattern and keeps the audit log readable.

  BOTTOM: audit log, newest first: "Aug 15 3:12 PM - Ryan gave Ben
  Barwick: invoice; removed: pay.rates", "Aug 15 3:02 PM - Ryan
  created account for kate@...". Read-only, no delete.

Add user flow: name + email + optional instructor binding + role
template. Server generates a temporary password (wp_generate_password,
14 chars), shown ONCE in the confirmation dialog for the admin to
copy into the password manager / hand to the user. It is never
emailed (K12) and never stored in plain text anywhere. First sign-in
with a temporary password forces a password change before anything
else renders. Reset password does the same thing.

REST routes (namespace jaxauth/v1): save-grants, create-user,
set-password (admin reset), set-state (enable/disable), and
change-password (self, for the forced first change). All admin routes
require BOTH a logged-in user with the jaxauth_admin capability AND a
standard REST nonce. This is real capability checking, not the
rendered-token pattern - the token pattern exists because pages had
no identity; these pages have identity, so use it. The existing
jaxpay/jaxreq token routes are untouched (open question 7 for later
tightening).

Safety rails:
  - An admin cannot disable or de-admin their own account (prevents
    locking everyone out); a second admin can.
  - At least one enabled admin must exist; the last one cannot be
    disabled.
  - Break-glass: Ryan's real WordPress admin account can always fix
    things from wp-admin regardless of this system.


## 8. What this does NOT change

  - The data pipeline. Cron builds, transients, verified refresh, the
    office PC loop: untouched.
  - The pay model, rates, locks, bonuses: untouched.
  - Snippets 5-10 keep their shortcodes and pages. They gain render
    guards only.
  - The requests board write model (page access = write access) can
    stay as is initially; the board simply moves behind a login like
    every other page.


## 9. Rollout phases

  Phase 0  This document + mockup. Ryan answers the open questions.
  Phase 1  Build snippet 11: login, home, admin UI, guards in
           snippets 5-10 behind function_exists. Accounts for Ryan
           and Ben only. Every page keeps its password (dual access).
           Prove: sign-in on desktop AND phone, lockout, audit log,
           forced password change, a widget toggle visibly changing
           Ben's AUTO page.
  Phase 2  Instructor accounts (16), each bound to their slug with
           the Instructor template. Instructors get ONE url + their
           own temporary password. Their invoice pages accept login
           or the old page password during the overlap.
  Phase 3  Remove page passwords from the internal pages. Decide
           separately for the tax page (attorneys) and requests page.
  Any time Postmark is fixed: add self-service password reset.

  B12 NOTE: Saturday Aug 16 distribution of the 16 password pairs
  happens on the CURRENT system regardless of this project. Do not
  hold it. If Ryan prefers, hold the DISTRIBUTION and go straight to
  accounts in Phase 2 next week - his call, flagged in the open
  questions. Either way B13 (bonus review) still gates.


## 10. Testing plan (before any deploy)

  - php function-scope lint (the eval wrap from K8 finding 1), php -l.
  - node scripts/check-srcdoc.mjs on every touched file, raw AND
    stripped.
  - Offline harness for the admin matrix (build-access-harness.mjs,
    same pattern as the payroll harness), INSIDE an iframe - the K10
    lesson: the resize handshake must be tested in a real host page.
  - Auth cannot be harness-tested offline (it needs WordPress), so
    Phase 1 verification is live on the dev site with throwaway
    accounts, in a real browser, phone included, before any real
    credential is issued.
  - scripts/php/export-wp-state.php before the first deploy that
    touches snippet 9.


## 11. Open questions for Ryan

  Q1 TIMING. Does Saturday's B12 distribution go out as passwords
     (recommended - do not gate the pay date on new auth), or do you
     want to skip password distribution and wait for accounts?
  Q2 PEOPLE. Launch list of accounts and who is admin. Assumed: Ryan
     and Ben admins; 16 instructors as members bound to their slugs.
     Do Kim, John, Rachael get accounts on day one?
  Q3 GRANULARITY. Is the registry in section 4 the right first cut?
     Anything you want toggleable that is not listed (for example the
     revenue GOAL number, or the staleness pill)?
  Q4 LANDING. After login: card page listing allowed dashboards
     (recommended), or straight to one page per user?
  Q5 PASSWORDS. Admin-set passwords with out-of-band handoff is
     forced by K12 (no email). OK at launch? Should fixing the
     Postmark token be pulled forward so resets can be self-service?
  Q6 EXTERNALS. Do the tax attorneys and Rachael get accounts, or
     does the tax page keep its page password permanently?
  Q7 OLD TOKENS. Once logins exist, should the jaxpay/jaxreq REST
     writes ALSO require a logged-in user (belt and suspenders), or
     stay as is until the passwords are retired?
  Q8 SITE. Confirm this all stays on jaxaerodev per decision D15.
     Accounts make the "somewhat public dev hostname" more defensible,
     not less, but the hostname in the login URL is what instructors
     will bookmark.
