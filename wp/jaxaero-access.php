<?php
/* ===================================================================
   JAXAERO Access Control                              snippet 11
   prefix: jaxauth_
   shortcodes: [jaxaero_login]  [jaxaero_access_admin]

   WHAT THIS IS
     Real per-user access to the dashboards. Native WordPress users
     (email + password, custom no-wp-admin role), one sign-in page,
     self-service password change, and an admin panel that turns
     widgets on and off per user.

   HOW IT GATES WITHOUT TOUCHING SNIPPETS 5-10
     - pre_do_shortcode_tag: when a LOGGED-IN managed user views a
       page, each dashboard shortcode renders only if their grants
       include its key. Anonymous visitors are untouched - the page
       passwords keep working exactly as before (dual access during
       rollout) - EXCEPT for the keys in jaxauth_login_only_keys()
       (currently 'pay' and 'pay.rates'), which refuse anonymous
       visitors outright. Ben, punch list 12: page 5787 carries the
       payroll widget behind the SAME password as the Revenue AUTO
       dashboard, so anyone with that password was already inside
       payroll. See the gate itself for the full reasoning.
     - post_password_required: a logged-in user WITH the page's key
       skips the password prompt entirely.
     Deactivating this snippet restores the old behavior completely.

   WIDGET KEYS (phase 1 - shortcode granularity)
     rev        [jaxaero_revenue]         page 5785
     auto       [jaxaero_revenue_auto]    page 5787
     pay        [jaxaero_payroll]         widget on page 5787
     pay.rates  [jaxaero_rate_editor]     page 5795
     sales      [jaxaero_revenue_sales]   page 5788
     tax        [jaxaero_tax]             page 5789
     requests   [jaxaero_requests]        page 5816
     invoice    [jaxaero_instructor_pay]  only the bound slug renders
     access     the admin panel page
     lease      [jaxaero_leases]          lease management (VR Leasing) - canvas Accounting tab
     lessor     [jaxaero_lessor]          lessor portal - the VR Leasing login, read-only
     depr       [jaxaero_depreciation]    fixed-asset register - canvas Accounting tab
     depr_view  [jaxaero_depreciation]    the same register, read only (alt key)
     Sub-widget keys (rev.mom etc.) are phase 2 - they need guards
     inside snippets 5-9 and are deliberately not claimed here.

   SECURITY NOTES
     - Passwords are handled by WordPress core (wp_authenticate,
       wp_set_password). Nothing here stores or logs a password.
     - Login is rate limited: 5 failures per email+IP in 15 minutes.
       Unknown email, wrong password and disabled account all return
       the same generic message.
     - Admin REST routes require a logged-in dashboard admin
       (capability jaxauth_admin, or manage_options as break-glass)
       plus a standard REST nonce.
     - A dashboard admin can compose a WordPress administrator's canvas
       (grants, aircraft, home) but cannot reset, disable, rename or
       rebind that account - those take manage_options (SEC-1, Sep 4).
     - The site cannot send email (punch list K12), so there is no
       email reset flow. Admins set temporary passwords, shown once;
       the user is then required to choose a new one.

   OPTIONS
     jaxauth_pages        page_id => widget key (page gating map)
     jaxauth_signin_page  page id of the sign-in page
     jaxauth_admin_page   page id of the access admin page
     jaxauth_log          append-only audit trail, capped at 200
   USER META
     jaxauth_grants       array of widget keys
     jaxauth_instructor   instructor slug binding or ''
     jaxauth_disabled     '1' blocks sign-in and all gates
     jaxauth_must_change  '1' forces a password change after sign-in

   SRCDOC RULES (see CLAUDE.md - these have broken production before)
     WP Engine strips newlines from srcdoc. Inline JS below therefore
     has zero // comments, a semicolon on every statement, and no
     unescaped apostrophes inside single-quoted strings.
     Verify with: node scripts/check-srcdoc.mjs wp/jaxaero-access.php
   =================================================================== */

if (!defined('ABSPATH')) { exit; }

/* define(), NOT const - Code Snippets runs this through eval() inside a
   function, where const is a parse error (see snippet 10 lesson). */
if (!defined('JAXAUTH_ROLE'))      { define('JAXAUTH_ROLE', 'jaxaero_member'); }
if (!defined('JAXAUTH_CAP'))       { define('JAXAUTH_CAP', 'jaxauth_admin'); }
if (!defined('JAXAUTH_MAX_LOG'))   { define('JAXAUTH_MAX_LOG', 200); }
if (!defined('JAXAUTH_MIN_PW'))    { define('JAXAUTH_MIN_PW', 10); }
if (!defined('JAXAUTH_TRIES'))     { define('JAXAUTH_TRIES', 5); }
if (!defined('JAXAUTH_LOCK_SECS')) { define('JAXAUTH_LOCK_SECS', 900); }

/* -------------------- registry -------------------- */

function jaxauth_registry() {
  return [
    'auto'      => ['Revenue - AUTO', 'auto-refreshed dashboard'],
    'pay'       => ['Payroll Widget', 'the Pay Portal - instructors, contractors, salaried, MX'],
    'pay.rates' => ['Rate Editor', 'pay rates page'],
    'bonus'     => ['Bonus & Review Editor', 'add checkride passes + review mentions'],
    'sales'     => ['Sales', 'pipeline, enrollment tracking and commissions'],
    'marketing' => ['Marketing', 'Meta Ads + ad campaigns'],
    'safety'    => ['Safety', 'company-wide FOQA safety data'],
    /* Ben, Sep 6 2026: "Rebrand 'Timeclock' to 'My Hours'". The "(MX)" suffix keeps
       this grant distinct from the instructors' own My Hours in the Access admin
       list - theirs is the binding-driven 'myhours' canvas key, not a grant. Ben
       also asked to "Remove the Pay column entirely", so the blurb no longer
       promises pay here. */
    'mxtime'    => ['My Hours (MX)', 'mechanic clock in/out and hours by pay period'],
    /* Ryan, Sep 7 2026: "I want edit hours, especially for the MX department, to be a
       toggle that we can turn on for Bruce, the maintenance manager. Non-manager MX
       techs should not be able to do anything other than clock in and clock out."
       This is that toggle. It adds the Edit hours tab inside My Hours (MX); a tech
       without it sees the clock alone and asks a manager to fix a mistake. */
    'mxedit'    => ['Edit MX Hours', 'add or fix hours for every mechanic by pay period - the maintenance manager'],
    'tax'       => ['Sales Tax', 'aircraft sales tax page'],
    'lease'     => ['Leases', 'lease management - VR Leasing aircraft'],
    'depr'      => ['Depreciation', 'fixed assets - book and tax depreciation'],
    /* Sep 4 2026 review (SEC-3): the read-only tier the depreciation snippet's
       jaxdep_can_read already honours - an outside reader (Vargo) gets this,
       never 'depr', so nobody is handed event-writing rights to read. */
    'depr_view' => ['Depreciation (View Only)', 'fixed assets - read the register, schedule and documents'],
    'docs'      => ['Documents', 'archive & search'],
    'expense'   => ['Add Expenses', 'enter expenses on the owner P/L'],
    'ownerstmt' => ['Aircraft Owner Statements', 'staff view - every plane P/L'],
    'owner'     => ['My Aircraft', 'your aircraft statements (owners)'],
    'lessor'    => ['Lessor Portal', 'VR Leasing read-only statements'],
    'invoice'   => ['Own Pay Dashboard', 'only the bound person - instructor or 1099 contractor'],
    'access'    => ['Access Admin', 'this admin panel'],
    /* Ryan, Sep 3 2026: the IT status page (snippet 20) is deliberately NOT a grantable
       widget or canvas tab - only dashboard admins reach it, via the Access admin button. */
  ];
}

function jaxauth_shortcode_map() {
  return [
    'jaxaero_revenue_auto'   => 'auto',
    'jaxaero_payroll'        => 'pay',
    'jaxaero_rate_editor'    => 'pay.rates',
    'jaxaero_revenue_sales'  => 'sales',
    'jaxaero_sales_pipeline' => 'sales',
    'jaxaero_marketing'      => 'marketing',
    'jaxaero_safety'         => 'safety',
    'jaxaero_mx_time'        => 'mxtime',
    /* Ryan, Sep 7 2026: a mechanic's own pay page rides on the same My Hours toggle */
    'jaxaero_mx_pay'         => 'mxtime',
    /* Ryan, Sep 7 2026: the aircraft logbooks (snippet 23) live in the MX area on the same toggle */
    'jaxaero_mx_logbook'     => 'mxtime',
    /* Ryan, Sep 7 2026: the MX Overview (snippet 24, shipped as MX Briefing) - the maintenance
       team's Safety page */
    'jaxaero_mx_briefing'    => 'mxtime',
    'jaxaero_sales_marketing' => 'sm',
    'jaxaero_tax'            => 'tax',
    'jaxaero_requests'       => 'requests',
    'jaxaero_documents'      => 'docs',
    'jaxaero_instructor_pay' => 'invoice',
    /* Ben, Sep 2 (punch list 13B): My Hours and Log Detailing are the bound
       person's own data, so both ride the SAME invoice gate as the pay page (key
       attr must match the binding; pay holders and admins pass). Sep 3 review:
       Log Detailing was first drafted as its own 'logdetail' grant, which coupled
       the deploy - snippet 9 drops Sam's hour form from My Pay the moment it
       lands, and the tab only came back once someone flipped the new toggle. On
       the invoice gate it is live the day snippet 9 lands, nothing to toggle;
       snippet 9's own shortcode still limits it to tails-flagged manual-time
       people (Sam), so nobody else can reach it through this door. */
    'jaxaero_my_hours'       => 'invoice',
    'jaxaero_log_detailing'  => 'invoice',
    'jaxaero_owner_portal'   => 'owner',
    'jaxaero_aircraft_owner' => 'ownerstmt',
    /* Ryan, Sep 4 2026 (lease): the VR Leasing lease widget (staff) and the
       lessor's read-only statements. Both are ordinary grants. */
    'jaxaero_leases'         => 'lease',
    'jaxaero_lessor'         => 'lessor',
    /* Ryan, Sep 4 2026 (depreciation): the fixed-asset register, Accounting's
       fourth tab. An ordinary grant. */
    'jaxaero_depreciation'   => 'depr',
  ];
}

/* Sep 4 2026 review (SEC-3): tags that open on more than one grant. The map
   above names each tag's primary key (what the page map and the canvas use);
   the gate below renders the tag when the viewer holds ANY key listed here.
   The widgets' own read gates agree: jaxdep_can_read admits 'depr_view',
   jaxlease_can_read admits 'lease' holders (staff mode) as well as 'lessor'. */
function jaxauth_shortcode_alt_keys() {
  return [
    'jaxaero_depreciation' => ['depr', 'depr_view'],
    'jaxaero_lessor'       => ['lessor', 'lease'],
  ];
}

/* -------------------- helpers -------------------- */

function jaxauth_is_admin($user = null) {
  /* WP invokes REST permission_callbacks with the WP_REST_Request as the
     first argument - anything that is not a WP_User means "current user". */
  $user = ($user instanceof WP_User) ? $user : wp_get_current_user();
  if (!$user || !$user->exists()) { return false; }
  return user_can($user, JAXAUTH_CAP) || user_can($user, 'manage_options');
}

/* A "managed" user is one this system governs: a member, or anyone
   carrying a grants meta. Real WP admins are managed only if opted in. */
function jaxauth_is_managed($user = null) {
  $user = $user ? $user : wp_get_current_user();
  if (!$user || !$user->exists()) { return false; }
  if (in_array(JAXAUTH_ROLE, (array) $user->roles, true)) { return true; }
  return metadata_exists('user', $user->ID, 'jaxauth_grants');
}

function jaxauth_grants($uid = 0) {
  $uid = $uid ? $uid : get_current_user_id();
  if (!$uid) { return []; }
  $g = get_user_meta($uid, 'jaxauth_grants', true);
  if (!is_array($g)) { return []; }
  return array_values(array_intersect($g, array_keys(jaxauth_registry())));
}

function jaxauth_enabled($uid) {
  return get_user_meta($uid, 'jaxauth_disabled', true) !== '1';
}

/* Ryan, Aug 25: the page a bound CFI's own invoice lives on, or ['', 0].
   Requires the invoice grant (admins pass) plus an instructor binding whose
   page instructor-pay-<slug> exists. */
function jaxauth_invoice_page($user = null) {
  $user = ($user instanceof WP_User) ? $user : wp_get_current_user();
  if (!$user || !$user->exists()) { return ['', 0]; }
  if (!jaxauth_is_admin($user) && !jaxauth_enabled($user->ID)) { return ['', 0]; }
  if (!jaxauth_is_admin($user) && !in_array('invoice', jaxauth_grants($user->ID), true)) { return ['', 0]; }
  $bound = (string) get_user_meta($user->ID, 'jaxauth_instructor', true);
  if ($bound === '') { return ['', 0]; }
  /* Ryan, Aug 31: contractors' pages live at contractor-pay-<slug>; instructors
     keep instructor-pay-<slug>. Resolve contractor first, fall back. */
  $pg = get_page_by_path('contractor-pay-' . sanitize_title($bound));
  if (!$pg) { $pg = get_page_by_path('instructor-pay-' . sanitize_title($bound)); }
  if (!$pg || $pg->post_status !== 'publish') { return ['', 0]; }
  return [get_permalink($pg), (int) $pg->ID];
}

/* Ryan, Aug 25: all pages this user can open - mapped widgets they hold a
   grant for (access admin only for admins) plus their bound invoice page. */
function jaxauth_openable($user = null) {
  $user = ($user instanceof WP_User) ? $user : wp_get_current_user();
  if (!$user || !$user->exists()) { return []; }
  $reg = jaxauth_registry();
  $pages = get_option('jaxauth_pages', []);
  $out = [];
  if (is_array($pages)) {
    foreach ($pages as $pid => $key) {
      if ($key === '' || !isset($reg[$key])) { continue; }
      if ($key === 'access' && !jaxauth_is_admin($user)) { continue; }
      if (!jaxauth_can($key, $user->ID)) { continue; }
      if (get_post_status($pid) !== 'publish') { continue; }
      $l = get_permalink($pid);
      if ($l) { $out[] = ['k' => $key, 't' => $reg[$key][0], 'u' => $l]; }
    }
  }
  $ipd = jaxauth_invoice_page($user);
  if ($ipd[0] !== '') { $out[] = ['k' => 'invoice', 't' => 'My pay dashboard', 'u' => $ipd[0]]; }
  return $out;
}

function jaxauth_can($key, $uid = 0) {
  $uid = $uid ? $uid : get_current_user_id();
  if (!$uid) { return false; }
  $user = get_user_by('id', $uid);
  /* Sep 4 2026 review (SEC-1): a WordPress administrator passes every gate
     BEFORE the enabled check, so a stray jaxauth_disabled meta - which a
     dashboard admin could once write - can never lock Ryan out. */
  if ($user && user_can($user, 'manage_options')) { return true; }
  if (!jaxauth_enabled($uid)) { return false; }
  if (jaxauth_is_admin($user)) { return true; }
  return in_array($key, jaxauth_grants($uid), true);
}

/* Ryan, Aug 25: audit entries carry the acting user's IP. WP Engine's edge
   sets REMOTE_ADDR to the real client; X-Forwarded-For's first hop is the
   fallback. Server-side contexts (cron, CLI) log with no IP. */
function jaxauth_client_ip() {
  $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
  if ($ip === '' && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $parts = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']);
    $ip = trim($parts[0]);
  }
  return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

function jaxauth_log_add($txt) {
  $log = get_option('jaxauth_log', []);
  if (!is_array($log)) { $log = []; }
  $who = wp_get_current_user();
  array_unshift($log, [
    't'   => current_time('M j, g:i A'),
    'who' => ($who && $who->exists()) ? $who->display_name : 'system',
    'txt' => sanitize_text_field($txt),
    'ip'  => jaxauth_client_ip(),
  ]);
  if (count($log) > JAXAUTH_MAX_LOG) { $log = array_slice($log, 0, JAXAUTH_MAX_LOG); }
  update_option('jaxauth_log', $log, false);
}

/* -------------------- house design tokens --------------------

   docs/DESIGN-SYSTEM.md is the single source of truth for colour, type and
   radius. Every <style> this snippet prints opens with the token block below:
   the sign-in page, the settings page, the Access admin (all three inside
   srcdoc frames) and the User Canvas chrome, the hamburger pane and the
   view-as banner (all three straight onto an Elementor page).

   The six *-tint / *-line entries after --r-pill are the tinted alert surfaces
   this snippet genuinely needs - the error box, the "Saved." box and the
   temporary-password notice. They are lighter forms of --red / --green /
   --amber with no token of their own. Names and values match the rest of the
   fleet (jaxaero-instructor-pay.php and four other widgets declare the same
   six) and are now written into DESIGN-SYSTEM.md, so the same surface renders
   identically side by side. --scrim and --lift close the set: one backdrop and
   one drop shadow for every overlay. Nothing else may invent a colour. */
function jaxauth_tokens_css() {
  return ':root{--ink:#1F2F54;--ink-d:#16223f;--ink2:#5b6577;--ink3:#8A93A5;--brand:#C10F1B;--gold:#C0A788;--ground:#F4F6F9;--panel:#FFFFFF;--hair:#e6e9ef;--hair2:#d9dee7;--track:#eef1f5;--tint:#F7F9FC;--green:#1e6b3a;--amber:#8a5a12;--red:#b23b3b;--shadow:0 1px 3px rgba(20,35,70,.05);--r-sm:8px;--r-md:10px;--r-lg:14px;--r-pill:999px;'
    . '--red-tint:#FCEBEA;--red-line:#E3A6A4;--green-tint:#EAF5EE;--green-line:#BFE0C9;--amber-tint:#FBF3E1;--amber-line:#E7D3A6;'
    . '--scrim:rgba(31,47,84,.55);--lift:0 12px 40px rgba(20,35,70,.25)}';
}

/* The one font stack. Every rule in this snippet takes it from here, so there
   is exactly one place to change it. The single deliberate exception is the
   temporary-password field in the Access admin, which stays monospace so a
   random string can be read character by character. */
function jaxauth_font_stack() {
  return '"Segoe UI",Roboto,-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif';
}

/* -------------------- role -------------------- */

add_action('init', function () {
  if (!get_role(JAXAUTH_ROLE)) {
    add_role(JAXAUTH_ROLE, 'JAXAERO Member', ['read' => true]);
  }
});

/* Members never see the admin bar or wp-admin. */
add_action('after_setup_theme', function () {
  $u = wp_get_current_user();
  if ($u && $u->exists() && jaxauth_is_managed($u) && !jaxauth_is_admin($u) && !user_can($u, 'edit_posts')) {
    show_admin_bar(false);
  }
});
/* Nobody - admins included - gets the admin toolbar ON dashboard pages; it
   stacked on top of the widgets on mobile and desktop. A dashboard page is any
   page whose content carries one of our [jax...] shortcodes. Everywhere else
   admins keep the bar. */
add_action('wp', function () {
  if (is_admin() || !is_singular()) { return; }
  $p = get_post();
  if ($p && strpos((string) $p->post_content, '[jax') !== false) {
    show_admin_bar(false);
  }
});

/* Ryan, Aug 25: after sign-in, staff land on the Revenue AUTO dashboard and
 * owner-only accounts land on their My Aircraft page. Users who can open
 * neither (or who must change their password first) get the portal home. */
function jaxauth_default_dest($user = null) {
  $user = ($user instanceof WP_User) ? $user : wp_get_current_user();
  $homeP = get_option('jaxauth_signin_page');
  $home  = $homeP ? get_permalink($homeP) : home_url('/');
  if (!$user || !$user->exists()) { return $home; }
  /* disabled mid-session: every grant check fails, so the only honest
     destination is the portal home - never a page that will deny them */
  if (!jaxauth_is_admin($user) && !jaxauth_enabled($user->ID)) { return $home; }
  $pages = get_option('jaxauth_pages', []);
  $find = function ($key) use ($pages) {
    if (is_array($pages)) { foreach ($pages as $pid => $k) { if ($k === $key && get_post_status($pid) === 'publish') { $l = get_permalink($pid); if ($l) { return $l; } } } }
    return '';
  };
  $grants = jaxauth_grants($user->ID);
  /* Ben, Aug 31 (punch list 12 follow-up): every user lands on their primary
     work area - their Canvas - never a widget selector. An explicit per-user
     canvas page wins outright; widgets are turned on and off ON that page. */
  $canvasP = (int) get_user_meta($user->ID, 'jaxauth_canvas', true);
  if ($canvasP && get_post_status($canvasP) === 'publish') {
    $cl = get_permalink($canvasP);
    if ($cl) { return $cl; }
  }
  /* Ryan, Aug 31: managed users land on THE User Canvas, which composes their
     widgets from the Access Admin toggles - so a toggle works the moment it is
     flipped. WP admins keep the legacy staff routing below. */
  /* Ryan, Sep 4 2026: WordPress administrators used to skip the canvas entirely,
     which is why Ryan's home looked nothing like Ben's. Anyone whose toggles
     compose at least one widget lands on the canvas; an admin with no toggles
     still falls through to the legacy staff routing below. */
  $sharedC = (int) get_option('jaxauth_canvas_page');
  if ($sharedC && get_post_status($sharedC) === 'publish' && count(jaxauth_canvas_widgets($user)) > 0) {
    $scl = get_permalink($sharedC);
    if ($scl) { return $scl; }
  }
  /* Ryan, Aug 25: a starred home screen wins while they can still open it */
  $pref = (string) get_user_meta($user->ID, 'jaxauth_home', true);
  if ($pref === 'access' && !jaxauth_is_admin($user)) { $pref = ''; }
  if ($pref === 'invoice') {
    $ipd = jaxauth_invoice_page($user);
    if ($ipd[0] !== '') { return $ipd[0]; }
    $pref = '';
  }
  if ($pref !== '' && (jaxauth_is_admin($user) || in_array($pref, $grants, true))) {
    $d = $find($pref);
    if ($d !== '') { return $d; }
  }
  /* Ben, Aug 31: a bound instructor or contractor's canvas IS their own page */
  $bp = jaxauth_invoice_page($user);
  if ($bp[0] !== '' && !jaxauth_is_admin($user) && count(array_diff($grants, ['invoice', 'owner'])) === 0) {
    return $bp[0];
  }
  $isStaff = jaxauth_is_admin($user) || count(array_diff($grants, ['owner'])) > 0;
  if ($isStaff && (jaxauth_is_admin($user) || in_array('auto', $grants, true))) {
    $d = $find('auto'); if ($d !== '') { return $d; }
  }
  if (!$isStaff && in_array('owner', $grants, true)) {
    $d = $find('owner'); if ($d !== '') { return $d; }
  }
  /* Ryan, Aug 25: anyone whose account opens exactly one widget lands on it */
  $open = jaxauth_openable($user);
  if (count($open) === 1) { return $open[0]['u']; }
  return $home;
}

add_filter('login_redirect', function ($to, $requested, $user) {
  if ($user instanceof WP_User && jaxauth_is_managed($user) && !user_can($user, 'edit_posts')) {
    if (get_user_meta($user->ID, 'jaxauth_must_change', true) === '1') {
      $p = get_option('jaxauth_signin_page');
      return $p ? get_permalink($p) : home_url('/');
    }
    return jaxauth_default_dest($user);
  }
  return $to;
}, 10, 3);

add_action('admin_init', function () {
  $u = wp_get_current_user();
  if ($u && $u->exists() && jaxauth_is_managed($u) && !jaxauth_is_admin($u) && !user_can($u, 'edit_posts') && !wp_doing_ajax()) {
    $p = get_option('jaxauth_signin_page');
    wp_safe_redirect($p ? get_permalink($p) : home_url('/'));
    exit;
  }
});

/* -------------------- gating -------------------- */

/* Ben, punch list 12: "user access locked down to Kim, me, Ryan, and John, no
   one else - Do that now."

   These keys do NOT fall through to the page password. Every other gated widget
   does, on purpose: the Elementor password is the outer door and the 16
   instructor pages are reached that way by design. But page 5787 carries the
   payroll widget alongside the Revenue AUTO dashboard behind ONE shared
   password, so every holder of that password was already inside payroll - and
   window.PAY carries each instructor's rate, net pay and home address.

   So for these two: no account, no payroll. The password stays exactly as it is,
   which is what keeps the Revenue AUTO audience on 5787 undisturbed. Keep this
   list to the money keys - a blanket rule would deny anonymous visitors on every
   mapped shortcode and lock all 16 instructors out of their own pages. */
function jaxauth_login_only_keys() {
  return array('pay', 'pay.rates');
}

/* Widget gate: a signed-in managed user only renders shortcodes they
   hold the key for. Anonymous visitors fall through to page passwords,
   EXCEPT for jaxauth_login_only_keys() - see above. */
add_filter('pre_do_shortcode_tag', function ($ret, $tag, $attr) {
  $map = jaxauth_shortcode_map();
  if (!isset($map[$tag])) { return $ret; }
  $key = $map[$tag];
  $u = wp_get_current_user();
  $signedIn = ($u && $u->exists());
  if (in_array($key, jaxauth_login_only_keys(), true)) {
    /* admins are not "managed" - they carry no grants meta - so they are
       answered here before the managed check below would drop them */
    if ($signedIn && jaxauth_is_admin($u)) { return $ret; }
    if (!$signedIn) { return jaxauth_denied_html('signin'); }
    if (!jaxauth_is_managed($u) || !jaxauth_can($key, $u->ID)) { return jaxauth_denied_html(); }
    return $ret;
  }
  if (!$signedIn || !jaxauth_is_managed($u)) { return $ret; }
  if ($key === 'invoice') {
    if (jaxauth_is_admin($u)) { return $ret; }
    /* holders of the payroll grant already see every instructor's pay in the
       payroll widget - IP View shows them strictly less than that */
    if (jaxauth_can('pay', $u->ID)) { return $ret; }
    $slug = isset($attr['key']) ? $attr['key'] : '';
    $bound = get_user_meta($u->ID, 'jaxauth_instructor', true);
    if (!jaxauth_can('invoice', $u->ID) || $bound === '' || $slug !== $bound) {
      return jaxauth_denied_html();
    }
    return $ret;
  }
  $altKeys = jaxauth_shortcode_alt_keys();
  $anyKey = isset($altKeys[$tag]) ? $altKeys[$tag] : array($key);
  $holds = false;
  foreach ($anyKey as $ak) { if (jaxauth_can($ak, $u->ID)) { $holds = true; break; } }
  if (!$holds) { return jaxauth_denied_html(); }
  return $ret;
}, 10, 3);

function jaxauth_denied_html($mode = 'grant') {
  $p = get_option('jaxauth_signin_page');
  $home = $p ? esc_url(get_permalink($p)) : esc_url(home_url('/'));
  /* "not enabled for your account" reads wrong at someone who has no account -
     they arrived on a page password, so tell them the actual next step */
  $head = ($mode === 'signin')
    ? 'Please sign in to see this.'
    : 'This widget is not enabled for your account.';
  $sub = ($mode === 'signin')
    ? 'Payroll needs a JAXAERO account. The page password does not open it.'
    : 'If you think it should be, ask Ryan.';
  $link = ($mode === 'signin') ? 'Sign in' : 'Back to your dashboard';
  /* House empty/error state (DESIGN-SYSTEM.md): the page header - brand mark,
     navy title, grey sub, 3px gold rule - then ONE .mod card carrying the
     sentence and the way out. Never a bare <em> or a naked <b>. The brand mark
     is suppressed inside the User Canvas, which has already printed one.
     This renders straight onto an Elementor page, so every declaration the
     .elementor-kit-35 kit could repaint is pinned with !important. */
  $css = '<style>' . jaxauth_tokens_css()
    . '.jaxden{max-width:520px;margin:40px auto;padding:0 16px !important;font-family:' . jaxauth_font_stack() . ' !important;color:var(--ink) !important}'
    . '.jaxden .jaxden-hd{border-bottom:3px solid var(--gold) !important;padding-bottom:9px;margin-bottom:14px}'
    . '.jaxden .jaxden-brand{font-weight:800 !important;letter-spacing:.14em !important;font-size:13px !important;color:var(--brand) !important;text-transform:uppercase !important;line-height:1.2 !important}'
    . '.jaxden .jaxden-t{margin:6px 0 4px !important;font-size:26px !important;font-weight:800 !important;letter-spacing:-.01em !important;color:var(--ink) !important;line-height:1.25 !important}'
    . '.jaxden .jaxden-sub{color:var(--ink2) !important;font-size:13.5px !important;line-height:1.5 !important;margin-top:6px !important}'
    . '.jaxden .jaxden-mod{background:var(--panel) !important;border:1px solid var(--hair) !important;border-radius:var(--r-lg) !important;padding:22px !important;box-shadow:var(--shadow) !important;color:var(--ink2) !important;font-size:13.5px !important;line-height:1.5 !important}'
    . '.jaxden .jaxden-a{display:inline-block !important;margin-top:14px !important;padding:9px 16px !important;border-radius:var(--r-sm) !important;background:var(--ink) !important;border:1px solid var(--ink) !important;color:#fff !important;font-weight:700 !important;font-size:13.5px !important;text-decoration:none !important;letter-spacing:0 !important;text-transform:none !important}'
    . '.jaxden .jaxden-a:hover{background:var(--ink-d) !important;border-color:var(--ink-d) !important;color:#fff !important}'
    . '</style>';
  return $css
    . '<div class="jaxden"><div class="jaxden-hd">'
    . (empty($GLOBALS['jaxauth_canvas_render']) ? '<div class="jaxden-brand">JAXAERO</div>' : '')
    . '<div class="jaxden-t">' . esc_html($head) . '</div>'
    . '<div class="jaxden-sub">JAXAERO portal &middot; widget access is set per person.</div>'
    . '</div>'
    . '<div class="jaxden-mod">' . esc_html($sub)
    . '<br><a class="jaxden-a" href="' . $home . '">' . esc_html($link) . '</a></div></div>';
}

/* Password bypass: a signed-in user who holds the page key does not
   need the page password. Everyone else sees the form as before. */
/* Ryan, Aug 31: contractor pages moved from instructor-pay-<slug> to
   contractor-pay-<slug>; WP's old-slug redirect does not cover these page
   renames, so 301 the old paths ourselves. Driven by jaxpay_contractors, so a
   future contractor's rename needs no code change. */
add_action('template_redirect', function () {
  if (!is_404()) { return; }
  $path = trim((string) wp_parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH), '/');
  if (strpos($path, 'instructor-pay-') !== 0) { return; }
  $slug = substr($path, strlen('instructor-pay-'));
  $ct = get_option('jaxpay_contractors', array());
  if (!is_array($ct) || !in_array($slug, $ct, true)) { return; }
  $pg = get_page_by_path('contractor-pay-' . $slug);
  if ($pg && $pg->post_status === 'publish') { wp_safe_redirect(get_permalink($pg), 301); exit; }
});

add_filter('post_password_required', function ($required, $post) {
  if (!$required || !$post) { return $required; }
  $u = wp_get_current_user();
  /* bound people open their OWN pay page (instructor-pay-* or contractor-pay-*);
     admins and pay-holders any of them */
  $jxPayPage = (strpos($post->post_name, 'instructor-pay-') === 0 && $post->post_name !== 'instructor-pay-rates')
            || strpos($post->post_name, 'contractor-pay-') === 0;
  if ($u && $u->exists() && $jxPayPage) {
    if (jaxauth_is_admin($u)) { return false; }
    if (jaxauth_is_managed($u) && jaxauth_enabled($u->ID) && jaxauth_can('pay', $u->ID)) { return false; }
    if (jaxauth_is_managed($u) && jaxauth_enabled($u->ID) && in_array('invoice', jaxauth_grants($u->ID), true)) {
      $jxB = sanitize_title((string) get_user_meta($u->ID, 'jaxauth_instructor', true));
      if ($jxB !== '' && in_array($post->post_name, array('instructor-pay-' . $jxB, 'contractor-pay-' . $jxB), true)) {
        return false;
      }
    }
  }
  /* dashboard admins skip the page password on every MAPPED page - some mapped
     pages (the punch list) carry a random password nobody knows, portal-only */
  if ($u && $u->exists() && jaxauth_is_admin($u)) {
    $adminPages = get_option('jaxauth_pages', []);
    if (is_array($adminPages) && isset($adminPages[$post->ID])) { return false; }
    return $required;
  }
  if (!$u || !$u->exists() || !jaxauth_is_managed($u)) { return $required; }
  $pages = get_option('jaxauth_pages', []);
  if (!is_array($pages) || !isset($pages[$post->ID])) { return $required; }
  $key = $pages[$post->ID];
  if ($key === '' || jaxauth_can($key, $u->ID)) { return false; }
  return $required;
}, 10, 2);

/* Ryan, Sep 8 2026: the page-password form WordPress prints for a protected page (the canvas
   and the mapped pages carry one) gets the same show-password eye as the sign-in and settings
   frames. The form is inline, so the wrapper stays inline there. */
add_filter('the_password_form', function ($form) {
  if (strpos($form, 'jaxauth-pweye') !== false) { return $form; }
  return '<style>' . jaxauth_tokens_css() . jaxauth_pw_eye_css() . '.post-password-form .pwf{display:inline-block;vertical-align:middle}.post-password-form .pwf input{padding-right:40px}</style>'
       . $form . '<script id="jaxauth-pweye">' . jaxauth_pw_eye_js() . '</script>';
}, 20);

/* Ryan, Sep 8 2026: "set the temp password expiration for three days instead of 24 hours" - the
   set-password / reset links WordPress mints (the go-live emails, Reset it by email) were good
   for one day and most instructors opened theirs too late. Three days now. */
add_filter('password_reset_expiration', function () { return 3 * DAY_IN_SECONDS; });

/* Admin page + no-cache for signed-in views of gated pages. */
add_action('template_redirect', function () {
  if (!is_page()) { return; }
  $pid = get_queried_object_id();
  $adminPage = (int) get_option('jaxauth_admin_page');
  if ($adminPage && $pid === $adminPage && !jaxauth_is_admin()) {
    /* this 302 depends on WHO is asking, so it must never be stored: without
       this the "not an admin, go to signin" answer was cacheable for 600s and
       got replayed to an admin, bouncing them to their home screen */
    nocache_headers();
    $p = get_option('jaxauth_signin_page');
    wp_safe_redirect($p ? get_permalink($p) : home_url('/'));
    exit;
  }
  /* Ryan, Aug 25: the signin/home page acts as a router for signed-in users -
     staff go to Revenue AUTO, owner-only accounts to My Aircraft. The cards
     screen still renders for ?chpw=1 (password form) and forced changes.
     Loop guard: never redirect when the destination IS this page. */
  $signinP = (int) get_option('jaxauth_signin_page');
  if ($signinP && $pid === $signinP && is_user_logged_in() && !isset($_GET['chpw']) && !isset($_GET['settings'])) {
    $ru = wp_get_current_user();
    /* Ryan, Sep 4 2026: a View-as preview cannot change the target's password,
       so the temporary-password hold does not apply there - the preview goes on
       to the person's real landing (Sam Davis -> Log Detailing). */
    $ruPreview = !empty($GLOBALS['jaxauth_viewas_target']);
    if (($ru && $ru->exists() && (jaxauth_is_managed($ru) || jaxauth_is_admin($ru)))
        && ($ruPreview || get_user_meta($ru->ID, 'jaxauth_must_change', true) !== '1')) {
      $rdest = jaxauth_default_dest($ru);
      if ($rdest !== '' && untrailingslashit($rdest) !== untrailingslashit(get_permalink($signinP))) {
        nocache_headers();
        wp_safe_redirect($rdest);
        exit;
      }
    }
  }
  $pages = get_option('jaxauth_pages', []);
  if (is_user_logged_in() && is_array($pages) && isset($pages[$pid])) {
    nocache_headers();
  }
});

/* -------------------- rate limiting -------------------- */

function jaxauth_rl_key($email) {
  $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
  return 'jaxauth_rl_' . md5(strtolower($email) . '|' . $ip);
}
function jaxauth_rl_hit($email) {
  $k = jaxauth_rl_key($email);
  $n = (int) get_transient($k);
  set_transient($k, $n + 1, JAXAUTH_LOCK_SECS);
  return $n + 1;
}
function jaxauth_rl_blocked($email) {
  return (int) get_transient(jaxauth_rl_key($email)) >= JAXAUTH_TRIES;
}

/* -------------------- REST -------------------- */

add_action('rest_api_init', function () {
  register_rest_route('jaxauth/v1', '/login', [
    'methods' => 'POST', 'permission_callback' => '__return_true',
    'callback' => 'jaxauth_rest_login',
  ]);
  register_rest_route('jaxauth/v1', '/logout', [
    'methods' => 'POST',
    'permission_callback' => function () { return is_user_logged_in(); },
    'callback' => function () { wp_logout(); return ['ok' => true]; },
  ]);
  register_rest_route('jaxauth/v1', '/change-password', [
    'methods' => 'POST',
    /* a disabled account must not be able to set a fresh password and collect
       a new 14-day cookie on the way out */
    'permission_callback' => function () { return is_user_logged_in() && jaxauth_enabled(get_current_user_id()); },
    'callback' => 'jaxauth_rest_change_pw',
  ]);
  register_rest_route('jaxauth/v1', '/admin/save-user', [
    'methods' => 'POST',
    'permission_callback' => 'jaxauth_is_admin',
    'callback' => 'jaxauth_rest_save_user',
  ]);
  register_rest_route('jaxauth/v1', '/admin/create-user', [
    'methods' => 'POST',
    'permission_callback' => 'jaxauth_is_admin',
    'callback' => 'jaxauth_rest_create_user',
  ]);
  register_rest_route('jaxauth/v1', '/me/home', [
    'methods' => 'POST',
    'permission_callback' => function () {
      $u = wp_get_current_user();
      if (!$u || !$u->exists() || !jaxauth_enabled($u->ID)) { return false; }
      return jaxauth_is_managed($u) || jaxauth_is_admin($u);
    },
    'callback' => 'jaxauth_rest_me_home',
  ]);
  register_rest_route('jaxauth/v1', '/help', [
    'methods' => 'POST',
    'permission_callback' => function () {
      $u = wp_get_current_user();
      if (!$u || !$u->exists() || !jaxauth_enabled($u->ID)) { return false; }
      return jaxauth_is_managed($u) || jaxauth_is_admin($u);
    },
    'callback' => 'jaxauth_rest_help',
  ]);
  register_rest_route('jaxauth/v1', '/admin/viewas', [
    'methods' => 'POST',
    /* Ben, punch list 13: every Pay Portal holder may preview - admins plus
       the pay grant (Kim, John). The handler narrows what non-admins may
       target; jaxauth_viewas_boot applies the same rule at swap time. */
    'permission_callback' => function () {
      $u = wp_get_current_user();
      if (!$u || !$u->exists()) { return false; }
      if (jaxauth_is_admin($u)) { return true; }
      return jaxauth_is_managed($u) && jaxauth_enabled($u->ID) && jaxauth_can('pay', $u->ID);
    },
    'callback' => 'jaxauth_rest_viewas',
  ]);
  register_rest_route('jaxauth/v1', '/admin/reset-password', [
    'methods' => 'POST',
    'permission_callback' => 'jaxauth_is_admin',
    'callback' => 'jaxauth_rest_reset_pw',
  ]);
  register_rest_route('jaxauth/v1', '/admin/delete-user', [
    'methods' => 'POST',
    'permission_callback' => 'jaxauth_is_admin',
    'callback' => 'jaxauth_rest_delete_user',
  ]);
  register_rest_route('jaxauth/v1', '/admin/ai-key', [
    'methods' => 'POST',
    'permission_callback' => 'jaxauth_is_admin',
    'callback' => 'jaxauth_rest_ai_key',
  ]);
});

function jaxauth_generic_fail() {
  return new WP_Error('jaxauth_fail',
    'That email and password combination did not work.', ['status' => 403]);
}

function jaxauth_rest_login(WP_REST_Request $req) {
  $rawId = trim((string) $req->get_param('email'));
  $email = sanitize_email($rawId);
  /* Ryan, Sep 4 2026 (lease): the VR Leasing lessor account has no email and
     signs in with its plain sign-in name (vr-leasing). Input that is not
     email-shaped is handed to wp_authenticate as a login name ONLY when it
     names an account that has no email; every account that has one keeps
     failing here exactly as before, so this open route never becomes a
     username door for WP administrator logins. Email sign-in is unchanged;
     the rate limit keys on whatever was typed, as before. */
  if ($email === '' && $rawId !== '') {
    $lu = get_user_by('login', sanitize_user($rawId, true));
    if ($lu && (string) $lu->user_email === '') { $email = $lu->user_login; }
  }
  $pw    = (string) $req->get_param('password');
  if ($email === '' || $pw === '') { return jaxauth_generic_fail(); }
  if (jaxauth_rl_blocked($email)) {
    return new WP_Error('jaxauth_locked',
      'Too many attempts. Wait 15 minutes and try again.', ['status' => 429]);
  }
  $user = wp_authenticate($email, $pw);
  if (is_wp_error($user) || !jaxauth_enabled($user->ID)) {
    jaxauth_rl_hit($email);
    return jaxauth_generic_fail();
  }
  wp_set_auth_cookie($user->ID, true);
  jaxauth_log_add($user->display_name . ' signed in.');
  $mustNow = get_user_meta($user->ID, 'jaxauth_must_change', true) === '1';
  $dest = $mustNow ? '' : jaxauth_default_dest($user);
  return [
    'ok' => true,
    'mustChange' => $mustNow,
    'dest' => $dest,
  ];
}

function jaxauth_rest_change_pw(WP_REST_Request $req) {
  $u = wp_get_current_user();
  $cur = (string) $req->get_param('current');
  $new = (string) $req->get_param('new_password');
  if (!wp_check_password($cur, $u->user_pass, $u->ID)) {
    return new WP_Error('jaxauth_badcur', 'Your current password is not right.', ['status' => 403]);
  }
  if (strlen($new) < JAXAUTH_MIN_PW) {
    return new WP_Error('jaxauth_short',
      'The new password must be at least ' . JAXAUTH_MIN_PW . ' characters.', ['status' => 400]);
  }
  wp_set_password($new, $u->ID);
  delete_user_meta($u->ID, 'jaxauth_must_change');
  wp_set_auth_cookie($u->ID, true);
  jaxauth_log_add($u->display_name . ' changed their password.');
  return ['ok' => true, 'dest' => jaxauth_default_dest($u)];
}

function jaxauth_rest_save_user(WP_REST_Request $req) {
  $uid = (int) $req->get_param('user_id');
  $user = get_user_by('id', $uid);
  /* Ryan, Sep 4 2026: "mine and Ben Gabriel's views and access should be identical".
     A WordPress administrator carries no jaxauth_grants meta and no member role, so
     the Access admin could not manage him and his canvas composed to nothing. Staff
     admins are editable here; delete-user and reset-password keep the old guard. */
  if (!$user || (!jaxauth_is_managed($user) && !user_can($user->ID, 'manage_options'))) {
    return new WP_Error('jaxauth_nouser', 'No such managed user.', ['status' => 404]);
  }
  $me = get_current_user_id();
  $newName = sanitize_text_field((string) $req->get_param('name'));
  $grants = $req->get_param('grants');
  $grants = is_array($grants)
    ? array_values(array_intersect(array_map('sanitize_text_field', $grants), array_keys(jaxauth_registry())))
    : [];
  $inst = sanitize_title((string) $req->get_param('instructor'));
  $disabled = $req->get_param('disabled') ? '1' : '';
  if ($uid === $me && $disabled === '1') {
    return new WP_Error('jaxauth_self', 'You cannot disable your own account.', ['status' => 400]);
  }
  /* Sep 4 2026 review (SEC-1): a dashboard admin (Ben) may compose a WordPress
     administrator's canvas - the widget toggles, the aircraft list that only
     derives 'owner', and the home star - and nothing else. Disabling (which
     also destroys every session), renaming and rebinding Ryan's account take
     manage_options. Sits above every write so a refused save changes nothing. */
  if (user_can($user, 'manage_options') && !current_user_can('manage_options')) {
    if ($disabled === '1') {
      return new WP_Error('jaxauth_wpadmin', 'Only a WordPress administrator can disable another administrator.', ['status' => 403]);
    }
    if ($newName !== '' && $newName !== $user->display_name) {
      return new WP_Error('jaxauth_wpadmin', 'Only a WordPress administrator can rename another administrator.', ['status' => 403]);
    }
    if ($inst !== sanitize_title((string) get_user_meta($uid, 'jaxauth_instructor', true))) {
      return new WP_Error('jaxauth_wpadmin', 'Only a WordPress administrator can change the pay page binding of another administrator.', ['status' => 403]);
    }
  }
  /* Ryan, Sep 3 2026: "add a toggle switch to turn on admin access for people".
     Dashboard admin = the jaxauth_admin capability (Access admin, view-as, every
     gated page). Only a real WordPress administrator may grant or revoke it; a
     dashboard admin cannot mint other admins, nobody can demote themselves, and
     WordPress administrators are left alone (they are admin regardless). Sits
     above every write so a rejected save changes nothing at all. */
  $admParam = $req->get_param('admin');
  $wantAdmin = ($admParam === true || $admParam === 'true' || $admParam === 1 || $admParam === '1');
  /* a WordPress administrator already IS an admin (jaxauth_is_admin), so the
     UI's locked-on toggle for such a row is not a change and never trips the
     guard below; asking to turn it OFF still lands on the refusals. */
  $hasAdmin = user_can($user, JAXAUTH_CAP) || user_can($user, 'manage_options');
  $admChanged = false;
  if ($admParam !== null && $wantAdmin !== $hasAdmin) {
    if (!current_user_can('manage_options')) {
      return new WP_Error('jaxauth_admonly', 'Only a WordPress administrator can change admin access.', ['status' => 403]);
    }
    if ($uid === $me && !$wantAdmin) {
      return new WP_Error('jaxauth_self', 'You cannot remove your own admin access.', ['status' => 400]);
    }
    if (user_can($user, 'manage_options')) {
      return new WP_Error('jaxauth_wpadmin', 'That account is already a WordPress administrator.', ['status' => 400]);
    }
    $admChanged = true;
  }
  /* Ryan, Aug 25: admins can fix name spelling after creation. Sits below the
     guard so a rejected save writes nothing at all. */
  if ($newName !== '' && $newName !== $user->display_name) {
    $oldName = $user->display_name;
    $upd = wp_update_user(['ID' => $uid, 'display_name' => $newName]);
    if (!is_wp_error($upd)) {
      jaxauth_log_add('renamed "' . $oldName . '" to "' . $newName . '".');
      $user->display_name = $newName;
    }
  }
  /* per-owner aircraft assignment drives the read-only owner widget and the
     'owner' card: any assigned tail grants 'owner', none removes it */
  $acd = get_option('jaxac_data_last', array());
  $validTails = (is_array($acd) && !empty($acd['fleet']) && is_array($acd['fleet']))
    ? array_keys($acd['fleet']) : array('N768SP', 'N146F', 'N1196M', 'N234ZG', 'N9711S');
  $ac = $req->get_param('aircraft');
  $ac = is_array($ac) ? array_values(array_intersect(array_map('sanitize_text_field', $ac), $validTails)) : array();
  update_user_meta($uid, 'jaxown_aircraft', $ac);
  $grants = array_values(array_diff($grants, array('owner')));
  if ($ac) { $grants[] = 'owner'; }
  $old = jaxauth_grants($uid);
  update_user_meta($uid, 'jaxauth_grants', $grants);
  /* Sep 4 2026 review (SEC-7): the binding is written BEFORE the home check
     below, which reads it through jaxauth_canvas_widgets - so binding a person
     and starring their pay tab in the same save keeps the star. */
  update_user_meta($uid, 'jaxauth_instructor', $inst);
  /* starred home screen - only a granted widget that has a page qualifies */
  $homeSel = sanitize_text_field((string) $req->get_param('home'));
  $homePageKeys = array_values(array_diff(array_intersect(array_values((array) get_option('jaxauth_pages', [])), array_keys(jaxauth_registry())), ['access']));
  /* Ryan, Sep 4 2026: a canvas tab key (Sam's binding-driven 'logdetail') is
     also a valid home - the canvas opens on that tab. Grants and the binding
     were both saved above, so a binding-driven key resolves on the same save. */
  $homeCanvasKeys = array_map(function ($x) { return $x['key']; }, jaxauth_canvas_widgets($user));
  if ($homeSel !== '' && !in_array($homeSel, $homeCanvasKeys, true) && (!in_array($homeSel, $grants, true) || !in_array($homeSel, $homePageKeys, true))) { $homeSel = ''; }
  $oldHome = (string) get_user_meta($uid, 'jaxauth_home', true);
  /* the admin screen has no star for a canvas-tab home, so its empty 'home' is
     not a clear - keep the stored tab. Send home=none to clear one on purpose. */
  if ($homeSel === '' && $oldHome !== '' && (string) $req->get_param('home') !== 'none'
      && in_array($oldHome, $homeCanvasKeys, true) && !in_array($oldHome, $homePageKeys, true)) { $homeSel = $oldHome; }
  if ($homeSel !== $oldHome) {
    if ($homeSel === '') { delete_user_meta($uid, 'jaxauth_home'); }
    else { update_user_meta($uid, 'jaxauth_home', $homeSel); }
    jaxauth_log_add($homeSel === ''
      ? 'cleared the home screen for "' . $user->display_name . '".'
      : 'set "' . $user->display_name . '" home screen to ' . $homeSel . '.');
  }
  if ($disabled === '1') {
    update_user_meta($uid, 'jaxauth_disabled', '1');
    /* the meta alone only blocks future gate checks - an already-signed-in
       browser kept working. End every session so "Disabled" takes effect now. */
    $st = WP_Session_Tokens::get_instance($uid);
    if ($st) { $st->destroy_all(); }
  }
  else { delete_user_meta($uid, 'jaxauth_disabled'); }
  if ($admChanged) {
    if ($wantAdmin) { $user->add_cap(JAXAUTH_CAP); } else { $user->remove_cap(JAXAUTH_CAP); }
    jaxauth_log_add(($wantAdmin ? 'GRANTED dashboard admin to "' : 'REVOKED dashboard admin from "') . $user->display_name . '".');
  }
  $added = implode(', ', array_diff($grants, $old));
  $removed = implode(', ', array_diff($old, $grants));
  jaxauth_log_add('saved ' . $user->display_name
    . '. Gave: ' . ($added !== '' ? $added : 'none')
    . '. Removed: ' . ($removed !== '' ? $removed : 'none')
    . ($disabled === '1' ? '. Account disabled.' : '.')
    . ' Aircraft: ' . ($ac ? implode('/', $ac) : 'none') . '.');
  return ['ok' => true];
}

function jaxauth_rest_ai_key(WP_REST_Request $req) {
  $key = trim((string) $req->get_param('key'));
  if ($key === '' || !preg_match('/^sk-ant-[A-Za-z0-9_\-]{20,}$/', $key)) {
    return new WP_Error('jaxauth_badkey',
      'That does not look like an Anthropic API key (they start with sk-ant-).', ['status' => 400]);
  }
  update_option('jaxaero_anthropic_key', $key, false);
  update_option('jaxaero_anthropic_key_at', wp_date('M j, g:i A'), false);
  jaxauth_log_add('Anthropic API key updated (ends ' . substr($key, -4) . ').');
  return ['ok' => true, 'ends' => substr($key, -4)];
}

function jaxauth_rest_create_user(WP_REST_Request $req) {
  $name  = sanitize_text_field((string) $req->get_param('name'));
  $email = sanitize_email((string) $req->get_param('email'));
  /* Ryan, Sep 4 2026 (lease): optional starting grants (registry keys only,
     default none - the Access admin UI sends none and is unchanged). The VR
     Leasing lessor login has NO email, Ryan's call: an empty email is accepted
     ONLY when the requested grants are exactly ['lessor']; the sign-in name is
     then the 'login' param (else the name slugged, "VR Leasing" -> vr-leasing)
     and the audit line says so. Every other account still needs a valid email. */
  $grants = $req->get_param('grants');
  $grants = is_array($grants)
    ? array_values(array_unique(array_intersect(array_map('sanitize_text_field', $grants), array_keys(jaxauth_registry()))))
    : [];
  /* 'owner' is derived from aircraft bindings and 'access' is the admin
     capability - save-user manages both by other means, so neither can be
     seeded here. */
  $grants = array_values(array_diff($grants, ['owner', 'access']));
  $lessorOnly = (count($grants) === 1 && $grants[0] === 'lessor');
  if ($name === '' || ($email === '' && !$lessorOnly) || ($email !== '' && !is_email($email))) {
    return new WP_Error('jaxauth_bad', 'A name and a valid email are required.', ['status' => 400]);
  }
  if ($email !== '' && get_user_by('email', $email)) {
    return new WP_Error('jaxauth_dup', 'A user with that email already exists.', ['status' => 409]);
  }
  $login = $email;
  if ($email === '') {
    $login = sanitize_user((string) $req->get_param('login'), true);
    if ($login === '') { $login = sanitize_user(sanitize_title($name), true); }
    if ($login === '') { return new WP_Error('jaxauth_bad', 'A sign-in name is required for an account with no email.', ['status' => 400]); }
    if (username_exists($login)) { return new WP_Error('jaxauth_dup', 'A user with that sign-in name already exists.', ['status' => 409]); }
  }
  $temp = wp_generate_password(14, false, false);
  $uid = wp_insert_user([
    'user_login'   => $login,
    'user_email'   => $email,
    'user_pass'    => $temp,
    'display_name' => $name,
    'role'         => JAXAUTH_ROLE,
  ]);
  if (is_wp_error($uid)) { return $uid; }
  update_user_meta($uid, 'jaxauth_grants', $grants);
  update_user_meta($uid, 'jaxauth_instructor', '');
  update_user_meta($uid, 'jaxauth_must_change', '1');
  jaxauth_log_add('created account for ' . $name
    . ($email === '' ? ' with NO email (lessor-only account; sign-in name "' . $login . '").' : '.')
    . ($grants ? ' Gave: ' . implode(', ', $grants) . '.' : '')
    . ' Temporary password shown once.');
  return ['ok' => true, 'user_id' => $uid, 'login' => $login, 'temp_password' => $temp];
}

/* Ryan, Aug 25: each user can star one of their own home cards to pick
 * their landing page - the same jaxauth_home meta the admin star writes. */
function jaxauth_rest_me_home(WP_REST_Request $req) {
  $u = wp_get_current_user();
  if (!$u || !$u->exists()) { return new WP_Error('jaxauth_auth', 'Sign in first.', ['status' => 401]); }
  $sel = sanitize_text_field((string) $req->get_param('home'));
  $keys = array_values(array_diff(array_intersect(array_values((array) get_option('jaxauth_pages', [])), array_keys(jaxauth_registry())), ['access']));
  $invOk = false;
  if ($sel === 'invoice') { $ipd = jaxauth_invoice_page($u); $invOk = $ipd[0] !== ''; }
  if ($sel !== '' && !$invOk && (!in_array($sel, $keys, true) || !jaxauth_can($sel, $u->ID))) {
    return new WP_Error('jaxauth_badkey', 'That widget cannot be a home screen.', ['status' => 400]);
  }
  if ($sel === '') { delete_user_meta($u->ID, 'jaxauth_home'); }
  else { update_user_meta($u->ID, 'jaxauth_home', $sel); }
  jaxauth_log_add($u->display_name . ($sel === '' ? ' cleared their own home screen.' : ' set their own home screen to ' . $sel . '.'));
  return ['ok' => true, 'home' => $sel];
}

/* Ryan, Aug 25: "request user help" from the menu - emails Ryan directly.
 * Lightly rate-limited per user so a stuck retry button cannot flood him. */
function jaxauth_rest_help(WP_REST_Request $req) {
  $u = wp_get_current_user();
  if (!$u || !$u->exists()) { return new WP_Error('jaxauth_auth', 'Sign in first.', ['status' => 401]); }
  if (get_transient('jaxauth_help_' . $u->ID)) {
    return new WP_Error('jaxauth_slow', 'A help request was sent moments ago. Give Ryan a few minutes to see it.', ['status' => 429]);
  }
  $msg = substr(sanitize_textarea_field((string) $req->get_param('message')), 0, 2000);
  if (trim($msg) === '') { return new WP_Error('jaxauth_empty', 'Describe the problem in a sentence or two first.', ['status' => 400]); }
  $page = substr(sanitize_text_field((string) $req->get_param('page')), 0, 300);
  $body = "Help request from the JAXAERO portal\n\n"
        . 'Who:  ' . $u->display_name . ' (' . $u->user_email . ")\n"
        . 'Page: ' . $page . "\n"
        . 'When: ' . wp_date('M j, Y g:i A') . "\n\nMessage:\n" . $msg . "\n";
  /* lock BEFORE the slow wp_mail round-trip so parallel clicks cannot burst past the limit */
  set_transient('jaxauth_help_' . $u->ID, 1, 5 * MINUTE_IN_SECONDS);
  $sent = wp_mail('ryan.winter@flyjaxaero.com', 'Portal help request - ' . $u->display_name, $body);
  if (!$sent) { delete_transient('jaxauth_help_' . $u->ID); return new WP_Error('jaxauth_mail', 'The email could not be sent - call or text Ryan directly.', ['status' => 500]); }
  jaxauth_log_add($u->display_name . ' sent a help request.');
  return ['ok' => true];
}

/* -------------------- view-as preview (Ryan, Aug 25) --------------------
   An admin sees the portal exactly as a managed user sees it. The swap covers
   FRONT-END page requests only: wp-json, wp-admin, wp-login and the
   access-admin page keep the REAL identity, so the preview cannot write -
   REST nonces minted under the preview identity never validate against the
   admin's session. Auto-expires after 15 minutes; banner link ends it. */
function jaxauth_rest_viewas(WP_REST_Request $req) {
  $uid = (int) $req->get_param('user_id');
  $t = get_user_by('id', $uid);
  if (!$t || (!jaxauth_is_managed($t) && !jaxauth_is_admin($t))) { return new WP_Error('jaxauth_nouser', 'No such user.', ['status' => 404]); }
  if (!jaxauth_is_admin($t) && !jaxauth_enabled($t->ID)) { return new WP_Error('jaxauth_off', 'That account is disabled - nothing to preview.', ['status' => 400]); }
  if (!jaxauth_is_admin() && jaxauth_is_admin($t)) { return new WP_Error('jaxauth_scope', 'Only an admin can preview an admin account.', ['status' => 403]); }
  set_transient('jaxauth_viewas_' . get_current_user_id(), $t->ID, 15 * MINUTE_IN_SECONDS);
  /* Ben, punch list 11: exiting a preview dropped you on the Access Admin page no
     matter where you started. Anyone who launched from the payroll widget on Home
     - which is where the View as IP button actually lives - got bounced somewhere
     they had never been. Remember the launching URL and return to it on exit.
     wp_validate_redirect keeps this to our own host, so a crafted "from" cannot
     turn Exit preview into an open redirect. */
  $from = trim((string) $req->get_param('from'));
  /* These widgets render inside an iframe srcdoc, where location.href is the
     literal string "about:srcdoc" - it validates to nothing and the preview would
     silently fall back to Access Admin, which is the very complaint being fixed.
     The callers send window.top.location.href; the Referer is the safety net for
     any caller that forgets. */
  if ($from === '' || stripos($from, 'about:') === 0) {
    $from = isset($_SERVER['HTTP_REFERER']) ? (string) $_SERVER['HTTP_REFERER'] : '';
  }
  $from = ($from !== '') ? wp_validate_redirect(esc_url_raw($from), '') : '';
  if ($from !== '') { set_transient('jaxauth_viewas_from_' . get_current_user_id(), $from, 15 * MINUTE_IN_SECONDS); }
  else { delete_transient('jaxauth_viewas_from_' . get_current_user_id()); }
  /* Ryan, Sep 7 2026: the preview header names where its Back button goes ("Back to
     Pay Portal"), so the launcher may send a short human label for the origin. Plain
     text, capped, and only kept when there is an origin to go back to. */
  $fromLabel = sanitize_text_field((string) $req->get_param('fromLabel'));
  $fromLabel = function_exists('mb_substr') ? mb_substr($fromLabel, 0, 40) : substr($fromLabel, 0, 40);
  if ($from !== '' && $fromLabel !== '') { set_transient('jaxauth_viewas_fromlabel_' . get_current_user_id(), $fromLabel, 15 * MINUTE_IN_SECONDS); }
  else { delete_transient('jaxauth_viewas_fromlabel_' . get_current_user_id()); }
  jaxauth_log_add('started a 15-minute view-as preview of "' . $t->display_name . '".');
  $p = get_option('jaxauth_signin_page');
  return ['ok' => true, 'start' => $p ? get_permalink($p) : home_url('/')];
}

add_action('init', 'jaxauth_viewas_boot', 0);
function jaxauth_viewas_boot() {
  /* runs at init, where every WP API is safely available - never earlier */
  if (is_admin()) { return; }
  $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : 'GET';
  if ($method !== 'GET' && $method !== 'HEAD') { return; }
  if (isset($_GET['jaxviewas'])) { return; }
  $urlp = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
  /* Aug 26: WordPress also serves REST at /?rest_route=..., which matches neither the
     pretty prefix below nor the derived REST path, so a preview would swap identity on
     those reads too. Keep the real identity for every REST shape. */
  if ($urlp === '' || strpos($urlp, '/wp-json') === 0 || strpos($urlp, 'rest_route=') !== false || strpos($urlp, 'wp-login.php') !== false) { return; }
  $uid = get_current_user_id();
  if (!$uid) { return; }
  $ru = wp_get_current_user();
  if (!$ru || !$ru->exists()) { return; }
  /* Ben, punch list 13: pay-grant holders preview too. The route only ever
     arms a transient for someone this same rule admits, so the check here is
     belt and suspenders. */
  if (!jaxauth_is_admin($ru)
      && !(jaxauth_is_managed($ru) && jaxauth_enabled($uid) && jaxauth_can('pay', $uid))) { return; }
  $t = (int) get_transient('jaxauth_viewas_' . $uid);
  if (!$t || $t === (int) $uid) { return; }
  $restP = (string) wp_parse_url(rest_url(), PHP_URL_PATH);
  if ($restP !== '' && strpos($urlp, $restP) === 0) { return; }
  $adminPage = (int) get_option('jaxauth_admin_page');
  if ($adminPage) {
    $ap = (string) wp_parse_url(get_permalink($adminPage), PHP_URL_PATH);
    /* compare on the normalized path: a raw prefix test let /access-admin
       (no trailing slash) miss the exemption, which would swap identity to the
       previewed user on the one page that must keep the real one */
    $reqPath = (string) wp_parse_url($urlp, PHP_URL_PATH);
    if ($ap !== '' && $ap !== '/'
        && untrailingslashit($reqPath) === untrailingslashit($ap)) { return; }
  }
  $tu = get_user_by('id', $t);
  if (!$tu) { return; }
  /* the target half of the route's rule, re-checked at swap time: a role change
     inside the 15-minute window must not let a pay-grant viewer wear an admin */
  if (!jaxauth_is_admin($ru) && jaxauth_is_admin($tu)) { return; }
  if (!jaxauth_is_admin($tu) && (!jaxauth_is_managed($tu) || !jaxauth_enabled($t))) { return; }
  $GLOBALS['jaxauth_viewas_real'] = (int) $uid;
  $GLOBALS['jaxauth_viewas_target'] = $t;
  wp_set_current_user($t);
}

add_action('init', function () {
  if (!isset($_GET['jaxviewas']) || $_GET['jaxviewas'] !== 'off') { return; }
  /* jaxauth_viewas_boot bails out whenever jaxviewas is present, so the identity
     is NOT swapped on this request - get_current_user_id() is the real admin and
     the transient keys line up. */
  $uid = get_current_user_id();
  $back = '';
  if ($uid) {
    $back = (string) get_transient('jaxauth_viewas_from_' . $uid);
    delete_transient('jaxauth_viewas_from_' . $uid);
    delete_transient('jaxauth_viewas_fromlabel_' . $uid);
    if ($back !== '') { $back = wp_validate_redirect($back, ''); }
  }
  if ($uid && get_transient('jaxauth_viewas_' . $uid)) {
    delete_transient('jaxauth_viewas_' . $uid);
    jaxauth_log_add('ended the view-as preview.');
  }
  if ($back === '') {
    $adminPage = (int) get_option('jaxauth_admin_page');
    $back = $adminPage ? get_permalink($adminPage) : home_url('/');
  }
  wp_safe_redirect($back);
  exit;
});

add_action('wp_footer', 'jaxauth_viewas_banner', 5);
function jaxauth_viewas_banner() {
  if (empty($GLOBALS['jaxauth_viewas_target'])) { return; }
  $t = get_user_by('id', (int) $GLOBALS['jaxauth_viewas_target']);
  $name = $t ? $t->display_name : 'user';
  $exit = esc_url(add_query_arg('jaxviewas', 'off', home_url('/')));
  /* Ryan, Sep 7 2026: "When I click IP View ... I want a button that returns me to
     the previous screen" and "It should be a preview screen, not the instructor's
     actual screen." The bar was a thin strip fixed to the bottom of the page whose
     link said Exit preview, so the page read as the instructor's real screen with a
     footnote. It is now a preview header fixed to the TOP: a PREVIEW chip, the
     person's name, and a Back button that names where it goes. The page is also
     framed in the amber line so no scroll position can pass for the real thing.
     This prints under the swapped identity, so the origin transients are read with
     the real admin id that jaxauth_viewas_boot recorded. The exit handler is the
     one that deletes them. */
  $real = isset($GLOBALS['jaxauth_viewas_real']) ? (int) $GLOBALS['jaxauth_viewas_real'] : 0;
  $from = $real ? (string) get_transient('jaxauth_viewas_from_' . $real) : '';
  $from = ($from !== '') ? (string) wp_validate_redirect($from, '') : '';
  $fromLabel = $real ? (string) get_transient('jaxauth_viewas_fromlabel_' . $real) : '';
  $btn = ($from !== '') ? ('Back to ' . ($fromLabel !== '' ? $fromLabel : 'previous screen')) : 'Exit preview';
  ?>
<style>
<?php echo jaxauth_tokens_css(); ?>
/* Ryan, Sep 6 2026 design audit: the house amber alert surface (--amber-tint fill,
   --amber-line border, --amber text); the button is the .b2 set in amber. */
/* Ryan, Sep 7 2026, measured live: a theme script rewrites this element's inline style
   after load (position:static, top, transform - the sticky-header signature), which
   dropped the bar into the page flow 656px down. The geometry is pinned with
   !important, which outranks an inline style, the same way the house pins every
   other non-iframe element against the Elementor kit (elementor-theme-bleed). */
.jaxva{position:fixed !important;left:0 !important;right:0 !important;top:0 !important;bottom:auto !important;transform:none !important;width:auto !important;margin:0 !important;z-index:2147483000 !important;background:var(--amber-tint) !important;color:var(--amber) !important;border-bottom:1px solid var(--amber-line);font-family:<?php echo jaxauth_font_stack(); ?> !important;font-size:13.5px !important;line-height:1.5 !important;padding:9px 20px !important;display:flex !important;align-items:center !important;justify-content:space-between !important;gap:14px !important;flex-wrap:wrap !important;box-sizing:border-box !important}
.jaxva b{color:var(--amber) !important;font-weight:800 !important}
.jaxva .jaxva-chip{display:inline-block;font-size:11.5px !important;font-weight:800 !important;letter-spacing:.08em !important;text-transform:uppercase !important;background:var(--amber) !important;color:#fff !important;padding:2px 9px !important;border-radius:var(--r-pill) !important;margin-right:10px !important;vertical-align:1px}
.jaxva .jaxva-x{color:var(--amber) !important;background:var(--panel) !important;border:1px solid var(--amber-line) !important;border-radius:var(--r-sm) !important;padding:9px 16px !important;font-weight:700 !important;font-size:13.5px !important;text-decoration:none !important;letter-spacing:0 !important;text-transform:none !important;white-space:nowrap;flex:0 0 auto}
.jaxva .jaxva-x:hover{background:var(--tint) !important;color:var(--amber) !important}
/* the frame: a fixed amber line around the whole viewport, click-through, so the
   preview is recognizable at any scroll position. Sits just under the header. */
.jaxva-frame{position:fixed;left:0;right:0;top:0;bottom:0;z-index:2147482999;pointer-events:none;border:3px solid var(--amber-line);box-sizing:border-box}
/* Ryan, Sep 6 2026 graphics and mobile review: reserve the space this fixed bar
   occupies so it never overlaps page content underneath it. 130px covers the worst
   case (sentence wraps to 3 lines plus the button on phone widths); 56px covers the
   normal single-line height at 560px and up. Scoped to the same conditional print
   as .jaxva, so it disappears with the header. */
body{padding-top:130px !important}
@media(min-width:560px){body{padding-top:56px !important}}
@media(max-width:560px){.jaxva .jaxva-x{min-height:44px !important;display:inline-flex !important;align-items:center !important}}
</style>
<div class="jaxva-frame" aria-hidden="true"></div>
<div class="jaxva" role="status">
  <span><span class="jaxva-chip">Preview</span>You are looking at the portal as <b><?php echo esc_html($name); ?></b> sees it. Nothing here saves or sends.</span>
  <a class="jaxva-x" href="<?php echo $exit; ?>" data-exit="<?php echo $exit; ?>" data-back="<?php echo esc_url($from); ?>"><?php echo esc_html($btn); ?></a>
</div>
<script>
/* Ryan, Sep 7 2026: a preview that the Pay Portal opened in its OWN tab arrives with
   jaxip=tab on the URL. Its Back button ends the preview server-side, then closes
   this tab so the person lands on the Pay Portal tab they left - instead of loading
   a second copy of it here. If the browser refuses to close the tab, fall back to a
   plain navigation to the origin (the preview is already ended by then). Same-tab
   previews keep the ordinary link. */
(function(){var a=document.querySelector('.jaxva-x');if(!a){return;}
if(!/[?&]jaxip=tab(?:&|$)/.test(window.location.search)){return;}
a.addEventListener('click',function(e){e.preventDefault();
var u=a.getAttribute('data-exit')||a.getAttribute('href');var back=a.getAttribute('data-back')||u;var done=false;
function go(){if(done){return;}done=true;window.location.href=back;}
fetch(u,{credentials:'same-origin'}).then(function(){try{window.close();}catch(x){}setTimeout(go,400);}).catch(go);});})();
</script>
  <?php
}

/* Ryan, Aug 25: delete a managed account. Admins and your own account are
   untouchable from here; the audit log keeps the person's history. */
function jaxauth_rest_delete_user(WP_REST_Request $req) {
  $uid = (int) $req->get_param('user_id');
  $user = get_user_by('id', $uid);
  if (!$user || !jaxauth_is_managed($user)) { return new WP_Error('jaxauth_nouser', 'No such managed user.', ['status' => 404]); }
  if (jaxauth_is_admin($user)) { return new WP_Error('jaxauth_admin', 'Admins cannot be deleted from here.', ['status' => 400]); }
  if ($uid === get_current_user_id()) { return new WP_Error('jaxauth_self', 'You cannot delete your own account.', ['status' => 400]); }
  $name = $user->display_name;
  $email = $user->user_email;
  require_once ABSPATH . 'wp-admin/includes/user.php';
  if (!wp_delete_user($uid)) { return new WP_Error('jaxauth_fail', 'The account could not be deleted.', ['status' => 500]); }
  jaxauth_log_add('deleted the account "' . $name . '" (' . $email . '). Their history stays in this log.');
  return ['ok' => true];
}

function jaxauth_rest_reset_pw(WP_REST_Request $req) {
  $uid = (int) $req->get_param('user_id');
  $user = get_user_by('id', $uid);
  if (!$user || !jaxauth_is_managed($user)) {
    return new WP_Error('jaxauth_nouser', 'No such managed user.', ['status' => 404]);
  }
  /* Sep 4 2026 review (SEC-1): a WordPress administrator's password is reset
     only by another WordPress administrator - a dashboard admin (jaxauth_admin)
     must never be handed a temporary password for Ryan's account. Mirrors the
     administrator refusal in delete-user. */
  if (user_can($user, 'manage_options') && !current_user_can('manage_options')) {
    return new WP_Error('jaxauth_wpadmin', 'Only a WordPress administrator can reset another administrator.', ['status' => 403]);
  }
  $temp = wp_generate_password(14, false, false);
  wp_set_password($temp, $uid);
  update_user_meta($uid, 'jaxauth_must_change', '1');
  jaxauth_log_add('reset the password for ' . $user->display_name . '. Temporary password shown once.');
  return ['ok' => true, 'temp_password' => $temp];
}

/* -------------------- the User Canvas (Ryan/Ben, Aug 31) --------------------
 * One page, composed per viewer: every widget whose Access Admin toggle is ON
 * for the CURRENT user renders here, in canonical order. View-as previews swap
 * the current user at init, so a preview shows exactly what that person sees.
 * Widgets are skipped, never replaced with denial panels - the canvas is what
 * you have, not a list of what you lack. Order: the money dashboards first,
 * then statements, then the person's own pay page, then tools. */
function jaxauth_canvas_widgets($u) {
  /* each entry: key (anchor id + grant), tag (shortcode), label (menu text) */
  $out = array();
  $order = array(
    array('auto', '[jaxaero_revenue_auto]', 'Revenue Dashboard'),
    array('pay', '[jaxaero_payroll]', 'Pay Portal'),
    array('safety', '[jaxaero_safety]', 'Safety'),
    /* Ben, Sep 6 2026: "Rebrand 'Timeclock' to 'My Hours'" - this label is the
       hamburger-menu text and the canvas tab text. The department bubble the
       widget sits in stays 'MX' ($gmap / $gorder below), like Accounting. */
    array('mxtime', '[jaxaero_mx_time]', 'My Hours'),
    /* Ryan, Sep 9 2026 (Ben, punch list 15): headings are title case, matching the registry label */
    array('ownerstmt', '[jaxaero_aircraft_owner]', 'Aircraft Owner Statements'),
    array('owner', '[jaxaero_owner_portal]', 'My Aircraft'),
    array('lessor', '[jaxaero_lessor]', 'Lease Statements'),
    array('sales', '[jaxaero_sales_pipeline]', 'Sales'),
    array('marketing', '[jaxaero_marketing]', 'Marketing'),
    /* Ryan, Sep 9 2026 (Ben, punch list 15): headings are title case, matching the Accounting sub-label */
    array('tax', '[jaxaero_tax]', 'Sales Tax'),
    array('lease', '[jaxaero_leases]', 'Leases'),
    array('depr', '[jaxaero_depreciation]', 'Depreciation'),
    array('depr_view', '[jaxaero_depreciation]', 'Depreciation'),
    array('docs', '[jaxaero_documents]', 'Documents'),
  );
  /* Ryan, Aug 31 PM: the canvas follows the ACTUAL Access Admin toggles for
     everyone - including admins. jaxauth_can()'s admin bypass put every widget
     on Ben's canvas regardless of his switches; jaxauth_grants() is the raw
     toggle state. */
  $cvsG = jaxauth_grants($u->ID);
  foreach ($order as $w) {
    /* Sep 4 2026 review (SEC-3): 'depr_view' is the same register read-only;
       a person holding both keys gets ONE Depreciation tab, the writing one. */
    if ($w[0] === 'depr_view' && in_array('depr', $cvsG, true)) { continue; }
    /* Ryan, Sep 7 2026: the MX Overview leads the MX widgets - it becomes a bound mechanic's
       landing tab (like Safety for instructors) and sits ahead of My Hours in the menu */
    if ($w[0] === 'mxtime' && in_array('mxtime', $cvsG, true) && shortcode_exists('jaxaero_mx_briefing')) {
      $out[] = array('key' => 'mxbrief', 'tag' => '[jaxaero_mx_briefing]', 'label' => 'MX Overview');
    }
    if (in_array($w[0], $cvsG, true)) { $out[] = array('key' => $w[0], 'tag' => $w[1], 'label' => $w[2]); }
    /* Ryan, Sep 7 2026: "MX users should be My hours and My pay." A person BOUND to a
       mechanic clock (user meta jaxmx_mechanic, written only by the admin bind route)
       gets their own pay page beside My Hours, on the same toggle. Editors who hold
       the toggle without a clock (Ryan, Ben, Kim, John) do not - they have the Pay
       Portal. Listed only once snippet 18 provides the shortcode. */
    /* Ben, Sep 7 2026 (punch list 14): "For now, no My Pay functionality for mechanics at
       all. Lets limit functionality to hours." The mechanic My Pay page is no longer
       listed; the shortcode stays in snippet 18 for the day it comes back. */
    /* Ryan, Sep 7 2026: "In the MX area, I want a logbook tab." Every My Hours holder
       (mechanics and editors alike) gets the aircraft logbooks, listed only while
       snippet 23 provides the shortcode. */
    if ($w[0] === 'mxtime' && in_array('mxtime', $cvsG, true) && shortcode_exists('jaxaero_mx_logbook')) {
      $out[] = array('key' => 'mxlog', 'tag' => '[jaxaero_mx_logbook]', 'label' => 'Logbook');
    }
    if ($w[0] === 'owner') {
      /* the person's own pay page sits after statements, before the tools */
      $ipd = jaxauth_invoice_page($u);
      $bound = (string) get_user_meta($u->ID, 'jaxauth_instructor', true);
      /* Ben, Sep 2 (punch list 13B): Sam's Log Detailing - snippet 9's
         [jaxaero_log_detailing] - is his primary work area and sits directly
         ahead of My Pay, the way Christina's statements lead hers. Sep 3 review:
         BINDING-driven, no Access Admin toggle - it appears for exactly the
         people snippet 9 gives the widget to (bound to a pay page, profile
         carries the tails flag, on the manual-time list), so the tab is there
         the moment snippet 9 removes his hour form from My Pay. Snippet 9's two
         helpers are read behind function_exists and never written; while
         snippet 9 is absent the tab simply is not listed. */
      $cvsBs = sanitize_title($bound);
      $cvsLd = ($ipd[0] !== '' && $cvsBs !== '' && function_exists('jaxpay_tails_required') && function_exists('jaxpay_manual_who')
                && jaxpay_tails_required($cvsBs) && in_array($cvsBs, (array) jaxpay_manual_who(), true));
      if ($cvsLd) { $out[] = array('key' => 'logdetail', 'tag' => '[jaxaero_log_detailing key="' . esc_attr($cvsBs) . '"]', 'label' => 'Log Detailing'); }
      if ($ipd[0] !== '' && $bound !== '') { $out[] = array('key' => 'mypay', 'tag' => '[jaxaero_instructor_pay key="' . esc_attr(sanitize_title($bound)) . '"]', 'label' => 'My Pay'); }
      /* Ben, Sep 2 (punch list 13B): instructors get My Hours as its own tab.
         The widget is snippet 9's [jaxaero_my_hours]; it is listed only once that
         shortcode exists (until then the canvas is Safety / My Pay, nothing
         breaks) and never for a contractor - My Hours is an instructor widget
         (punch list 13). jaxpay_contractors is read, never written, here. */
      if ($ipd[0] !== '' && $bound !== '' && shortcode_exists('jaxaero_my_hours')) {
        $cvsCt = get_option('jaxpay_contractors', array());
        if (!is_array($cvsCt) || !in_array(sanitize_title($bound), $cvsCt, true)) { $out[] = array('key' => 'myhours', 'tag' => '[jaxaero_my_hours key="' . esc_attr(sanitize_title($bound)) . '"]', 'label' => 'My Hours'); }
      }
    }
  }
  /* Ben, Sep 6 2026 review: the MX 'mxtime' entry and the instructors'
     binding-driven 'myhours' entry are both labeled 'My Hours' - Ben's words
     for each. Nobody holds both today (Ben and Ryan hold mxtime and neither
     is bound to an instructor pay page). If someone ever does, the MX entry
     takes the registry's "(MX)" suffix so the hamburger menu and the loading
     placeholders do not show two identical 'My Hours'. Mechanics, who hold
     only mxtime, keep the plain label Ben asked for. */
  $cvsKeys = array_map(function ($x) { return $x['key']; }, $out);
  if (in_array('mxtime', $cvsKeys, true) && in_array('myhours', $cvsKeys, true)) {
    foreach ($out as $cvsI => $cvsW) { if ($cvsW['key'] === 'mxtime') { $out[$cvsI]['label'] = 'My Hours (MX)'; } }
  }
  return $out;
}

/* Ryan, Sep 2 (Tier 1): lazy-canvas fragments answer BEFORE the theme and
   Elementor render - each ?jaxw fetch was spending ~65% of its time building
   page chrome the loader immediately throws away. This handler replicates
   the canvas shortcode's exact gates, emits the same #jaxwLazyPayload
   fragment (accepting a comma list of keys) and exits. Anonymous, ungated
   and unknown keys get the empty payload div - fails closed. The shortcode's
   own lazy branch below stays as the fallback path. View-as still applies:
   the identity swap ran at init 0, long before template_redirect. */
add_action('template_redirect', function () {
  $qid = (int) get_queried_object_id();
  if (!$qid) { return; }
  $shared = (int) get_option('jaxauth_canvas_page');
  $mine = is_user_logged_in() ? (int) get_user_meta(get_current_user_id(), 'jaxauth_canvas', true) : 0;
  if ($qid !== $shared && ($mine === 0 || $qid !== $mine)) { return; }
  if (!isset($_GET['jaxw']) || !is_string($_GET['jaxw'])) {
    /* full canvas page view: the render varies on the jaxDashTab cookie and
       the signed-in identity - never let an edge cache replay it */
    nocache_headers();
    return;
  }
  if (!empty($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== 'GET') { return; }
  nocache_headers();
  header('Content-Type: text/html; charset=utf-8');
  $out = '';
  $u = wp_get_current_user();
  $pg = get_post($qid);
  $pwOk = !($pg && post_password_required($pg));
  if ($pwOk && $u && $u->exists()
      && (jaxauth_is_admin($u) || jaxauth_is_managed($u))
      && (jaxauth_is_admin($u) || jaxauth_enabled($u->ID))) {
    $tags = jaxauth_canvas_widgets($u);
    if ($tags && count($tags) > 1) {
      $want = array();
      foreach (explode(',', (string) $_GET['jaxw']) as $lk) { $lk = sanitize_key($lk); if ($lk !== '') { $want[$lk] = 1; } }
      $GLOBALS['jaxauth_canvas_render'] = true;
      foreach ($tags as $t) {
        if (isset($want[$t['key']])) { $out .= '<div id="jaxw-' . esc_attr($t['key']) . '">' . do_shortcode($t['tag']) . '</div>'; }
      }
      unset($GLOBALS['jaxauth_canvas_render']);
    }
  }
  echo '<div id="jaxwLazyPayload">' . $out . '</div>';
  exit;
}, 0);

add_shortcode('jaxauth_user_canvas', function () {
  $u = wp_get_current_user();
  if (!$u || !$u->exists()) { return ''; }
  if (!jaxauth_is_admin($u) && !jaxauth_is_managed($u)) { return ''; }
  if (!jaxauth_is_admin($u) && !jaxauth_enabled($u->ID)) { return ''; }
  $tags = jaxauth_canvas_widgets($u);
  /* House empty state: the page header - brand mark, navy title, grey sub,
     3px gold rule - then one .mod sentence saying who fixes it. Nothing has
     printed a greeting above it, so the brand mark stays. Rendered onto an
     Elementor page, so the kit-repaintable declarations are pinned. */
  if (!$tags) {
    return '<style>' . jaxauth_tokens_css()
      /* Ryan, Sep 6 2026 design audit: the widgets' .wrap box (1080 border-box, 20px inset) */
      . '.jaxcv-empty{max-width:1080px;margin:20px auto 24px;padding:0 20px;box-sizing:border-box;font-family:' . jaxauth_font_stack() . ' !important;color:var(--ink) !important}'
      . '.jaxcv-empty .jaxcv-hd{border-bottom:3px solid var(--gold) !important;padding-bottom:9px;margin-bottom:14px}'
      . '.jaxcv-empty .jaxcv-brand{font-weight:800 !important;letter-spacing:.14em !important;font-size:13px !important;color:var(--brand) !important;line-height:1.2 !important}'
      . '.jaxcv-empty .jaxcv-t{margin:6px 0 4px !important;font-size:26px !important;font-weight:800 !important;letter-spacing:-.01em !important;color:var(--ink) !important;line-height:1.25 !important}'
      . '.jaxcv-empty .jaxcv-sub{color:var(--ink2) !important;font-size:13.5px !important;line-height:1.5 !important;margin-top:6px !important}'
      . '.jaxcv-empty .jaxcv-mod{background:var(--panel) !important;border:1px solid var(--hair) !important;border-radius:var(--r-lg) !important;padding:22px !important;box-shadow:var(--shadow) !important;color:var(--ink2) !important;font-size:13.5px !important;line-height:1.5 !important}'
      . '</style>'
      . '<div class="jaxcv-empty"><div class="jaxcv-hd">'
      . (empty($GLOBALS['jaxauth_canvas_render']) ? '<div class="jaxcv-brand">JAXAERO</div>' : '')
      . '<div class="jaxcv-t">Nothing is switched on for your account yet.</div>'
      . '<div class="jaxcv-sub">Your dashboard is built from the widgets turned on for you in Access admin.</div>'
      . '</div>'
      . '<div class="jaxcv-mod">Ask Ryan to switch on the widgets you need and they will appear here on your next sign-in.</div></div>';
  }
  /* Ryan, Aug 31 PM: the welcome appears exactly ONCE, at the top of the
     canvas. Widgets suppress their own greeting while this flag is up (they
     keep it on standalone pages). */
  $first = trim((string) strtok($u->display_name, ' '));
  /* Ryan, Sep 4 2026: a company account (the VR Leasing lessor login, grants exactly
     ['lessor']) is greeted by its full name, not by "VR". */
  if (function_exists('jaxauth_grants') && jaxauth_grants($u->ID) === array('lessor')) { $first = trim((string) $u->display_name); }
  /* Ryan, Sep 4 2026 (design pass): the greeting keeps exactly the behaviour it
     had - one welcome, printed once, brand mark above it - and now draws its
     colours and its type from the house tokens (brand mark 13/800/.14em, title
     26/800/-.01em). It deliberately does NOT grow a gold rule: the widget
     directly beneath it prints its own, and two rules a few pixels apart read
     as a mistake. This block lands on an Elementor page, so it is pinned. */
  $html = '<style>' . jaxauth_tokens_css()
        . 'div[id^="jaxw-"]{scroll-margin-top:72px}'
        /* Ryan, Sep 6 2026 design audit: the widgets' .wrap box (1080 border-box, 20px inset) */
        . '.jaxcv-greet{max-width:1080px;margin:20px auto 4px;padding:0 20px;box-sizing:border-box;font-family:' . jaxauth_font_stack() . ' !important}'
        . '.jaxcv-greet .jaxcv-brand{color:var(--brand) !important;font-weight:800 !important;font-size:13px !important;letter-spacing:.14em !important;line-height:1.2 !important;text-transform:uppercase !important}'
        . '.jaxcv-greet h1{font-size:26px !important;font-weight:800 !important;color:var(--ink) !important;letter-spacing:-.01em !important;margin:4px 0 0 !important;line-height:1.25 !important}'
        . '.jaxcv-ph{font-family:' . jaxauth_font_stack() . ' !important;color:var(--ink3) !important;font-size:13px !important;padding:40px 0;line-height:1.5}'
        . '</style>';
  $html .= '<div class="jaxcv-greet">'
        . '<div class="jaxcv-brand">JAXAERO</div>'
        . '<h1>Welcome ' . esc_html($first !== '' ? $first : $u->display_name) . '!</h1>'
        . '</div>';
  /* Ryan, Aug 31 late: lazy canvas. A ?jaxw=<key> request returns ONLY that
     widget, rendered through the same identity/gate path as any page load
     (the view-as swap has already run at init). The normal request renders
     the first widget inline and placeholders for the rest; the loader below
     fetches them one at a time. Single-widget canvases skip all of this. */
  $lazyReq = (isset($_GET['jaxw']) && is_string($_GET['jaxw'])) ? (string) $_GET['jaxw'] : '';
  if ($lazyReq !== '' && count($tags) > 1) {
    $want = array();
    foreach (explode(',', $lazyReq) as $lk) { $lk = sanitize_key($lk); if ($lk !== '') { $want[$lk] = 1; } }
    $out = '';
    $GLOBALS['jaxauth_canvas_render'] = true;
    foreach ($tags as $t) {
      if (isset($want[$t['key']])) { $out .= '<div id="jaxw-' . esc_attr($t['key']) . '">' . do_shortcode($t['tag']) . '</div>'; }
    }
    unset($GLOBALS['jaxauth_canvas_render']);
    return '<div id="jaxwLazyPayload">' . $out . '</div>';
  }
  $GLOBALS['jaxauth_canvas_render'] = true;
  /* Ben, Sep-eve: multi-page Dashboard. Widgets group into Pay-Portal-style
     tabs; one-group users keep the plain canvas exactly as before. */
  /* Ryan, Sep 4 2026 (lease): the Revenue bubble is now the Accounting
     department (Revenue / Sales tax / Leases / Depreciation as a sub-menu, see $subGroups
     below); the lessor's statements are their own bubble. */
  $gmap = array('logdetail' => 'Log Detailing', 'auto' => 'Accounting', 'tax' => 'Accounting', 'lease' => 'Accounting', 'depr' => 'Accounting', 'depr_view' => 'Accounting', 'ownerstmt' => 'Airplanes', 'owner' => 'Airplanes', 'pay' => 'Payroll', 'mypay' => 'My Pay', 'myhours' => 'My Hours', 'safety' => 'Safety', 'sales' => 'Sales & Marketing', 'marketing' => 'Sales & Marketing', 'mxtime' => 'MX', 'docs' => 'Documents', 'lessor' => 'Lease Statements', 'mxpay' => 'My Pay', 'mxlog' => 'MX', 'mxbrief' => 'MX');
  /* Ryan, Sep 7 2026: "MX users should be My hours and My pay ... model the user
     experience for MX users after that of 1099 contractors (with regard to
     navigation)." A contractor's canvas is work area first, then My Pay, as plain
     top-level tabs. A bound mechanic (the widget list carries 'mxpay' only for one)
     gets the same shape: their clock is the My Hours tab, their pay page the My Pay
     tab, no department bubble. Editors without a clock keep the MX bubble. */
  /* Sep 7 2026: a bound mechanic is recognised by the binding itself (user meta
     jaxmx_mechanic) now that My Pay is no longer listed for them */
  $cvsHasMx = false;
  foreach ($tags as $cvsT) { if ($cvsT['key'] === 'mxtime') { $cvsHasMx = true; break; } }
  $cvsMech = $cvsHasMx && (string) get_user_meta($u->ID, 'jaxmx_mechanic', true) !== '';
  /* a bound mechanic's logbooks are their own Logbook tab after My Pay (Sep 7 2026) */
  /* a bound mechanic gets the briefing as its own landing tab (Ryan, Sep 7 2026: "similar
     to the Safety page"); editors keep it as the first sub-tab of the MX department so no
     saved tab index moves for them */
  if ($cvsMech) { $gmap['mxtime'] = 'My Hours'; $gmap['mxlog'] = 'Logbook'; $gmap['mxbrief'] = 'MX Overview'; }
  /* Ben, Sep 2 (punch list 13B): Log Detailing leads so Sam's canvas opens on
     it with My Pay as the next tab. Safety now precedes My Pay and My Hours
     follows it, so an instructor's tabs read Safety / My Pay / My Hours. Nobody
     else's relative order moves - only a holder of BOTH Safety and their own
     pay page sees Safety step ahead of My Pay. */
  /* 'Accounting' sits at the index 'Revenue' held so saved jaxDashTab cookies
     keep pointing at the same bubble; 'Lease statements' is appended LAST so
     no existing user's group index moves (nobody holds 'lessor' yet). */
  /* 'Logbook' (a bound mechanic's third tab) sits right after 'My Hours' so the
     reorder below yields My Hours / My Pay / Logbook; nobody held it before Sep 7 2026. */
  /* 'MX Overview' sits right after 'Safety' and ahead of My Hours / Logbook, so a mechanic
     lands on the briefing (Ryan, Sep 7 2026: "similar to the Safety page for instructors") */
  $gorder = array('Log Detailing', 'Accounting', 'Airplanes', 'Payroll', 'Safety', 'MX Overview', 'My Pay', 'My Hours', 'Logbook', 'Sales & Marketing', 'MX', 'Documents', 'Lease Statements');
  $groups = array();
  foreach ($gorder as $gl) { $groups[$gl] = array(); }
  foreach ($tags as $t) { $gl = isset($gmap[$t['key']]) ? $gmap[$t['key']] : 'Documents'; $groups[$gl][] = $t; }
  $groups = array_filter($groups);
  /* Ryan, Sep 7 2026: for a mechanic the landing tab is My Hours, with My Pay next -
     the contractor order (work area, then pay). $gorder keeps Ben's instructor order
     (Safety / My Pay / My Hours) for everyone else, so only the mechanic's two tabs
     swap, and the first group is the default tab a fresh browser opens on. */
  if ($cvsMech && isset($groups['My Hours'], $groups['My Pay'])) {
    $cvsRe = array();
    foreach ($groups as $cvsGl => $cvsGv) {
      if ($cvsGl === 'My Pay') { continue; }
      $cvsRe[$cvsGl] = $cvsGv;
      if ($cvsGl === 'My Hours') { $cvsRe['My Pay'] = $groups['My Pay']; }
    }
    $groups = $cvsRe;
  }
  $isDash = count($groups) > 1;
  $lazyKeys = array();
  $phFn = function ($t) {
    /* Ryan, Sep 6 2026 design audit: data-jaxl carries the widget label so a
       load error can still say which widget it belongs to (markErr below). */
    return '<div id="jaxw-' . esc_attr($t['key']) . '" class="jaxw-lazy" data-jaxw="' . esc_attr($t['key']) . '" data-jaxl="' . esc_attr($t['label']) . '" style="min-height:340px;display:flex;align-items:center;justify-content:center">'
         . '<div class="jaxcv-ph">Loading ' . esc_html($t['label']) . '&hellip;</div>'
         . '</div>';
  };
  if (!$isDash) {
    foreach ($tags as $i => $t) {
      if ($i === 0) {
        $html .= '<div id="jaxw-' . esc_attr($t['key']) . '">' . do_shortcode($t['tag']) . '</div>';
      } else {
        $lazyKeys[] = $t['key'];
        $html .= $phFn($t);
      }
    }
  } else {
    /* The token block is declared once per document, in the greeting <style>
       above, which is always printed before this one - so these rules just
       reference the variables. */
    /* Ryan, Sep 6 2026 design audit: bubble row, sub-tab strip, gold rule and MX
       empty state all share the widgets' .wrap box (1080 border-box, 20px inset). */
    $html .= '<style>.jaxdash-tabs{display:flex;gap:8px;flex-wrap:wrap;max-width:1080px;margin:14px auto 4px;padding:0 20px;box-sizing:border-box;font-family:' . jaxauth_font_stack() . '}'
           . '.jaxdash-tab{font:700 13.5px ' . jaxauth_font_stack() . ' !important;padding:9px 18px !important;border:1px solid var(--hair2) !important;background:var(--panel) !important;border-radius:var(--r-pill) !important;cursor:pointer;color:var(--ink) !important;letter-spacing:0 !important;text-transform:none !important;box-shadow:none !important;min-width:0 !important;width:auto !important;line-height:1.2 !important}'
           . '.jaxdash-tab:hover{background:var(--tint) !important}'
           . '.jaxdash-tab.on{background:var(--ink) !important;color:#fff !important;border-color:var(--ink) !important}'
           . '.jaxdash-g{display:none}.jaxdash-g.on{display:block}'
           /* Ryan, Sep 4 2026 (lease): the department sub-menu strip - snippet 9's
              Pay Portal .ptabs/.ptab treatment (grey --ink2, navy --ink on,
              --brand underline). It renders OUTSIDE any iframe, so every
              declaration Elementor's kit could repaint is pinned. */
           /* Ryan, Sep 6 2026 design audit: 18px under the gold rule, the .hd/.ptabs
              rhythm of the Pay Portal header; 20px inset like the widgets. */
           . '.jaxsub{display:flex !important;flex-wrap:wrap;gap:2px;max-width:1080px;margin:18px auto 0 !important;padding:0 20px !important;border-bottom:1px solid var(--hair);box-sizing:border-box;font-family:' . jaxauth_font_stack() . '}'
           . '.jaxsub .ptab{font:700 13.5px ' . jaxauth_font_stack() . ' !important;padding:9px 16px !important;border:0 !important;border-bottom:3px solid transparent !important;margin:0 0 -1px !important;background:none !important;border-radius:0 !important;box-shadow:none !important;color:var(--ink2) !important;cursor:pointer;white-space:nowrap;letter-spacing:0 !important;text-transform:none !important;min-width:0 !important;width:auto !important;line-height:1.2 !important}'
           . '.jaxsub .ptab:hover{color:var(--ink) !important}'
           . '.jaxsub .ptab.on{color:var(--ink) !important;border-bottom-color:var(--brand) !important}'
           . '.jaxsub-rule{max-width:1080px;margin:14px auto 0 !important;padding:0 20px;box-sizing:border-box}'
           . '.jaxsub-rule i{display:block;height:3px;background:var(--gold)}'
           . '.jaxsub-p{display:none}.jaxsub-p.on{display:block}'
           /* the MX "coming soon" bubble is an empty state, so it gets the house
              header (title, grey sub, gold rule) and one .mod sentence */
           . '.jaxmx{max-width:1080px;margin:22px auto 30px;padding:0 20px;box-sizing:border-box;font-family:' . jaxauth_font_stack() . ' !important;color:var(--ink) !important}'
           . '.jaxmx .jaxmx-hd{border-bottom:3px solid var(--gold) !important;padding-bottom:9px;margin-bottom:14px}'
           . '.jaxmx .jaxmx-t{font-size:26px !important;font-weight:800 !important;letter-spacing:-.01em !important;color:var(--ink) !important;margin:0 !important;line-height:1.25 !important}'
           . '.jaxmx .jaxmx-sub{color:var(--ink2) !important;font-size:13.5px !important;line-height:1.5 !important;margin-top:6px !important}'
           . '.jaxmx .jaxmx-mod{background:var(--panel) !important;border:1px solid var(--hair) !important;border-radius:var(--r-lg) !important;padding:22px !important;box-shadow:var(--shadow) !important;color:var(--ink2) !important;font-size:13.5px !important;line-height:1.5 !important}'
           /* Ryan, Sep 6 2026 graphics and mobile review: DESIGN-SYSTEM.md,
              "Phone, scroll and focus" - tab buttons get the 44px touch target
              too. !important to match every other rule in this block (renders
              outside any iframe, so the Elementor kit can repaint it). Desktop
              sizes are untouched above 560px. */
           . '@media(max-width:560px){.jaxdash-tab,.jaxsub .ptab{min-height:44px !important}}'
           . '</style>';
    /* Ryan, Sep 2 (Tier 1): inline the SAVED tab's first widget, not always
       group 0's - act() mirrors the shown tab into a cookie so a returning
       Payroll user gets Payroll at first paint. Invalid/absent cookie falls
       back to group 0, which is exactly the old behavior. */
    $savedG = isset($_COOKIE['jaxDashTab']) ? (int) $_COOKIE['jaxDashTab'] : 0;
    if ($savedG < 0 || $savedG >= count($groups)) { $savedG = 0; }
    /* Ryan, Sep 4 2026: a user's stored home (jaxauth_home) names the tab the
       canvas opens on at EVERY load - Sam Davis starts on Log Detailing. The
       remembered-tab cookie only steers users who have no home set. */
    $homeK = (string) get_user_meta($u->ID, 'jaxauth_home', true);
    /* Ben, Sep 7 2026 (punch list 14): "All instructor Dashboard default interface should
       be the Safety Page (Safety First). Right now it is defaulting to my hours." Safety
       already led the instructor's tab order; what put them on My Hours was the year-long
       remembered-tab cookie (and an admin's own saved index inside a View-as preview). So
       an instructor canvas - the only kind carrying BOTH a Safety bubble and the
       binding-driven instructor My Hours key, never a contractor, never an editor - gets
       Safety as a derived home unless one is stored. The same rule pins a bound mechanic
       to the MX Overview (Ryan, Sep 7: "landing tab for mechanics"). $gorder is untouched,
       so nobody's saved index moves; a #jaxw- deep link still wins for that one load.
       Shapes, decided before branching: an INSTRUCTOR canvas (Safety + the 'myhours' key)
       wins over the mechanic rule, so Chandara - instructor and bound mechanic - lands on
       Safety like every instructor; a MECHANIC canvas is a bound mechanic WITHOUT any staff
       department (no Accounting / Payroll / Airplanes), so an editor bound for testing
       (Ben as ben-test, or Kim / John if they are bound for a live overtime test) keeps
       their remembered tab. */
    if ($homeK === '') {
      $cvsInstr = false;
      if (isset($groups['Safety'], $groups['My Hours'])) {
        foreach ($groups['My Hours'] as $cvsHx) { if ($cvsHx['key'] === 'myhours') { $cvsInstr = true; break; } }
      }
      $cvsMechOnly = !empty($cvsMech) && isset($groups['MX Overview']) && !isset($groups['Accounting']) && !isset($groups['Payroll']) && !isset($groups['Airplanes']);
      if ($cvsInstr) { $homeK = 'safety'; }
      elseif ($cvsMechOnly) { $homeK = 'mxbrief'; }
    }
    $homeG = -1;
    if ($homeK !== '') {
      $hgi = 0;
      foreach ($groups as $hgw) {
        foreach ($hgw as $hx) { if ($hx['key'] === $homeK) { $homeG = $hgi; } }
        $hgi++;
      }
    }
    if ($homeG > -1) { $savedG = $homeG; }
    /* Ryan, Sep 4 2026 (lease): department sub-menus. A group named in
       $subGroups renders a Pay-Portal-style strip (one .ptab per widget, labels
       from $subLabels, else the widget's menu label) and shows ONE widget at a
       time; every other group stacks its widgets exactly as before. Only the
       first (or the stored home's) sub-panel of the shown bubble is inlined;
       the rest are lazy placeholders the loader still fetches - it drains its
       whole queue, visible or not. A group with a single widget gets no strip. */
    /* Ryan, Sep 7 2026: the MX bubble is a department too - My Hours | Logbook as sub-tabs */
    $subGroups = array('Accounting', 'MX');
    $subLabels = array('auto' => 'Revenue', 'tax' => 'Sales Tax', 'lease' => 'Leases', 'depr' => 'Depreciation', 'depr_view' => 'Depreciation', 'mxbrief' => 'Overview', 'mxtime' => 'My Hours', 'mxlog' => 'Logbook');
    $gi = 0; $tabsH = ''; $bodyH = '';
    foreach ($groups as $gl => $gw) {
      $tabsH .= '<button type="button" class="jaxdash-tab" data-g="' . $gi . '">' . esc_html($gl) . '</button>';
      $keysCsv = implode(',', array_map(function ($x) { return $x['key']; }, $gw));
      $bodyH .= '<div class="jaxdash-g" id="jaxg-' . $gi . '" data-gkeys="' . esc_attr($keysCsv) . '">';
      $isSub = in_array($gl, $subGroups, true) && count($gw) > 1;
      $inlineJ = 0;
      /* pick() below mirrors the chosen sub-tab into a jaxSub-<group> cookie
         (the jaxDashTab pattern), so a returning user's last sub-panel is the
         one inlined at first paint instead of arriving by a lazy fetch. The
         stored home key still wins inside the home group; an absent or unknown
         cookie inlines the first sub-panel, exactly as before. */
      /* Sep 7 2026 review: a view-as preview must neither read nor write the admin's own sub-tab memory */
      $subC = (isset($_COOKIE['jaxSub-' . $gl]) && empty($GLOBALS['jaxauth_viewas_target'])) ? sanitize_key((string) $_COOKIE['jaxSub-' . $gl]) : '';
      if ($isSub) {
        /* Ryan, Sep 4 2026: the house accent - a gold rule with the sub-widget
           tabs directly underneath, the same rhythm as the Pay Portal header. */
        $bodyH .= '<div class="jaxsub-rule"><i></i></div>';
        $bodyH .= '<nav class="jaxsub ptabs" data-sg="' . esc_attr($gl) . '" aria-label="' . esc_attr($gl) . ' sections">';
        foreach ($gw as $j => $t) {
          $bodyH .= '<button type="button" class="ptab" data-k="' . esc_attr($t['key']) . '">' . esc_html(isset($subLabels[$t['key']]) ? $subLabels[$t['key']] : $t['label']) . '</button>';
          if ($gi !== $homeG && $subC !== '' && $t['key'] === $subC) { $inlineJ = $j; }
          if ($gi === $homeG && $t['key'] === $homeK) { $inlineJ = $j; }
        }
        $bodyH .= '</nav>';
      }
      foreach ($gw as $j => $t) {
        if ($gi === $savedG && $j === $inlineJ) {
          $wH = '<div id="jaxw-' . esc_attr($t['key']) . '">' . do_shortcode($t['tag']) . '</div>';
        } else {
          $lazyKeys[] = $t['key'];
          $wH = $phFn($t);
        }
        $bodyH .= $isSub ? ('<div class="jaxsub-p" data-k="' . esc_attr($t['key']) . '">' . $wH . '</div>') : $wH;
      }
      $bodyH .= '</div>';
      $gi++;
    }
    /* Sep 7 2026: an admin bound as a test mechanic (Ben as ben-test) already carries the MX
       widgets as their own bubbles, so the "coming soon" placeholder must not appear too */
    if (jaxauth_is_admin($u) && !isset($groups['MX']) && empty($cvsMech)) {
      $tabsH .= '<button type="button" class="jaxdash-tab" data-g="' . $gi . '">MX</button>';
      $bodyH .= '<div class="jaxdash-g" id="jaxg-' . $gi . '" data-gkeys="">'
        . '<div class="jaxmx"><div class="jaxmx-hd"><div class="jaxmx-t">MX portal coming soon!</div>'
        . '<div class="jaxmx-sub">Maintenance department tools will live here.</div></div>'
        /* Ben, Sep 6 2026: "Rebrand 'Timeclock' to 'My Hours'" - the admin-only
           empty state names the feature the way the mechanics will see it.
           Ryan, Sep 6 2026 design audit: the old word is gone from the copy too. */
        . '<div class="jaxmx-mod">Nothing to show yet. The mechanic My Hours, task mix and MX pay views land in this tab when they are built.</div></div></div>';
    }
    $html .= '<div class="jaxdash-tabs" id="jaxdashTabs">' . $tabsH . '</div>' . $bodyH;
    /* Sep 7 2026 review: a View-as / IP View preview runs under the target's identity but
       in the ADMIN's browser, so remembering the tab there would overwrite the admin's own
       saved index with the previewed person's (Safety = 0 on an instructor canvas). PV=1
       keeps the preview from persisting anything. */
    $html .= '<script>(function(){var tabs=document.querySelectorAll(".jaxdash-tab");var gs=document.querySelectorAll(".jaxdash-g");var PV=' . (!empty($GLOBALS['jaxauth_viewas_target']) ? 1 : 0) . ';'
      . 'function act(i){for(var x=0;x<gs.length;x++){gs[x].classList.toggle("on",x===i);}for(var x=0;x<tabs.length;x++){tabs[x].classList.toggle("on",x===i);}if(PV){return;}try{localStorage.setItem("jaxDashTab",String(i));}catch(e){}try{document.cookie="jaxDashTab="+i+";path=/;max-age=31536000;SameSite=Lax;Secure";}catch(e2){}}'
      . 'for(var x=0;x<tabs.length;x++){(function(i){tabs[i].addEventListener("click",function(){act(i);});})(x);}'
      . 'function byHash(){var h=(window.location.hash||"").replace("#jaxw-","");if(!h){return -1;}for(var x=0;x<gs.length;x++){var ks=(gs[x].getAttribute("data-gkeys")||"").split(",");if(ks.indexOf(h)>-1){return x;}}return -1;}'
      . 'var st=0;try{st=parseInt(localStorage.getItem("jaxDashTab")||"0",10)||0;}catch(e){}if(st<0||st>=gs.length){st=0;}'
      . 'var hm=' . (int) $homeG . ';if(hm>-1){st=hm;}'
      . 'var hi=byHash();act(hi>-1?hi:st);'
      . 'window.addEventListener("hashchange",function(){var i=byHash();if(i>-1){act(i);var el=document.getElementById("jaxw-"+((window.location.hash||"").replace("#jaxw-","")));if(el){el.scrollIntoView();}}});'
      . '})();</script>';
    /* Ryan, Sep 4 2026 (lease): sub-menu behaviour. A click selects; the choice
       is remembered per group in localStorage jaxSub-<group>; a #jaxw-<key>
       deep link (menu pane, hashchange) selects the matching sub-panel; the
       stored home key wins at every load, the way the home tab does above.
       Block comments only, every statement terminated - same rules as srcdoc. */
    /* Sep 7 2026 review: the same PV guard as the tab script - a preview neither reads nor
       writes the admin's own sub-tab memory (localStorage or cookie) */
    $html .= '<script>(function(){var navs=document.querySelectorAll(".jaxsub");if(!navs.length){return;}var HK=' . wp_json_encode($homeK) . ';var PV=' . (!empty($GLOBALS['jaxauth_viewas_target']) ? 1 : 0) . ';'
      . 'function keyOf(h){return (h||"").replace("#jaxw-","");}'
      . 'function has(nav,k){if(!k){return false;}var ts=nav.querySelectorAll(".ptab");for(var i=0;i<ts.length;i++){if(ts[i].getAttribute("data-k")===k){return true;}}return false;}'
      . 'function pick(nav,k,save){var ts=nav.querySelectorAll(".ptab");if(!has(nav,k)){k=ts.length?ts[0].getAttribute("data-k"):"";}for(var i=0;i<ts.length;i++){ts[i].classList.toggle("on",ts[i].getAttribute("data-k")===k);}var ps=nav.parentNode.querySelectorAll(".jaxsub-p");for(var j=0;j<ps.length;j++){ps[j].classList.toggle("on",ps[j].getAttribute("data-k")===k);}if(save&&!PV){try{localStorage.setItem("jaxSub-"+nav.getAttribute("data-sg"),k);}catch(e){}try{document.cookie="jaxSub-"+nav.getAttribute("data-sg")+"="+k+";path=/;max-age=31536000;SameSite=Lax;Secure";}catch(e2){}}}'
      . 'function initial(nav){var hk=keyOf(window.location.hash);if(has(nav,hk)){return hk;}if(has(nav,HK)){return HK;}var s="";if(!PV){try{s=localStorage.getItem("jaxSub-"+nav.getAttribute("data-sg"))||"";}catch(e){}}return s;}'
      . 'for(var n=0;n<navs.length;n++){(function(nav){pick(nav,initial(nav),false);nav.addEventListener("click",function(ev){var b=ev.target&&ev.target.closest?ev.target.closest(".ptab"):null;if(!b){return;}pick(nav,b.getAttribute("data-k"),true);});})(navs[n]);}'
      . 'window.addEventListener("hashchange",function(){var hk=keyOf(window.location.hash);for(var n=0;n<navs.length;n++){if(has(navs[n],hk)){pick(navs[n],hk,true);var el=document.getElementById("jaxw-"+hk);if(el){el.scrollIntoView();}}}});'
      . '})();</script>';
  }
  unset($GLOBALS['jaxauth_canvas_render']);
  if ($lazyKeys) {
    /* Ryan, Sep 2 (Tier 1): the loader now runs TWO fetches at once, batches
       every hidden-tab widget into one comma-list request (one WP boot
       instead of one per widget), starts at DOMContentLoaded instead of
       window load, and a tab click promotes that group's keys to the front.
       A batch that comes back missing a widget re-queues those keys once as
       single fetches (covers the fallback path, which also parses commas). */
    $html .= '<script>(function(){'
      . 'var KEYS=' . wp_json_encode(array_values($lazyKeys)) . ';var MAX=2;var inflight=0;var failed={};'
      . 'function runScripts(root){var ss=root.querySelectorAll("script");for(var i=0;i<ss.length;i++){var o=ss[i];var n=document.createElement("script");if(o.src){n.src=o.src;}else{n.text=o.text;}o.parentNode.replaceChild(n,o);}}'
      . 'function phOf(key){return document.querySelector(".jaxw-lazy[data-jaxw=\""+key+"\"]");}'
      . 'function hiddenKey(key){var ph=phOf(key);if(!ph||!ph.closest){return false;}var g=ph.closest(".jaxdash-g");var sp=ph.closest(".jaxsub-p");return !!((g&&!g.classList.contains("on"))||(sp&&!sp.classList.contains("on")));}'
      . 'var singles=[],batch=[];KEYS.forEach(function(k){(hiddenKey(k)?batch:singles).push(k);});'
      . 'var queue=singles.map(function(k){return [k];});if(batch.length){queue.push(batch.slice());}'
      /* Ryan, Sep 6 2026 design audit: the error names its widget (data-jaxl) and
         reads in --ink2 - "every error says which widget it belongs to". The
         placeholder rule pins --ink3 with !important, so the color is set the same way. */
      . 'function markErr(key,msg){var ph=phOf(key);if(ph&&ph.firstElementChild){ph.firstElementChild.textContent=(ph.getAttribute("data-jaxl")||"This section")+" "+msg;ph.firstElementChild.style.setProperty("color","var(--ink2)","important");}}'
      . 'function insertOne(pay,key){var ph=phOf(key);if(!ph){return true;}var w=pay.querySelector("[id=\"jaxw-"+key+"\"]");if(!w){return false;}var node=document.importNode(w,true);ph.parentNode.replaceChild(node,ph);runScripts(node);return true;}'
      . 'function load(keys,done){'
      . 'fetch(window.location.pathname+"?jaxw="+encodeURIComponent(keys.join(",")),{credentials:"same-origin"}).then(function(r){return r.text();}).then(function(t){'
      . 'var doc=new DOMParser().parseFromString(t,"text/html");var pay=doc.getElementById("jaxwLazyPayload");'
      . 'var missing=[];keys.forEach(function(k){if(!(pay&&insertOne(pay,k))){missing.push(k);}});'
      . 'missing.forEach(function(k){if(keys.length>1&&!failed[k]){failed[k]=1;queue.unshift([k]);}else{markErr(k,"could not load - pull to refresh or reload the page.");}});'
      . 'done();'
      . '}).catch(function(){keys.forEach(function(k){if(keys.length>1&&!failed[k]){failed[k]=1;queue.unshift([k]);}else{markErr(k,"could not load - check the connection and reload.");}});done();});}'
      . 'function next(){while(inflight<MAX&&queue.length){var ks=queue.shift();inflight++;load(ks,function(){inflight--;next();});}}'
      . 'function promote(key){for(var i=0;i<queue.length;i++){var ix=queue[i].indexOf(key);if(ix>-1){if(queue[i].length===1){if(i>0){var it=queue.splice(i,1)[0];queue.unshift(it);}return;}queue[i].splice(ix,1);if(!queue[i].length){queue.splice(i,1);}queue.unshift([key]);return;}}}'
      . 'if("IntersectionObserver" in window){var io=new IntersectionObserver(function(es){var any=false;es.forEach(function(e){if(e.isIntersecting){promote(e.target.getAttribute("data-jaxw"));io.unobserve(e.target);any=true;}});if(any){next();}},{rootMargin:"600px 0px"});'
      . 'document.querySelectorAll(".jaxw-lazy").forEach(function(el){io.observe(el);});}'
      . 'var tabsEl=document.getElementById("jaxdashTabs");'
      . 'if(tabsEl){tabsEl.addEventListener("click",function(ev){var b=ev.target&&ev.target.closest?ev.target.closest(".jaxdash-tab"):null;if(!b){return;}var g=document.getElementById("jaxg-"+b.getAttribute("data-g"));if(!g){return;}var ks=(g.getAttribute("data-gkeys")||"").split(",");for(var i=ks.length-1;i>=0;i--){if(ks[i]){promote(ks[i]);}}next();});}'
      . 'var subNavs=document.querySelectorAll(".jaxsub");for(var sn=0;sn<subNavs.length;sn++){subNavs[sn].addEventListener("click",function(ev){var b=ev.target&&ev.target.closest?ev.target.closest(".ptab"):null;if(!b){return;}promote(b.getAttribute("data-k"));next();});}'
      . 'function kick(){setTimeout(next,150);}'
      . 'if(document.readyState==="interactive"||document.readyState==="complete"){kick();}else{document.addEventListener("DOMContentLoaded",kick);}'
      . '})();</script>';
  }
  return $html;
});

/* -------------------- portal menu (Ryan, Aug 25) --------------------
 * A hamburger on every front-end page for signed-in portal users: their
 * pages, the admin panel for admins, change password, request help, sign
 * out. Anonymous visitors and non-portal users never see it. */
/* Ryan, Sep 9 2026, from a phone screenshot: "Remove the Instagram pop up at the bottom of
   Wordpress." That card is Smash Balloon's critical-issue notice (Instagram Feed Pro 6.9.0).
   The plugin STAYS and the notice is not a bug: the feed is genuinely used on the Home page and
   the Thank You page, it is genuinely broken, and only signed-in admins ever see the warning.
   What is wrong is where it shows up - it floats over the JAXAERO dashboard pages, which carry
   no Instagram feed at all, and on a phone it lands on top of the content.
   So it is suppressed on OUR pages only (the ones in jaxauth_pages plus the canvas and admin
   pages) and left alone everywhere else, so it keeps nagging on the marketing pages where the
   broken feed actually lives.
   Two belts: a CSS rule for the class and id shapes Smash Balloon uses, and - because the exact
   markup of that card could not be inspected from here without signing in - a one-pass sweep
   that removes any floating element announcing itself as an Instagram Feed notice. The sweep
   runs once on load and once more after 1.5s, since the plugin injects the card late. */
function jaxauth_on_dash_page() {
  if (is_admin()) { return false; }
  $id = (int) get_queried_object_id();
  if ($id <= 0) { return false; }
  $pages = get_option('jaxauth_pages', array());
  if (is_array($pages) && array_key_exists($id, $pages)) { return true; }
  return $id === (int) get_option('jaxauth_canvas_page') || $id === (int) get_option('jaxauth_admin_page');
}
add_action('wp_footer', 'jaxauth_hide_feed_notice', 99);
function jaxauth_hide_feed_notice() {
  static $done = false;
  if ($done || !jaxauth_on_dash_page()) { return; }
  $done = true;
  $amp = chr(38);
  echo '<style id="jaxauth-no-sb">'
     . '[class*="sbi"][class*="notice"],[id*="sbi"][id*="notice"],'
     . '[class*="sb-notice"],[id*="sb-notice"],[class*="sb_notice"],[id*="sb_notice"],'
     . '.sbi_frontend_notice,.sbi-frontend-license-notice{display:none !important}'
     . '</style>';
  echo '<script id="jaxauth-no-sb-js">(function(){'
     . 'function sweep(){'
     . 'var all=document.body?document.body.querySelectorAll("div,section,aside"):[];'
     . 'for(var i=0;i<all.length;i++){var e=all[i];'
     . 'if(e.childElementCount>6){continue;}'
     . 'var t=(e.textContent||"");'
     . 'if(t.length>260){continue;}'
     . 'if(!/Instagram Feed/i.test(t)){continue;}'
     . 'if(!/Critical Issue|preventing your Instagram|Resolve this issue/i.test(t)){continue;}'
     . 'var p=getComputedStyle(e).position;'
     . 'if(p!=="fixed"' . $amp . $amp . 'p!=="absolute"' . $amp . $amp . 'p!=="sticky"){continue;}'
     . 'e.style.setProperty("display","none","important");}'
     . '}'
     . 'try{sweep();}catch(e){}'
     . 'setTimeout(function(){try{sweep();}catch(e){}},1500);'
     . '})();</script>';
}
add_action('wp_footer', 'jaxauth_menu_footer');
function jaxauth_menu_footer() {
  static $done = false;
  if ($done || is_admin()) { return; }
  $u = wp_get_current_user();
  if (!$u || !$u->exists()) { return; }
  if (!jaxauth_is_managed($u) && !jaxauth_is_admin($u)) { return; }
  $done = true;
  /* Ryan, Aug 31: the pane is four doors, not a site map - My Data (your User
     Canvas), User Preferences, Get Help, and Admin Portal for admins. The old
     every-page list tripled "Aircraft owner statements" as soon as the canvas
     pages mapped to ownerstmt. */
  $myData = jaxauth_default_dest($u);
  $adminUrl = '';
  if (jaxauth_is_admin($u)) {
    $pgs = get_option('jaxauth_pages', []);
    if (is_array($pgs)) {
      foreach ($pgs as $pid => $key) {
        if ($key === 'access' && get_post_status($pid) === 'publish') { $l = get_permalink($pid); if ($l) { $adminUrl = $l; } }
      }
    }
  }
  $homeP = get_option('jaxauth_signin_page');
  $home = $homeP ? get_permalink($homeP) : home_url('/');
  $restOut = esc_url(rest_url('jaxauth/v1/logout'));
  $nonce = wp_create_nonce('wp_rest');
  /* Ben (Sep-eve doc, Ryan confirmed): widget links are back in the pane,
     above Home. On the canvas a link's hash activates the matching tab. */
  $mnuW = array();
  $cvsP = (int) get_option('jaxauth_canvas_page');
  $cvsUrl = ($cvsP && get_post_status($cvsP) === 'publish') ? get_permalink($cvsP) : '';
  if ($cvsUrl) { $mnuW = jaxauth_canvas_widgets($u); }
  ?>
<style>
<?php echo jaxauth_tokens_css(); ?>
/* Ryan, Sep 6 2026 design audit: control radius --r-sm and the one overlay shadow token, no literal */
.jaxmnu-btn{position:fixed;top:12px;right:12px;z-index:99990;width:42px !important;height:42px !important;min-width:0 !important;border-radius:var(--r-sm) !important;border:1px solid var(--hair2) !important;background:var(--panel) !important;box-shadow:var(--lift) !important;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0 !important;line-height:1 !important}
.jaxmnu-btn span{display:block;width:18px;height:2px;background:var(--ink);position:relative}
.jaxmnu-btn span:before,.jaxmnu-btn span:after{content:'';position:absolute;left:0;width:18px;height:2px;background:var(--ink)}
.jaxmnu-btn span:before{top:-6px}.jaxmnu-btn span:after{top:6px}
/* Ryan, Sep 8 2026: "Mobile hamburger menu does not scroll properly." The pane is position:fixed,
   so page scrolling never moves it; with a dozen widget links it ran past the bottom of a phone
   screen and the overflow:hidden clipped the rest. It now caps at the viewport (dvh where the
   browser has it, so the iOS toolbar does not eat the last items) and scrolls inside itself. */
.jaxmnu-pane{position:fixed;top:60px;right:12px;z-index:99990;width:min(300px,calc(100vw - 24px));max-height:calc(100vh - 72px);max-height:calc(100dvh - 72px);background:var(--panel);border:1px solid var(--hair);border-radius:var(--r-lg);box-shadow:var(--lift);display:none;overflow-x:hidden;overflow-y:auto;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;font-family:<?php echo jaxauth_font_stack(); ?>}
.jaxmnu-pane.on{display:block}
body.admin-bar .jaxmnu-btn{top:44px}body.admin-bar .jaxmnu-pane{top:92px;max-height:calc(100vh - 104px);max-height:calc(100dvh - 104px)}
<?php if (!empty($GLOBALS['jaxauth_viewas_target'])) { ?>
/* Sep 7 2026 review: the view-as preview header is fixed to the top (130px on phones, 56px from
   560px up - the same reserve jaxauth_viewas_banner gives the body), so the menu button and its
   pane step down below it instead of disappearing behind it */
.jaxmnu-btn{top:142px}.jaxmnu-pane{top:190px;max-height:calc(100vh - 202px);max-height:calc(100dvh - 202px)}
@media(min-width:560px){.jaxmnu-btn{top:68px}.jaxmnu-pane{top:116px;max-height:calc(100vh - 128px);max-height:calc(100dvh - 128px)}}
<?php } ?>
.jaxmnu-hd{padding:12px 16px 10px;border-bottom:1px solid var(--hair);font-weight:800 !important;color:var(--brand) !important;font-size:13px !important;letter-spacing:.14em !important;text-transform:uppercase !important;line-height:1.2 !important}
.jaxmnu-pane a,.jaxmnu-pane button.jaxmnu-item{display:block !important;width:100% !important;min-width:0 !important;text-align:left !important;background:none !important;border:0 !important;border-radius:0 !important;box-shadow:none !important;padding:11px 16px !important;font:inherit !important;font-size:13.5px !important;font-weight:400 !important;color:var(--ink) !important;text-decoration:none !important;letter-spacing:0 !important;text-transform:none !important;cursor:pointer}
.jaxmnu-pane a:hover,.jaxmnu-pane button.jaxmnu-item:hover{background:var(--ground) !important;color:var(--ink) !important}
.jaxmnu-sep{border-top:1px solid var(--hair);margin:4px 0}
.jaxmnu-help{display:none;padding:10px 16px 14px}
.jaxmnu-help.on{display:block}
.jaxmnu-help textarea{width:100% !important;min-height:76px;font:inherit !important;font-size:13.5px !important;padding:8px 10px !important;border:1px solid var(--hair2) !important;border-radius:var(--r-sm) !important;background:var(--panel) !important;color:var(--ink) !important;box-sizing:border-box !important}
/* Ryan, Sep 6 2026 design audit: 13.5px, the button spec */
.jaxmnu-help .jaxmnu-send{margin-top:8px;background:var(--ink) !important;color:#fff !important;border:1px solid var(--ink) !important;border-radius:var(--r-sm) !important;box-shadow:none !important;width:auto !important;min-width:0 !important;padding:9px 16px !important;font:inherit !important;font-size:13.5px !important;font-weight:700 !important;letter-spacing:0 !important;text-transform:none !important;cursor:pointer}
.jaxmnu-help .jaxmnu-send:hover{background:var(--ink-d) !important;border-color:var(--ink-d) !important;color:#fff !important}
.jaxmnu-note{font-size:12.5px;padding:0 16px 10px;color:var(--ink2)}
</style>
<button type="button" class="jaxmnu-btn" id="jaxmnuBtn" aria-label="Menu" aria-expanded="false"><span></span></button>
<div class="jaxmnu-pane" id="jaxmnuPane" role="menu">
  <div class="jaxmnu-hd">JAXAERO</div>
  <?php foreach ($mnuW as $mw) { ?><a href="<?php echo esc_url($cvsUrl . '#jaxw-' . $mw['key']); ?>"><?php echo esc_html($mw['label']); ?></a><?php } ?>
  <?php if ($mnuW) { ?><div class="jaxmnu-sep"></div><?php } ?>
  <a href="<?php echo esc_url($myData); ?>">Home</a>
  <a href="<?php echo esc_url(add_query_arg('settings', '1', $home)); ?>">Settings</a>
  <button type="button" class="jaxmnu-item" id="jaxmnuHelpBtn">Help</button>
  <div class="jaxmnu-help" id="jaxmnuHelp">
    <textarea id="jaxmnuHelpTxt" placeholder="What do you need help with?"></textarea>
    <button type="button" class="jaxmnu-send" id="jaxmnuHelpSend">Send to Ryan</button>
  </div>
  <div class="jaxmnu-note" id="jaxmnuNote" style="display:none"></div>
  <?php /* Ryan, Sep 6 2026 design audit: the menu item carries the name of the page it opens */ ?>
  <?php if ($adminUrl !== '') { ?><div class="jaxmnu-sep"></div><a href="<?php echo esc_url($adminUrl); ?>">Access Admin</a><?php } ?>
  <div class="jaxmnu-sep"></div>
  <?php /* Ryan, Sep 6 2026 design audit: one name for the action, same as the settings page */ ?>
  <button type="button" class="jaxmnu-item" id="jaxmnuOut">Sign out</button>
</div>
<script>
(function(){
  var OUTU=<?php echo wp_json_encode($restOut); ?>,MN=<?php echo wp_json_encode($nonce); ?>,HOMEU=<?php echo wp_json_encode(esc_url($home)); ?>,LOUT=<?php echo wp_json_encode(esc_url_raw(wp_specialchars_decode(wp_logout_url($home)))); ?>;
  var btn=document.getElementById('jaxmnuBtn'),pane=document.getElementById('jaxmnuPane');
  if(!btn||!pane){return;}
  btn.addEventListener('click',function(e){e.stopPropagation();var on=pane.classList.toggle('on');btn.setAttribute('aria-expanded',on?'true':'false');});
  document.addEventListener('click',function(e){if(pane.classList.contains('on')&&!pane.contains(e.target)&&e.target!==btn){pane.classList.remove('on');}});
  pane.addEventListener('click',function(e){var a=e.target.closest?e.target.closest('a'):null;if(a){pane.classList.remove('on');}});
  window.addEventListener('keydown',function(e){if(e.key==='Escape'){pane.classList.remove('on');}});
  var hb=document.getElementById('jaxmnuHelpBtn'),hp=document.getElementById('jaxmnuHelp'),hn=document.getElementById('jaxmnuNote');
  if(hb&&hp){hb.addEventListener('click',function(){hp.classList.toggle('on');});}
  var hs=document.getElementById('jaxmnuHelpSend');
  if(hs){hs.addEventListener('click',function(){
    var tx=document.getElementById('jaxmnuHelpTxt');
    var v=tx&&tx.value?tx.value.replace(/^\s+|\s+$/g,''):'';
    if(!v){if(hn){hn.textContent='Say a few words about what you need.';hn.style.display='block';}return;}
    hs.disabled=true;
    fetch(<?php echo wp_json_encode(esc_url_raw(rest_url('jaxauth/v1/help'))); ?>,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-WP-Nonce':MN},body:JSON.stringify({message:v,page:window.location.href})})
      .then(function(r){return r.json().catch(function(){return {};});})
      .then(function(j){hs.disabled=false;if(hn){hn.textContent=(j&&j.ok)?'Sent - Ryan will get back to you.':((j&&j.message)?j.message:'Could not send - try again in a minute.');hn.style.display='block';}if(j&&j.ok&&tx){tx.value='';hp.classList.remove('on');}})
      .catch(function(){hs.disabled=false;if(hn){hn.textContent='Could not send - check the connection.';hn.style.display='block';}});
  });}
  document.getElementById('jaxmnuOut').addEventListener('click',function(){
    fetch(OUTU,{method:'POST',credentials:'same-origin',headers:{'X-WP-Nonce':MN}}).then(function(r){if(r.ok){location=HOMEU;}else{location=LOUT;}}).catch(function(){location=LOUT;});
  });
})();
</script>
  <?php
}

/* -------------------- shared iframe wrapper -------------------- */

/* body.scrollHeight, never documentElement (the K10 ratchet lesson). */
function jaxauth_iframe($html, $fid, $title) {
  /* No scrolling="no"/overflow:hidden: if the parent resize listener is ever
     delayed or killed (WP Rocket delay-JS), the frame scrolls internally
     instead of hard-clipping the buttons below the fold. When the listener
     runs, the height is exact and no scrollbar shows. */
  /* Ryan, Aug 24 (KJ mobile test): on phones the theme's page template offsets
     its content container, clipping the frame's left edge. Below 700px the
     wrapper full-bleeds to the real viewport (100vw self-centered), immune to
     whatever margins the theme applies. Desktop keeps the contained layout. */
  /* Ryan, Sep 6 2026 graphics and mobile review: 100vw includes a reserved
     desktop scrollbar gutter (Chrome/Edge/Firefox on Windows), so narrowing
     such a browser below 700px could push this wrapper past the true edge and
     put a horizontal scrollbar on the whole outer page. --jax-vw, set from
     clientWidth by the script below, excludes the gutter; 100vw is only the
     fallback for the instant before that script runs. */
  return '<style>@media(max-width:700px){#' . esc_attr($fid) . '_w{width:var(--jax-vw,100vw) !important;position:relative;left:50%;margin-left:calc(var(--jax-vw, 100vw) / -2) !important}}</style>'
    . '<div id="' . esc_attr($fid) . '_w" style="display:block;width:100%;margin:0;padding:0;line-height:0">'
    . '<iframe id="' . esc_attr($fid) . '" srcdoc="' . esc_attr($html) . '" '
    . 'style="display:block;width:100%;height:1100px;border:0;margin:0;overflow:auto" '
    . 'title="' . esc_attr($title) . '"></iframe></div>'
    . '<script>(function(){var f=document.getElementById("' . esc_js($fid) . '");var last=0;'
    /* Ryan, Sep 6 2026 graphics and mobile review: true visible width for the
       CSS custom property the style block above reads, not the
       scrollbar-inclusive vw unit. */
    . 'function setJaxVw(){try{document.documentElement.style.setProperty("--jax-vw",document.documentElement.clientWidth+"px");}catch(e3){}}'
    . 'setJaxVw();window.addEventListener("resize",setJaxVw);'
    . 'window.addEventListener("message",function(e){var d=e.data;if(d&&d.jaxauthH&&Math.abs(d.jaxauthH-last)>2){last=d.jaxauthH;var fl=0;try{fl=window.innerHeight-f.getBoundingClientRect().top-(window.pageYOffset||0)*0;fl=window.innerHeight-f.getBoundingClientRect().top;}catch(e2){}f.style.height=Math.max(d.jaxauthH+24,fl)+"px";}});})();</script>';
}

/* Ryan, Sep 8 2026: 'Add a "show password" eyeball button when people enter a password.' One
   CSS block and one script, shared by the sign-in frame, the settings frame (current / new /
   new again) and the page-password form WordPress prints for a protected page: every
   input[type=password] is wrapped and gets an eye button that flips it to text and back.
   The button is type=button, so Enter still submits the form it sits in. */
function jaxauth_pw_eye_css() {
  return '.pwf{position:relative;display:block}.pwf input{padding-right:46px}'
       . '.pweye{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:36px;height:36px;border:0;background:none;padding:0;margin:0;cursor:pointer;color:var(--ink2);display:flex;align-items:center;justify-content:center;border-radius:var(--r-sm);box-shadow:none}'
       . '.pweye:hover{color:var(--ink)}.pweye svg{width:20px;height:20px;display:block}';
}
function jaxauth_pw_eye_js() {
  $js = <<<'JS'
(function(){
  var EYE='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  var OFF='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/><path d="M3 3l18 18"/></svg>';
  var ins=document.querySelectorAll('input[type="password"]');
  for(var i=0;i<ins.length;i++){(function(inp){
    if(inp.getAttribute('data-eye')==='1'){return;}
    inp.setAttribute('data-eye','1');
    var w=document.createElement('span');w.className='pwf';
    inp.parentNode.insertBefore(w,inp);w.appendChild(inp);
    var b=document.createElement('button');b.type='button';b.className='pweye';b.setAttribute('aria-label','Show password');b.setAttribute('aria-pressed','false');b.setAttribute('tabindex','-1');b.innerHTML=EYE;
    b.addEventListener('click',function(){var show=inp.type==='password';inp.type=show?'text':'password';b.innerHTML=show?OFF:EYE;b.setAttribute('aria-label',show?'Hide password':'Show password');b.setAttribute('aria-pressed',show?'true':'false');inp.focus();});
    w.appendChild(b);
  })(ins[i]);}
})();
JS;
  return $js;
}

function jaxauth_frame_head() {
  /* The shared head for the three srcdoc documents this snippet renders - the
     sign-in page, the user settings page and the Access admin. It opens with
     the house token block (docs/DESIGN-SYSTEM.md) and then defines only house
     components: the .hd page header, the .mod card, .b1/.b2 buttons, the table
     and the three alert surfaces. No rule below invents a colour, a radius or
     a font stack. Inside a frame there is no Elementor kit to fight, so
     nothing here needs an !important pin.
     The bare .brand / h1 / .sub rules below the .hd block are a deliberate
     fallback for any header that is not wrapped in .hd. Every header in the
     three frame documents today IS wrapped, so .hd .brand / .hd h1 / .hd .sub
     win on specificity in every current case and the bare rules paint nothing.
     Keep them or delete them as a pair with that fact in mind.
     .btn / .btn.ghost / .btn.red are kept as aliases of .b1 / .b2 so any
     markup that still carries the old class name renders identically - this
     is the sign-in page, and a missed class must not become a dead button.
     Note the alias is not value-neutral: .btn.red resolves to the navy .b1
     fill, so legacy "btn red" markup injected from elsewhere would change
     meaning, not just colour.
     Remove the .btn aliases after one clean deploy - grep confirmed zero .btn
     markup in this file on Sep 4 2026. */
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    . '<meta name="viewport" content="width=device-width,initial-scale=1"><style>'
    . jaxauth_tokens_css()
    . '*{box-sizing:border-box}'
    /* Ryan, Sep 6 2026 design audit: body 13.5/1.5, the type scale; inputs keep their own 15px */
    . 'body{margin:0;background:var(--ground);color:var(--ink);font-family:' . jaxauth_font_stack() . ';font-size:13.5px;line-height:1.5}'
    . '.wrap{max-width:1080px;margin:0 auto;padding:6px 20px 14px}'
    . '.hd{border-bottom:3px solid var(--gold);padding-bottom:9px;margin-bottom:14px}'
    . '.hd .brand{display:block;font-weight:800;letter-spacing:.14em;font-size:13px;color:var(--brand);text-transform:uppercase}'
    . '.hd h1{margin:6px 0 4px;font-size:26px;color:var(--ink);font-weight:800;letter-spacing:-.01em;line-height:1.25}'
    . '.hd .sub{color:var(--ink2);font-size:13.5px;line-height:1.5;margin-top:6px}'
    . '.brand{font-weight:800;letter-spacing:.14em;font-size:13px;color:var(--brand)}'
    . 'h1{margin:6px 0 4px;font-size:26px;font-weight:800;letter-spacing:-.01em;color:var(--ink)}'
    . '.sub{color:var(--ink2);font-size:13.5px;line-height:1.5}'
    . '.mod{background:var(--panel);border:1px solid var(--hair);border-radius:var(--r-lg);padding:22px;box-shadow:var(--shadow);margin:0 0 18px}'
    . '.cardh,.mod>b:first-child{display:block;font-size:15.5px;font-weight:700;color:var(--ink);margin-bottom:4px}'
    . '.fld{margin-bottom:13px}'
    . '.fld label{display:block;font-size:11.5px;font-weight:800;letter-spacing:.08em;color:var(--ink2);margin-bottom:5px;text-transform:uppercase}'
    . '.fld input,.fld select,.fld textarea{width:100%;border:1px solid var(--hair2);border-radius:var(--r-sm);padding:10px 12px;font:inherit;font-size:15px;color:var(--ink);background:var(--panel)}'
    . jaxauth_pw_eye_css()
    . '.b1,.b2,.btn{display:inline-block;border-radius:var(--r-sm);padding:9px 16px;font:inherit;font-size:13.5px;font-weight:700;line-height:1.2;cursor:pointer;text-decoration:none}'
    . '.b1,.btn,.btn.red{background:var(--ink);color:#fff;border:1px solid var(--ink)}'
    . '.b1:hover,.btn:hover,.btn.red:hover{background:var(--ink-d);border-color:var(--ink-d);color:#fff}'
    . '.b2,.btn.ghost{background:var(--panel);color:var(--ink);border:1px solid var(--hair2)}'
    . '.b2:hover,.btn.ghost:hover{background:var(--tint);color:var(--ink)}'
    /* destructive: --red text on white, never a red fill (DESIGN-SYSTEM.md) */
    . '.bdel,.bdel:hover{color:var(--red)}'
    . '.b1:disabled,.b2:disabled,.btn:disabled,.tg:disabled{opacity:.45;cursor:default}'
    /* Ryan, Sep 6 2026 graphics and mobile review: one focus ring, everywhere
       in this document (DESIGN-SYSTEM.md, "Phone, scroll and focus"). No
       outline:none exists in this file. */
    . ':focus-visible{outline:2px solid var(--ink);outline-offset:2px;border-radius:var(--r-sm)}'
    . '.err{display:none;background:var(--red-tint);border:1px solid var(--red-line);color:var(--red);border-radius:var(--r-md);padding:10px 12px;font-size:13.5px;margin-bottom:12px}'
    . '.err.on{display:block}'
    . '.okmsg{display:none;background:var(--green-tint);border:1px solid var(--green-line);color:var(--green);border-radius:var(--r-md);padding:10px 12px;font-size:13.5px;margin-bottom:12px}'
    . '.okmsg.on{display:block}'
    /* Ryan, Sep 6 2026 design audit: 13.5px like its .err/.okmsg siblings */
    . '.note{background:var(--amber-tint);border:1px solid var(--amber-line);color:var(--amber);border-radius:var(--r-md);padding:10px 12px;font-size:13.5px;margin-bottom:12px}'
    . '.small{font-size:12.5px;color:var(--ink2)}'
    . 'table{width:100%;border-collapse:collapse}'
    . 'th{text-align:left;font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink2);font-weight:800;padding:7px 9px;border-bottom:1px solid var(--hair);background:var(--tint)}'
    . 'td{padding:8px 9px;border-bottom:1px solid var(--hair);font-size:13.5px;vertical-align:middle}'
    . '.ulist{max-height:560px;overflow-y:auto}'
    . '.urow{display:flex;align-items:center;gap:9px;width:100%;text-align:left;background:none;border:0;border-radius:var(--r-sm);padding:8px 9px;cursor:pointer;font:inherit;color:var(--ink)}'
    . '.urow:hover{background:var(--ground)}.urow.on{background:var(--ink);color:#fff}'
    . '.urow>span:first-child{min-width:0;overflow:hidden}'
    . '.urow .em{display:block;font-size:11.5px;color:var(--ink2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.urow.on .em{color:var(--hair2)}'
    /* Ryan, Sep 6 2026 design audit: tokens on the selected row, no alpha whites */
    . '.chip{margin-left:auto;font-size:11.5px;font-weight:800;letter-spacing:.04em;border-radius:var(--r-pill);padding:2px 8px;background:var(--track);color:var(--ink2)}'
    . '.urow.on .chip{background:var(--panel);color:var(--ink)}'
    . '.grid2{display:grid;grid-template-columns:270px 1fr;gap:14px;align-items:start}'
    . '@media(max-width:820px){.grid2{grid-template-columns:1fr}}'
    /* Ryan, Sep 6 2026 graphics and mobile review: DESIGN-SYSTEM.md, "Phone,
       scroll and focus" - touch targets are 44px. .b1/.b2/.btn at padding:9px
       16px with 13.5px type land at 38px; .fld input/select/textarea land
       around the same. Desktop sizes are untouched above 560px. */
    . '@media(max-width:560px){.b1,.b2,.btn,.fld input,.fld select,.fld textarea{min-height:44px}}'
    . '.tg{position:relative;width:42px;height:24px;border-radius:var(--r-pill);border:0;cursor:pointer;background:var(--ink3)}'
    /* Ryan, Sep 6 2026 design audit: the knob shadow is the token; an enabled toggle
       is chrome, so it is navy like every other selected state here, not --green */
    . '.tg:after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:var(--panel);box-shadow:var(--shadow)}'
    . '.tg.on{background:var(--ink)}.tg.on:after{left:21px}'
    . '.hstar{background:none;border:0;cursor:pointer;font:inherit;font-size:16px;line-height:1;color:var(--ink3);padding:0 3px;margin-left:4px;vertical-align:middle}.hstar.on{color:var(--gold)}'
    . '.arow{display:flex;gap:12px;padding:8px 2px;border-top:1px solid var(--hair);font-size:13px}'
    . '.arow time{flex:none;width:120px;color:var(--ink3);font-size:12.5px;font-variant-numeric:tabular-nums}'
    . '</style></head><body>';
}

function jaxauth_frame_foot() {
  /* Ryan, Sep 8 2026: the show-password eye runs in every frame document first */
  return '<script>' . jaxauth_pw_eye_js() . '</script><script>(function(){var l=0;function h(){var v=document.body.scrollHeight;var t=v;try{var fe=window.frameElement;if(fe){var pIH=(window.parent&&window.parent.innerHeight)||0;var top=fe.getBoundingClientRect().top+((window.parent&&window.parent.pageYOffset)||0);t=Math.max(v+24,pIH-Math.max(0,top));if(Math.abs(fe.getBoundingClientRect().height-t)>8){fe.style.height=t+"px";}}}catch(e){}if(Math.abs(v-l)>2){l=v;if(window.parent!==window){window.parent.postMessage({jaxauthH:v},"*");}}}h();setInterval(h,700);})();</script></body></html>';
}

/* -------------------- [jaxaero_login] -------------------- */

add_shortcode('jaxaero_login', function () {
  $u = wp_get_current_user();
  if ($u && $u->exists() && jaxauth_is_managed($u)) {
    return jaxauth_iframe(jaxauth_home_html($u), 'jaxAuthHome', 'JAXAERO dashboard home');
  }
  if ($u && $u->exists() && jaxauth_is_admin($u)) {
    return jaxauth_iframe(jaxauth_home_html($u), 'jaxAuthHome', 'JAXAERO dashboard home');
  }
  return jaxauth_iframe(jaxauth_login_html(), 'jaxAuthLogin', 'JAXAERO sign in');
});

function jaxauth_login_html() {
  $rest = esc_url_raw(rest_url('jaxauth/v1/login'));
  ob_start(); ?>
<?php echo jaxauth_frame_head(); ?>
<div class="wrap" style="max-width:440px">
  <?php /* Ryan, Sep 6 2026 design audit: left-aligned like every other header; the doc has no centered variant */ ?>
  <div class="hd">
    <?php if (empty($GLOBALS['jaxauth_canvas_render'])): ?><span class="brand">JAXAERO</span><?php endif; ?>
    <h1>Sign In to Your Dashboard</h1>
    <div class="sub">Your dashboards, pay and documents in one place.</div>
  </div>
  <div class="mod">
    <div class="err" id="err"></div>
    <div class="fld"><label for="em">Email or sign-in name</label>
      <input id="em" type="text" autocomplete="username" placeholder="you@flyjaxaero.com" inputmode="email" autocapitalize="none" spellcheck="false"></div>
    <div class="fld"><label for="pw">Password</label>
      <input id="pw" type="password" autocomplete="current-password"></div>
    <button class="b1" id="go" style="width:100%">Sign in</button>
  </div>
  <p class="small" style="line-height:1.55">Forgot your password? <a href="<?= esc_url(wp_lostpassword_url()) ?>" target="_top" style="color:var(--ink);font-weight:700">Reset it by email</a>.<br>Five failed attempts locks sign-in for 15 minutes.<br>This page never asks for a Flight Schedule Pro login.</p>
</div>
<script>
(function(){
  var REST=<?php echo wp_json_encode($rest); ?>;
  var go=document.getElementById('go'),err=document.getElementById('err');
  function fail(m){err.textContent=m;err.classList.add('on');go.disabled=false;go.textContent='Sign in';}
  function submit(){
    err.classList.remove('on');go.disabled=true;go.textContent='Signing in...';
    fetch(REST,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:document.getElementById('em').value.trim(),password:document.getElementById('pw').value})})
    .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});})
    .then(function(x){
      if(x.s===200&&x.j&&x.j.ok){var w=(window.parent!==window)?window.parent:window;var d=x.j.dest||'';if(d&&!x.j.mustChange){w.location=d;}else{w.location.reload();}return;}
      fail(x.j&&x.j.message?x.j.message:'That email and password combination did not work.');
    })
    .catch(function(){fail('Could not reach the site. Check your connection and try again.');});
  }
  go.addEventListener('click',submit);
  document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter'){submit();}});
})();
</script>
<?php echo jaxauth_frame_foot();
  return ob_get_clean();
}

function jaxauth_home_html($u) {
  $restPw  = esc_url_raw(rest_url('jaxauth/v1/change-password'));
  $restOut = esc_url_raw(rest_url('jaxauth/v1/logout'));
  $nonce   = wp_create_nonce('wp_rest');
  $must    = get_user_meta($u->ID, 'jaxauth_must_change', true) === '1';
  $chpw    = isset($_GET['chpw']);
  /* Ryan, Aug 31: the widget selector (cards + home-screen stars) is gone for
     everyone - landing is the User Canvas and navigation is My Data in the menu.
     This screen is preferences only: password, help, sign out. The stored
     jaxauth_home pref still routes for anyone who set one; only its UI left. */
  ob_start(); ?>
<?php echo jaxauth_frame_head(); ?>

<div class="wrap">
  <div class="hd">
    <?php if (empty($GLOBALS['jaxauth_canvas_render'])): ?><span class="brand">JAXAERO</span><?php endif; ?>
    <?php /* Ryan, Sep 6 2026 design audit: the h1 is the page name (the menu calls it Settings);
             the canvas greeting is the one welcome. Sign out renders at the .b2 spec. */ ?>
    <h1>Settings</h1>
    <div class="sub">Your account preferences. Signed in as <?php echo esc_html((string) $u->user_email !== '' ? $u->user_email : $u->user_login); ?>.</div>
  </div>
  <div style="margin:0 0 14px"><button class="b2" id="out">Sign out</button></div>
  <?php if ($must) { ?><div class="note"><b>Please choose a new password now.</b> The one you signed in with was temporary.</div><?php } ?>
  <div class="mod" id="chpw" style="max-width:430px">
    <b>Change Your Password</b>
    <div class="small" style="margin-bottom:10px">At least <?php echo (int) JAXAUTH_MIN_PW; ?> characters. Takes effect immediately.</div>
    <div class="err" id="perr"></div><div class="okmsg" id="pok">Password changed.</div>
    <div class="fld"><label for="cur">Current password</label><input id="cur" type="password" autocomplete="current-password"></div>
    <div class="fld"><label for="nw">New password</label><input id="nw" type="password" autocomplete="new-password"></div>
    <div class="fld"><label for="nw2">New password again</label><input id="nw2" type="password" autocomplete="new-password"></div>
    <button class="b1" id="pgo">Change password</button>
  </div>
  <div class="mod" id="helpmod" style="max-width:430px">
    <b>Request Help</b>
    <div class="small" style="margin-bottom:10px">Describe the problem - this goes straight to Ryan by email.</div>
    <div class="err" id="herr"></div><div class="okmsg" id="hok">Sent - Ryan has it in his inbox.</div>
    <div class="fld"><textarea id="htxt" rows="4" style="font-size:13.5px;padding:8px 10px" placeholder="What is going wrong?"></textarea></div>
    <button class="b1" id="hgo">Send to Ryan</button>
  </div>
</div>
<script>
(function(){
  var PW=<?php echo wp_json_encode($restPw); ?>,OUT=<?php echo wp_json_encode($restOut); ?>,N=<?php echo wp_json_encode($nonce); ?>;
  var HLP=<?php echo wp_json_encode(esc_url_raw(rest_url('jaxauth/v1/help'))); ?>;
  var MUSTN=<?php echo $must ? 'true' : 'false'; ?>,CHW=<?php echo $chpw ? 'true' : 'false'; ?>;
  var perr=document.getElementById('perr'),pok=document.getElementById('pok'),pgo=document.getElementById('pgo');
  function pfail(m){perr.textContent=m;perr.classList.add('on');pgo.disabled=false;}
  document.getElementById('pgo').addEventListener('click',function(){
    perr.classList.remove('on');pok.classList.remove('on');
    var nw=document.getElementById('nw').value;
    if(nw!==document.getElementById('nw2').value){pfail('The two new passwords do not match.');return;}
    pgo.disabled=true;
    fetch(PW,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-WP-Nonce':N},
      body:JSON.stringify({current:document.getElementById('cur').value,new_password:nw})})
    .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});})
    .then(function(x){
      if(x.s===200&&x.j&&x.j.ok){pok.classList.add('on');pgo.disabled=false;
        document.getElementById('cur').value='';document.getElementById('nw').value='';document.getElementById('nw2').value='';
        var nt=document.querySelector('.note');if(nt){nt.style.display='none';}
        if(MUSTN&&x.j.dest){setTimeout(function(){var w=(window.parent!==window)?window.parent:window;w.location=x.j.dest;},900);}
        return;}
      pfail(x.j&&x.j.message?x.j.message:'That did not work.');
    })
    .catch(function(){pfail('Could not reach the site.');});
  });
  document.getElementById('out').addEventListener('click',function(){
    fetch(OUT,{method:'POST',credentials:'same-origin',headers:{'X-WP-Nonce':N}})
    .then(function(){if(window.parent!==window){window.parent.location.reload();}else{location.reload();}});
  });
  if(CHW){setTimeout(function(){var m=document.getElementById('chpw');if(m){m.scrollIntoView({block:'start'});}var c=document.getElementById('cur');if(c){c.focus({preventScroll:true});}},350);}
  var hgo=document.getElementById('hgo');
  if(hgo){hgo.addEventListener('click',function(){
    var herr=document.getElementById('herr'),hok=document.getElementById('hok'),t=document.getElementById('htxt');
    herr.classList.remove('on');hok.classList.remove('on');
    if(!t.value.trim()){herr.textContent='Describe the problem first.';herr.classList.add('on');return;}
    hgo.disabled=true;
    fetch(HLP,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-WP-Nonce':N},body:JSON.stringify({message:t.value,page:'user settings page'})})
    .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});})
    .then(function(x){hgo.disabled=false;
      if(x.s===200&&x.j&&x.j.ok){t.value='';hok.classList.add('on');return;}
      herr.textContent=(x.j&&x.j.message)?x.j.message:'Could not send - call or text Ryan.';herr.classList.add('on');})
    .catch(function(){hgo.disabled=false;herr.textContent='Could not reach the site.';herr.classList.add('on');});
  });}
})();
</script>
<?php echo jaxauth_frame_foot();
  return ob_get_clean();
}

/* -------------------- [jaxaero_access_admin] -------------------- */

add_shortcode('jaxaero_access_admin', function () {
  if (!jaxauth_is_admin()) {
    return jaxauth_denied_html();
  }
  return jaxauth_iframe(jaxauth_admin_html(), 'jaxAuthAdmin', 'JAXAERO access admin');
});

function jaxauth_admin_html() {
  $nonce = wp_create_nonce('wp_rest');
  /* Ryan, Sep 3 2026: a button to the IT status page (snippet 20) from the admin portal */
  $itPg = get_page_by_path('it-status'); $itUrl = $itPg ? get_permalink($itPg) : home_url('/it-status/');
  $restBase = esc_url_raw(rest_url('jaxauth/v1/'));
  $reg = jaxauth_registry();
  $users = [];
  /* Ryan, Sep 4 2026: Sam Davis is a 1099 detailer, not a CFI. The list chip
     must say which kind of pay page a binding points at, so each row carries
     'ct' (binding is in jaxpay_contractors - read only, never written here). */
  $ctSlugs = get_option('jaxpay_contractors', array());
  if (!is_array($ctSlugs)) { $ctSlugs = array(); }
  /* Ryan, Sep 4 2026: staff administrators (Ryan) list beside managed members
     (Ben) so one screen drives both and their canvases can be made identical. */
  $jxPeople = get_users(['role' => JAXAUTH_ROLE]);
  $jxSeen = array();
  foreach ($jxPeople as $wu) { $jxSeen[$wu->ID] = true; }
  foreach (get_users(['role' => 'administrator']) as $wa) {
    if (empty($jxSeen[$wa->ID])) { $jxPeople[] = $wa; $jxSeen[$wa->ID] = true; }
  }
  usort($jxPeople, function ($a, $b) { return strcasecmp($a->display_name, $b->display_name); });
  foreach ($jxPeople as $wu) {
    $bSlug = (string) get_user_meta($wu->ID, 'jaxauth_instructor', true);
    $users[] = [
      /* a no-email (lessor) account shows its sign-in name where the email would be */
      'id' => $wu->ID, 'n' => $wu->display_name, 'e' => ((string) $wu->user_email !== '' ? $wu->user_email : $wu->user_login),
      'g' => jaxauth_grants($wu->ID),
      'b' => $bSlug,
      'ct' => ($bSlug !== '' && in_array(sanitize_title($bSlug), $ctSlugs, true)),
      'd' => !jaxauth_enabled($wu->ID),
      'ac' => array_values((array) get_user_meta($wu->ID, 'jaxown_aircraft', true)),
      'hm' => (string) get_user_meta($wu->ID, 'jaxauth_home', true),
      /* Sep 4 2026 review (SEC-6): a WordPress administrator is an admin
         regardless of the jaxauth_admin cap (jaxauth_is_admin says so), so his
         row reads ADMIN; 'wp' locks the toggle - nothing here can change it. */
      'a' => user_can($wu, JAXAUTH_CAP) || user_can($wu, 'manage_options'),
      'wp' => user_can($wu, 'manage_options'),
    ];
  }
  $acd0 = get_option('jaxac_data_last', array());
  $acTails = (is_array($acd0) && !empty($acd0['fleet']) && is_array($acd0['fleet']))
    ? array_keys($acd0['fleet']) : array('N768SP', 'N146F', 'N1196M', 'N234ZG', 'N9711S');
  $slugs = array_keys((array) get_option('jaxpay_instructors', []));
  $pageKeys = array_values(array_diff(array_unique(array_intersect(array_values((array) get_option('jaxauth_pages', [])), array_keys($reg))), ['access']));
  $log = get_option('jaxauth_log', []);
  if (!is_array($log)) { $log = []; }
  $log = array_slice($log, 0, 40);
  $aiKey = (string) get_option('jaxaero_anthropic_key', '');
  $aiSet = $aiKey !== '' ? ('Set - ends ' . substr($aiKey, -4)) : 'Not set';
  $aiAt = (string) get_option('jaxaero_anthropic_key_at', '');
  $aiNote = $aiKey !== '' ? ('An Anthropic API key has been added (ends ' . substr($aiKey, -4) . ($aiAt !== '' ? ', saved ' . $aiAt : '') . ').') : '';
  ob_start(); ?>
<?php echo jaxauth_frame_head(); ?>
<style>
.arow>span{min-width:0;overflow-wrap:anywhere}
/* Ryan, Sep 6 2026 graphics and mobile review: 820px matches .grid2's own
   stack breakpoint (frame head, jaxauth_frame_head) so the touch-enlarged
   toggles/star/buttons below turn on at the same width where this screen
   already drops to one column - was 700px, missing 701-820px (iPad Mini,
   iPad, iPad Air/Pro portrait). */
@media(max-width:820px){
.tg{width:58px;height:40px;border:8px solid transparent;background-clip:padding-box}
.hstar{font-size:22px;padding:9px 12px;margin-left:2px}
#addU{padding:12px 14px !important}
#dd{width:24px;height:24px}
}
</style>
<div class="wrap">
  <div class="hd">
    <?php if (empty($GLOBALS['jaxauth_canvas_render'])): ?><span class="brand">JAXAERO</span><?php endif; ?>
    <h1>Access Admin</h1>
    <div class="sub">Pick a person, flip toggles, save. Changes apply on their next page load. Every save is logged below.</div>
  </div>
  <?php /* Ryan, Sep 6 2026 design audit: no inline font-size or padding on buttons - .b1/.b2 render at the 13.5px / 9px 16px spec */ ?>
  <?php /* Ryan, Sep 9 2026: "Make the IT infrastructure tool a submenu item in an IT status
           section that lives in the admin dashboard." One IT section, two entries, each opening
           its own tab of the IT widget. */ ?>
  <div class="mod" style="margin:0 0 14px">
    <span class="cardh">IT</span>
    <?php /* Ryan, Sep 9 2026: "remove the descriptors ... that live around the buttons for
             those" - the two entries are self-describing, and on a phone the sentences pushed
             the second button most of a screen below the first. */ ?>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:4px">
      <a class="b2" href="<?php echo esc_url($itUrl); ?>" target="_top">IT Status</a>
      <a class="b2" href="<?php echo esc_url($itUrl . '#infrastructure'); ?>" target="_top">IT Infrastructure</a>
    </div>
  </div>
  <div class="grid2">
    <div class="mod ulist">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px">
        <span class="cardh" style="margin-bottom:0">People</span><button class="b2" id="addU">+ Add user</button></div>
      <div id="ulist"></div>
    </div>
    <div class="mod">
      <div class="err" id="aerr"></div><div class="okmsg" id="aok">Saved.</div>
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;border-bottom:1px solid var(--hair);padding-bottom:14px;margin-bottom:14px">
        <div class="fld" style="flex:1;min-width:150px;margin:0"><label>Name</label><input id="dn" autocomplete="off"></div>
        <div class="fld" style="flex:1;min-width:170px;margin:0"><label>Email</label><input id="de" readonly></div>
        <div class="fld" style="flex:1;min-width:150px;margin:0"><label>Pay page binding</label><select id="db"></select></div>
        <label class="small" style="display:flex;align-items:center;gap:6px;padding-bottom:4px"><input type="checkbox" id="dd"> Disabled</label>
        <label class="small" id="admwrap" style="display:flex;align-items:center;gap:8px;padding-bottom:4px" title="Dashboard admin can open Access admin, view as anyone and see every gated page. Only a WordPress administrator can change it."><button type="button" class="tg" id="adm" aria-label="toggle dashboard admin"></button> Dashboard admin</label>
        <?php /* Ryan, Sep 6 2026 design audit: no inline font-size, .b2 renders at the 13.5px spec */ ?>
        <button class="b2" id="resetPw">Reset password</button>
        <button class="b2" id="viewAs">View as user</button>
        <button class="b2 bdel" id="delU">Delete user</button>
      </div>
      <div style="overflow-x:auto"><table id="mx">
        <tr><th>Widget</th><th></th><th style="width:48px">On</th></tr>
      </table></div>
      <div class="small" style="margin:10px 2px 0">&#9733; marks this person's home screen - the page they land on right after signing in. Turn a widget on, then click its star; click it again to return to the default (staff land on Revenue - AUTO, aircraft owners on My Aircraft). "View as user" opens a new tab showing the portal exactly as they see it; the banner at the bottom of that view ends the 15-minute preview.</div>
      <div style="display:flex;justify-content:flex-end;align-items:center;gap:12px;border-top:1px solid var(--hair);margin-top:12px;padding-top:14px">
        <button class="b1" id="save">Save access</button></div>
    </div>
  </div>
  <div class="mod" id="fqamod">
    <b>FOQA Safety Deck</b>
    <div class="small" style="margin-bottom:8px">Drop Kasen's monthly .pptx to update the instructor safety panel. Parsed and shown to you before anything is saved. <span id="fqamonths"></span></div>
    <div id="fqaZone" style="border:2px dashed var(--hair2);border-radius:var(--r-md);background:var(--tint);padding:14px;text-align:center;cursor:pointer;font-size:13px">
      <b>Drop the .pptx here</b> <span style="color:var(--ink2)">or click to choose</span>
      <input type="file" id="fqaFile" accept=".pptx" style="display:none">
    </div>
    <div id="fqaMsg" class="small" style="margin-top:8px;font-weight:700;min-height:16px"></div>
    <div id="fqaOut" class="small" style="margin-top:6px;display:none"></div>
  </div>
  <div class="mod">
    <b>Anthropic API Key &mdash; Key Only</b>
    <div class="small" style="margin-bottom:8px">This box takes ONLY the Anthropic API key that powers invoice reading. It is not a place to upload documents. Stored server-side and never shown again after saving. Status: <span id="aist"><?php echo esc_html($aiSet); ?></span></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input type="password" id="aikey" placeholder="sk-ant-..." autocomplete="off" style="flex:1;min-width:220px;font:inherit;padding:10px 12px;border:1px solid var(--hair2);border-radius:var(--r-sm);color:var(--ink);background:var(--panel)">
      <?php /* Ryan, Sep 6 2026 design audit: no inline font-size, .b1 renders at the 13.5px spec */ ?>
      <button class="b1" id="aisave">Save key</button>
    </div>
    <div id="ainote" class="small" style="margin-top:8px;font-weight:700;color:var(--green);<?php echo $aiNote === '' ? 'display:none' : ''; ?>"><?php echo esc_html($aiNote); ?></div>
  </div>
  <div id="pwov" style="display:none;position:fixed;inset:0;background:var(--scrim);z-index:99;align-items:flex-start;justify-content:center;padding:96px 16px 16px">
    <div style="background:var(--panel);border:1px solid var(--hair);border-radius:var(--r-lg);padding:22px;max-width:430px;width:100%;box-shadow:var(--lift)">
      <b id="pwtitle" class="cardh">Temporary Password</b>
      <div class="small" style="margin:6px 0 10px">Shown once. Hand it over out of band - the site never emails it. A new password is required at first sign-in.</div>
      <div style="display:flex;gap:8px">
        <input id="pwval" readonly autocomplete="off" style="flex:1;font-family:Consolas,Menlo,monospace;font-size:15px;padding:10px 12px;border:1px solid var(--hair2);border-radius:var(--r-sm);color:var(--ink);background:var(--panel)">
        <button class="b1" id="pwcopy" type="button">Copy</button>
      </div>
      <div class="small" id="pwcopied" style="color:var(--green);font-weight:700;margin-top:6px;display:none">Copied to clipboard.</div>
      <div style="text-align:right;margin-top:10px"><button class="b2" id="pwclose" type="button">Close</button></div>
    </div>
  </div>
  <div class="mod">
    <b>Audit Log</b>
    <div class="small" style="margin-bottom:6px">Append-only. Nothing here can be deleted.</div>
    <div id="alog"></div>
  </div>
</div>
<script>
(function(){
  var REST=<?php echo wp_json_encode($restBase); ?>,N=<?php echo wp_json_encode($nonce); ?>;
  var REG=<?php echo wp_json_encode($reg); ?>;
  var CANADM=<?php echo current_user_can('manage_options') ? 'true' : 'false'; ?>;var USERS=<?php echo wp_json_encode($users); ?>;
  var SLUGS=<?php echo wp_json_encode($slugs); ?>;
  var ACTAILS=<?php echo wp_json_encode($acTails); ?>;
  var PKEYS=<?php echo wp_json_encode($pageKeys); ?>;
  var LOG=<?php echo wp_json_encode($log); ?>;
  var sel=USERS.length?USERS[0].id:0;
  var hmPend='';
  var aerr=document.getElementById('aerr'),aok=document.getElementById('aok');
  function api(path,body){
    return fetch(REST+path,{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-WP-Nonce':N},body:JSON.stringify(body)})
      .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});});
  }
  function fail(m){aerr.textContent=m;aerr.classList.add('on');}
  function okFlash(){aok.classList.add('on');setTimeout(function(){aok.classList.remove('on');},1800);}
  var aisaveBtn=document.getElementById('aisave');
  if(aisaveBtn){aisaveBtn.addEventListener('click',function(){
    aerr.classList.remove('on');
  /* ---- FOQA deck upload. srcdoc-safe: block comments only, no closing script
     tag in any string. Calls the routes registered by snippet 17. ---- */
  (function(){
    var z=document.getElementById('fqaZone'),fi=document.getElementById('fqaFile'),
        ms=document.getElementById('fqaMsg'),ou=document.getElementById('fqaOut'),
        mo=document.getElementById('fqamonths');
    if(!z){return;}
    var BASE=(location.origin||'')+'/wp-json/jaxfoqa/v1/';
    var parsed=null;
    function say(t,c){ms.textContent=t||'';ms.style.color=c==='e'?'var(--red)':(c==='k'?'var(--green)':'var(--ink2)');}
    function esc(s){return String(s).replace(/[<>&]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
    z.addEventListener('click',function(){fi.click();});
    ['dragenter','dragover'].forEach(function(e){z.addEventListener(e,function(ev){ev.preventDefault();ev.stopPropagation();z.style.borderColor='var(--ink)';z.style.background='var(--track)';});});
    ['dragleave','drop'].forEach(function(e){z.addEventListener(e,function(ev){ev.preventDefault();ev.stopPropagation();z.style.borderColor='var(--hair2)';z.style.background='var(--tint)';});});
    z.addEventListener('drop',function(ev){if(ev.dataTransfer&&ev.dataTransfer.files.length){go(ev.dataTransfer.files[0]);}});
    fi.addEventListener('change',function(){if(fi.files.length){go(fi.files[0]);}});
    function go(file){
      if(!/\.pptx$/i.test(file.name)){say('That is not a .pptx file.','e');return;}
      say('Reading '+file.name+'...');ou.style.display='none';
      var fd=new FormData();fd.append('file',file);
      fetch(BASE+'upload',{method:'POST',credentials:'same-origin',headers:{'X-WP-Nonce':NONCE},body:fd})
        .then(function(r){return r.json();})
        .then(function(j){
          if(!j||!j.ok){say((j&&j.err)?j.err:'Could not read that file.','e');return;}
          parsed=j.parsed;show(j.parsed);say('');
        }).catch(function(){say('Upload failed.','e');});
    }
    function show(p){
      var fo=p.found||{},mi=p.missing||[],h='';
      h+='<b>'+esc(fo.label||'Month not found')+'</b> &middot; '+p.slideCount+' slides';
      if(fo.cre_tier_2000!=null){h+='<br>Traffic proximity: '+fo.cre_tier_2000+' / '+(fo.cre_tier_1000!=null?fo.cre_tier_1000:'-')+' / '+(fo.cre_tier_500!=null?fo.cre_tier_500:'-')+' (2000/1000/500 ft)';}
      if(fo.braking_avg!=null){h+='<br>Braking: '+fo.braking_avg+' G';}
      if(fo.go_around_pct!=null){h+='<br>Go-around: '+fo.go_around_pct+'%';}
      if(mi.length){h+='<br><span style="color:var(--amber)">Not found: '+esc(mi.join('; '))+'. Nothing saved yet.</span>';}
      /* Ryan, Sep 6 2026 design audit: no inline font-size, .b1 renders at the 13.5px spec */
      h+='<br><button type="button" class="b1" id="fqaSave" style="margin-top:8px"'+(fo.month_key?'':' disabled')+'>Save '+esc(fo.label||'')+'</button>';
      ou.innerHTML=h;ou.style.display='';
      var b=document.getElementById('fqaSave');if(b){b.addEventListener('click',save);}
    }
    function save(){
      if(!parsed||!parsed.found||!parsed.found.month_key){return;}
      var b=document.getElementById('fqaSave');if(b){b.disabled=true;}
      say('Saving...');
      fetch(BASE+'save-month',{method:'POST',credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-WP-Nonce':NONCE},
        body:JSON.stringify({month_key:parsed.found.month_key,month:parsed.found})})
        .then(function(r){return r.json();})
        .then(function(j){
          if(j&&j.ok){say('Saved '+parsed.found.label+'. Instructors see it now.','k');if(mo){mo.textContent='Loaded: '+j.months.join(', ');}}
          else{say((j&&j.err)?j.err:'Could not save.','e');if(b){b.disabled=false;}}
        }).catch(function(){say('Could not save.','e');if(b){b.disabled=false;}});
    }
  })();

    var v=document.getElementById('aikey').value.trim();
    if(!v){fail('Paste the key first.');return;}
    api('admin/ai-key',{key:v}).then(function(r){
      if(r.s===200&&r.j&&r.j.ok){document.getElementById('aikey').value='';document.getElementById('aist').textContent='Set - ends '+r.j.ends;var nt=document.getElementById('ainote');if(nt){nt.style.display='block';nt.textContent='An Anthropic API key has been added (ends '+r.j.ends+', saved just now).';}okFlash();}
      else{fail((r.j&&r.j.message)?r.j.message:'Could not save the key.');}
    });
  });}
  function cur(){for(var i=0;i<USERS.length;i++){if(USERS[i].id===sel){return USERS[i];}}return null;}
  function esc(s){var d=document.createElement('span');d.textContent=String(s);return d.innerHTML;}
  function renderUsers(){
    var box=document.getElementById('ulist');box.innerHTML='';
    USERS.forEach(function(u){
      var b=document.createElement('button');b.className='urow'+(u.id===sel?' on':'');
      /* Ryan, Sep 6 2026 graphics and mobile review: title shows the full
         address when the row's own text is ellipsis-truncated (.urow .em). */
      b.innerHTML='<span><b>'+esc(u.n)+'</b><span class="em" title="'+esc(u.e)+'">'+esc(u.e)+(u.d?' - disabled':'')+'</span></span>'
        +'<span class="chip">'+(u.d?'OFF':(u.a?'ADMIN':(u.b?(u.ct?'1099':'CFI'):'USER')))+'</span>';
      b.addEventListener('click',function(){sel=u.id;renderAll();});
      box.appendChild(b);
    });
    if(!USERS.length){box.innerHTML='<div class="small">No member accounts yet. Use Add user.</div>';}
  }
  function renderDetail(){
    var u=cur();if(!u){return;}
    hmPend=u.hm||'';
    document.getElementById('dn').value=u.n;
    document.getElementById('de').value=u.e;
    var db=document.getElementById('db');db.innerHTML='';
    var o0=document.createElement('option');o0.value='';o0.textContent='none';db.appendChild(o0);
    SLUGS.forEach(function(s){var o=document.createElement('option');o.value=s;o.textContent=s;db.appendChild(o);});
    db.value=u.b||'';
    document.getElementById('dd').checked=!!u.d;
    var adm=document.getElementById('adm');adm.classList.toggle('on',!!u.a);adm.disabled=!!u.wp;adm.style.opacity=(CANADM&&!u.wp)?'1':'.45';adm.title=u.wp?'WordPress administrator':(CANADM?'':'Only a WordPress administrator (Ryan) can change this');
    var mx=document.getElementById('mx');
    mx.innerHTML='<tr><th>Widget</th><th></th><th style="width:48px">On</th></tr>';
    Object.keys(REG).forEach(function(k){
      if(k==='owner'||k==='access'){return;}
      var tr=document.createElement('tr');
      var starBtn=(PKEYS.indexOf(k)>=0)?('<button class="hstar'+(hmPend===k?' on':'')+'" data-hk="'+esc(k)+'" title="Make this the home screen" aria-label="home screen star for '+esc(REG[k][0])+'">'+(hmPend===k?'\u2605':'\u2606')+'</button>'):'';
      tr.innerHTML='<td><b>'+esc(REG[k][0])+'</b>'+starBtn+'</td><td class="small">'+esc(REG[k][1])+'</td>'
        +'<td><button class="tg'+(u.g.indexOf(k)>=0?' on':'')+'" data-k="'+esc(k)+'" aria-label="toggle '+esc(REG[k][0])+'"></button></td>';
      mx.appendChild(tr);
    });
    var achdr=document.createElement('tr');
    achdr.innerHTML='<th colspan="3" style="text-align:left;padding-top:12px;border-top:1px solid var(--hair)">Aircraft owner statements (view-only)</th>';
    mx.appendChild(achdr);
    var uac=u.ac||[];
    ACTAILS.forEach(function(tl){
      var tr=document.createElement('tr');
      tr.innerHTML='<td><b>'+esc(tl)+'</b></td><td class="small">owner sees this aircraft only</td>'
        +'<td><button class="tg actg'+(uac.indexOf(tl)>=0?' on':'')+'" data-ac="'+esc(tl)+'" aria-label="toggle '+esc(tl)+'"></button></td>';
      mx.appendChild(tr);
    });
    mx.querySelectorAll('.tg').forEach(function(t){
      t.addEventListener('click',function(){t.classList.toggle('on');});
    });
    mx.querySelectorAll('.hstar').forEach(function(st){
      st.addEventListener('click',function(ev){
        ev.stopPropagation();
        var k=st.dataset.hk;
        var tg=mx.querySelector('.tg[data-k="'+k+'"]');
        if(hmPend!==k&&(!tg||!tg.classList.contains('on'))){fail('Turn that widget on first, then star it.');return;}
        aerr.classList.remove('on');
        hmPend=(hmPend===k)?'':k;
        mx.querySelectorAll('.hstar').forEach(function(s2){
          var on2=s2.dataset.hk===hmPend;
          s2.classList.toggle('on',on2);
          s2.textContent=on2?'\u2605':'\u2606';
        });
      });
    });
  }
  function renderLog(){
    var box=document.getElementById('alog');box.innerHTML='';
    LOG.forEach(function(e){
      var r=document.createElement('div');r.className='arow';
      r.innerHTML='<time>'+esc(e.t)+'</time><span><b>'+esc(e.who)+'</b> '+esc(e.txt)+(e.ip?' <span style="color:var(--ink3);font-size:11.5px">from '+esc(e.ip)+'</span>':'')+'</span>';
      box.appendChild(r);
    });
    if(!LOG.length){box.innerHTML='<div class="small">Nothing logged yet.</div>';}
  }
  function renderAll(){renderUsers();renderDetail();renderLog();}
  var pwov=document.getElementById('pwov');
  function showTempPw(who,pw){document.getElementById('pwtitle').textContent='Temporary Password for '+who;var v=document.getElementById('pwval');v.value=pw;document.getElementById('pwcopied').style.display='none';pwov.style.display='flex';v.focus();v.select();}
  document.getElementById('pwclose').addEventListener('click',function(){document.getElementById('pwval').value='';pwov.style.display='none';});
  document.getElementById('pwval').addEventListener('click',function(){this.select();});
  document.getElementById('pwcopy').addEventListener('click',function(){
    var v=document.getElementById('pwval');v.focus();v.select();
    var done=function(){document.getElementById('pwcopied').style.display='block';};
    var ok=false;try{ok=document.execCommand('copy');}catch(e){}
    if(ok){done();return;}
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(v.value).then(done);}
  });
  document.getElementById('adm').addEventListener('click',function(){
    var cu=cur();
    if(cu&&cu.wp){fail('That account is a WordPress administrator - always an admin.');return;}
    if(!CANADM){fail('Only a WordPress administrator (Ryan) can change admin access.');return;}
    this.classList.toggle('on');
  });
  document.getElementById('save').addEventListener('click',function(){
    var u=cur();if(!u){return;}
    aerr.classList.remove('on');
    var on=[];document.querySelectorAll('#mx .tg.on:not(.actg)').forEach(function(t){on.push(t.dataset.k);});
    var ac=[];document.querySelectorAll('#mx .actg.on').forEach(function(t){ac.push(t.dataset.ac);});
    var body={user_id:u.id,grants:on,aircraft:ac,home:(on.indexOf(hmPend)>=0?hmPend:''),
      name:document.getElementById('dn').value.trim(),
      instructor:document.getElementById('db').value,
      disabled:document.getElementById('dd').checked,
      admin:document.getElementById('adm').classList.contains('on')};
    api('admin/save-user',body).then(function(x){
      if(x.s===200&&x.j&&x.j.ok){u.g=on;u.ac=ac;u.hm=body.home;hmPend=body.home;u.b=body.instructor;u.d=body.disabled;u.a=body.admin;if(body.name){u.n=body.name;}okFlash();renderUsers();renderDetail();
        LOG.unshift({t:'just now',who:'you',txt:'saved '+u.n+'.'});renderLog();return;}
      fail(x.j&&x.j.message?x.j.message:'Save failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  document.getElementById('resetPw').addEventListener('click',function(){
    var u=cur();if(!u){return;}
    if(!window.confirm('Set a new temporary password for '+u.n+'? Their current one stops working immediately.')){return;}
    api('admin/reset-password',{user_id:u.id}).then(function(x){
      if(x.s===200&&x.j&&x.j.temp_password){showTempPw(u.n,x.j.temp_password);return;}
      fail(x.j&&x.j.message?x.j.message:'Reset failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  document.getElementById('viewAs').addEventListener('click',function(){
    var u=cur();if(!u){return;}
    aerr.classList.remove('on');
    api('admin/viewas',{user_id:u.id}).then(function(x){
      if(x.s===200&&x.j&&x.j.ok){window.open(x.j.start,'_blank');return;}
      fail(x.j&&x.j.message?x.j.message:'Could not start the preview.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  document.getElementById('delU').addEventListener('click',function(){
    var u=cur();if(!u){return;}
    aerr.classList.remove('on');
    if(!window.confirm('Permanently delete '+u.n+' ('+u.e+')? They will no longer be able to sign in. Their past actions stay in the audit log. This cannot be undone.')){return;}
    api('admin/delete-user',{user_id:u.id}).then(function(x){
      if(x.s===200&&x.j&&x.j.ok){
        for(var i=0;i<USERS.length;i++){if(USERS[i].id===u.id){USERS.splice(i,1);break;}}
        sel=USERS.length?USERS[0].id:0;renderAll();okFlash();
        LOG.unshift({t:'just now',who:'you',txt:'deleted the account "'+u.n+'".'});renderLog();return;}
      fail(x.j&&x.j.message?x.j.message:'Delete failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  document.getElementById('addU').addEventListener('click',function(){
    var name=window.prompt('Full name for the new account:');if(!name){return;}
    var email=window.prompt('Email address (their sign-in name):');if(!email){return;}
    api('admin/create-user',{name:name,email:email}).then(function(x){
      if(x.s===200&&x.j&&x.j.temp_password){
        USERS.push({id:x.j.user_id,n:name,e:email,g:[],b:'',d:false});sel=x.j.user_id;renderAll();
        showTempPw(name,x.j.temp_password);return;}
      fail(x.j&&x.j.message?x.j.message:'Create failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  renderAll();
})();
</script>
<?php echo jaxauth_frame_foot();
  return ob_get_clean();
}
