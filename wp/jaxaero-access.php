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
    'pay'       => ['Payroll widget', 'the Pay Portal - instructors, contractors, W2, MX'],
    'pay.rates' => ['Rate editor', 'pay rates page'],
    'bonus'     => ['Bonus & review editor', 'add checkride passes + review mentions'],
    'sales'     => ['Sales', 'pipeline, enrollment tracking and commissions'],
    'marketing' => ['Marketing', 'Meta Ads + ad campaigns'],
    'safety'    => ['Safety', 'company-wide FOQA safety data'],
    'mxtime'    => ['MX Timeclock', 'mechanic clock in/out, pay and task mix'],
    'tax'       => ['Sales tax', 'aircraft sales tax page'],
    'lease'     => ['Leases', 'lease management - VR Leasing aircraft'],
    'docs'      => ['Documents', 'archive & search'],
    'expense'   => ['Add expenses', 'enter expenses on the owner P/L'],
    'ownerstmt' => ['Aircraft owner statements', 'staff view - every plane P/L'],
    'owner'     => ['My Aircraft', 'your aircraft statements (owners)'],
    'lessor'    => ['Lessor portal', 'VR Leasing read-only statements'],
    'invoice'   => ['Own pay dashboard', 'only the bound person - instructor or 1099 contractor'],
    'access'    => ['Access admin', 'this admin panel'],
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
  if (!jaxauth_enabled($uid)) { return false; }
  $user = get_user_by('id', $uid);
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
  if (!user_can($user->ID, 'manage_options')) {
    $sharedC = (int) get_option('jaxauth_canvas_page');
    if ($sharedC && get_post_status($sharedC) === 'publish' && count(jaxauth_canvas_widgets($user)) > 0) {
      $scl = get_permalink($sharedC);
      if ($scl) { return $scl; }
    }
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
  if (!jaxauth_can($key, $u->ID)) { return jaxauth_denied_html(); }
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
  return '<div style="max-width:480px;margin:40px auto;padding:24px;text-align:center;'
    . 'font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1F2F54;'
    . 'background:#fff;border:1px solid #e6e9ef;border-radius:14px">'
    . '<b>' . esc_html($head) . '</b><br>'
    . '<span style="font-size:13px;color:#5b6577">' . esc_html($sub) . '</span><br><br>'
    . '<a href="' . $home . '" style="color:#C10F1B;font-weight:700;font-size:13px">' . esc_html($link) . '</a></div>';
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
  if (!$user || !jaxauth_is_managed($user)) {
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
  /* Ryan, Sep 3 2026: "add a toggle switch to turn on admin access for people".
     Dashboard admin = the jaxauth_admin capability (Access admin, view-as, every
     gated page). Only a real WordPress administrator may grant or revoke it; a
     dashboard admin cannot mint other admins, nobody can demote themselves, and
     WordPress administrators are left alone (they are admin regardless). Sits
     above every write so a rejected save changes nothing at all. */
  $admParam = $req->get_param('admin');
  $wantAdmin = ($admParam === true || $admParam === 'true' || $admParam === 1 || $admParam === '1');
  $hasAdmin = user_can($user, JAXAUTH_CAP);
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
  /* starred home screen - only a granted widget that has a page qualifies */
  $homeSel = sanitize_text_field((string) $req->get_param('home'));
  $homePageKeys = array_values(array_diff(array_intersect(array_values((array) get_option('jaxauth_pages', [])), array_keys(jaxauth_registry())), ['access']));
  /* Ryan, Sep 4 2026: a canvas tab key (Sam's binding-driven 'logdetail') is
     also a valid home - the canvas opens on that tab. Grants were just saved
     above; the binding save follows, so a binding-driven key needs the binding
     already stored (true for every existing user). */
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
  update_user_meta($uid, 'jaxauth_instructor', $inst);
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
  ?>
<div style="position:fixed;left:0;right:0;bottom:0;z-index:2147483000;background:#7a4b00;color:#fff;font-family:'Segoe UI',Roboto,Arial,sans-serif;font-size:13.5px;padding:10px 16px;display:flex;align-items:center;justify-content:center;gap:14px;flex-wrap:wrap;box-shadow:0 -4px 16px rgba(0,0,0,.25)">
  <span>Preview: you are seeing the portal exactly as <b><?php echo esc_html($name); ?></b> sees it. Buttons that save or send will not work in this preview.</span>
  <a href="<?php echo $exit; ?>" style="color:#fff !important;background:rgba(255,255,255,.18) !important;border:1px solid rgba(255,255,255,.5) !important;border-radius:8px !important;padding:5px 14px !important;font-weight:700 !important;text-decoration:none !important">Exit preview</a>
</div>
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
    array('mxtime', '[jaxaero_mx_time]', 'MX Timeclock'),
    array('ownerstmt', '[jaxaero_aircraft_owner]', 'Aircraft Owner Statements'),
    array('owner', '[jaxaero_owner_portal]', 'My Aircraft'),
    array('lessor', '[jaxaero_lessor]', 'Lease statements'),
    array('sales', '[jaxaero_sales_pipeline]', 'Sales'),
    array('marketing', '[jaxaero_marketing]', 'Marketing'),
    array('tax', '[jaxaero_tax]', 'Sales Tax'),
    array('lease', '[jaxaero_leases]', 'Leases'),
    array('docs', '[jaxaero_documents]', 'Documents'),
  );
  /* Ryan, Aug 31 PM: the canvas follows the ACTUAL Access Admin toggles for
     everyone - including admins. jaxauth_can()'s admin bypass put every widget
     on Ben's canvas regardless of his switches; jaxauth_grants() is the raw
     toggle state. */
  $cvsG = jaxauth_grants($u->ID);
  foreach ($order as $w) {
    if (in_array($w[0], $cvsG, true)) { $out[] = array('key' => $w[0], 'tag' => $w[1], 'label' => $w[2]); }
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
  if (!$tags) { return '<div style="max-width:480px;margin:40px auto;padding:24px;text-align:center;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#1F2F54;background:#fff;border:1px solid #e6e9ef;border-radius:14px"><b>Nothing is switched on for your account yet.</b><br><span style="font-size:13px;color:#5b6577">Ask Ryan.</span></div>'; }
  /* Ryan, Aug 31 PM: the welcome appears exactly ONCE, at the top of the
     canvas. Widgets suppress their own greeting while this flag is up (they
     keep it on standalone pages). */
  $first = trim((string) strtok($u->display_name, ' '));
  /* Ryan, Sep 4 2026: a company account (the VR Leasing lessor login, grants exactly
     ['lessor']) is greeted by its full name, not by "VR". */
  if (function_exists('jaxauth_grants') && jaxauth_grants($u->ID) === array('lessor')) { $first = trim((string) $u->display_name); }
  $html = '<style>div[id^="jaxw-"]{scroll-margin-top:72px}</style>';
  $html .= '<div style="max-width:1080px;margin:20px auto 4px;padding:0 16px;font-family:\'Segoe UI\',Roboto,Arial,sans-serif">'
        . '<div style="color:#C10F1B;font-weight:800;font-size:12px;letter-spacing:.12em">JAXAERO</div>'
        . '<h1 style="font-size:28px;font-weight:800;color:#1F2F54;margin:2px 0 0">Welcome ' . esc_html($first !== '' ? $first : $u->display_name) . '!</h1>'
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
     department (Revenue / Sales tax / Leases as a sub-menu, see $subGroups
     below); the lessor's statements are their own bubble. */
  $gmap = array('logdetail' => 'Log Detailing', 'auto' => 'Accounting', 'tax' => 'Accounting', 'lease' => 'Accounting', 'ownerstmt' => 'Airplanes', 'owner' => 'Airplanes', 'pay' => 'Payroll', 'mypay' => 'My Pay', 'myhours' => 'My Hours', 'safety' => 'Safety', 'sales' => 'Sales & Marketing', 'marketing' => 'Sales & Marketing', 'mxtime' => 'MX', 'docs' => 'Documents', 'lessor' => 'Lease statements');
  /* Ben, Sep 2 (punch list 13B): Log Detailing leads so Sam's canvas opens on
     it with My Pay as the next tab. Safety now precedes My Pay and My Hours
     follows it, so an instructor's tabs read Safety / My Pay / My Hours. Nobody
     else's relative order moves - only a holder of BOTH Safety and their own
     pay page sees Safety step ahead of My Pay. */
  /* 'Accounting' sits at the index 'Revenue' held so saved jaxDashTab cookies
     keep pointing at the same bubble; 'Lease statements' is appended LAST so
     no existing user's group index moves (nobody holds 'lessor' yet). */
  $gorder = array('Log Detailing', 'Accounting', 'Airplanes', 'Payroll', 'Safety', 'My Pay', 'My Hours', 'Sales & Marketing', 'MX', 'Documents', 'Lease statements');
  $groups = array();
  foreach ($gorder as $gl) { $groups[$gl] = array(); }
  foreach ($tags as $t) { $gl = isset($gmap[$t['key']]) ? $gmap[$t['key']] : 'Documents'; $groups[$gl][] = $t; }
  $groups = array_filter($groups);
  $isDash = count($groups) > 1;
  $lazyKeys = array();
  $phFn = function ($t) {
    return '<div id="jaxw-' . esc_attr($t['key']) . '" class="jaxw-lazy" data-jaxw="' . esc_attr($t['key']) . '" style="min-height:340px;display:flex;align-items:center;justify-content:center">'
         . '<div style="font-family:\'Segoe UI\',Roboto,Arial,sans-serif;color:#8A93A5;font-size:13px;padding:40px 0">Loading ' . esc_html($t['label']) . '&hellip;</div>'
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
    $html .= '<style>.jaxdash-tabs{display:flex;gap:8px;flex-wrap:wrap;max-width:1080px;margin:14px auto 4px;padding:0 16px;font-family:\'Segoe UI\',Roboto,Arial,sans-serif}'
           . '.jaxdash-tab{font:700 13.5px \'Segoe UI\',Roboto,Arial,sans-serif !important;padding:9px 18px !important;border:1px solid #d9dee7 !important;background:#fff !important;border-radius:999px !important;cursor:pointer;color:#1F2F54 !important;letter-spacing:0 !important;text-transform:none !important;box-shadow:none !important;min-width:0 !important;width:auto !important;line-height:1.2 !important}'
           . '.jaxdash-tab.on{background:#1F2F54 !important;color:#fff !important;border-color:#1F2F54 !important}'
           . '.jaxdash-g{display:none}.jaxdash-g.on{display:block}'
           /* Ryan, Sep 4 2026 (lease): the department sub-menu strip - snippet 9's
              Pay Portal .ptabs/.ptab treatment (grey #6b7484, navy #1F2F54 on,
              red #C10F1B underline). It renders OUTSIDE any iframe, so every
              declaration Elementor's kit could repaint is pinned. */
           . '.jaxsub{display:flex !important;flex-wrap:wrap;gap:2px;max-width:1080px;margin:8px auto 0 !important;padding:0 16px !important;border-bottom:1px solid #e6e9ef;box-sizing:border-box;font-family:\'Segoe UI\',Roboto,Arial,sans-serif}'
           . '.jaxsub .ptab{font:700 13.5px \'Segoe UI\',Roboto,Arial,sans-serif !important;padding:9px 16px !important;border:0 !important;border-bottom:3px solid transparent !important;margin:0 0 -1px !important;background:none !important;border-radius:0 !important;box-shadow:none !important;color:#6b7484 !important;cursor:pointer;white-space:nowrap;letter-spacing:0 !important;text-transform:none !important;min-width:0 !important;width:auto !important;line-height:1.2 !important}'
           . '.jaxsub .ptab:hover{color:#1F2F54 !important}'
           . '.jaxsub .ptab.on{color:#1F2F54 !important;border-bottom-color:#C10F1B !important}'
           . '.jaxsub-p{display:none}.jaxsub-p.on{display:block}</style>';
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
    $subGroups = array('Accounting');
    $subLabels = array('auto' => 'Revenue', 'tax' => 'Sales tax', 'lease' => 'Leases');
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
      $subC = isset($_COOKIE['jaxSub-' . $gl]) ? sanitize_key((string) $_COOKIE['jaxSub-' . $gl]) : '';
      if ($isSub) {
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
    if (jaxauth_is_admin($u) && !isset($groups['MX'])) {
      $tabsH .= '<button type="button" class="jaxdash-tab" data-g="' . $gi . '">MX</button>';
      $bodyH .= '<div class="jaxdash-g" id="jaxg-' . $gi . '" data-gkeys=""><div style="max-width:1080px;margin:30px auto;padding:46px 16px;text-align:center;font-family:\'Segoe UI\',Roboto,Arial,sans-serif;color:#1F2F54;background:#fff;border:1px solid #e6e9ef;border-radius:14px"><b style="font-size:20px">MX portal coming soon!</b><br><span style="font-size:13.5px;color:#5b6577">Maintenance department tools will live here.</span></div></div>';
    }
    $html .= '<div class="jaxdash-tabs" id="jaxdashTabs">' . $tabsH . '</div>' . $bodyH;
    $html .= '<script>(function(){var tabs=document.querySelectorAll(".jaxdash-tab");var gs=document.querySelectorAll(".jaxdash-g");'
      . 'function act(i){for(var x=0;x<gs.length;x++){gs[x].classList.toggle("on",x===i);}for(var x=0;x<tabs.length;x++){tabs[x].classList.toggle("on",x===i);}try{localStorage.setItem("jaxDashTab",String(i));}catch(e){}try{document.cookie="jaxDashTab="+i+";path=/;max-age=31536000;SameSite=Lax;Secure";}catch(e2){}}'
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
    $html .= '<script>(function(){var navs=document.querySelectorAll(".jaxsub");if(!navs.length){return;}var HK=' . wp_json_encode($homeK) . ';'
      . 'function keyOf(h){return (h||"").replace("#jaxw-","");}'
      . 'function has(nav,k){if(!k){return false;}var ts=nav.querySelectorAll(".ptab");for(var i=0;i<ts.length;i++){if(ts[i].getAttribute("data-k")===k){return true;}}return false;}'
      . 'function pick(nav,k,save){var ts=nav.querySelectorAll(".ptab");if(!has(nav,k)){k=ts.length?ts[0].getAttribute("data-k"):"";}for(var i=0;i<ts.length;i++){ts[i].classList.toggle("on",ts[i].getAttribute("data-k")===k);}var ps=nav.parentNode.querySelectorAll(".jaxsub-p");for(var j=0;j<ps.length;j++){ps[j].classList.toggle("on",ps[j].getAttribute("data-k")===k);}if(save){try{localStorage.setItem("jaxSub-"+nav.getAttribute("data-sg"),k);}catch(e){}try{document.cookie="jaxSub-"+nav.getAttribute("data-sg")+"="+k+";path=/;max-age=31536000;SameSite=Lax;Secure";}catch(e2){}}}'
      . 'function initial(nav){var hk=keyOf(window.location.hash);if(has(nav,hk)){return hk;}if(has(nav,HK)){return HK;}var s="";try{s=localStorage.getItem("jaxSub-"+nav.getAttribute("data-sg"))||"";}catch(e){}return s;}'
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
      . 'function markErr(key,msg){var ph=phOf(key);if(ph&&ph.firstElementChild){ph.firstElementChild.textContent=msg;}}'
      . 'function insertOne(pay,key){var ph=phOf(key);if(!ph){return true;}var w=pay.querySelector("[id=\"jaxw-"+key+"\"]");if(!w){return false;}var node=document.importNode(w,true);ph.parentNode.replaceChild(node,ph);runScripts(node);return true;}'
      . 'function load(keys,done){'
      . 'fetch(window.location.pathname+"?jaxw="+encodeURIComponent(keys.join(",")),{credentials:"same-origin"}).then(function(r){return r.text();}).then(function(t){'
      . 'var doc=new DOMParser().parseFromString(t,"text/html");var pay=doc.getElementById("jaxwLazyPayload");'
      . 'var missing=[];keys.forEach(function(k){if(!(pay&&insertOne(pay,k))){missing.push(k);}});'
      . 'missing.forEach(function(k){if(keys.length>1&&!failed[k]){failed[k]=1;queue.unshift([k]);}else{markErr(k,"This section could not load - pull to refresh or reload the page.");}});'
      . 'done();'
      . '}).catch(function(){keys.forEach(function(k){if(keys.length>1&&!failed[k]){failed[k]=1;queue.unshift([k]);}else{markErr(k,"This section could not load - check the connection and reload.");}});done();});}'
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
.jaxmnu-btn{position:fixed;top:12px;right:12px;z-index:99990;width:42px !important;height:42px !important;min-width:0 !important;border-radius:10px !important;border:1px solid #d9dee7 !important;background:#fff !important;box-shadow:0 2px 10px rgba(20,35,70,.18) !important;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0 !important;line-height:1 !important}
.jaxmnu-btn span{display:block;width:18px;height:2px;background:#1F2F54;border-radius:2px;position:relative}
.jaxmnu-btn span:before,.jaxmnu-btn span:after{content:'';position:absolute;left:0;width:18px;height:2px;background:#1F2F54;border-radius:2px}
.jaxmnu-btn span:before{top:-6px}.jaxmnu-btn span:after{top:6px}
.jaxmnu-pane{position:fixed;top:60px;right:12px;z-index:99990;width:min(300px,calc(100vw - 24px));background:#fff;border:1px solid #e6e9ef;border-radius:14px;box-shadow:0 14px 44px rgba(15,23,42,.28);display:none;overflow:hidden;font-family:"Segoe UI",Roboto,Arial,sans-serif}
.jaxmnu-pane.on{display:block}
body.admin-bar .jaxmnu-btn{top:44px}body.admin-bar .jaxmnu-pane{top:92px}
.jaxmnu-hd{padding:12px 16px 10px;border-bottom:1px solid #eef1f5;font-weight:800;color:#C10F1B;font-size:12px;letter-spacing:.12em}
.jaxmnu-pane a,.jaxmnu-pane button.jaxmnu-item{display:block !important;width:100% !important;min-width:0 !important;text-align:left !important;background:none !important;border:0 !important;border-radius:0 !important;box-shadow:none !important;padding:11px 16px !important;font:inherit !important;font-size:14px !important;font-weight:400 !important;color:#1F2F54 !important;text-decoration:none !important;letter-spacing:0 !important;text-transform:none !important;cursor:pointer}
.jaxmnu-pane a:hover,.jaxmnu-pane button.jaxmnu-item:hover{background:#F4F6F9 !important;color:#1F2F54 !important}
.jaxmnu-sep{border-top:1px solid #eef1f5;margin:4px 0}
.jaxmnu-help{display:none;padding:10px 16px 14px}
.jaxmnu-help.on{display:block}
.jaxmnu-help textarea{width:100% !important;min-height:76px;font:inherit !important;font-size:13.5px !important;padding:8px 10px !important;border:1px solid #d9dee7 !important;border-radius:8px !important;background:#fff !important;color:#1F2F54 !important;box-sizing:border-box !important}
.jaxmnu-help .jaxmnu-send{margin-top:8px;background:#1F2F54 !important;color:#fff !important;border:0 !important;border-radius:8px !important;box-shadow:none !important;width:auto !important;min-width:0 !important;padding:8px 16px !important;font:inherit !important;font-size:13px !important;font-weight:700 !important;letter-spacing:0 !important;text-transform:none !important;cursor:pointer}
.jaxmnu-note{font-size:12px;padding:0 16px 10px;color:#5b6577}
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
  <?php if ($adminUrl !== '') { ?><div class="jaxmnu-sep"></div><a href="<?php echo esc_url($adminUrl); ?>">Admin Portal</a><?php } ?>
  <div class="jaxmnu-sep"></div>
  <button type="button" class="jaxmnu-item" id="jaxmnuOut">Sign off</button>
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
  return '<style>@media(max-width:700px){#' . esc_attr($fid) . '_w{width:100vw !important;position:relative;left:50%;margin-left:-50vw !important}}</style>'
    . '<div id="' . esc_attr($fid) . '_w" style="display:block;width:100%;margin:0;padding:0;line-height:0">'
    . '<iframe id="' . esc_attr($fid) . '" srcdoc="' . esc_attr($html) . '" '
    . 'style="display:block;width:100%;height:1100px;border:0;margin:0;overflow:auto" '
    . 'title="' . esc_attr($title) . '"></iframe></div>'
    . '<script>(function(){var f=document.getElementById("' . esc_js($fid) . '");var last=0;window.addEventListener("message",function(e){var d=e.data;if(d&&d.jaxauthH&&Math.abs(d.jaxauthH-last)>2){last=d.jaxauthH;var fl=0;try{fl=window.innerHeight-f.getBoundingClientRect().top-(window.pageYOffset||0)*0;fl=window.innerHeight-f.getBoundingClientRect().top;}catch(e2){}f.style.height=Math.max(d.jaxauthH+24,fl)+"px";}});})();</script>';
}

function jaxauth_frame_head() {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    . '<meta name="viewport" content="width=device-width,initial-scale=1"><style>'
    . '*{box-sizing:border-box}'
    . 'body{margin:0;background:#F4F6F9;color:#1F2F54;font-family:"Segoe UI",Roboto,-apple-system,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5}'
    . '.wrap{max-width:980px;margin:0 auto;padding:22px 18px 34px}'
    . '.brand{font-weight:800;letter-spacing:.14em;font-size:13px;color:#C10F1B}'
    . 'h1{margin:6px 0 4px;font-size:24px;font-weight:800}'
    . '.sub{color:#5b6577;font-size:13.5px;margin-bottom:16px}'
    . '.mod{background:#fff;border:1px solid #e6e9ef;border-radius:14px;padding:22px;box-shadow:0 1px 3px rgba(20,35,70,.05);margin-bottom:14px}'
    . '.fld{margin-bottom:13px}'
    . '.fld label{display:block;font-size:12px;font-weight:700;letter-spacing:.04em;color:#5b6577;margin-bottom:5px;text-transform:uppercase}'
    . '.fld input,.fld select{width:100%;border:1px solid #e6e9ef;border-radius:9px;padding:10px 12px;font-size:15px;color:#1F2F54;background:#fff}'
    . '.btn{display:inline-block;border:0;border-radius:9px;padding:10px 20px;font-size:14px;font-weight:700;cursor:pointer;background:#1F2F54;color:#fff}'
    . '.btn.red{background:#C10F1B}.btn.ghost{background:#fff;color:#1F2F54;border:1px solid #e6e9ef;font-weight:600}'
    . '.btn:disabled{opacity:.55;cursor:default}'
    . '.err{display:none;background:#fbe9ea;border:1px solid #f0c4c7;color:#8f1219;border-radius:9px;padding:10px 12px;font-size:13.5px;margin-bottom:12px}'
    . '.err.on{display:block}'
    . '.okmsg{display:none;background:#e3f5ec;border:1px solid #bfe8d2;color:#0f7a4d;border-radius:9px;padding:10px 12px;font-size:13.5px;margin-bottom:12px}'
    . '.okmsg.on{display:block}'
    . '.note{background:#fdf3e2;border:1px solid #f0dcb2;color:#8a5b00;border-radius:9px;padding:10px 12px;font-size:13px;margin-bottom:12px}'
    . '.small{font-size:12.5px;color:#5b6577}'
    . 'table{width:100%;border-collapse:collapse}'
    . 'th{text-align:left;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:#8b93a3;font-weight:700;padding:7px 9px;border-bottom:1px solid #e6e9ef}'
    . 'td{padding:8px 9px;border-bottom:1px solid #e6e9ef;font-size:13.5px;vertical-align:middle}'
    . '.ulist{max-height:560px;overflow-y:auto}'
    . '.urow{display:flex;align-items:center;gap:9px;width:100%;text-align:left;background:none;border:0;border-radius:9px;padding:8px 9px;cursor:pointer;font:inherit;color:#1F2F54}'
    . '.urow:hover{background:#F4F6F9}.urow.on{background:#1F2F54;color:#fff}'
    . '.urow .em{display:block;font-size:11.5px;color:#5b6577}.urow.on .em{color:#c6cddd}'
    . '.chip{margin-left:auto;font-size:10.5px;font-weight:700;border-radius:999px;padding:2px 8px;background:#eef1f5;color:#5b6577}'
    . '.urow.on .chip{background:rgba(255,255,255,.16);color:#fff}'
    . '.grid2{display:grid;grid-template-columns:270px 1fr;gap:14px;align-items:start}'
    . '@media(max-width:820px){.grid2{grid-template-columns:1fr}}'
    . '.tg{position:relative;width:42px;height:24px;border-radius:999px;border:0;cursor:pointer;background:#cfd5df}'
    . '.tg:after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.18)}'
    . '.tg.on{background:#0f7a4d}.tg.on:after{left:21px}'
    . '.hstar{background:none;border:0;cursor:pointer;font:inherit;font-size:16px;line-height:1;color:#c8cfda;padding:0 3px;margin-left:4px;vertical-align:middle}.hstar.on{color:#E8A100}'
    . '.arow{display:flex;gap:12px;padding:8px 2px;border-top:1px solid #e6e9ef;font-size:13px}'
    . '.arow time{flex:none;width:120px;color:#8b93a3;font-size:12px}'
    . '</style></head><body>';
}

function jaxauth_frame_foot() {
  return '<script>(function(){var l=0;function h(){var v=document.body.scrollHeight;var t=v;try{var fe=window.frameElement;if(fe){var pIH=(window.parent&&window.parent.innerHeight)||0;var top=fe.getBoundingClientRect().top+((window.parent&&window.parent.pageYOffset)||0);t=Math.max(v+24,pIH-Math.max(0,top));if(Math.abs(fe.getBoundingClientRect().height-t)>8){fe.style.height=t+"px";}}}catch(e){}if(Math.abs(v-l)>2){l=v;if(window.parent!==window){window.parent.postMessage({jaxauthH:v},"*");}}}h();setInterval(h,700);})();</script></body></html>';
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
<div class="wrap" style="max-width:420px">
  <div style="text-align:center"><span class="brand">JAXAERO</span></div>
  <h1 style="text-align:center;font-size:20px">Sign in to your dashboard</h1>
  <div class="mod" style="margin-top:14px">
    <div class="err" id="err"></div>
    <div class="fld"><label for="em">Email or sign-in name</label>
      <input id="em" type="text" autocomplete="username" placeholder="you@flyjaxaero.com" inputmode="email" autocapitalize="none" spellcheck="false"></div>
    <div class="fld"><label for="pw">Password</label>
      <input id="pw" type="password" autocomplete="current-password"></div>
    <button class="btn red" id="go" style="width:100%">Sign in</button>
  </div>
  <p class="small" style="text-align:center;line-height:1.55">Forgot your password? <a href="<?= esc_url(wp_lostpassword_url()) ?>" target="_top" style="color:#1F2F54;font-weight:700">Reset it by email</a>.<br>Five failed attempts locks sign-in for 15 minutes.<br>This page never asks for a Flight Schedule Pro login.</p>
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
  <span class="brand">JAXAERO</span>
  <h1>Welcome, <?php echo esc_html($u->display_name); ?></h1>
  <div class="sub">Your account preferences. Signed in as <?php echo esc_html((string) $u->user_email !== '' ? $u->user_email : $u->user_login); ?>.
    <button class="btn ghost" id="out" style="padding:9px 16px;font-size:13px;margin-left:8px;vertical-align:middle">Sign out</button></div>
  <?php if ($must) { ?><div class="note"><b>Please choose a new password now.</b> The one you signed in with was temporary.</div><?php } ?>
  <div class="mod" id="chpw" style="margin-top:16px;max-width:430px">
    <b>Change your password</b>
    <div class="small" style="margin-bottom:10px">At least <?php echo (int) JAXAUTH_MIN_PW; ?> characters. Takes effect immediately.</div>
    <div class="err" id="perr"></div><div class="okmsg" id="pok">Password changed.</div>
    <div class="fld"><label for="cur">Current password</label><input id="cur" type="password" autocomplete="current-password"></div>
    <div class="fld"><label for="nw">New password</label><input id="nw" type="password" autocomplete="new-password"></div>
    <div class="fld"><label for="nw2">New password again</label><input id="nw2" type="password" autocomplete="new-password"></div>
    <button class="btn" id="pgo">Change password</button>
  </div>
  <div class="mod" id="helpmod" style="margin-top:16px;max-width:430px">
    <b>Request help</b>
    <div class="small" style="margin-bottom:10px">Describe the problem - this goes straight to Ryan by email.</div>
    <div class="err" id="herr"></div><div class="okmsg" id="hok">Sent - Ryan has it in his inbox.</div>
    <div class="fld"><textarea id="htxt" rows="4" style="width:100%;box-sizing:border-box;font:inherit;font-size:13.5px;padding:8px 10px;border:1px solid #d9dee7;border-radius:8px" placeholder="What is going wrong?"></textarea></div>
    <button class="btn" id="hgo">Send to Ryan</button>
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
  foreach (get_users(['role' => JAXAUTH_ROLE]) as $wu) {
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
      'a' => user_can($wu, JAXAUTH_CAP),
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
@media(max-width:700px){
.tg{width:58px;height:40px;border:8px solid transparent;background-clip:padding-box}
.hstar{font-size:22px;padding:9px 12px;margin-left:2px}
#addU{padding:12px 14px !important}
#dd{width:24px;height:24px}
}
</style>
<div class="wrap">
  <span class="brand">JAXAERO</span>
  <h1>Access admin</h1>
  <div class="sub">Pick a person, flip toggles, save. Changes apply on their next page load. Every save is logged below.</div>
  <div style="display:flex;gap:10px;align-items:center;margin:-4px 0 14px"><a class="btn ghost" href="<?php echo esc_url($itUrl); ?>" target="_top" style="font-size:12.5px;text-decoration:none;display:inline-block">IT status</a><span class="small">How every tool, server and job behind the dashboard is doing.</span></div>
  <div class="grid2">
    <div class="mod ulist">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <b>People</b><button class="btn ghost" id="addU" style="padding:4px 12px;font-size:12px">+ Add user</button></div>
      <div id="ulist"></div>
    </div>
    <div class="mod">
      <div class="err" id="aerr"></div><div class="okmsg" id="aok">Saved.</div>
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;border-bottom:1px solid #e6e9ef;padding-bottom:14px;margin-bottom:14px">
        <div class="fld" style="flex:1;min-width:150px;margin:0"><label>Name</label><input id="dn" autocomplete="off"></div>
        <div class="fld" style="flex:1;min-width:170px;margin:0"><label>Email</label><input id="de" readonly></div>
        <div class="fld" style="flex:1;min-width:150px;margin:0"><label>Pay page binding</label><select id="db"></select></div>
        <label class="small" style="display:flex;align-items:center;gap:6px;padding-bottom:4px"><input type="checkbox" id="dd"> Disabled</label>
        <label class="small" id="admwrap" style="display:flex;align-items:center;gap:8px;padding-bottom:4px" title="Dashboard admin can open Access admin, view as anyone and see every gated page. Only a WordPress administrator can change it."><button type="button" class="tg" id="adm" aria-label="toggle dashboard admin"></button> Dashboard admin</label>
        <button class="btn ghost" id="resetPw" style="font-size:12.5px">Reset password</button>
        <button class="btn ghost" id="viewAs" style="font-size:12.5px">View as user</button>
        <button class="btn ghost" id="delU" style="font-size:12.5px;color:#C0161C;border-color:#e3b3b6">Delete user</button>
      </div>
      <div style="overflow-x:auto"><table id="mx">
        <tr><th>Widget</th><th></th><th style="width:48px">On</th></tr>
      </table></div>
      <div class="small" style="margin:10px 2px 0">&#9733; marks this person's home screen - the page they land on right after signing in. Turn a widget on, then click its star; click it again to return to the default (staff land on Revenue - AUTO, aircraft owners on My Aircraft). "View as user" opens a new tab showing the portal exactly as they see it; the banner at the bottom of that view ends the 15-minute preview.</div>
      <div style="display:flex;justify-content:flex-end;align-items:center;gap:12px;border-top:1px solid #e6e9ef;margin-top:12px;padding-top:14px">
        <button class="btn" id="save">Save access</button></div>
    </div>
  </div>
  <div class="mod" id="fqamod">
    <b>FOQA safety deck</b>
    <div class="small" style="margin-bottom:8px">Drop Kasen's monthly .pptx to update the instructor safety panel. Parsed and shown to you before anything is saved. <span id="fqamonths"></span></div>
    <div id="fqaZone" style="border:2px dashed #d9dee7;border-radius:9px;background:#fafbfd;padding:14px;text-align:center;cursor:pointer;font-size:13px">
      <b>Drop the .pptx here</b> <span style="color:#6b7488">or click to choose</span>
      <input type="file" id="fqaFile" accept=".pptx" style="display:none">
    </div>
    <div id="fqaMsg" class="small" style="margin-top:8px;font-weight:700;min-height:16px"></div>
    <div id="fqaOut" class="small" style="margin-top:6px;display:none"></div>
  </div>
  <div class="mod">
    <b>Anthropic API key &mdash; key only</b>
    <div class="small" style="margin-bottom:8px">This box takes ONLY the Anthropic API key that powers invoice reading. It is not a place to upload documents. Stored server-side and never shown again after saving. Status: <span id="aist"><?php echo esc_html($aiSet); ?></span></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input type="password" id="aikey" placeholder="sk-ant-..." autocomplete="off" style="flex:1;min-width:220px;font:inherit;padding:8px 10px;border:1px solid #d9dee7;border-radius:8px">
      <button class="btn" id="aisave" style="font-size:13px">Save key</button>
    </div>
    <div id="ainote" class="small" style="margin-top:8px;font-weight:700;color:#1E7C46;<?php echo $aiNote === '' ? 'display:none' : ''; ?>"><?php echo esc_html($aiNote); ?></div>
  </div>
  <div id="pwov" style="display:none;position:fixed;inset:0;background:rgba(15,29,61,.5);z-index:99;align-items:flex-start;justify-content:center;padding:96px 16px 16px">
    <div style="background:#fff;border-radius:12px;padding:20px;max-width:430px;width:100%;box-shadow:0 14px 44px rgba(15,23,42,.35)">
      <b id="pwtitle">Temporary password</b>
      <div class="small" style="margin:6px 0 10px">Shown once. Hand it over out of band - the site never emails it. A new password is required at first sign-in.</div>
      <div style="display:flex;gap:8px">
        <input id="pwval" readonly autocomplete="off" style="flex:1;font-family:Consolas,Menlo,monospace;font-size:15px;padding:9px 10px;border:1px solid #d9dee7;border-radius:8px">
        <button class="btn" id="pwcopy" type="button">Copy</button>
      </div>
      <div class="small" id="pwcopied" style="color:#1E7C46;font-weight:700;margin-top:6px;display:none">Copied to clipboard.</div>
      <div style="text-align:right;margin-top:10px"><button class="btn ghost" id="pwclose" type="button">Close</button></div>
    </div>
  </div>
  <div class="mod">
    <b>Audit log</b>
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
    function say(t,c){ms.textContent=t||'';ms.style.color=c==='e'?'#C0161C':(c==='k'?'#1E7C46':'#44506a');}
    function esc(s){return String(s).replace(/[<>&]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
    z.addEventListener('click',function(){fi.click();});
    ['dragenter','dragover'].forEach(function(e){z.addEventListener(e,function(ev){ev.preventDefault();ev.stopPropagation();z.style.borderColor='#B9822B';z.style.background='#fffaf0';});});
    ['dragleave','drop'].forEach(function(e){z.addEventListener(e,function(ev){ev.preventDefault();ev.stopPropagation();z.style.borderColor='#d9dee7';z.style.background='#fafbfd';});});
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
      if(mi.length){h+='<br><span style="color:#B9822B">Not found: '+esc(mi.join('; '))+'. Nothing saved yet.</span>';}
      h+='<br><button type="button" class="btn" id="fqaSave" style="font-size:13px;margin-top:8px"'+(fo.month_key?'':' disabled')+'>Save '+esc(fo.label||'')+'</button>';
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
      b.innerHTML='<span><b>'+esc(u.n)+'</b><span class="em">'+esc(u.e)+(u.d?' - disabled':'')+'</span></span>'
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
    var adm=document.getElementById('adm');adm.classList.toggle('on',!!u.a);adm.style.opacity=CANADM?'1':'.45';adm.title=CANADM?'':'Only a WordPress administrator (Ryan) can change this';
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
    achdr.innerHTML='<th colspan="3" style="text-align:left;padding-top:12px;border-top:1px solid #e6e9ef">Aircraft owner statements (view-only)</th>';
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
      r.innerHTML='<time>'+esc(e.t)+'</time><span><b>'+esc(e.who)+'</b> '+esc(e.txt)+(e.ip?' <span style="color:#8b93a3;font-size:11.5px">from '+esc(e.ip)+'</span>':'')+'</span>';
      box.appendChild(r);
    });
    if(!LOG.length){box.innerHTML='<div class="small">Nothing logged yet.</div>';}
  }
  function renderAll(){renderUsers();renderDetail();renderLog();}
  var pwov=document.getElementById('pwov');
  function showTempPw(who,pw){document.getElementById('pwtitle').textContent='Temporary password for '+who;var v=document.getElementById('pwval');v.value=pw;document.getElementById('pwcopied').style.display='none';pwov.style.display='flex';v.focus();v.select();}
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
