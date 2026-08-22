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
       rollout).
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
    'pay'       => ['Payroll widget', 'all-instructor pay table'],
    'pay.rates' => ['Rate editor', 'instructor pay rates page'],
    'sales'     => ['Sales pipeline', 'revenue + pipeline dashboard'],
    'tax'       => ['Sales tax', 'aircraft sales tax page'],
    'requests'  => ['Punch list', 'current tasks'],
    'docs'      => ['Documents', 'archive & search'],
    'expense'   => ['Add expenses', 'enter expenses on the owner P/L'],
    'owner'     => ['My Aircraft', 'your aircraft statements (owners)'],
    'invoice'   => ['Own Instructor Invoice', 'only the bound instructor'],
    'access'    => ['Access admin', 'this admin panel'],
  ];
}

function jaxauth_shortcode_map() {
  return [
    'jaxaero_revenue_auto'   => 'auto',
    'jaxaero_payroll'        => 'pay',
    'jaxaero_rate_editor'    => 'pay.rates',
    'jaxaero_revenue_sales'  => 'sales',
    'jaxaero_tax'            => 'tax',
    'jaxaero_requests'       => 'requests',
    'jaxaero_documents'      => 'docs',
    'jaxaero_instructor_pay' => 'invoice',
    'jaxaero_owner_portal'   => 'owner',
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

function jaxauth_can($key, $uid = 0) {
  $uid = $uid ? $uid : get_current_user_id();
  if (!$uid) { return false; }
  if (!jaxauth_enabled($uid)) { return false; }
  $user = get_user_by('id', $uid);
  if (jaxauth_is_admin($user)) { return true; }
  return in_array($key, jaxauth_grants($uid), true);
}

function jaxauth_log_add($txt) {
  $log = get_option('jaxauth_log', []);
  if (!is_array($log)) { $log = []; }
  $who = wp_get_current_user();
  array_unshift($log, [
    't'   => current_time('M j, g:i A'),
    'who' => ($who && $who->exists()) ? $who->display_name : 'system',
    'txt' => sanitize_text_field($txt),
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

add_filter('login_redirect', function ($to, $requested, $user) {
  if ($user instanceof WP_User && jaxauth_is_managed($user) && !jaxauth_is_admin($user) && !user_can($user, 'edit_posts')) {
    $p = get_option('jaxauth_signin_page');
    return $p ? get_permalink($p) : home_url('/');
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

/* Widget gate: a signed-in managed user only renders shortcodes they
   hold the key for. Anonymous visitors fall through to page passwords. */
add_filter('pre_do_shortcode_tag', function ($ret, $tag, $attr) {
  $map = jaxauth_shortcode_map();
  if (!isset($map[$tag])) { return $ret; }
  $u = wp_get_current_user();
  if (!$u || !$u->exists() || !jaxauth_is_managed($u)) { return $ret; }
  $key = $map[$tag];
  if ($key === 'invoice') {
    if (jaxauth_is_admin($u)) { return $ret; }
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

function jaxauth_denied_html() {
  $p = get_option('jaxauth_signin_page');
  $home = $p ? esc_url(get_permalink($p)) : esc_url(home_url('/'));
  return '<div style="max-width:480px;margin:40px auto;padding:24px;text-align:center;'
    . 'font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1F2F54;'
    . 'background:#fff;border:1px solid #e6e9ef;border-radius:14px">'
    . '<b>This widget is not enabled for your account.</b><br>'
    . '<span style="font-size:13px;color:#5b6577">If you think it should be, ask Ryan.</span><br><br>'
    . '<a href="' . $home . '" style="color:#C10F1B;font-weight:700;font-size:13px">Back to your dashboard</a></div>';
}

/* Password bypass: a signed-in user who holds the page key does not
   need the page password. Everyone else sees the form as before. */
add_filter('post_password_required', function ($required, $post) {
  if (!$required || !$post) { return $required; }
  $u = wp_get_current_user();
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
    $p = get_option('jaxauth_signin_page');
    wp_safe_redirect($p ? get_permalink($p) : home_url('/'));
    exit;
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
    'permission_callback' => function () { return is_user_logged_in(); },
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
  register_rest_route('jaxauth/v1', '/admin/reset-password', [
    'methods' => 'POST',
    'permission_callback' => 'jaxauth_is_admin',
    'callback' => 'jaxauth_rest_reset_pw',
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
  $email = sanitize_email((string) $req->get_param('email'));
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
  return [
    'ok' => true,
    'mustChange' => get_user_meta($user->ID, 'jaxauth_must_change', true) === '1',
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
  return ['ok' => true];
}

function jaxauth_rest_save_user(WP_REST_Request $req) {
  $uid = (int) $req->get_param('user_id');
  $user = get_user_by('id', $uid);
  if (!$user || !jaxauth_is_managed($user)) {
    return new WP_Error('jaxauth_nouser', 'No such managed user.', ['status' => 404]);
  }
  $me = get_current_user_id();
  $grants = $req->get_param('grants');
  $grants = is_array($grants)
    ? array_values(array_intersect(array_map('sanitize_text_field', $grants), array_keys(jaxauth_registry())))
    : [];
  $inst = sanitize_title((string) $req->get_param('instructor'));
  $disabled = $req->get_param('disabled') ? '1' : '';
  if ($uid === $me && $disabled === '1') {
    return new WP_Error('jaxauth_self', 'You cannot disable your own account.', ['status' => 400]);
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
  update_user_meta($uid, 'jaxauth_instructor', $inst);
  if ($disabled === '1') { update_user_meta($uid, 'jaxauth_disabled', '1'); }
  else { delete_user_meta($uid, 'jaxauth_disabled'); }
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
  if ($name === '' || !is_email($email)) {
    return new WP_Error('jaxauth_bad', 'A name and a valid email are required.', ['status' => 400]);
  }
  if (get_user_by('email', $email)) {
    return new WP_Error('jaxauth_dup', 'A user with that email already exists.', ['status' => 409]);
  }
  $temp = wp_generate_password(14, false, false);
  $uid = wp_insert_user([
    'user_login'   => $email,
    'user_email'   => $email,
    'user_pass'    => $temp,
    'display_name' => $name,
    'role'         => JAXAUTH_ROLE,
  ]);
  if (is_wp_error($uid)) { return $uid; }
  update_user_meta($uid, 'jaxauth_grants', []);
  update_user_meta($uid, 'jaxauth_instructor', '');
  update_user_meta($uid, 'jaxauth_must_change', '1');
  jaxauth_log_add('created account for ' . $name . '. Temporary password shown once.');
  return ['ok' => true, 'user_id' => $uid, 'temp_password' => $temp];
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

/* -------------------- shared iframe wrapper -------------------- */

/* body.scrollHeight, never documentElement (the K10 ratchet lesson). */
function jaxauth_iframe($html, $fid, $title) {
  /* No scrolling="no"/overflow:hidden: if the parent resize listener is ever
     delayed or killed (WP Rocket delay-JS), the frame scrolls internally
     instead of hard-clipping the buttons below the fold. When the listener
     runs, the height is exact and no scrollbar shows. */
  return '<div style="display:block;width:100%;margin:0;padding:0;line-height:0">'
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
    . '.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}'
    . '.card{display:block;background:#fff;border:1px solid #e6e9ef;border-radius:12px;padding:16px;text-decoration:none;color:#1F2F54}'
    . '.card:hover{border-color:#C0A788}'
    . '.card b{font-size:15px}.card span{display:block;font-size:12.5px;color:#5b6577;margin-top:3px}'
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
    <div class="fld"><label for="em">Email address</label>
      <input id="em" type="email" autocomplete="username" placeholder="you@flyjaxaero.com"></div>
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
      if(x.s===200&&x.j&&x.j.ok){if(window.parent!==window){window.parent.location.reload();}else{location.reload();}return;}
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
  $reg     = jaxauth_registry();
  $pages   = get_option('jaxauth_pages', []);
  $cards   = [];
  if (is_array($pages)) {
    foreach ($pages as $pid => $key) {
      if ($key === '' || !isset($reg[$key])) { continue; }
      if (!jaxauth_can($key, $u->ID)) { continue; }
      if ($key === 'pay') { continue; }
      $cards[] = ['t' => $reg[$key][0], 'd' => $reg[$key][1], 'u' => get_permalink($pid)];
    }
  }
  ob_start(); ?>
<?php echo jaxauth_frame_head(); ?>
<div class="wrap">
  <span class="brand">JAXAERO</span>
  <h1>Welcome, <?php echo esc_html($u->display_name); ?></h1>
  <div class="sub">Everything your account can open. Signed in as <?php echo esc_html($u->user_email); ?>.
    <button class="btn ghost" id="out" style="padding:4px 12px;font-size:12px;margin-left:8px">Sign out</button></div>
  <?php if ($must) { ?><div class="note"><b>Please choose a new password now.</b> The one you signed in with was temporary.</div><?php } ?>
  <?php if (count($cards) === 0) { ?><div class="mod small">No pages are enabled for your account yet. Ask Ryan.</div><?php } ?>
  <div class="cards">
  <?php foreach ($cards as $c) { ?>
    <a class="card" href="<?php echo esc_url($c['u']); ?>"><b><?php echo esc_html($c['t']); ?></b><span><?php echo esc_html($c['d']); ?></span></a>
  <?php } ?>
  </div>
  <div class="mod" style="margin-top:16px;max-width:430px">
    <b>Change your password</b>
    <div class="small" style="margin-bottom:10px">At least <?php echo (int) JAXAUTH_MIN_PW; ?> characters. Takes effect immediately.</div>
    <div class="err" id="perr"></div><div class="okmsg" id="pok">Password changed.</div>
    <div class="fld"><label for="cur">Current password</label><input id="cur" type="password" autocomplete="current-password"></div>
    <div class="fld"><label for="nw">New password</label><input id="nw" type="password" autocomplete="new-password"></div>
    <div class="fld"><label for="nw2">New password again</label><input id="nw2" type="password" autocomplete="new-password"></div>
    <button class="btn" id="pgo">Change password</button>
  </div>
</div>
<script>
(function(){
  var PW=<?php echo wp_json_encode($restPw); ?>,OUT=<?php echo wp_json_encode($restOut); ?>,N=<?php echo wp_json_encode($nonce); ?>;
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
        document.getElementById('cur').value='';document.getElementById('nw').value='';document.getElementById('nw2').value='';return;}
      pfail(x.j&&x.j.message?x.j.message:'That did not work.');
    })
    .catch(function(){pfail('Could not reach the site.');});
  });
  document.getElementById('out').addEventListener('click',function(){
    fetch(OUT,{method:'POST',credentials:'same-origin',headers:{'X-WP-Nonce':N}})
    .then(function(){if(window.parent!==window){window.parent.location.reload();}else{location.reload();}});
  });
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
  $restBase = esc_url_raw(rest_url('jaxauth/v1/'));
  $reg = jaxauth_registry();
  $users = [];
  foreach (get_users(['role' => JAXAUTH_ROLE]) as $wu) {
    $users[] = [
      'id' => $wu->ID, 'n' => $wu->display_name, 'e' => $wu->user_email,
      'g' => jaxauth_grants($wu->ID),
      'b' => (string) get_user_meta($wu->ID, 'jaxauth_instructor', true),
      'd' => !jaxauth_enabled($wu->ID),
      'ac' => array_values((array) get_user_meta($wu->ID, 'jaxown_aircraft', true)),
    ];
  }
  $acd0 = get_option('jaxac_data_last', array());
  $acTails = (is_array($acd0) && !empty($acd0['fleet']) && is_array($acd0['fleet']))
    ? array_keys($acd0['fleet']) : array('N768SP', 'N146F', 'N1196M', 'N234ZG', 'N9711S');
  $slugs = array_keys((array) get_option('jaxpay_instructors', []));
  $log = get_option('jaxauth_log', []);
  if (!is_array($log)) { $log = []; }
  $log = array_slice($log, 0, 40);
  $aiKey = (string) get_option('jaxaero_anthropic_key', '');
  $aiSet = $aiKey !== '' ? ('Set - ends ' . substr($aiKey, -4)) : 'Not set';
  $aiAt = (string) get_option('jaxaero_anthropic_key_at', '');
  $aiNote = $aiKey !== '' ? ('An Anthropic API key has been added (ends ' . substr($aiKey, -4) . ($aiAt !== '' ? ', saved ' . $aiAt : '') . ').') : '';
  ob_start(); ?>
<?php echo jaxauth_frame_head(); ?>
<div class="wrap">
  <span class="brand">JAXAERO</span>
  <h1>Access admin</h1>
  <div class="sub">Pick a person, flip toggles, save. Changes apply on their next page load. Every save is logged below.</div>
  <div class="grid2">
    <div class="mod ulist">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <b>People</b><button class="btn ghost" id="addU" style="padding:4px 12px;font-size:12px">+ Add user</button></div>
      <div id="ulist"></div>
    </div>
    <div class="mod">
      <div class="err" id="aerr"></div><div class="okmsg" id="aok">Saved.</div>
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;border-bottom:1px solid #e6e9ef;padding-bottom:14px;margin-bottom:14px">
        <div class="fld" style="flex:1;min-width:150px;margin:0"><label>Name</label><input id="dn" readonly></div>
        <div class="fld" style="flex:1;min-width:170px;margin:0"><label>Email</label><input id="de" readonly></div>
        <div class="fld" style="flex:1;min-width:150px;margin:0"><label>Instructor binding</label><select id="db"></select></div>
        <label class="small" style="display:flex;align-items:center;gap:6px;padding-bottom:4px"><input type="checkbox" id="dd"> Disabled</label>
        <button class="btn ghost" id="resetPw" style="font-size:12.5px">Reset password</button>
      </div>
      <div style="overflow-x:auto"><table id="mx">
        <tr><th>Widget</th><th></th><th style="width:48px">On</th></tr>
      </table></div>
      <div style="display:flex;justify-content:flex-end;align-items:center;gap:12px;border-top:1px solid #e6e9ef;margin-top:12px;padding-top:14px">
        <button class="btn" id="save">Save access</button></div>
    </div>
  </div>
  <div class="mod">
    <b>AI document intake</b>
    <div class="small" style="margin-bottom:8px">Anthropic API key for the invoice-reading feature. Stored server-side only and never displayed again after saving. Status: <span id="aist"><?php echo esc_html($aiSet); ?></span></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input type="password" id="aikey" placeholder="sk-ant-..." autocomplete="off" style="flex:1;min-width:220px;font:inherit;padding:8px 10px;border:1px solid #d9dee7;border-radius:8px">
      <button class="btn" id="aisave" style="font-size:13px">Save key</button>
    </div>
    <div id="ainote" class="small" style="margin-top:8px;font-weight:700;color:#1E7C46;<?php echo $aiNote === '' ? 'display:none' : ''; ?>"><?php echo esc_html($aiNote); ?></div>
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
  var USERS=<?php echo wp_json_encode($users); ?>;
  var SLUGS=<?php echo wp_json_encode($slugs); ?>;
  var ACTAILS=<?php echo wp_json_encode($acTails); ?>;
  var LOG=<?php echo wp_json_encode($log); ?>;
  var sel=USERS.length?USERS[0].id:0;
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
        +'<span class="chip">'+(u.d?'OFF':(u.b?'CFI':'USER'))+'</span>';
      b.addEventListener('click',function(){sel=u.id;renderAll();});
      box.appendChild(b);
    });
    if(!USERS.length){box.innerHTML='<div class="small">No member accounts yet. Use Add user.</div>';}
  }
  function renderDetail(){
    var u=cur();if(!u){return;}
    document.getElementById('dn').value=u.n;
    document.getElementById('de').value=u.e;
    var db=document.getElementById('db');db.innerHTML='';
    var o0=document.createElement('option');o0.value='';o0.textContent='none';db.appendChild(o0);
    SLUGS.forEach(function(s){var o=document.createElement('option');o.value=s;o.textContent=s;db.appendChild(o);});
    db.value=u.b||'';
    document.getElementById('dd').checked=!!u.d;
    var mx=document.getElementById('mx');
    mx.innerHTML='<tr><th>Widget</th><th></th><th style="width:48px">On</th></tr>';
    Object.keys(REG).forEach(function(k){
      if(k==='owner'){return;}
      var tr=document.createElement('tr');
      tr.innerHTML='<td><b>'+esc(REG[k][0])+'</b></td><td class="small">'+esc(REG[k][1])+'</td>'
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
  }
  function renderLog(){
    var box=document.getElementById('alog');box.innerHTML='';
    LOG.forEach(function(e){
      var r=document.createElement('div');r.className='arow';
      r.innerHTML='<time>'+esc(e.t)+'</time><span><b>'+esc(e.who)+'</b> '+esc(e.txt)+'</span>';
      box.appendChild(r);
    });
    if(!LOG.length){box.innerHTML='<div class="small">Nothing logged yet.</div>';}
  }
  function renderAll(){renderUsers();renderDetail();renderLog();}
  document.getElementById('save').addEventListener('click',function(){
    var u=cur();if(!u){return;}
    aerr.classList.remove('on');
    var on=[];document.querySelectorAll('#mx .tg.on:not(.actg)').forEach(function(t){on.push(t.dataset.k);});
    var ac=[];document.querySelectorAll('#mx .actg.on').forEach(function(t){ac.push(t.dataset.ac);});
    var body={user_id:u.id,grants:on,aircraft:ac,instructor:document.getElementById('db').value,
      disabled:document.getElementById('dd').checked};
    api('admin/save-user',body).then(function(x){
      if(x.s===200&&x.j&&x.j.ok){u.g=on;u.ac=ac;u.b=body.instructor;u.d=body.disabled;okFlash();renderUsers();
        LOG.unshift({t:'just now',who:'you',txt:'saved '+u.n+'.'});renderLog();return;}
      fail(x.j&&x.j.message?x.j.message:'Save failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  document.getElementById('resetPw').addEventListener('click',function(){
    var u=cur();if(!u){return;}
    if(!window.confirm('Set a new temporary password for '+u.n+'? Their current one stops working immediately.')){return;}
    api('admin/reset-password',{user_id:u.id}).then(function(x){
      if(x.s===200&&x.j&&x.j.temp_password){
        window.alert('Temporary password for '+u.n+':\n\n  '+x.j.temp_password+'\n\nShown once - copy it now. Hand it over out of band; the site cannot email it. A new password is required at first sign-in.');
        return;}
      fail(x.j&&x.j.message?x.j.message:'Reset failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  document.getElementById('addU').addEventListener('click',function(){
    var name=window.prompt('Full name for the new account:');if(!name){return;}
    var email=window.prompt('Email address (their sign-in name):');if(!email){return;}
    api('admin/create-user',{name:name,email:email}).then(function(x){
      if(x.s===200&&x.j&&x.j.temp_password){
        USERS.push({id:x.j.user_id,n:name,e:email,g:[],b:'',d:false});sel=x.j.user_id;renderAll();
        window.alert('Account created. Temporary password for '+name+':\n\n  '+x.j.temp_password+'\n\nShown once - copy it now. A new password is required at first sign-in.');
        return;}
      fail(x.j&&x.j.message?x.j.message:'Create failed.');
    }).catch(function(){fail('Could not reach the site.');});
  });
  renderAll();
})();
</script>
<?php echo jaxauth_frame_foot();
  return ob_get_clean();
}
