<?php
/* ===================================================================
   ONE-TIME SETUP for snippet 11 (JAXAERO Access Control)
   Run via Novamira execute-php AFTER snippet 11 is installed+active.

   PASSWORD HANDLING - READ FIRST
     The first account (Ben Gabriel) is created with the password in
     JAXAUTH_SETUP_PW below. The checked-in value is a placeholder;
     Ryan supplies the real one AT RUN TIME. Substitute it in the
     payload you execute, NEVER in this file, and NEVER commit a real
     password to the repo (CLAUDE.md hard rule 4). The script aborts
     loudly if the placeholder was not replaced.

   Safe to re-run: every step checks before it creates.
   =================================================================== */

if (!defined('ABSPATH')) { exit('run inside WordPress'); }

if (!defined('JAXAUTH_SETUP_PW')) { define('JAXAUTH_SETUP_PW', '<<REPLACE_AT_RUN_TIME>>'); }

$out = [];

if (!function_exists('jaxauth_registry')) {
  exit('ABORT: snippet 11 (jaxauth_) is not active. Install and activate it first.');
}
if (JAXAUTH_SETUP_PW === '<<REPLACE_AT_RUN_TIME>>') {
  exit('ABORT: the setup password placeholder was not replaced. Substitute it in the payload at run time.');
}

/* ---- 1. sign-in page ---- */
$signin = (int) get_option('jaxauth_signin_page');
if (!$signin || !get_post($signin)) {
  $signin = wp_insert_post(wp_slash([
    'post_title'   => 'Sign in',
    'post_name'    => 'signin',
    'post_type'    => 'page',
    'post_status'  => 'publish',
    'post_content' => '[jaxaero_login]',
  ]));
  update_post_meta($signin, '_wp_page_template', 'elementor_canvas');
  update_option('jaxauth_signin_page', $signin, false);
  $out[] = "created /signin page id $signin";
} else { $out[] = "signin page already exists: $signin"; }

/* ---- 2. access admin page ---- */
$adminp = (int) get_option('jaxauth_admin_page');
if (!$adminp || !get_post($adminp)) {
  $adminp = wp_insert_post(wp_slash([
    'post_title'   => 'Access admin',
    'post_name'    => 'access-admin',
    'post_type'    => 'page',
    'post_status'  => 'publish',
    'post_content' => '[jaxaero_access_admin]',
  ]));
  update_post_meta($adminp, '_wp_page_template', 'elementor_canvas');
  update_option('jaxauth_admin_page', $adminp, false);
  $out[] = "created /access-admin page id $adminp";
} else { $out[] = "admin page already exists: $adminp"; }

/* ---- 3. page gating map (page id => widget key) ---- */
$pages = get_option('jaxauth_pages', []);
if (!is_array($pages)) { $pages = []; }
$want = [
  5785 => 'rev', 5787 => 'auto', 5788 => 'sales', 5789 => 'tax',
  5795 => 'pay.rates', 5816 => 'requests',
  $signin => '', $adminp => 'access',
];
foreach ($want as $pid => $key) { $pages[$pid] = $key; }
update_option('jaxauth_pages', $pages, false);
$out[] = 'page map set: ' . wp_json_encode($pages);

/* ---- 4. Ben Gabriel, first member, all dashboard widgets ---- */
$email = 'ben@flyjaxaero.com';
$ben = get_user_by('email', $email);
if (!$ben) {
  $uid = wp_insert_user([
    'user_login'   => $email,
    'user_email'   => $email,
    'user_pass'    => JAXAUTH_SETUP_PW,
    'display_name' => 'Ben Gabriel',
    'role'         => 'jaxaero_member',
  ]);
  if (is_wp_error($uid)) { exit('ABORT creating Ben: ' . $uid->get_error_message()); }
  $out[] = "created member account for Ben Gabriel, user id $uid";
} else {
  $uid = $ben->ID;
  $out[] = "Ben already exists as user $uid - grants refreshed, password NOT touched";
}
/* "All widgets" = every dashboard widget. The access-admin panel is an
   admin tool, not a widget, so it is deliberately not granted; flip it
   here if Ryan wants Ben administering. No instructor binding - Ben
   Gabriel is not a CFI, so the invoice key would render nothing. */
update_user_meta($uid, 'jaxauth_grants',
  ['rev', 'auto', 'pay', 'pay.rates', 'sales', 'tax', 'requests']);
update_user_meta($uid, 'jaxauth_instructor', '');
delete_user_meta($uid, 'jaxauth_disabled');
delete_user_meta($uid, 'jaxauth_must_change');
$out[] = 'Ben grants: rev, auto, pay, pay.rates, sales, tax, requests';

/* ---- 5. seed the audit log ---- */
if (function_exists('jaxauth_log_add')) {
  jaxauth_log_add('Setup ran: pages created, page map written, Ben Gabriel account ready.');
}

echo implode("\n", $out) . "\nSETUP COMPLETE\n";
echo 'Sign-in URL: ' . get_permalink((int) get_option('jaxauth_signin_page')) . "\n";
echo 'Admin URL:   ' . get_permalink((int) get_option('jaxauth_admin_page')) . "\n";
