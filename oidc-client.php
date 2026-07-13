<?php
/**
 * Plugin Name:  OIDC Client
 * Plugin URI:   https://github.com/johannesroesch/oidc-client
 * Description:  Ermöglicht die Anmeldung per OpenID Connect (Authorization Code Flow + PKCE). Unterstützt Token-Verschlüsselung, Rollen-Mapping, Session-Management, Frontchannel- und Backchannel-Logout sowie Account-Linking.
 * Version:      1.2.0
 * Author:       Johannes Rösch
 * Author URI:   https://github.com/johannesroesch
 * License:      GPL-2.0-or-later
 * License URI:  https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright (C) 2026 Johannes Rösch
 * Requires PHP: 8.1
 * Requires at least: 6.7
 * Text Domain:  oidc-client
 * Domain Path:  /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'OIDC_CLIENT_VERSION', '1.2.0' );
define( 'OIDC_CLIENT_DIR',     plugin_dir_path( __FILE__ ) );
define( 'OIDC_CLIENT_URL',     plugin_dir_url( __FILE__ ) );

// Activation Hook – Datenbanktabelle anlegen und sichere Standardwerte setzen
register_activation_hook( __FILE__, function () {
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-oidc-log.php';
    OIDC_Log::install();
    // Token-Verschlüsselung standardmäßig aktivieren (add_option überschreibt keine bestehenden Werte).
    add_option( 'oidc_token_encryption', '1' );
} );

require_once OIDC_CLIENT_DIR . 'includes/class-oidc-jwk-helper.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-jwt-helper.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-log.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-tokens.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-roles.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-token-exchange.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-user-manager.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-logout.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-profile.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-admin-fields.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-admin-sanitize.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-admin.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-auth.php';
require_once OIDC_CLIENT_DIR . 'includes/class-oidc-login.php';

function oidc_client_init() {
    // Instanzen registrieren ihre WordPress-Hooks im Konstruktor.
    $GLOBALS['oidc_log']     = new OIDC_Log();
    $GLOBALS['oidc_logout']  = new OIDC_Logout();
    $GLOBALS['oidc_profile'] = new OIDC_Profile();
    $GLOBALS['oidc_admin']   = new OIDC_Admin();
    $GLOBALS['oidc_auth']    = new OIDC_Auth();
    $GLOBALS['oidc_login']   = new OIDC_Login();
}
add_action( 'plugins_loaded', 'oidc_client_init' );
