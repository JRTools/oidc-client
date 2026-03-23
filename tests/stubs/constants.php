<?php
/**
 * Gemeinsame WordPress-Konstanten für PHPUnit- und PHPStan-Bootstrap.
 *
 * @package   OIDC_Client
 * @copyright 2026 Johannes Rösch
 * @license   GPL-2.0-or-later
 */

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'AUTH_KEY' ) ) {
    define( 'AUTH_KEY', 'test-auth-key-for-unit-tests-only' );
}
if ( ! defined( 'SECURE_AUTH_KEY' ) ) {
    define( 'SECURE_AUTH_KEY', 'test-secure-auth-key-for-unit-tests-only' );
}
if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
    define( 'HOUR_IN_SECONDS', 3600 );
}
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
    define( 'MINUTE_IN_SECONDS', 60 );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
    define( 'DAY_IN_SECONDS', 86400 );
}
if ( ! defined( 'OPENSSL_RAW_DATA' ) ) {
    define( 'OPENSSL_RAW_DATA', 1 );
}
if ( ! defined( 'OPENSSL_ALGO_SHA256' ) ) {
    define( 'OPENSSL_ALGO_SHA256', 7 );
}
