<?php
/**
 * WordPress-Funktions-Stubs für PHPUnit-Tests.
 *
 * Diese Datei wird von WpTestCase::setUp() geladen – NACH Brain\Monkey\setUp().
 * Nur so kann Patchwork die Funktionen instrumentieren und Brain\Monkey sie
 * pro Test neu definieren.
 *
 * WICHTIG: Nur Funktionen hierher, die per Brain\Monkey\Functions\when() /
 *          expect() in Tests gemockt werden. Funktionen, die nie gemockt werden
 *          (plugin_dir_path, register_activation_hook, …), bleiben in bootstrap.php.
 *
 * @package   OIDC_Client
 * @copyright 2026 Johannes Rösch
 * @license   GPL-2.0-or-later
 */

if ( ! function_exists( 'add_action' ) ) {
    function add_action( $hook = '', $callback = null, $priority = 10, $accepted_args = 1 ) {}
}
if ( ! function_exists( 'add_filter' ) ) {
    function add_filter( $hook = '', $callback = null, $priority = 10, $accepted_args = 1 ) {}
}
if ( ! function_exists( 'get_option' ) ) {
    function get_option( $option = '', $default = false ) {
        return $default;
    }
}
if ( ! function_exists( 'do_action' ) ) {
    function do_action( $hook = '', ...$args ) {}
}
if ( ! function_exists( 'apply_filters' ) ) {
    function apply_filters( $hook = '', $value = null ) {
        return $value;
    }
}
if ( ! function_exists( 'sanitize_key' ) ) {
    function sanitize_key( $key = '' ) {
        return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
    }
}
