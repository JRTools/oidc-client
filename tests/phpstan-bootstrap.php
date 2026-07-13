<?php
/**
 * PHPStan Bootstrap – WP-Stubs ohne Brain\Monkey.
 *
 * @package   OIDC_Client
 * @copyright 2026 Johannes Rösch
 * @license   GPL-2.0-or-later
 */

// Gemeinsame WordPress-Konstanten
require_once __DIR__ . '/stubs/constants.php';

// Plugin-spezifische Konstanten
if ( ! defined( 'JRTOOLS_OIDC_VERSION' ) ) {
    define( 'JRTOOLS_OIDC_VERSION', '1.0.0' );
}
if ( ! defined( 'JRTOOLS_OIDC_DIR' ) ) {
    define( 'JRTOOLS_OIDC_DIR', __DIR__ . '/../' );
}
if ( ! defined( 'JRTOOLS_OIDC_URL' ) ) {
    define( 'JRTOOLS_OIDC_URL', 'https://example.com/wp-content/plugins/jrtools-openid-connect/' );
}

if ( ! class_exists( 'WP_Error' ) ) {
    class WP_Error {
        public string $code    = '';
        public string $message = '';

        public function __construct( string $code = '', string $message = '', mixed $_data = '' ) {
            $this->code    = $code;
            $this->message = $message;
        }

        public function get_error_message( string $_code = '' ): string {
            return $this->message;
        }

        public function get_error_code(): string {
            return $this->code;
        }
    }
}

if ( ! class_exists( 'WP_User' ) ) {
    class WP_User {
        public int    $ID    = 0;
        public array  $roles = array();
        public ?object $data  = null;

        public function set_role( string $_role ): void { /* Stub – keine Implementierung nötig */ }
        public function add_role( string $_role ): void { /* Stub – keine Implementierung nötig */ }
    }
}

if ( ! class_exists( 'WP_REST_Request' ) ) {
    class WP_REST_Request {
        public function get_param( string $_key ): mixed { return null; }
        public function get_params(): array { return array(); }
    }
}

if ( ! class_exists( 'WP_REST_Response' ) ) {
    class WP_REST_Response {
        public function __construct( mixed $_data = null, int $_status = 200 ) { /* Stub – keine Implementierung nötig */ }
    }
}
