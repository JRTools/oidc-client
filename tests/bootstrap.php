<?php
/**
 * PHPUnit Test Bootstrap für den OIDC Client.
 *
 * Lädt Composer-Autoloader und definiert WP-Stubs, die vom Plugin-Code
 * benötigt werden, ohne eine echte WordPress-Instanz aufzusetzen.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Brain\Monkey;

// Mindest-WordPress-Konstanten
require_once __DIR__ . '/stubs/constants.php';

// WP_Error Stub
if ( ! class_exists( 'WP_Error' ) ) {
    class WP_Error {
        public $code;
        public $message;
        public $data;

        public function __construct( $code = '', $message = '', $data = '' ) {
            $this->code    = $code;
            $this->message = $message;
            $this->data    = $data;
        }

        public function get_error_message( $_code = '' ) {
            return $this->message;
        }

        public function get_error_code() {
            return $this->code;
        }

        public function add( $code, $message, $data = '' ) {
            $this->code    = $code;
            $this->message = $message;
            $this->data    = $data ?: $this->data;
        }
    }
}

// WP_User Stub
if ( ! class_exists( 'WP_User' ) ) {
    class WP_User {
        public $ID   = 0;
        public $data;
        public $roles        = array();
        public $user_email   = '';
        private $set_role_calls  = array();
        private $add_role_calls  = array();

        public function set_role( $role ) {
            $this->set_role_calls[] = $role;
        }

        public function add_role( $role ) {
            $this->add_role_calls[] = $role;
        }

        public function get_set_role_calls() {
            return $this->set_role_calls;
        }

        public function get_add_role_calls() {
            return $this->add_role_calls;
        }
    }
}

// WP_Post Stub
if ( ! class_exists( 'WP_Post' ) ) {
    class WP_Post {
        public $post_author = 0;
        public function __construct( $author = 0 ) {
            $this->post_author = $author;
        }
    }
}

// WP_Comment Stub
if ( ! class_exists( 'WP_Comment' ) ) {
    class WP_Comment {
        public $comment_author_email = '';
        public function __construct( $email = '' ) {
            $this->comment_author_email = $email;
        }
    }
}

// WP-Funktions-Stubs für den Ladevorgang von Plugin-Dateien.
// WICHTIG: Nur Funktionen definieren, die NICHT per Brain\Monkey gemockt werden!
// add_action, add_filter, get_option etc. werden von Brain\Monkey per Test gemockt
// und dürfen daher NICHT hier als PHP-Funktionen definiert werden.
if ( ! function_exists( 'plugin_dir_path' ) ) {
    function plugin_dir_path( $file ) {
        return dirname( $file ) . '/';
    }
}
if ( ! function_exists( 'plugin_dir_url' ) ) {
    function plugin_dir_url( $file ) {
        return 'https://example.com/wp-content/plugins/oidc-client/';
    }
}
if ( ! function_exists( 'register_activation_hook' ) ) {
    function register_activation_hook( $file, $callback ) {}
}

// Shared Test-Hilfsstubs (in allen Unit-Tests verfügbar)
if ( ! class_exists( 'OidcTestException' ) ) {
    class OidcTestException extends RuntimeException {}
}

if ( ! class_exists( 'FakeWpdb' ) ) {
    class FakeWpdb {
        public $prefix   = 'wp_';
        public $users    = 'wp_users';
        public $inserted = array();

        public function insert( $table, $data, $_formats ) {
            $this->inserted = array( 'table' => $table, 'data' => $data );
        }

        public function prepare( $sql, ...$args ) {
            return $sql;
        }

        public function get_results( $sql ) {
            return array();
        }

        public function get_var( $sql ) {
            return 0;
        }

        public function query( $sql ) {
            return true;
        }
    }
}

// Plugin-Klassen laden
require_once __DIR__ . '/../includes/class-oidc-jwt-helper.php';
require_once __DIR__ . '/../includes/class-oidc-tokens.php';
require_once __DIR__ . '/../includes/class-oidc-roles.php';
require_once __DIR__ . '/../includes/class-oidc-admin.php';
require_once __DIR__ . '/../includes/class-oidc-auth.php';
require_once __DIR__ . '/../includes/class-oidc-log.php';
require_once __DIR__ . '/../includes/class-oidc-login.php';
require_once __DIR__ . '/../includes/class-oidc-logout.php';
require_once __DIR__ . '/../includes/class-oidc-profile.php';
