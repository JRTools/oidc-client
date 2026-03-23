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

// Plugin-spezifische Konstanten
if ( ! defined( 'OIDC_CLIENT_VERSION' ) ) {
    define( 'OIDC_CLIENT_VERSION', '1.0.0' );
}
if ( ! defined( 'OIDC_CLIENT_DIR' ) ) {
    define( 'OIDC_CLIENT_DIR', __DIR__ . '/../' );
}
if ( ! defined( 'OIDC_CLIENT_URL' ) ) {
    define( 'OIDC_CLIENT_URL', 'https://example.com/wp-content/plugins/oidc-client/' );
}

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

// Plugin-Klassen laden (ohne ABSPATH-Check, da wir ihn oben definiert haben)
require_once __DIR__ . '/../includes/class-oidc-jwt-helper.php';
require_once __DIR__ . '/../includes/class-oidc-tokens.php';
require_once __DIR__ . '/../includes/class-oidc-roles.php';
