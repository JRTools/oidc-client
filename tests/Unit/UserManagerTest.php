<?php
/**
 * Tests für OIDC_User_Manager – Benutzer-Authentifizierung und Login-Fehler.
 *
 * Extrahiert aus AuthTest (SA-1 Refactoring).
 */

use Brain\Monkey\Functions;

require_once __DIR__ . '/WpTestCase.php';

// OIDC_User_Manager benötigt OIDC_Log – Stub bereitstellen
if ( ! class_exists( 'OIDC_Log' ) ) {
    class OIDC_Log {
        public static function write( $_user_id, $_success, $_message ) { /* Stub */ }
    }
}

if ( ! class_exists( 'OIDC_User_Manager' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-user-manager.php';
}

class UserManagerTest extends WpTestCase {

    /** @var OIDC_User_Manager */
    private $manager;

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        Functions\when( 'get_option' )->justReturn( '' );

        $this->manager = new OIDC_User_Manager();
    }

    protected function tearDown(): void {
        unset( $GLOBALS['wpdb'] );
        parent::tearDown();
    }

    /**
     * Gemeinsame Mocks für Login-Abschluss (wp_safe_redirect).
     */
    private function setUpLoginMocks(): void {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'update_user_meta' )->justReturn( true );
        Functions\when( 'wp_set_current_user' )->justReturn( null );
        Functions\when( 'wp_set_auth_cookie' )->justReturn( null );
        Functions\when( 'do_action' )->justReturn( null );
        Functions\when( 'apply_filters' )->justReturn( 'https://example.com/wp-admin/' );
        Functions\when( 'admin_url' )->justReturn( 'https://example.com/wp-admin/' );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );
    }

    /** Gemeinsamer get_option-Alias für Neuerstellungs-Tests. */
    private function newUserOptions(): \Closure {
        return function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_create_user' )    { return true; }
            if ( $key === 'oidc_default_role' )   { return 'subscriber'; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'never'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        };
    }

    // -------------------------------------------------------------------------
    // authenticate_user – Active-Claim
    // -------------------------------------------------------------------------

    public function test_authenticate_user_active_claim_false_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_active_claim' ) { return 'active'; }
            return $default;
        } );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user( array( 'email' => 'user@example.com', 'active' => false ) );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – Ungültige E-Mail
    // -------------------------------------------------------------------------

    public function test_authenticate_user_invalid_email_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( false );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user( array( 'email' => 'not-an-email' ) );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – Kein User, kein Create
    // -------------------------------------------------------------------------

    public function test_authenticate_user_no_user_no_create_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )  { return ''; }
            if ( $key === 'oidc_create_user' )   { return false; }
            return $default;
        } );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( false );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user( array( 'email' => 'new@example.com', 'sub' => 'sub123' ) );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – Neuen User anlegen
    // -------------------------------------------------------------------------

    public function test_authenticate_user_creates_new_user_and_logs_in() {
        $newUser            = new WP_User();
        $newUser->ID        = 42;
        $newUser->user_login = 'newuser';

        Functions\when( 'get_option' )->alias( $this->newUserOptions() );
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( $newUser );
        Functions\when( 'sanitize_user' )->returnArg();
        Functions\when( 'username_exists' )->justReturn( false );
        Functions\when( 'wp_insert_user' )->justReturn( 42 );
        Functions\when( 'wp_generate_password' )->justReturn( 'randompass' );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array( 'email' => 'new@example.com', 'sub' => 'sub123' ),
            array( 'id_token' => 'tok', 'access_token' => 'acc' )
        );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – Bestehender User
    // -------------------------------------------------------------------------

    public function test_authenticate_user_existing_user_updates_and_logs_in() {
        $existingUser            = new WP_User();
        $existingUser->ID        = 7;
        $existingUser->user_login = 'existinguser';

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'always'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        } );
        Functions\when( 'get_users' )->justReturn( array( $existingUser ) );
        Functions\when( 'wp_update_user' )->justReturn( 7 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array(
                'email'       => 'existing@example.com',
                'sub'         => 'sub-exists',
                'given_name'  => 'Max',
                'family_name' => 'Muster',
                'name'        => 'Max Muster',
            ),
            array()
        );
    }

    // -------------------------------------------------------------------------
    // SE-2: sub-Claim ist mandatory
    // -------------------------------------------------------------------------

    public function test_authenticate_user_missing_sub_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' ) { return ''; }
            return $default;
        } );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\expect( 'get_users' )->never();
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array( 'email' => 'nosub@example.com' ),
            array()
        );
    }

    public function test_authenticate_user_empty_sub_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' ) { return ''; }
            return $default;
        } );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\expect( 'get_users' )->never();
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array( 'email' => 'emptysub@example.com', 'sub' => '' ),
            array()
        );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – Username-Kollision
    // -------------------------------------------------------------------------

    public function test_authenticate_user_create_user_with_username_collision() {
        $newUser            = new WP_User();
        $newUser->ID        = 55;
        $newUser->user_login = 'newuser_abc12';

        Functions\when( 'get_option' )->alias( $this->newUserOptions() );
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( $newUser );
        Functions\when( 'sanitize_user' )->returnArg();
        Functions\when( 'username_exists' )->justReturn( true );
        Functions\when( 'wp_generate_password' )->justReturn( 'abc12' );
        Functions\when( 'wp_insert_user' )->justReturn( 55 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array(
                'email'              => 'new@example.com',
                'sub'                => 'sub-new',
                'preferred_username' => 'newuser',
            ),
            array()
        );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – wp_insert_user Fehler
    // -------------------------------------------------------------------------

    public function test_authenticate_user_wp_insert_user_error_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( $this->newUserOptions() );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( false );
        Functions\when( 'sanitize_user' )->returnArg();
        Functions\when( 'username_exists' )->justReturn( false );
        Functions\when( 'wp_generate_password' )->justReturn( 'rndpass' );
        Functions\when( 'wp_insert_user' )->justReturn( new WP_Error( 'insert_failed', 'DB-Fehler' ) );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user( array( 'email' => 'new@example.com', 'sub' => 'sub123' ) );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – website-Claim
    // -------------------------------------------------------------------------

    public function test_authenticate_user_updates_website_url_from_userinfo() {
        $existingUser             = new WP_User();
        $existingUser->ID         = 7;
        $existingUser->user_login = 'existinguser';

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'never'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        } );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array( $existingUser ) );
        Functions\when( 'wp_update_user' )->justReturn( 7 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array(
                'email'   => 'existing@example.com',
                'sub'     => 'sub-exists',
                'website' => 'https://user.example.com',
            ),
            array()
        );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – User per Subject-Meta finden
    // -------------------------------------------------------------------------

    public function test_authenticate_user_valid_sub_finds_user_by_subject_meta() {
        $existingUser             = new WP_User();
        $existingUser->ID         = 11;
        $existingUser->user_login = 'subuser';

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'never'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        } );
        Functions\when( 'get_users' )->justReturn( array( $existingUser ) );
        Functions\expect( 'get_user_by' )->never();
        Functions\when( 'wp_update_user' )->justReturn( 11 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->manager->authenticate_user(
            array( 'email' => 'sub@example.com', 'sub' => 'valid-sub-123' ),
            array()
        );
    }
}
