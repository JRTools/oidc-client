<?php
/**
 * Tests für OIDC_Profile – E-Mail-Sperre, Passwort-Sperre, Account-Linking.
 *
 * Brain\Monkey mockt WordPress-Funktionen.
 * WP_Error und WP_User kommen aus tests/bootstrap.php.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

if ( ! class_exists( 'OIDC_Profile' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-profile.php';
}

class ProfileTest extends WpTestCase {

    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        $_GET  = array();
        $_POST = array();
    }

    protected function tearDown(): void {
        $_GET  = array();
        $_POST = array();
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // maybe_lock_email
    // -------------------------------------------------------------------------

    public function test_lock_email_option_disabled_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_email' ? '' : $default;
        } );
        Functions\expect( 'get_user_meta' )->never();

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_email( $errors, true, $user );
        $this->addToAssertionCount( 1 );
    }

    public function test_lock_email_not_update_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_email' ? '1' : $default;
        } );
        Functions\expect( 'get_user_meta' )->never();

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_email( $errors, false, $user );
        $this->addToAssertionCount( 1 );
    }

    public function test_lock_email_no_oidc_subject_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_email' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\expect( 'get_user_by' )->never();

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_email( $errors, true, $user );
        $this->addToAssertionCount( 1 );
    }

    public function test_lock_email_same_email_no_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_email' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( 'sub-123' );

        $existing             = new WP_User();
        $existing->user_email = 'user@example.com';
        Functions\when( 'get_user_by' )->justReturn( $existing );

        $errors             = new WP_Error();
        $user               = new WP_User();
        $user->ID           = 1;
        $user->user_email   = 'user@example.com'; // gleiche E-Mail

        $profile = new OIDC_Profile();
        $profile->maybe_lock_email( $errors, true, $user );

        $this->assertSame( '', $errors->code ); // kein Fehler
    }

    public function test_lock_email_different_email_adds_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_email' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( 'sub-123' );
        Functions\when( '__' )->returnArg();

        $existing             = new WP_User();
        $existing->user_email = 'original@example.com';
        Functions\when( 'get_user_by' )->justReturn( $existing );

        $errors             = new WP_Error();
        $user               = new WP_User();
        $user->ID           = 1;
        $user->user_email   = 'new@example.com'; // geänderte E-Mail

        $profile = new OIDC_Profile();
        $profile->maybe_lock_email( $errors, true, $user );

        $this->assertSame( 'oidc_email_locked', $errors->code );
        $this->assertSame( 'original@example.com', $user->user_email );
    }

    // -------------------------------------------------------------------------
    // maybe_lock_password
    // -------------------------------------------------------------------------

    public function test_lock_password_option_disabled_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_password' ? '' : $default;
        } );
        Functions\expect( 'get_user_meta' )->never();

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_password( $errors, true, $user );
        $this->addToAssertionCount( 1 );
    }

    public function test_lock_password_no_oidc_subject_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_password' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_password( $errors, true, $user );

        $this->assertSame( '', $errors->code );
    }

    public function test_lock_password_no_post_pass_no_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_password' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( 'sub-123' );

        $_POST = array(); // kein pass1-Feld

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_password( $errors, true, $user );

        $this->assertSame( '', $errors->code );
    }

    public function test_lock_password_with_post_pass_adds_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_lock_password' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( 'sub-123' );
        Functions\when( '__' )->returnArg();

        $_POST['pass1'] = 'newpassword';

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_password( $errors, true, $user );

        $this->assertSame( 'oidc_password_locked', $errors->code );
    }

    // -------------------------------------------------------------------------
    // initiate_link_login
    // -------------------------------------------------------------------------

    public function test_initiate_link_login_no_param_returns_early() {
        Functions\expect( 'is_user_logged_in' )->never();

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_initiate_link_login_wrong_value_returns_early() {
        $_GET['oidc_link'] = '0';
        Functions\expect( 'is_user_logged_in' )->never();

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_initiate_link_login_not_logged_in_returns_early() {
        $_GET['oidc_link'] = '1';
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        Functions\expect( 'wp_verify_nonce' )->never();

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_initiate_link_login_invalid_nonce_calls_wp_die() {
        $_GET['oidc_link']       = '1';
        $_GET['oidc_link_nonce'] = 'bad-nonce';

        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( false );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'wp_die' )->alias( function ( $msg ) {
            throw new OidcTestException( $msg );
        } );

        $profile = new OIDC_Profile();
        $this->expectException( OidcTestException::class );
        $profile->initiate_link_login();
    }

    public function test_initiate_link_login_valid_sets_transient_and_fires_action() {
        $_GET['oidc_link']       = '1';
        $_GET['oidc_link_nonce'] = 'valid-nonce';

        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 7 );
        Functions\expect( 'set_transient' )->once()->with( 'oidc_link_pending_7', 1, 300 );
        Functions\expect( 'do_action' )->once()->with( 'oidc_initiate_login', array( 'prompt' => 'login' ) );

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // handle_unlink
    // -------------------------------------------------------------------------

    public function test_handle_unlink_not_logged_in_calls_wp_die() {
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'wp_die' )->alias( function ( $msg ) {
            throw new OidcTestException( $msg );
        } );

        $this->expectException( OidcTestException::class );
        $profile = new OIDC_Profile();
        $profile->handle_unlink();
    }

    public function test_handle_unlink_invalid_nonce_calls_wp_die() {
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 3 );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( false );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'wp_die' )->alias( function ( $msg ) {
            throw new OidcTestException( $msg );
        } );

        $_POST['oidc_unlink_nonce'] = 'bad-nonce';

        $this->expectException( OidcTestException::class );
        $profile = new OIDC_Profile();
        $profile->handle_unlink();
    }

    public function test_handle_unlink_valid_deletes_meta_and_redirects() {
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 5 );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( true );
        Functions\expect( 'delete_user_meta' )->once()->with( 5, '_oidc_subject' );
        Functions\when( 'get_edit_profile_url' )->justReturn( 'https://example.com/wp-admin/profile.php' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $_POST['oidc_unlink_nonce'] = 'valid-nonce';

        $this->expectException( OidcTestException::class );
        $profile = new OIDC_Profile();
        $profile->handle_unlink();
    }
}
