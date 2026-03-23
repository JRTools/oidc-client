<?php
/**
 * Tests für OIDC_Login – Login-Button, Fehleranzeige, Hide-Form, Auto-Login.
 *
 * Brain\Monkey mockt WordPress-Funktionen.
 * $_GET wird in setUp/tearDown gesäubert.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

// OIDC_Login laden (Konstruktor registriert Hooks – müssen gestubbt sein)
if ( ! class_exists( 'OIDC_Login' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-login.php';
}

class LoginTest extends WpTestCase {

    protected function setUp(): void {
        parent::setUp();

        // Hooks im Konstruktor immer stubben
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );

        // $_GET sauber halten
        $_GET = array();
    }

    protected function tearDown(): void {
        $_GET = array();
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // maybe_hide_wp_login_form
    // -------------------------------------------------------------------------

    public function test_hide_form_option_disabled_outputs_nothing() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_hide_wp_login' ? '' : $default;
        } );

        $login = new OIDC_Login();
        ob_start();
        $login->maybe_hide_wp_login_form();
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_hide_form_showlogin_param_skips_hiding() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_hide_wp_login' ? '1' : $default;
        } );

        $_GET['showlogin'] = '1';

        $login = new OIDC_Login();
        ob_start();
        $login->maybe_hide_wp_login_form();
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_hide_form_outputs_css_when_enabled() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_hide_wp_login' ? '1' : $default;
        } );

        $login = new OIDC_Login();
        ob_start();
        $login->maybe_hide_wp_login_form();
        $output = ob_get_clean();

        $this->assertStringContainsString( '#loginform', $output );
        $this->assertStringContainsString( 'display: none', $output );
    }

    // -------------------------------------------------------------------------
    // render_error_message
    // -------------------------------------------------------------------------

    public function test_render_error_message_no_param_outputs_nothing() {
        $login = new OIDC_Login();
        ob_start();
        $login->render_error_message();
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_render_error_message_empty_error_outputs_nothing() {
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $_GET['oidc_error'] = '';

        $login = new OIDC_Login();
        ob_start();
        $login->render_error_message();
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_render_error_message_displays_escaped_error() {
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();

        $_GET['oidc_error'] = 'access_denied';

        $login = new OIDC_Login();
        ob_start();
        $login->render_error_message();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'oidc-error', $output );
        $this->assertStringContainsString( 'access_denied', $output );
    }

    // -------------------------------------------------------------------------
    // maybe_auto_login
    // -------------------------------------------------------------------------

    public function test_auto_login_disabled_does_nothing() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '' : $default;
        } );
        Functions\expect( 'is_user_logged_in' )->never();

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_auto_login_logged_in_does_nothing() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '1' : $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\expect( 'do_action' )->never();

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_auto_login_showlogin_param_skips() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '1' : $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( false );

        $_GET['showlogin'] = '1';
        Functions\expect( 'do_action' )->never();

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_auto_login_loggedout_param_skips() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '1' : $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( false );

        $_GET['loggedout'] = 'true';
        Functions\expect( 'do_action' )->never();

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_auto_login_oidc_error_param_skips() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '1' : $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( false );

        $_GET['oidc_error'] = 'some_error';
        Functions\expect( 'do_action' )->never();

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_auto_login_logout_action_skips() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '1' : $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $_GET['action'] = 'logout';
        Functions\expect( 'do_action' )->never();

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_auto_login_fires_do_action() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_auto_login' ? '1' : $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\expect( 'do_action' )->once()->with( 'oidc_initiate_login' );

        $login = new OIDC_Login();
        $login->maybe_auto_login();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // handle_login_action
    // -------------------------------------------------------------------------

    public function test_handle_login_action_no_param_does_nothing() {
        Functions\expect( 'wp_verify_nonce' )->never();

        $login = new OIDC_Login();
        $login->handle_login_action();
        $this->addToAssertionCount( 1 );
    }

    public function test_handle_login_action_invalid_nonce_calls_wp_die() {
        $_GET['oidc_login'] = '1';
        $_GET['_wpnonce']   = 'bad-nonce';

        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( false );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'wp_die' )->alias( function ( $msg ) {
            throw new OidcTestException( $msg );
        } );

        $login = new OIDC_Login();
        $this->expectException( OidcTestException::class );
        $login->handle_login_action();
    }

    public function test_handle_login_action_valid_nonce_fires_do_action() {
        $_GET['oidc_login'] = '1';
        $_GET['_wpnonce']   = 'valid-nonce';

        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( true );
        Functions\expect( 'do_action' )->once()->with( 'oidc_initiate_login' );

        $login = new OIDC_Login();
        $login->handle_login_action();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // enqueue_styles
    // -------------------------------------------------------------------------

    public function test_enqueue_styles_skips_when_no_client_id() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_client_id' ? '' : $default;
        } );
        Functions\expect( 'wp_enqueue_style' )->never();

        $login = new OIDC_Login();
        $login->enqueue_styles();
        $this->addToAssertionCount( 1 );
    }

    public function test_enqueue_styles_enqueues_when_client_id_set() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_client_id' ? 'my-client-id' : $default;
        } );
        Functions\expect( 'wp_enqueue_style' )->once()->with( 'oidc-login', \Mockery::type( 'string' ), \Mockery::type( 'array' ), \Mockery::any() );

        $login = new OIDC_Login();
        $login->enqueue_styles();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // render_login_button
    // -------------------------------------------------------------------------

    public function test_render_login_button_outputs_nothing_without_client_id() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_client_id' ? '' : $default;
        } );

        $login = new OIDC_Login();
        ob_start();
        $login->render_login_button();
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_render_login_button_outputs_link_with_client_id() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_client_id' ) {
                return 'my-client-id';
            }
            if ( $key === 'oidc_provider_name' ) {
                return 'TestProvider';
            }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_login=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_nonce_url' )->justReturn( 'https://example.com/wp-login.php?oidc_login=1&_wpnonce=abc' );
        Functions\when( 'esc_url' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();
        Functions\when( 'esc_html_e' )->justReturn( null );
        Functions\when( '__' )->returnArg();

        $login = new OIDC_Login();
        ob_start();
        $login->render_login_button();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'oidc-login-button', $output );
    }
}
