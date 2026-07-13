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
            return $key === 'jrtools_oidc_lock_email' ? '' : $default;
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
            return $key === 'jrtools_oidc_lock_email' ? '1' : $default;
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
            return $key === 'jrtools_oidc_lock_email' ? '1' : $default;
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
            return $key === 'jrtools_oidc_lock_email' ? '1' : $default;
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
            return $key === 'jrtools_oidc_lock_email' ? '1' : $default;
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

        $this->assertSame( 'jrtools_oidc_email_locked', $errors->code );
        $this->assertSame( 'original@example.com', $user->user_email );
    }

    // -------------------------------------------------------------------------
    // maybe_lock_password
    // -------------------------------------------------------------------------

    public function test_lock_password_option_disabled_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'jrtools_oidc_lock_password' ? '' : $default;
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
            return $key === 'jrtools_oidc_lock_password' ? '1' : $default;
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
            return $key === 'jrtools_oidc_lock_password' ? '1' : $default;
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
            return $key === 'jrtools_oidc_lock_password' ? '1' : $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( 'sub-123' );
        Functions\when( '__' )->returnArg();

        $_POST['pass1'] = 'newpassword';

        $errors   = new WP_Error();
        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        $profile->maybe_lock_password( $errors, true, $user );

        $this->assertSame( 'jrtools_oidc_password_locked', $errors->code );
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
        $_GET['jrtools_oidc_link'] = '0';
        Functions\expect( 'is_user_logged_in' )->never();

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_initiate_link_login_not_logged_in_returns_early() {
        $_GET['jrtools_oidc_link'] = '1';
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        Functions\expect( 'wp_verify_nonce' )->never();

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_initiate_link_login_invalid_nonce_calls_wp_die() {
        $_GET['jrtools_oidc_link']       = '1';
        $_GET['jrtools_oidc_link_nonce'] = 'bad-nonce';

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
        $_GET['jrtools_oidc_link']       = '1';
        $_GET['jrtools_oidc_link_nonce'] = 'valid-nonce';

        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 7 );
        Functions\when( 'get_user_meta' )->justReturn( '' ); // kein bestehender Subject
        Functions\expect( 'set_transient' )->once()->with(
            'jrtools_oidc_link_pending_7',
            array( 'pending' => true, 'sub' => '' ),
            300
        );
        Functions\expect( 'do_action' )->once()->with( 'jrtools_oidc_initiate_login', array( 'prompt' => 'login' ) );

        $profile = new OIDC_Profile();
        $profile->initiate_link_login();
        $this->addToAssertionCount( 1 );
    }

    public function test_initiate_link_login_stores_existing_subject_in_transient() {
        $_GET['jrtools_oidc_link']       = '1';
        $_GET['jrtools_oidc_link_nonce'] = 'valid-nonce';

        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_verify_nonce' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 7 );
        Functions\when( 'get_user_meta' )->justReturn( 'existing-sub-abc' );
        Functions\expect( 'set_transient' )->once()->with(
            'jrtools_oidc_link_pending_7',
            array( 'pending' => true, 'sub' => 'existing-sub-abc' ),
            300
        );
        Functions\expect( 'do_action' )->once()->with( 'jrtools_oidc_initiate_login', array( 'prompt' => 'login' ) );

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

        $_POST['jrtools_oidc_unlink_nonce'] = 'bad-nonce';

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
        Functions\expect( 'delete_user_meta' )->once()->with( 5, '_jrtools_oidc_subject' );
        Functions\when( 'get_edit_profile_url' )->justReturn( 'https://example.com/wp-admin/profile.php' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $_POST['jrtools_oidc_unlink_nonce'] = 'valid-nonce';

        $this->expectException( OidcTestException::class );
        $profile = new OIDC_Profile();
        $profile->handle_unlink();
    }

    // -------------------------------------------------------------------------
    // lock_profile_fields_ui
    // -------------------------------------------------------------------------

    public function test_lock_profile_fields_ui_no_subject_outputs_nothing() {
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->lock_profile_fields_ui( $user );
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_lock_profile_fields_ui_no_locks_outputs_nothing() {
        Functions\when( 'get_user_meta' )->justReturn( 'some-subject' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'jrtools_oidc_lock_email' )    { return ''; }
            if ( $key === 'jrtools_oidc_lock_password' ) { return ''; }
            return $default;
        } );

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->lock_profile_fields_ui( $user );
        $output = ob_get_clean();

        $this->assertSame( '', $output );
    }

    public function test_lock_profile_fields_ui_email_lock_outputs_style() {
        Functions\when( 'get_user_meta' )->justReturn( 'some-subject' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'jrtools_oidc_lock_email' )    { return '1'; }
            if ( $key === 'jrtools_oidc_lock_password' ) { return ''; }
            return $default;
        } );
        Functions\when( 'wp_json_encode' )->alias( 'json_encode' );
        Functions\when( '__' )->returnArg();

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->lock_profile_fields_ui( $user );
        $output = ob_get_clean();

        $this->assertStringContainsString( '#email', $output );
        $this->assertStringContainsString( 'pointer-events: none', $output );
    }

    public function test_lock_profile_fields_ui_password_lock_outputs_style() {
        Functions\when( 'get_user_meta' )->justReturn( 'some-subject' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'jrtools_oidc_lock_email' )    { return ''; }
            if ( $key === 'jrtools_oidc_lock_password' ) { return '1'; }
            return $default;
        } );
        Functions\when( 'wp_json_encode' )->alias( 'json_encode' );
        Functions\when( '__' )->returnArg();

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->lock_profile_fields_ui( $user );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'display: none', $output );
        $this->assertStringContainsString( 'user-pass1-wrap', $output );
    }

    // -------------------------------------------------------------------------
    // render_profile_section
    // -------------------------------------------------------------------------

    public function test_render_profile_section_linked_outputs_heading() {
        Functions\when( 'get_user_meta' )->justReturn( 'some-subject' );
        Functions\when( 'get_current_user_id' )->justReturn( 99 ); // anderer User
        Functions\when( 'esc_html_e' )->justReturn( null );

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->render_profile_section( $user );
        $output = ob_get_clean();

        $this->assertStringContainsString( '<h2>', $output );
        $this->assertStringContainsString( 'dashicons-yes-alt', $output );
    }

    public function test_render_profile_section_linked_same_user_shows_unlink_button() {
        Functions\when( 'get_user_meta' )->justReturn( 'some-subject' );
        Functions\when( 'get_current_user_id' )->justReturn( 1 ); // gleicher User
        Functions\when( 'esc_html_e' )->justReturn( null );
        Functions\when( 'esc_url' )->returnArg();
        Functions\when( 'admin_url' )->justReturn( 'https://example.com/wp-admin/admin-post.php' );
        Functions\when( 'wp_nonce_field' )->alias( function () {
            echo '<input type="hidden" name="jrtools_oidc_unlink_nonce" value="nonce123">';
        } );
        Functions\when( 'esc_attr_e' )->justReturn( null );

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->render_profile_section( $user );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'jrtools_oidc_unlink', $output );
        $this->assertStringContainsString( 'button', $output );
    }

    public function test_render_profile_section_not_linked_outputs_link_button() {
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'get_current_user_id' )->justReturn( 1 );
        Functions\when( 'esc_html_e' )->justReturn( null );
        Functions\when( 'esc_url' )->returnArg();
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?jrtools_oidc_link=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_create_nonce' )->justReturn( 'nonce123' );

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->render_profile_section( $user );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'dashicons-no-alt', $output );
        $this->assertStringContainsString( 'button-primary', $output );
    }

    public function test_render_profile_section_not_linked_other_user_no_link_button() {
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'get_current_user_id' )->justReturn( 99 ); // anderer User
        Functions\when( 'esc_html_e' )->justReturn( null );

        $user     = new WP_User();
        $user->ID = 1;

        $profile = new OIDC_Profile();
        ob_start();
        $profile->render_profile_section( $user );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'dashicons-no-alt', $output );
        $this->assertStringNotContainsString( 'button-primary', $output );
    }

    // -------------------------------------------------------------------------
    // filter_avatar_url (verschoben aus AuthTest, SA-1 Refactoring)
    // -------------------------------------------------------------------------

    public function test_filter_avatar_url_numeric_id_with_avatar() {
        $user     = new WP_User();
        $user->ID = 5;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/avatar.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'fallback.jpg', 5, array() );
        $this->assertSame( 'https://example.com/avatar.jpg', $result );
    }

    public function test_filter_avatar_url_numeric_id_no_avatar_returns_original() {
        $user     = new WP_User();
        $user->ID = 5;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'fallback.jpg', 5, array() );
        $this->assertSame( 'fallback.jpg', $result );
    }

    public function test_filter_avatar_url_string_email_with_avatar() {
        $user     = new WP_User();
        $user->ID = 7;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://cdn.example.com/pic.png' );
        Functions\when( 'esc_url' )->returnArg();

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'default.jpg', 'user@example.com', array() );
        $this->assertSame( 'https://cdn.example.com/pic.png', $result );
    }

    public function test_filter_avatar_url_wp_user_object_with_avatar() {
        $user     = new WP_User();
        $user->ID = 9;
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/oidc-avatar.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'fallback.jpg', $user, array() );
        $this->assertSame( 'https://example.com/oidc-avatar.jpg', $result );
    }

    public function test_filter_avatar_url_wp_user_no_avatar_returns_original() {
        $user     = new WP_User();
        $user->ID = 9;
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'original.jpg', $user, array() );
        $this->assertSame( 'original.jpg', $result );
    }

    public function test_filter_avatar_url_wp_post_with_avatar() {
        $post = new WP_Post( 3 );
        $user     = new WP_User();
        $user->ID = 3;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/post-author.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'fallback.jpg', $post, array() );
        $this->assertSame( 'https://example.com/post-author.jpg', $result );
    }

    public function test_filter_avatar_url_wp_comment_with_avatar() {
        $comment = new WP_Comment( 'commenter@example.com' );
        $user     = new WP_User();
        $user->ID = 11;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/commenter.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'fallback.jpg', $comment, array() );
        $this->assertSame( 'https://example.com/commenter.jpg', $result );
    }

    public function test_filter_avatar_url_unknown_type_returns_original() {
        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'original.jpg', new stdClass(), array() );
        $this->assertSame( 'original.jpg', $result );
    }

    public function test_filter_avatar_url_user_not_found_returns_original() {
        Functions\when( 'get_user_by' )->justReturn( false );

        $profile = new OIDC_Profile();
        $result  = $profile->filter_avatar_url( 'original.jpg', 99, array() );
        $this->assertSame( 'original.jpg', $result );
    }

    public function test_constructor_registers_avatar_filter_when_sync_avatar_enabled() {
        $filter_called = false;
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->alias( function ( $hook ) use ( &$filter_called ) {
            if ( $hook === 'get_avatar_url' ) {
                $filter_called = true;
            }
        } );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'jrtools_oidc_sync_avatar' ) { return '1'; }
            return $default;
        } );

        $profile = new OIDC_Profile();
        unset( $profile );
        $this->assertTrue( $filter_called );
    }
}
