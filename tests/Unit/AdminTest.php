<?php
/**
 * Tests für OIDC_Admin – Sanitize-Callbacks und Field-Methoden.
 *
 * UI-schwere Methoden (render_settings_page, register_settings, AJAX) werden
 * nicht getestet, da sie vollständig von der WordPress Settings-API / $wpdb
 * abhängen. Testbar sind: sanitize_*, field_text, field_url, field_password,
 * field_checkbox und der enqueue_scripts-Early-Return.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

if ( ! class_exists( 'OIDC_Admin' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-admin.php';
}

class AdminTest extends WpTestCase {

    /** @var OIDC_Admin */
    private $admin;

    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        $_POST = array();
        $this->admin = new OIDC_Admin();
    }

    protected function tearDown(): void {
        $_POST = array();
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // sanitize_checkbox
    // -------------------------------------------------------------------------

    public function test_sanitize_checkbox_string_one_returns_one() {
        $this->assertSame( '1', $this->admin->sanitize_checkbox( '1' ) );
    }

    public function test_sanitize_checkbox_bool_true_returns_one() {
        $this->assertSame( '1', $this->admin->sanitize_checkbox( true ) );
    }

    public function test_sanitize_checkbox_zero_returns_empty() {
        $this->assertSame( '', $this->admin->sanitize_checkbox( '0' ) );
    }

    public function test_sanitize_checkbox_empty_returns_empty() {
        $this->assertSame( '', $this->admin->sanitize_checkbox( '' ) );
    }

    public function test_sanitize_checkbox_false_returns_empty() {
        $this->assertSame( '', $this->admin->sanitize_checkbox( false ) );
    }

    public function test_sanitize_checkbox_arbitrary_string_returns_empty() {
        $this->assertSame( '', $this->admin->sanitize_checkbox( 'yes' ) );
    }

    // -------------------------------------------------------------------------
    // sanitize_secret
    // -------------------------------------------------------------------------

    public function test_sanitize_secret_trims_whitespace() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_secret( '  mysecret  ' );
        $this->assertSame( 'mysecret', $result );
    }

    public function test_sanitize_secret_removes_null_bytes() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_secret( "sec\x00ret" );
        $this->assertSame( 'secret', $result );
    }

    public function test_sanitize_secret_multiple_null_bytes() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_secret( "\x00sec\x00\x00ret\x00" );
        $this->assertSame( 'secret', $result );
    }

    public function test_sanitize_secret_normal_value_unchanged() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_secret( 'abc123XYZ!@#' );
        $this->assertSame( 'abc123XYZ!@#', $result );
    }

    public function test_sanitize_secret_empty_returns_empty() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_secret( '' );
        $this->assertSame( '', $result );
    }

    // -------------------------------------------------------------------------
    // sanitize_role_mapping
    // -------------------------------------------------------------------------

    public function test_sanitize_role_mapping_empty_returns_empty() {
        $this->assertSame( '', $this->admin->sanitize_role_mapping( '' ) );
    }

    public function test_sanitize_role_mapping_invalid_json_returns_empty() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_role_mapping( 'not-json' );
        $this->assertSame( '', $result );
    }

    public function test_sanitize_role_mapping_valid_json_sanitizes_entries() {
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_json_encode' )->alias( 'json_encode' );

        $input  = json_encode( array( 'editor-group' => 'editor', 'admin-group' => 'administrator' ) );
        $result = $this->admin->sanitize_role_mapping( $input );
        $decoded = json_decode( $result, true );

        $this->assertIsArray( $decoded );
        $this->assertSame( 'editor', $decoded['editor-group'] );
        $this->assertSame( 'administrator', $decoded['admin-group'] );
    }

    public function test_sanitize_role_mapping_non_array_json_returns_empty() {
        Functions\when( 'wp_unslash' )->returnArg();
        $result = $this->admin->sanitize_role_mapping( '"just-a-string"' );
        $this->assertSame( '', $result );
    }

    // -------------------------------------------------------------------------
    // field_text (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_text_outputs_input_element() {
        Functions\when( 'get_option' )->justReturn( 'my-client-id' );
        Functions\when( 'esc_attr' )->returnArg();

        ob_start();
        $this->admin->field_text( array( 'option' => 'oidc_client_id' ) );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'type="text"', $output );
        $this->assertStringContainsString( 'oidc_client_id', $output );
        $this->assertStringContainsString( 'my-client-id', $output );
    }

    public function test_field_text_outputs_description_when_set() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();

        ob_start();
        $this->admin->field_text( array(
            'option'      => 'oidc_client_id',
            'description' => 'Meine Beschreibung',
        ) );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'Meine Beschreibung', $output );
        $this->assertStringContainsString( 'description', $output );
    }

    public function test_field_text_uses_default_when_option_empty() {
        Functions\when( 'get_option' )->alias( function ( $_key, $default = '' ) {
            return $default;
        } );
        Functions\when( 'esc_attr' )->returnArg();

        ob_start();
        $this->admin->field_text( array(
            'option'  => 'oidc_scopes',
            'default' => 'openid email profile',
        ) );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'openid email profile', $output );
    }

    // -------------------------------------------------------------------------
    // field_url (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_url_outputs_url_input() {
        Functions\when( 'get_option' )->justReturn( 'https://provider.example.com/token' );
        Functions\when( 'esc_attr' )->returnArg();

        ob_start();
        $this->admin->field_url( array( 'option' => 'oidc_token_endpoint' ) );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'type="url"', $output );
        $this->assertStringContainsString( 'oidc_token_endpoint', $output );
        $this->assertStringContainsString( 'https://provider.example.com/token', $output );
    }

    // -------------------------------------------------------------------------
    // field_password (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_password_outputs_password_input() {
        Functions\when( 'get_option' )->justReturn( 'supersecret' );
        Functions\when( 'esc_attr' )->returnArg();

        ob_start();
        $this->admin->field_password( array( 'option' => 'oidc_client_secret' ) );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'type="password"', $output );
        $this->assertStringContainsString( 'oidc_client_secret', $output );
        $this->assertStringContainsString( 'supersecret', $output );
        $this->assertStringContainsString( 'autocomplete="new-password"', $output );
    }

    // -------------------------------------------------------------------------
    // field_checkbox (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_checkbox_checked_when_value_is_one() {
        Functions\when( 'get_option' )->justReturn( '1' );
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();
        Functions\when( 'checked' )->alias( function ( $checked, $current, $_echo = true ) {
            return ( $checked == $current ) ? ' checked="checked"' : '';
        } );

        ob_start();
        $this->admin->field_checkbox( array( 'option' => 'oidc_create_user', 'description' => '' ) );
        $output = ob_get_clean();

        $this->assertStringContainsString( 'checked', $output );
        $this->assertStringContainsString( 'type="checkbox"', $output );
    }

    public function test_field_checkbox_not_checked_when_value_is_empty() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();
        Functions\when( 'checked' )->alias( function ( $checked, $current, $_echo = true ) {
            return ( $checked == $current ) ? ' checked="checked"' : '';
        } );

        ob_start();
        $this->admin->field_checkbox( array( 'option' => 'oidc_create_user', 'description' => '' ) );
        $output = ob_get_clean();

        $this->assertStringNotContainsString( 'checked', $output );
    }

    // -------------------------------------------------------------------------
    // enqueue_scripts – Early Return wenn falscher Hook
    // -------------------------------------------------------------------------

    public function test_enqueue_scripts_returns_early_on_wrong_hook() {
        Functions\expect( 'wp_enqueue_style' )->never();
        Functions\expect( 'wp_enqueue_script' )->never();

        $this->admin->enqueue_scripts( 'options-general.php' );
        $this->assertTrue( true );
    }

    // -------------------------------------------------------------------------
    // section_provider_description / section_roles_description (Output-Test)
    // -------------------------------------------------------------------------

    public function test_section_provider_description_outputs_p_tag() {
        Functions\when( 'esc_html__' )->returnArg();

        ob_start();
        $this->admin->section_provider_description();
        $output = ob_get_clean();

        $this->assertStringContainsString( '<p>', $output );
    }

    public function test_section_roles_description_outputs_p_tag() {
        Functions\when( 'esc_html__' )->returnArg();

        ob_start();
        $this->admin->section_roles_description();
        $output = ob_get_clean();

        $this->assertStringContainsString( '<p>', $output );
    }

    // -------------------------------------------------------------------------
    // enqueue_scripts – korrekter Hook
    // -------------------------------------------------------------------------

    public function test_enqueue_scripts_enqueues_on_correct_hook() {
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'admin_url' )->justReturn( 'https://example.com/wp-admin/admin-ajax.php' );
        Functions\when( 'wp_create_nonce' )->justReturn( 'test-nonce' );
        Functions\when( '__' )->returnArg();
        Functions\expect( 'wp_enqueue_style' )->once();
        Functions\expect( 'wp_enqueue_script' )->once();
        Functions\when( 'wp_localize_script' )->justReturn( null );

        $this->admin->enqueue_scripts( 'settings_page_oidc-client' );
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // field_discovery_url (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_discovery_url_outputs_url_input() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html_e' )->justReturn( null );

        ob_start();
        $this->admin->field_discovery_url();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'type="url"', $output );
        $this->assertStringContainsString( 'oidc_discovery_url', $output );
        $this->assertStringContainsString( 'oidc-fetch-discovery', $output );
    }

    // -------------------------------------------------------------------------
    // field_redirect_uri (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_redirect_uri_outputs_readonly_input() {
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html_e' )->justReturn( null );

        ob_start();
        $this->admin->field_redirect_uri();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'readonly', $output );
        $this->assertStringContainsString( 'oidc_callback=1', $output );
    }

    // -------------------------------------------------------------------------
    // field_token_auth_method (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_token_auth_method_outputs_select() {
        Functions\when( 'get_option' )->justReturn( 'client_secret_post' );
        Functions\when( '__' )->returnArg();
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'selected' )->alias( function ( $selected, $current, $_echo = true ) {
            return $selected === $current ? ' selected="selected"' : '';
        } );

        ob_start();
        $this->admin->field_token_auth_method();
        $output = ob_get_clean();

        $this->assertStringContainsString( '<select', $output );
        $this->assertStringContainsString( 'client_secret_post', $output );
        $this->assertStringContainsString( 'client_secret_basic', $output );
    }

    // -------------------------------------------------------------------------
    // field_remember_me (Output-Test)
    // -------------------------------------------------------------------------

    public function test_field_remember_me_outputs_select_with_options() {
        Functions\when( 'get_option' )->justReturn( 'never' );
        Functions\when( '__' )->returnArg();
        Functions\when( 'esc_attr' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();
        Functions\when( 'selected' )->alias( function ( $selected, $current, $_echo = true ) {
            return $selected === $current ? ' selected="selected"' : '';
        } );

        ob_start();
        $this->admin->field_remember_me();
        $output = ob_get_clean();

        $this->assertStringContainsString( '<select', $output );
        $this->assertStringContainsString( 'never', $output );
        $this->assertStringContainsString( 'always', $output );
    }

    // -------------------------------------------------------------------------
    // ajax_fetch_discovery
    // -------------------------------------------------------------------------

    public function test_ajax_fetch_discovery_no_permission_sends_error() {
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( false );
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_send_json_error' )->alias( function ( $data, $status ) {
            throw new OidcTestException( 'error:' . $status );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'error:403' );
        $this->admin->ajax_fetch_discovery();
    }

    public function test_ajax_fetch_discovery_empty_url_sends_error() {
        $_POST['url'] = '';
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_send_json_error' )->alias( function ( $data, $status ) {
            throw new OidcTestException( 'error:' . $status );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'error:400' );
        $this->admin->ajax_fetch_discovery();
    }

    public function test_ajax_fetch_discovery_invalid_url_sends_error() {
        $_POST['url'] = 'not-a-url';
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_send_json_error' )->alias( function ( $data, $status ) {
            throw new OidcTestException( 'error:' . $status );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'error:400' );
        $this->admin->ajax_fetch_discovery();
    }

    public function test_ajax_fetch_discovery_http_error_sends_error() {
        $_POST['url'] = 'https://provider.example.com/.well-known/openid-configuration';
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_remote_get' )->justReturn( new WP_Error( 'http_request_failed', 'timeout' ) );
        Functions\when( 'wp_send_json_error' )->alias( function ( $data, $status ) {
            throw new OidcTestException( 'error:' . $status );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'error:500' );
        $this->admin->ajax_fetch_discovery();
    }

    public function test_ajax_fetch_discovery_non_200_sends_error() {
        $_POST['url'] = 'https://provider.example.com/.well-known/openid-configuration';
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 404 );
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_send_json_error' )->alias( function ( $data, $status ) {
            throw new OidcTestException( 'error:' . $status );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'error:500' );
        $this->admin->ajax_fetch_discovery();
    }

    public function test_ajax_fetch_discovery_invalid_json_sends_error() {
        $_POST['url'] = 'https://provider.example.com/.well-known/openid-configuration';
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( 'not-json' );
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_send_json_error' )->alias( function ( $data, $status ) {
            throw new OidcTestException( 'error:' . $status );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'error:500' );
        $this->admin->ajax_fetch_discovery();
    }

    public function test_ajax_fetch_discovery_success_sends_json_success() {
        $_POST['url'] = 'https://provider.example.com/.well-known/openid-configuration';
        $discovery = array(
            'authorization_endpoint'           => 'https://provider.example.com/auth',
            'token_endpoint'                   => 'https://provider.example.com/token',
            'userinfo_endpoint'                => 'https://provider.example.com/userinfo',
            'jwks_uri'                         => 'https://provider.example.com/jwks',
            'issuer'                           => 'https://provider.example.com',
            'end_session_endpoint'             => 'https://provider.example.com/logout',
            'code_challenge_methods_supported' => array( 'S256' ),
        );
        Functions\when( 'check_ajax_referer' )->justReturn( true );
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( json_encode( $discovery ) );
        Functions\when( 'sanitize_text_field' )->returnArg();
        $sent = null;
        Functions\when( 'wp_send_json_success' )->alias( function ( $data ) use ( &$sent ) {
            $sent = $data;
            throw new OidcTestException( 'success' );
        } );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessage( 'success' );
        $this->admin->ajax_fetch_discovery();
    }
}
