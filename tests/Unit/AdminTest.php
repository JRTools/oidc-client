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
        $this->admin = new OIDC_Admin();
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
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
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
        Functions\when( 'checked' )->alias( function ( $checked, $current, $echo = true ) {
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
        Functions\when( 'checked' )->alias( function ( $checked, $current, $echo = true ) {
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
}
