<?php
/**
 * Tests für oidc-client.php – Konstanten, init-Funktion und Klassen-Existenz.
 *
 * oidc-client.php wird von WpTestCase::setUp() einmalig geladen.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

/** Expected plugin version – updated automatically by the release workflow. */
define( 'OIDC_EXPECTED_VERSION', '1.2.0' );

class PluginMainTest extends WpTestCase {

    protected function setUp(): void {
        parent::setUp();
        // add_action / add_filter / get_option bereits in WpTestCase gemockt
        // für den ersten Test-Lauf. In späteren Tests hier neu stubben.
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        Functions\when( 'get_option' )->justReturn( '' );
    }

    // -------------------------------------------------------------------------
    // Konstanten – gesetzt von oidc-client.php
    // -------------------------------------------------------------------------

    public function test_version_constant_is_defined() {
        $this->assertTrue( defined( 'OIDC_CLIENT_VERSION' ) );
    }

    public function test_version_constant_value() {
        $this->assertSame( OIDC_EXPECTED_VERSION, OIDC_CLIENT_VERSION );
    }

    public function test_dir_constant_is_defined() {
        $this->assertTrue( defined( 'OIDC_CLIENT_DIR' ) );
    }

    public function test_dir_constant_ends_with_slash() {
        $this->assertStringEndsWith( '/', OIDC_CLIENT_DIR );
    }

    public function test_dir_constant_includes_dir_exists() {
        $this->assertDirectoryExists( OIDC_CLIENT_DIR . 'includes' );
    }

    public function test_url_constant_is_defined() {
        $this->assertTrue( defined( 'OIDC_CLIENT_URL' ) );
    }

    public function test_url_constant_is_non_empty_string() {
        $this->assertNotEmpty( OIDC_CLIENT_URL );
        $this->assertIsString( OIDC_CLIENT_URL );
    }

    // -------------------------------------------------------------------------
    // Klassen-Existenz – alle via oidc-client.php geladen
    // -------------------------------------------------------------------------

    public function test_all_plugin_classes_are_loaded() {
        $this->assertTrue( class_exists( 'OIDC_JWT_Helper' ) );
        $this->assertTrue( class_exists( 'OIDC_Log' ) );
        $this->assertTrue( class_exists( 'OIDC_Tokens' ) );
        $this->assertTrue( class_exists( 'OIDC_Roles' ) );
        $this->assertTrue( class_exists( 'OIDC_Logout' ) );
        $this->assertTrue( class_exists( 'OIDC_Profile' ) );
        $this->assertTrue( class_exists( 'OIDC_Admin' ) );
        $this->assertTrue( class_exists( 'OIDC_Auth' ) );
        $this->assertTrue( class_exists( 'OIDC_Login' ) );
    }

    // -------------------------------------------------------------------------
    // oidc_client_init – Funktion testen
    // -------------------------------------------------------------------------

    public function test_oidc_client_init_function_exists() {
        $this->assertTrue( function_exists( 'oidc_client_init' ) );
    }

    public function test_oidc_client_init_runs_without_error() {
        oidc_client_init();
        $this->addToAssertionCount( 1 );
    }
}
