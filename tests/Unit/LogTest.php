<?php
/**
 * Tests für OIDC_Log – write() und get_client_ip().
 *
 * install() und render_log_page() sind stark WP-DB-abhängig und werden
 * nicht Unit-getestet. write() und get_client_ip() sind testbar.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

if ( ! class_exists( 'OIDC_Log' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-log.php';
}

/**
 * Minimal-Stub für $wpdb der insert() als echte Methode anbietet.
 */
class FakeWpdb {
    public $prefix   = 'wp_';
    public $inserted = array();

    public function insert( $table, $data, $_formats ) {
        $this->inserted = array( 'table' => $table, 'data' => $data );
    }
}

class LogTest extends WpTestCase {

    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'add_action' )->justReturn( null );
    }

    // -------------------------------------------------------------------------
    // write – Datenbankaufruf prüfen
    // -------------------------------------------------------------------------

    public function test_write_inserts_into_db() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $wpdb            = new FakeWpdb();
        $GLOBALS['wpdb'] = $wpdb;

        OIDC_Log::write( 5, true, 'Login erfolgreich' );

        $this->assertSame( 'wp_oidc_login_log', $wpdb->inserted['table'] );
        $this->assertSame( 5, $wpdb->inserted['data']['user_id'] );
        $this->assertSame( 1, $wpdb->inserted['data']['success'] );
        $this->assertSame( 'Login erfolgreich', $wpdb->inserted['data']['message'] );

        unset( $GLOBALS['wpdb'] );
    }

    public function test_write_truncates_long_message() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $wpdb            = new FakeWpdb();
        $GLOBALS['wpdb'] = $wpdb;

        $long_message = str_repeat( 'x', 600 );
        OIDC_Log::write( 1, false, $long_message );

        $this->assertSame( 500, mb_strlen( $wpdb->inserted['data']['message'] ) );

        unset( $GLOBALS['wpdb'] );
    }

    public function test_write_false_success_stores_zero() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $wpdb            = new FakeWpdb();
        $GLOBALS['wpdb'] = $wpdb;

        OIDC_Log::write( 0, false, 'Login fehlgeschlagen' );

        $this->assertSame( 0, $wpdb->inserted['data']['success'] );

        unset( $GLOBALS['wpdb'] );
    }

    // -------------------------------------------------------------------------
    // get_client_ip (private, via write() indirekt getestet)
    // -------------------------------------------------------------------------

    public function test_write_uses_remote_addr_as_ip() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        $wpdb            = new FakeWpdb();
        $GLOBALS['wpdb'] = $wpdb;

        OIDC_Log::write( 1, true, 'Test' );

        $this->assertSame( '192.168.1.1', $wpdb->inserted['data']['ip'] );

        unset( $GLOBALS['wpdb'], $_SERVER['REMOTE_ADDR'] );
    }

    public function test_write_invalid_ip_stores_empty_string() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();

        $_SERVER['REMOTE_ADDR'] = 'not-an-ip';

        $wpdb            = new FakeWpdb();
        $GLOBALS['wpdb'] = $wpdb;

        OIDC_Log::write( 1, true, 'Test' );

        $this->assertSame( '', $wpdb->inserted['data']['ip'] );

        unset( $GLOBALS['wpdb'], $_SERVER['REMOTE_ADDR'] );
    }

    // -------------------------------------------------------------------------
    // add_log_page
    // -------------------------------------------------------------------------

    public function test_add_log_page_calls_add_management_page() {
        Functions\expect( 'add_management_page' )->once();
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( '__' )->returnArg();

        $log = new OIDC_Log();
        $log->add_log_page();
        $this->addToAssertionCount( 1 );
    }
}
