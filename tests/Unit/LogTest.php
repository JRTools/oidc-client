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

    // -------------------------------------------------------------------------
    // render_log_page – no permission path
    // -------------------------------------------------------------------------

    public function test_render_log_page_no_permission_calls_wp_die() {
        Functions\when( 'current_user_can' )->justReturn( false );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'wp_die' )->alias( function ( $msg ) {
            throw new OidcTestException( $msg );
        } );

        $log = new OIDC_Log();
        $this->expectException( OidcTestException::class );
        $log->render_log_page();
    }

    public function test_render_log_page_with_permission_outputs_table() {
        Functions\when( 'current_user_can' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( 'esc_html_e' )->justReturn( null );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'esc_html' )->returnArg();
        Functions\when( 'esc_url' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_kses_post' )->returnArg();
        Functions\when( 'paginate_links' )->justReturn( '' );
        Functions\when( 'add_query_arg' )->justReturn( '' );
        Functions\when( 'get_edit_user_link' )->justReturn( '' );

        $item              = new stdClass();
        $item->timestamp   = '2026-01-01 12:00:00';
        $item->user_id     = 1;
        $item->user_login  = 'admin';
        $item->ip          = '127.0.0.1';
        $item->success     = 1;
        $item->message     = 'Login erfolgreich';

        $wpdb            = new FakeWpdb();
        $wpdb->prefix    = 'wp_';
        $GLOBALS['wpdb'] = new class {
            public $prefix = 'wp_';
            public $users  = 'wp_users';
            public function prepare( $sql, ...$args ) { return $sql; }
            public function get_results( $sql ) {
                $item             = new stdClass();
                $item->timestamp  = '2026-01-01 12:00:00';
                $item->user_id    = 1;
                $item->user_login = 'admin';
                $item->ip         = '127.0.0.1';
                $item->success    = 1;
                $item->message    = 'Login erfolgreich';
                return array( $item );
            }
            public function get_var( $sql ) { return 1; }
        };

        ob_start();
        ( new OIDC_Log() )->render_log_page();
        $output = ob_get_clean();

        unset( $GLOBALS['wpdb'] );

        $this->assertStringContainsString( 'wrap', $output );
        $this->assertStringContainsString( 'oidc-log-table', $output );
    }
}
