<?php
/**
 * Basis-TestCase für alle OIDC-Client-Unit-Tests.
 *
 * @package   OIDC_Client
 * @copyright 2026 Johannes Rösch
 * @license   GPL-2.0-or-later
 */
declare(strict_types=1);

use Brain\Monkey;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

abstract class WpTestCase extends TestCase {

    use MockeryPHPUnitIntegration;

    /** Wird true, sobald oidc-client.php einmalig geladen wurde. */
    private static bool $oidc_file_loaded = false;

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
        // WP-Funktions-Stubs NACH Monkey\setUp() laden, damit Patchwork sie
        // instrumentieren kann und Brain\Monkey sie pro Test mocken kann.
        require_once dirname( __DIR__ ) . '/stubs/functions.php';

        // oidc-client.php einmalig laden: setzt Plugin-Konstanten und
        // definiert oidc_client_init(). Muss nach Monkey\setUp() stehen,
        // da add_action() beim Laden aufgerufen wird.
        if ( ! self::$oidc_file_loaded ) {
            self::$oidc_file_loaded = true;
            // add_action/add_filter/get_option als No-ops stubben,
            // damit der File-Level-Code durchläuft.
            Brain\Monkey\Functions\when( 'add_action' )->justReturn( null );
            Brain\Monkey\Functions\when( 'add_filter' )->justReturn( null );
            Brain\Monkey\Functions\when( 'get_option' )->justReturn( '' );
            require_once dirname( dirname( __DIR__ ) ) . '/oidc-client.php';
        }
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }
}
