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

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }
}
