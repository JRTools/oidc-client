<?php
/**
 * Tests für OIDC_Auth – Fokus auf reine Hilfsmethoden (kein WP-Hook-Aufruf).
 *
 * Da generate_random_string(), generate_code_verifier() und
 * generate_code_challenge() private sind, werden sie über eine
 * TestableOIDCAuth-Unterklasse mit public-Alias zugänglich gemacht.
 * Der Konstruktor von OIDC_Auth registriert Hooks – deshalb mocken wir
 * add_action/add_filter, bevor wir instanziieren.
 */

use Brain\Monkey\Functions;

require_once __DIR__ . '/WpTestCase.php';

// OIDC_Auth benötigt OIDC_Log, OIDC_Tokens – Stubs bereitstellen
if ( ! class_exists( 'OIDC_Log' ) ) {
    class OIDC_Log {
        public static function write( $user_id, $success, $message ) {}
    }
}

// Wir laden OIDC_Auth erst hier, da es Konstanten und Stubs braucht
if ( ! class_exists( 'OIDC_Auth' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-auth.php';
}

/**
 * Unterklasse, die private Hilfsmethoden als public exponiert.
 */
class TestableOIDCAuth extends OIDC_Auth {
    public function public_generate_random_string() {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'generate_random_string' );
        $method->setAccessible( true );
        return $method->invoke( $this );
    }

    public function public_generate_code_verifier() {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'generate_code_verifier' );
        $method->setAccessible( true );
        return $method->invoke( $this );
    }

    public function public_generate_code_challenge( $verifier ) {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'generate_code_challenge' );
        $method->setAccessible( true );
        return $method->invoke( $this, $verifier );
    }
}

class AuthTest extends WpTestCase {

    /** @var TestableOIDCAuth */
    private $auth;

    protected function setUp(): void {
        parent::setUp();

        // Hooks im Konstruktor abfangen
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        Functions\when( 'get_option' )->justReturn( '' );

        $this->auth = new TestableOIDCAuth();
    }

    // -------------------------------------------------------------------------
    // generate_random_string
    // -------------------------------------------------------------------------

    public function test_generate_random_string_is_hex() {
        $result = $this->auth->public_generate_random_string();
        $this->assertMatchesRegularExpression( '/^[0-9a-f]+$/', $result );
    }

    public function test_generate_random_string_is_32_chars() {
        // bin2hex( random_bytes(16) ) → 32 Hex-Zeichen
        $result = $this->auth->public_generate_random_string();
        $this->assertSame( 32, strlen( $result ) );
    }

    public function test_generate_random_string_is_unique() {
        $a = $this->auth->public_generate_random_string();
        $b = $this->auth->public_generate_random_string();
        $this->assertNotSame( $a, $b );
    }

    // -------------------------------------------------------------------------
    // generate_code_verifier
    // -------------------------------------------------------------------------

    public function test_generate_code_verifier_is_base64url() {
        $result = $this->auth->public_generate_code_verifier();
        // Base64url: nur A-Z a-z 0-9 - _
        $this->assertMatchesRegularExpression( '/^[A-Za-z0-9\-_]+$/', $result );
    }

    public function test_generate_code_verifier_length_in_range() {
        // RFC 7636: 43–128 Zeichen
        $result = $this->auth->public_generate_code_verifier();
        $len    = strlen( $result );
        $this->assertGreaterThanOrEqual( 43, $len );
        $this->assertLessThanOrEqual( 128, $len );
    }

    public function test_generate_code_verifier_no_padding() {
        $result = $this->auth->public_generate_code_verifier();
        $this->assertStringNotContainsString( '=', $result );
    }

    // -------------------------------------------------------------------------
    // generate_code_challenge
    // -------------------------------------------------------------------------

    public function test_generate_code_challenge_is_base64url() {
        $verifier = $this->auth->public_generate_code_verifier();
        $result   = $this->auth->public_generate_code_challenge( $verifier );
        $this->assertMatchesRegularExpression( '/^[A-Za-z0-9\-_]+$/', $result );
    }

    public function test_generate_code_challenge_no_padding() {
        $verifier = 'testverifier';
        $result   = $this->auth->public_generate_code_challenge( $verifier );
        $this->assertStringNotContainsString( '=', $result );
    }

    public function test_generate_code_challenge_s256_algorithm() {
        // S256: challenge = BASE64URL(SHA256(verifier))
        $verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $expected  = rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
        $result    = $this->auth->public_generate_code_challenge( $verifier );
        $this->assertSame( $expected, $result );
    }

    public function test_generate_code_challenge_is_deterministic() {
        $verifier = $this->auth->public_generate_code_verifier();
        $c1       = $this->auth->public_generate_code_challenge( $verifier );
        $c2       = $this->auth->public_generate_code_challenge( $verifier );
        $this->assertSame( $c1, $c2 );
    }
}
