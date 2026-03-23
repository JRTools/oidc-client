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
        public static function write( $_user_id, $_success, $_message ) { /* Stub – keine Implementierung nötig */ }
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

    // -------------------------------------------------------------------------
    // filter_avatar_url
    // -------------------------------------------------------------------------

    public function test_filter_avatar_url_numeric_id_with_avatar() {
        $user     = new WP_User();
        $user->ID = 5;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/avatar.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'fallback.jpg', 5, array() );
        $this->assertSame( 'https://example.com/avatar.jpg', $result );
    }

    public function test_filter_avatar_url_numeric_id_no_avatar_returns_original() {
        $user     = new WP_User();
        $user->ID = 5;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $result = $this->auth->filter_avatar_url( 'fallback.jpg', 5, array() );
        $this->assertSame( 'fallback.jpg', $result );
    }

    public function test_filter_avatar_url_string_email_with_avatar() {
        $user     = new WP_User();
        $user->ID = 7;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://cdn.example.com/pic.png' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'default.jpg', 'user@example.com', array() );
        $this->assertSame( 'https://cdn.example.com/pic.png', $result );
    }

    public function test_filter_avatar_url_wp_user_object_with_avatar() {
        $user     = new WP_User();
        $user->ID = 9;
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/oidc-avatar.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'fallback.jpg', $user, array() );
        $this->assertSame( 'https://example.com/oidc-avatar.jpg', $result );
    }

    public function test_filter_avatar_url_wp_user_no_avatar_returns_original() {
        $user     = new WP_User();
        $user->ID = 9;
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $result = $this->auth->filter_avatar_url( 'original.jpg', $user, array() );
        $this->assertSame( 'original.jpg', $result );
    }

    public function test_filter_avatar_url_wp_post_with_avatar() {
        $post              = new WP_Post( 3 );
        $user              = new WP_User();
        $user->ID          = 3;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/post-author.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'fallback.jpg', $post, array() );
        $this->assertSame( 'https://example.com/post-author.jpg', $result );
    }

    public function test_filter_avatar_url_wp_comment_with_avatar() {
        $comment                       = new WP_Comment( 'commenter@example.com' );
        $user                          = new WP_User();
        $user->ID                      = 11;
        Functions\when( 'get_user_by' )->justReturn( $user );
        Functions\when( 'get_user_meta' )->justReturn( 'https://example.com/commenter.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'fallback.jpg', $comment, array() );
        $this->assertSame( 'https://example.com/commenter.jpg', $result );
    }

    public function test_filter_avatar_url_unknown_type_returns_original() {
        $result = $this->auth->filter_avatar_url( 'original.jpg', new stdClass(), array() );
        $this->assertSame( 'original.jpg', $result );
    }

    public function test_filter_avatar_url_user_not_found_returns_original() {
        Functions\when( 'get_user_by' )->justReturn( false );

        $result = $this->auth->filter_avatar_url( 'original.jpg', 99, array() );
        $this->assertSame( 'original.jpg', $result );
    }

    // -------------------------------------------------------------------------
    // check_session_validity – Early Returns
    // -------------------------------------------------------------------------

    public function test_check_session_validity_disabled_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $key === 'oidc_session_management' ? '' : $default;
        } );
        Functions\expect( 'is_user_logged_in' )->never();

        $this->auth->check_session_validity();
        $this->addToAssertionCount( 1 );
    }

    public function test_check_session_validity_refresh_disabled_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_session_management' ) {
                return '1';
            }
            if ( $key === 'oidc_enable_refresh' ) {
                return '';
            }
            return $default;
        } );
        Functions\expect( 'is_user_logged_in' )->never();

        $this->auth->check_session_validity();
        $this->addToAssertionCount( 1 );
    }

    public function test_check_session_validity_not_logged_in_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_session_management' ) {
                return '1';
            }
            if ( $key === 'oidc_enable_refresh' ) {
                return '1';
            }
            return $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        Functions\expect( 'get_current_user_id' )->never();

        $this->auth->check_session_validity();
        $this->addToAssertionCount( 1 );
    }

    public function test_check_session_validity_no_oidc_subject_returns_early() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_session_management' ) {
                return '1';
            }
            if ( $key === 'oidc_enable_refresh' ) {
                return '1';
            }
            return $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 5 );
        Functions\when( 'get_user_meta' )->justReturn( '' ); // kein _oidc_subject
        Functions\expect( 'wp_logout' )->never();

        $this->auth->check_session_validity();
        $this->addToAssertionCount( 1 );
    }
}
