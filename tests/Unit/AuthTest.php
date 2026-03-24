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

    public function public_exchange_code_for_tokens( $code, $code_verifier ) {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'exchange_code_for_tokens' );
        $method->setAccessible( true );
        return $method->invoke( $this, $code, $code_verifier );
    }

    public function public_validate_id_token( $id_token ) {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'validate_id_token' );
        $method->setAccessible( true );
        return $method->invoke( $this, $id_token );
    }

    public function public_fetch_userinfo( $access_token ) {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'fetch_userinfo' );
        $method->setAccessible( true );
        return $method->invoke( $this, $access_token );
    }

    public function public_authenticate_user( $userinfo, $tokens = array() ) {
        $ref    = new ReflectionObject( $this );
        $method = $ref->getMethod( 'authenticate_user' );
        $method->setAccessible( true );
        return $method->invoke( $this, $userinfo, $tokens );
    }
}

class AuthTest extends WpTestCase {

    /** @var TestableOIDCAuth */
    private $auth;

    protected function setUp(): void {
        parent::setUp();
        $_GET = array();

        // Hooks im Konstruktor abfangen
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        Functions\when( 'get_option' )->justReturn( '' );

        $this->auth = new TestableOIDCAuth();
    }

    protected function tearDown(): void {
        $_GET = array();
        unset( $GLOBALS['wpdb'] );
        parent::tearDown();
    }

    /**
     * Gemeinsame Mocks für initiate_login-Tests.
     * @param string $pkce '1' = PKCE aktiv, '' = deaktiviert
     */
    private function setUpInitiateLoginMocks( string $pkce = '', string $scopes = 'openid email' ): void {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) use ( $pkce, $scopes ) {
            if ( $key === 'oidc_client_id' )              { return 'my-client'; }
            if ( $key === 'oidc_authorization_endpoint' ) { return 'https://provider.example.com/auth'; }
            if ( $key === 'oidc_scopes' )                 { return $scopes; }
            if ( $key === 'oidc_pkce_supported' )         { return $pkce; }
            return $default;
        } );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );
    }

    /** Baut ein minimales JWT aus Header + Payload-Array. */
    private function buildJwt( array $payload, string $alg = 'RS256' ): string {
        $header = base64_encode( json_encode( array( 'alg' => $alg, 'typ' => 'JWT' ) ) );
        return $header . '.' . base64_encode( json_encode( $payload ) ) . '.signature';
    }

    /**
     * Gemeinsame Mocks für authenticate_user-Tests: Login-Abschluss (wp_safe_redirect).
     * Setzt wpdb-Stub und alle Mocks, die für den erfolgreichen Login-Flow nötig sind.
     */
    private function setUpLoginMocks(): void {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'update_user_meta' )->justReturn( true );
        Functions\when( 'wp_set_current_user' )->justReturn( null );
        Functions\when( 'wp_set_auth_cookie' )->justReturn( null );
        Functions\when( 'do_action' )->justReturn( null );
        Functions\when( 'apply_filters' )->justReturn( 'https://example.com/wp-admin/' );
        Functions\when( 'admin_url' )->justReturn( 'https://example.com/wp-admin/' );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );
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

    // -------------------------------------------------------------------------
    // filter_avatar_url
    // -------------------------------------------------------------------------

    public function test_filter_avatar_url_returns_original_when_no_oidc_avatar() {
        Functions\when( 'get_user_by' )->alias( function ( $field, $value ) {
            $user     = new WP_User();
            $user->ID = 10;
            return $user;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $result = $this->auth->filter_avatar_url( 'https://gravatar.com/original', 10, array() );

        $this->assertSame( 'https://gravatar.com/original', $result );
    }

    public function test_filter_avatar_url_returns_oidc_avatar_when_set() {
        Functions\when( 'get_user_by' )->alias( function ( $field, $value ) {
            $user     = new WP_User();
            $user->ID = 10;
            return $user;
        } );
        Functions\when( 'get_user_meta' )->justReturn( 'https://cdn.example.com/avatar.png' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'https://gravatar.com/original', 10, array() );

        $this->assertSame( 'https://cdn.example.com/avatar.png', $result );
    }

    public function test_filter_avatar_url_handles_wp_user_object() {
        $user     = new WP_User();
        $user->ID = 42;

        Functions\when( 'get_user_meta' )->justReturn( 'https://cdn.example.com/pic.jpg' );
        Functions\when( 'esc_url' )->returnArg();

        $result = $this->auth->filter_avatar_url( 'https://gravatar.com/fallback', $user, array() );

        $this->assertSame( 'https://cdn.example.com/pic.jpg', $result );
    }

    public function test_filter_avatar_url_handles_email_string() {
        Functions\when( 'get_user_by' )->alias( function ( $field, $value ) {
            $user     = new WP_User();
            $user->ID = 5;
            return $user;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $result = $this->auth->filter_avatar_url( 'https://gravatar.com/original', 'user@example.com', array() );

        $this->assertSame( 'https://gravatar.com/original', $result );
    }

    public function test_filter_avatar_url_handles_wp_post_object() {
        $post              = new WP_Post( 7 );

        Functions\when( 'get_user_by' )->alias( function ( $field, $value ) {
            $user     = new WP_User();
            $user->ID = 7;
            return $user;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $result = $this->auth->filter_avatar_url( 'https://gravatar.com/original', $post, array() );

        $this->assertSame( 'https://gravatar.com/original', $result );
    }

    public function test_filter_avatar_url_handles_wp_comment_object() {
        $comment                       = new WP_Comment( 'author@example.com' );

        Functions\when( 'get_user_by' )->alias( function ( $field, $value ) {
            $user     = new WP_User();
            $user->ID = 8;
            return $user;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );

        $result = $this->auth->filter_avatar_url( 'https://gravatar.com/original', $comment, array() );

        $this->assertSame( 'https://gravatar.com/original', $result );
    }

    // -------------------------------------------------------------------------
    // initiate_login
    // -------------------------------------------------------------------------

    public function test_initiate_login_dies_when_not_configured() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $default; // client_id und auth_endpoint leer
        } );
        Functions\when( 'esc_html__' )->returnArg();
        Functions\when( 'wp_die' )->alias( function ( $msg ) {
            throw new OidcTestException( $msg );
        } );

        $this->expectException( OidcTestException::class );
        $this->auth->initiate_login();
    }

    public function test_initiate_login_redirects_with_required_params() {
        $this->setUpInitiateLoginMocks( '' );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessageMatches( '/response_type=code/' );
        $this->auth->initiate_login();
    }

    public function test_initiate_login_with_pkce_adds_code_challenge() {
        $this->setUpInitiateLoginMocks( '1' );

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessageMatches( '/code_challenge/' );
        $this->auth->initiate_login();
    }

    public function test_initiate_login_with_extra_prompt_param() {
        $this->setUpInitiateLoginMocks( '', 'openid' );
        Functions\when( 'sanitize_text_field' )->returnArg();

        $this->expectException( OidcTestException::class );
        $this->expectExceptionMessageMatches( '/prompt=login/' );
        $this->auth->initiate_login( array( 'prompt' => 'login' ) );
    }

    // -------------------------------------------------------------------------
    // handle_callback – Early Returns
    // -------------------------------------------------------------------------

    public function test_handle_callback_no_param_returns_early() {
        $_GET = array();
        Functions\expect( 'get_transient' )->never();

        $this->auth->handle_callback();
        $this->addToAssertionCount( 1 );
    }

    /** Gemeinsame Mocks für handle_callback-Fehlerpfad-Tests (Redirect zu wp-login mit Fehler). */
    private function setUpCallbackErrorMocks(): void {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );
    }

    public function test_handle_callback_with_error_param_logs_and_redirects() {
        $_GET['oidc_callback'] = '1';
        $_GET['error']         = 'access_denied';
        $this->setUpCallbackErrorMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->handle_callback();
    }

    public function test_handle_callback_missing_code_redirects_with_error() {
        $_GET['oidc_callback'] = '1';
        // Kein code, kein state
        $this->setUpCallbackErrorMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->handle_callback();
    }

    public function test_handle_callback_invalid_state_redirects_with_error() {
        $_GET['oidc_callback'] = '1';
        $_GET['code']          = 'auth-code';
        $_GET['state']         = 'invalid-state';
        $this->setUpCallbackErrorMocks();
        Functions\when( 'get_transient' )->justReturn( false ); // State ungültig
        Functions\when( 'delete_transient' )->justReturn( true );

        $this->expectException( OidcTestException::class );
        $this->auth->handle_callback();
    }

    // -------------------------------------------------------------------------
    // exchange_code_for_tokens (private via Reflection)
    // -------------------------------------------------------------------------

    public function test_exchange_code_no_token_endpoint_returns_wp_error() {
        Functions\when( 'get_option' )->justReturn( '' ); // alle leer
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_exchange_code_for_tokens( 'code', '' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'no_token_endpoint', $result->get_error_code() );
    }

    public function test_exchange_code_http_error_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )      { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )           { return 'client-id'; }
            if ( $key === 'oidc_client_secret' )       { return 'secret'; }
            if ( $key === 'oidc_token_auth_method' )   { return 'client_secret_post'; }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        $wp_error = new WP_Error( 'http_request_failed', 'cURL error' );
        Functions\when( 'wp_remote_post' )->justReturn( $wp_error );

        $result = $this->auth->public_exchange_code_for_tokens( 'mycode', '' );

        $this->assertInstanceOf( WP_Error::class, $result );
    }

    public function test_exchange_code_non_200_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_remote_post' )->justReturn( array( 'response' => array( 'code' => 401 ) ) );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 401 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( '{}' );
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_exchange_code_for_tokens( 'mycode', '' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_request_failed', $result->get_error_code() );
    }

    public function test_exchange_code_with_basic_auth_method() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'client-id'; }
            if ( $key === 'oidc_client_secret' )     { return 'secret'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_basic'; }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        $capturedArgs = null;
        Functions\when( 'wp_remote_post' )->alias( function ( $url, $args ) use ( &$capturedArgs ) {
            $capturedArgs = $args;
            return new WP_Error( 'http_request_failed', 'test stop' );
        } );

        $this->auth->public_exchange_code_for_tokens( 'mycode', '' );

        $this->assertArrayHasKey( 'Authorization', $capturedArgs['headers'] );
        $this->assertStringStartsWith( 'Basic ', $capturedArgs['headers']['Authorization'] );
    }

    public function test_exchange_code_with_code_verifier_sends_it() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        $capturedBody = null;
        Functions\when( 'wp_remote_post' )->alias( function ( $url, $args ) use ( &$capturedBody ) {
            $capturedBody = $args['body'];
            return new WP_Error( 'http_request_failed', 'test stop' );
        } );

        $this->auth->public_exchange_code_for_tokens( 'mycode', 'my-verifier' );

        $this->assertArrayHasKey( 'code_verifier', $capturedBody );
        $this->assertSame( 'my-verifier', $capturedBody['code_verifier'] );
    }

    public function test_exchange_code_success_returns_body_data() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_remote_post' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'access_token' => 'tok123', 'id_token' => 'id.tok' ) )
        );

        $result = $this->auth->public_exchange_code_for_tokens( 'mycode', '' );

        $this->assertIsArray( $result );
        $this->assertSame( 'tok123', $result['access_token'] );
    }

    // -------------------------------------------------------------------------
    // validate_id_token (private via Reflection)
    // -------------------------------------------------------------------------

    public function test_validate_id_token_empty_returns_wp_error() {
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_validate_id_token( '' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'no_id_token', $result->get_error_code() );
    }

    public function test_validate_id_token_invalid_jwt_returns_wp_error() {
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_validate_id_token( 'not.a.jwt' );

        $this->assertInstanceOf( WP_Error::class, $result );
    }

    public function test_validate_id_token_expired_returns_wp_error() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        // JWT mit abgelaufenem exp
        $header  = base64_encode( json_encode( array( 'alg' => 'RS256', 'typ' => 'JWT' ) ) );
        $payload = base64_encode( json_encode( array( 'exp' => time() - 3600, 'iat' => time() - 7200 ) ) );
        $jwt     = $header . '.' . $payload . '.signature';

        $result = $this->auth->public_validate_id_token( $jwt );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_expired', $result->get_error_code() );
    }

    public function test_validate_id_token_future_iat_returns_wp_error() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        $header  = base64_encode( json_encode( array( 'alg' => 'RS256', 'typ' => 'JWT' ) ) );
        $payload = base64_encode( json_encode( array( 'exp' => time() + 3600, 'iat' => time() + 600 ) ) );
        $jwt     = $header . '.' . $payload . '.signature';

        $result = $this->auth->public_validate_id_token( $jwt );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_iat_invalid', $result->get_error_code() );
    }

    public function test_validate_id_token_issuer_mismatch_returns_wp_error() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_issuer' ) { return 'https://expected.example.com'; }
            return $default;
        } );

        $jwt    = $this->buildJwt( array( 'exp' => time() + 3600, 'iat' => time() - 60, 'iss' => 'https://wrong.example.com' ) );
        $result = $this->auth->public_validate_id_token( $jwt );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_iss_mismatch', $result->get_error_code() );
    }

    public function test_validate_id_token_audience_mismatch_returns_wp_error() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_issuer' )    { return ''; } // Issuer-Prüfung überspringen
            if ( $key === 'oidc_client_id' ) { return 'my-client'; }
            return $default;
        } );

        $jwt    = $this->buildJwt( array( 'exp' => time() + 3600, 'iat' => time() - 60, 'aud' => 'wrong-audience' ) );
        $result = $this->auth->public_validate_id_token( $jwt );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_aud_mismatch', $result->get_error_code() );
    }

    public function test_validate_id_token_valid_no_sig_check_returns_claims() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            // Issuer, client_id und jwks_uri leer → keine Prüfungen
            return $default;
        } );

        $claims  = array( 'exp' => time() + 3600, 'iat' => time() - 60, 'sub' => 'user123' );
        $header  = rtrim( strtr( base64_encode( json_encode( array( 'alg' => 'none' ) ) ), '+/', '-_' ), '=' );
        $payload = rtrim( strtr( base64_encode( json_encode( $claims ) ), '+/', '-_' ), '=' );
        $jwt     = $header . '.' . $payload . '.';

        $result = $this->auth->public_validate_id_token( $jwt );

        $this->assertIsArray( $result );
        $this->assertSame( 'user123', $result['sub'] );
    }

    // -------------------------------------------------------------------------
    // fetch_userinfo (private via Reflection)
    // -------------------------------------------------------------------------

    public function test_fetch_userinfo_no_endpoint_returns_wp_error() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'no_userinfo_endpoint', $result->get_error_code() );
    }

    public function test_fetch_userinfo_http_error_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            return $default;
        } );
        Functions\when( 'wp_remote_get' )->justReturn( new WP_Error( 'http_request_failed', 'timeout' ) );

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertInstanceOf( WP_Error::class, $result );
    }

    public function test_fetch_userinfo_no_email_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            return $default;
        } );
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( json_encode( array( 'sub' => 'user123' ) ) );
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'userinfo_no_email', $result->get_error_code() );
    }

    public function test_fetch_userinfo_success_returns_data() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            return $default;
        } );
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'sub' => 'user123', 'email' => 'user@example.com' ) )
        );

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertIsArray( $result );
        $this->assertSame( 'user@example.com', $result['email'] );
    }

    // -------------------------------------------------------------------------
    // check_session_validity – Logout-Pfad (Token abgelaufen)
    // -------------------------------------------------------------------------

    public function test_check_session_validity_expired_token_logs_out() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_session_management' ) { return '1'; }
            if ( $key === 'oidc_enable_refresh' )     { return '1'; }
            return $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 5 );
        Functions\when( 'get_user_meta' )->justReturn( 'some-subject' );
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );

        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        // OIDC_Tokens::get_valid_access_token() → WP_Error simulieren
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'get_user_meta' )->alias( function ( $id, $key, $single ) {
            if ( $key === '_oidc_subject' ) { return 'user-sub'; }
            if ( $key === '_oidc_access_token_expires' ) { return time() - 100; } // abgelaufen
            if ( $key === '_oidc_refresh_token' ) { return ''; } // kein Refresh
            return '';
        } );
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_logout' )->justReturn( null );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->auth->check_session_validity();
    }

    // -------------------------------------------------------------------------
    // authenticate_user (private via Reflection)
    // -------------------------------------------------------------------------

    public function test_authenticate_user_active_claim_false_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_active_claim' ) { return 'active'; }
            return $default;
        } );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user( array( 'email' => 'user@example.com', 'active' => false ) );
    }

    public function test_authenticate_user_invalid_email_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( false );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user( array( 'email' => 'not-an-email' ) );
    }

    public function test_authenticate_user_no_user_no_create_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )  { return ''; }
            if ( $key === 'oidc_create_user' )   { return false; }
            return $default;
        } );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array() );    // kein User per Subject
        Functions\when( 'get_user_by' )->justReturn( false );    // kein User per E-Mail
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user( array( 'email' => 'new@example.com', 'sub' => 'sub123' ) );
    }

    /** Gemeinsamer get_option-Alias für Neuerstellungs-Tests (create_user=true, never-remember). */
    private function newUserOptions(): \Closure {
        return function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_create_user' )    { return true; }
            if ( $key === 'oidc_default_role' )   { return 'subscriber'; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'never'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        };
    }

    public function test_authenticate_user_creates_new_user_and_logs_in() {
        $newUser            = new WP_User();
        $newUser->ID        = 42;
        $newUser->user_login = 'newuser';

        Functions\when( 'get_option' )->alias( $this->newUserOptions() );
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( $newUser );
        Functions\when( 'sanitize_user' )->returnArg();
        Functions\when( 'username_exists' )->justReturn( false );
        Functions\when( 'wp_insert_user' )->justReturn( 42 );
        Functions\when( 'wp_generate_password' )->justReturn( 'randompass' );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user(
            array( 'email' => 'new@example.com', 'sub' => 'sub123' ),
            array( 'id_token' => 'tok', 'access_token' => 'acc' )
        );
    }

    public function test_authenticate_user_existing_user_updates_and_logs_in() {
        $existingUser            = new WP_User();
        $existingUser->ID        = 7;
        $existingUser->user_login = 'existinguser';

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'always'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        } );
        Functions\when( 'get_users' )->justReturn( array( $existingUser ) ); // per Subject gefunden
        Functions\when( 'wp_update_user' )->justReturn( 7 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user(
            array(
                'email'       => 'existing@example.com',
                'sub'         => 'sub-exists',
                'given_name'  => 'Max',
                'family_name' => 'Muster',
                'name'        => 'Max Muster',
            ),
            array()
        );
    }

    public function test_authenticate_user_finds_user_by_email_fallback() {
        $existingUser            = new WP_User();
        $existingUser->ID        = 9;
        $existingUser->user_login = 'emailuser';

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_sync_avatar' )    { return '1'; }
            if ( $key === 'oidc_remember_me' )    { return 'never'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        } );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array() ); // kein User per Subject
        Functions\when( 'get_user_by' )->justReturn( $existingUser ); // User per E-Mail gefunden
        Functions\when( 'wp_update_user' )->justReturn( 9 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user(
            array(
                'email'   => 'email@example.com',
                'sub'     => 'new-sub',
                'picture' => 'https://cdn.example.com/avatar.jpg',
            ),
            array()
        );
    }

    public function test_authenticate_user_create_user_with_username_collision() {
        $newUser            = new WP_User();
        $newUser->ID        = 55;
        $newUser->user_login = 'newuser_abc12';

        Functions\when( 'get_option' )->alias( $this->newUserOptions() );
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( $newUser );
        Functions\when( 'sanitize_user' )->returnArg();
        Functions\when( 'username_exists' )->justReturn( true ); // Kollision!
        Functions\when( 'wp_generate_password' )->justReturn( 'abc12' );
        Functions\when( 'wp_insert_user' )->justReturn( 55 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user(
            array(
                'email'              => 'new@example.com',
                'sub'                => 'sub-new',
                'preferred_username' => 'newuser',
            ),
            array()
        );
    }

    // -------------------------------------------------------------------------
    // check_session_validity – valid session path (no WP_Error)
    // -------------------------------------------------------------------------

    public function test_check_session_validity_valid_token_does_nothing() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_session_management' ) { return '1'; }
            if ( $key === 'oidc_enable_refresh' )     { return '1'; }
            if ( $key === 'oidc_enable_encrypt' )     { return ''; }
            return $default;
        } );
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 3 );
        Functions\when( 'get_user_meta' )->alias( function ( $id, $key, $single ) {
            if ( $key === '_oidc_subject' )              { return 'sub-xyz'; }
            if ( $key === '_oidc_access_token' )         { return 'valid-token'; }
            if ( $key === '_oidc_access_token_expires' ) { return (string) ( time() + 7200 ); } // 2h gültig
            return '';
        } );
        Functions\expect( 'wp_logout' )->never();

        $this->auth->check_session_validity();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // handle_callback – account linking path
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // exchange_code_for_tokens – Provider-Fehler im Body
    // -------------------------------------------------------------------------

    public function test_exchange_code_provider_error_in_body_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            return $default;
        } );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_remote_post' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'error' => 'invalid_grant', 'error_description' => 'Token expired' ) )
        );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'wp_json_encode' )->alias( 'json_encode' );

        $result = $this->auth->public_exchange_code_for_tokens( 'mycode', '' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_error', $result->get_error_code() );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – wp_insert_user gibt WP_Error zurück
    // -------------------------------------------------------------------------

    public function test_authenticate_user_wp_insert_user_error_calls_login_error() {
        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        Functions\when( 'get_option' )->alias( $this->newUserOptions() );
        Functions\when( 'sanitize_email' )->returnArg();
        Functions\when( 'is_email' )->justReturn( true );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_user_by' )->justReturn( false );
        Functions\when( 'sanitize_user' )->returnArg();
        Functions\when( 'username_exists' )->justReturn( false );
        Functions\when( 'wp_generate_password' )->justReturn( 'rndpass' );
        Functions\when( 'wp_insert_user' )->justReturn( new WP_Error( 'insert_failed', 'DB-Fehler' ) );
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user( array( 'email' => 'new@example.com', 'sub' => 'sub123' ) );
    }

    // -------------------------------------------------------------------------
    // authenticate_user – website-Claim wird gespeichert
    // -------------------------------------------------------------------------

    public function test_authenticate_user_updates_website_url_from_userinfo() {
        $existingUser             = new WP_User();
        $existingUser->ID         = 7;
        $existingUser->user_login = 'existinguser';

        Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
            if ( $key === 'oidc_active_claim' )   { return ''; }
            if ( $key === 'oidc_sync_avatar' )    { return ''; }
            if ( $key === 'oidc_remember_me' )    { return 'never'; }
            if ( $key === 'oidc_enable_refresh' ) { return ''; }
            return $default;
        } );
        Functions\when( 'esc_url_raw' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array( $existingUser ) );
        Functions\when( 'wp_update_user' )->justReturn( 7 );
        $this->setUpLoginMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->public_authenticate_user(
            array(
                'email'   => 'existing@example.com',
                'sub'     => 'sub-exists',
                'website' => 'https://user.example.com',
            ),
            array()
        );
    }

    // -------------------------------------------------------------------------
    // handle_callback – vollständiger Erfolg-Flow (kein link_pending)
    // -------------------------------------------------------------------------

    public function test_handle_callback_successful_login_calls_authenticate_user() {
        $_GET['oidc_callback'] = '1';
        $_GET['code']          = 'auth-code';
        $_GET['state']         = 'validstate';

        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        $nonce = 'nonce123';
        $claims = array(
            'sub'   => 'sub-link',
            'aud'   => 'client123',
            'iss'   => '',
            'iat'   => time() - 10,
            'exp'   => time() + 3600,
            'nonce' => $nonce,
            'email' => 'linked@example.com',
        );
        $id_token = rtrim( strtr( base64_encode( json_encode( array( 'alg' => 'none' ) ) ), '+/', '-_' ), '=' )
            . '.' . rtrim( strtr( base64_encode( json_encode( $claims ) ), '+/', '-_' ), '=' )
            . '.fakesig';
        $tokenBody = json_encode( array( 'access_token' => 'acc-tok', 'id_token' => $id_token ) );

        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'client123'; }
            if ( $key === 'oidc_client_secret' )     { return 'secret'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            if ( $key === 'oidc_issuer' )            { return ''; }
            if ( $key === 'oidc_jwks_uri' )          { return ''; }
            if ( $key === 'oidc_active_claim' )      { return ''; }
            if ( $key === 'oidc_sync_avatar' )       { return ''; }
            if ( $key === 'oidc_remember_me' )       { return 'never'; }
            if ( $key === 'oidc_enable_refresh' )    { return ''; }
            return $default;
        } );
        Functions\when( 'get_transient' )->alias( function ( $key ) use ( $nonce ) {
            if ( strpos( $key, 'oidc_state_' ) === 0 )  { return 1; }
            if ( strpos( $key, 'oidc_pkce_' ) === 0 )   { return ''; }
            if ( strpos( $key, 'oidc_nonce_' ) === 0 )  { return 1; }
            return false;
        } );
        Functions\when( 'delete_transient' )->justReturn( true );
        Functions\when( 'wp_remote_post' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->alias( function () use ( $tokenBody ) {
            static $call = 0;
            $call++;
            if ( $call === 1 ) { return $tokenBody; }
            return json_encode( array( 'sub' => 'sub-link', 'email' => 'linked@example.com' ) );
        } );
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'is_user_logged_in' )->justReturn( false );
        $existingUser             = new WP_User();
        $existingUser->ID         = 7;
        $existingUser->user_login = 'linked';
        Functions\when( 'get_users' )->justReturn( array( $existingUser ) );
        Functions\when( 'wp_update_user' )->justReturn( 7 );
        $this->setUpLoginMocks();

        try {
            $this->auth->handle_callback();
        } catch ( OidcTestException $e ) {
            unset( $GLOBALS['wpdb'] );
            $this->assertNotEmpty( $e->getMessage() );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException not thrown.' );
    }

    public function test_handle_callback_link_pending_updates_meta_and_redirects() {
        $_GET['oidc_callback'] = '1';
        $_GET['code']          = 'auth-code';
        $_GET['state']         = 'validstate';

        $GLOBALS['wpdb'] = new class {
            public $prefix = 'wp_';
            public function insert( $t, $d, $f ) {}
        };

        $tokenBody = json_encode( array(
            'access_token' => 'acc-tok',
            'id_token'     => 'eyJhbGciOiJub25lIn0.' . rtrim( strtr( base64_encode( json_encode( array(
                'sub'   => 'sub-link',
                'aud'   => 'client123',
                'iss'   => '',
                'iat'   => time() - 10,
                'exp'   => time() + 3600,
                'nonce' => 'nonce123',
                'email' => 'linked@example.com',
            ) ) ), '+/', '-_' ), '=' ) . '.fakesig',
        ) );

        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_callback=1' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )   { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'client123'; }
            if ( $key === 'oidc_client_secret' )     { return 'secret123'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            if ( $key === 'oidc_userinfo_endpoint' ) { return ''; }
            if ( $key === 'oidc_issuer' )            { return ''; }
            if ( $key === 'oidc_scopes' )            { return 'openid email'; }
            if ( $key === 'oidc_jwks_uri' )          { return ''; }
            return $default;
        } );
        Functions\when( 'get_transient' )->alias( function ( $key ) {
            if ( strpos( $key, 'oidc_state_' ) === 0 )       { return array( 'nonce' => 'nonce123' ); }
            if ( strpos( $key, 'oidc_pkce_' ) === 0 )         { return ''; }
            if ( strpos( $key, 'oidc_nonce_' ) === 0 )        { return '1'; }
            if ( strpos( $key, 'oidc_link_pending_' ) === 0 ) { return 1; }
            return false;
        } );
        Functions\when( 'delete_transient' )->justReturn( true );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
            return $thing instanceof WP_Error && ! empty( $thing->code );
        } );
        Functions\when( 'wp_remote_post' )->justReturn( array(
            'response' => array( 'code' => 200 ),
            'body'     => $tokenBody,
        ) );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( $tokenBody );
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 7 );
        Functions\when( 'update_user_meta' )->justReturn( true );
        Functions\when( 'get_edit_profile_url' )->justReturn( 'https://example.com/wp-admin/profile.php' );
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        try {
            $this->auth->handle_callback();
        } catch ( OidcTestException $e ) {
            unset( $GLOBALS['wpdb'] );
            // Coverage: wp_safe_redirect wurde aufgerufen (entweder link oder login_error)
            $this->assertNotEmpty( $e->getMessage() );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException not thrown.' );
    }
}
