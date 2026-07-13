<?php
/**
 * Tests für OIDC_Auth – Orchestrator (handle_callback, initiate_login,
 * check_session_validity, validate_id_token, fetch_userinfo).
 *
 * Token Exchange, PKCE und authenticate_user sind in eigene Klassen extrahiert
 * und werden in TokenExchangeTest / UserManagerTest getestet.
 */

use Brain\Monkey\Functions;

require_once __DIR__ . '/WpTestCase.php';

// OIDC_Auth benötigt OIDC_Log – Stub bereitstellen
if ( ! class_exists( 'OIDC_Log' ) ) {
    class OIDC_Log {
        public static function write( $_user_id, $_success, $_message ) { /* Stub */ }
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

    /** Gemeinsame Mocks für handle_callback-Fehlerpfad-Tests. */
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
        $this->setUpCallbackErrorMocks();

        $this->expectException( OidcTestException::class );
        $this->auth->handle_callback();
    }

    public function test_handle_callback_invalid_state_redirects_with_error() {
        $_GET['oidc_callback'] = '1';
        $_GET['code']          = 'auth-code';
        $_GET['state']         = 'invalid-state';
        $this->setUpCallbackErrorMocks();
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'delete_transient' )->justReturn( true );

        $this->expectException( OidcTestException::class );
        $this->auth->handle_callback();
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
            if ( $key === 'oidc_issuer' )    { return ''; }
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
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
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
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'sub' => 'user123', 'email' => 'user@example.com' ) )
        );

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertIsArray( $result );
        $this->assertSame( 'user@example.com', $result['email'] );
    }

    public function test_fetch_userinfo_401_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            return $default;
        } );
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 401 );
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'userinfo_request_failed', $result->get_error_code() );
        $this->assertStringContainsString( '401', $result->get_error_message() );
    }

    public function test_fetch_userinfo_403_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            return $default;
        } );
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 403 );
        Functions\when( '__' )->returnArg();

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'userinfo_request_failed', $result->get_error_code() );
        $this->assertStringContainsString( '403', $result->get_error_message() );
    }

    public function test_fetch_userinfo_network_error_returns_wp_error() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            return $default;
        } );
        Functions\when( 'wp_remote_get' )->justReturn( new WP_Error( 'http_request_failed', 'Connection timed out' ) );

        $result = $this->auth->public_fetch_userinfo( 'token' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'http_request_failed', $result->get_error_code() );
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

        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'wp_cache_delete' )->justReturn( true );
        Functions\when( 'get_user_meta' )->alias( function ( $id, $key, $single ) {
            if ( $key === '_oidc_subject' ) { return 'user-sub'; }
            if ( $key === '_oidc_access_token_expires' ) { return time() - 100; }
            if ( $key === '_oidc_refresh_token' ) { return ''; }
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
    // check_session_validity – valid session path
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
            if ( $key === '_oidc_access_token_expires' ) { return (string) ( time() + 7200 ); }
            return '';
        } );
        Functions\expect( 'wp_logout' )->never();

        $this->auth->check_session_validity();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // validate_id_token – aud als Array
    // -------------------------------------------------------------------------

    public function test_validate_id_token_audience_as_array_returns_claims() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_issuer' )    { return ''; }
            if ( $key === 'oidc_client_id' ) { return 'my-client'; }
            if ( $key === 'oidc_jwks_uri' )  { return ''; }
            return $default;
        } );

        $claims  = array(
            'exp' => time() + 3600,
            'iat' => time() - 60,
            'sub' => 'user-aud',
            'aud' => array( 'my-client', 'other-client' ),
        );
        $header  = rtrim( strtr( base64_encode( json_encode( array( 'alg' => 'none' ) ) ), '+/', '-_' ), '=' );
        $payload = rtrim( strtr( base64_encode( json_encode( $claims ) ), '+/', '-_' ), '=' );
        $jwt     = $header . '.' . $payload . '.';

        $result = $this->auth->public_validate_id_token( $jwt );

        $this->assertIsArray( $result );
        $this->assertSame( 'user-aud', $result['sub'] );
    }

    // -------------------------------------------------------------------------
    // handle_callback – vollständiger Erfolg-Flow
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
        Functions\when( 'get_transient' )->alias( function ( $key ) {
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

    // -------------------------------------------------------------------------
    // handle_callback – Nonce-Mismatch
    // -------------------------------------------------------------------------

    public function test_handle_callback_nonce_mismatch_calls_login_error() {
        $_GET['oidc_callback'] = '1';
        $_GET['code']          = 'auth-code';
        $_GET['state']         = 'validstate';

        $GLOBALS['wpdb'] = new class { public $prefix = 'wp_'; public function insert( $t, $d, $f ) {} };

        $nonce  = 'mynonce';
        $claims = array(
            'sub'   => 'sub-x',
            'aud'   => 'client-x',
            'iss'   => '',
            'iat'   => time() - 10,
            'exp'   => time() + 3600,
            'nonce' => $nonce,
        );
        $id_token = rtrim( strtr( base64_encode( json_encode( array( 'alg' => 'none' ) ) ), '+/', '-_' ), '=' )
            . '.' . rtrim( strtr( base64_encode( json_encode( $claims ) ), '+/', '-_' ), '=' )
            . '.fakesig';

        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_unslash' )->returnArg();
        Functions\when( '__' )->returnArg();
        Functions\when( 'add_query_arg' )->justReturn( 'https://example.com/wp-login.php?oidc_error=...' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'client-x'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            if ( $key === 'oidc_issuer' )            { return ''; }
            if ( $key === 'oidc_jwks_uri' )          { return ''; }
            return $default;
        } );
        Functions\when( 'get_transient' )->alias( function ( $key ) {
            if ( strpos( $key, 'oidc_state_' ) === 0 ) { return 1; }
            if ( strpos( $key, 'oidc_pkce_' ) === 0 )  { return ''; }
            if ( strpos( $key, 'oidc_nonce_' ) === 0 ) { return false; }
            return false;
        } );
        Functions\when( 'delete_transient' )->justReturn( true );
        Functions\when( 'wp_remote_post' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'access_token' => 'acc', 'id_token' => $id_token ) )
        );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

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

    // -------------------------------------------------------------------------
    // handle_callback – Account Linking
    // -------------------------------------------------------------------------

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
            if ( strpos( $key, 'oidc_link_pending_' ) === 0 ) { return array( 'pending' => true, 'sub' => '' ); }
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
            $this->assertNotEmpty( $e->getMessage() );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException not thrown.' );
    }

    // -------------------------------------------------------------------------
    // SE-1: Subject-Overwrite – Mismatch bei Account-Linking
    // -------------------------------------------------------------------------

    /**
     * Helper: Baut gemeinsame Mocks für Account-Linking-Tests im handle_callback.
     */
    private function setUpLinkingCallbackMocks( string $callback_sub, $transient_val ): void {
        $_GET['oidc_callback'] = '1';
        $_GET['code']          = 'auth-code';
        $_GET['state']         = 'validstate';

        $GLOBALS['wpdb'] = new class {
            public $prefix = 'wp_';
            public function insert( $t, $d, $f ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
        };

        $tokenBody = json_encode( array(
            'access_token' => 'acc-tok',
            'id_token'     => 'eyJhbGciOiJub25lIn0.' . rtrim( strtr( base64_encode( json_encode( array(
                'sub'   => $callback_sub,
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
        Functions\when( 'add_query_arg' )->alias( function () {
            $args = func_get_args();
            if ( is_string( $args[0] ) && 'oidc_error' === $args[0] ) {
                return 'https://example.com/wp-login.php?oidc_error=...';
            }
            return 'https://example.com/wp-login.php?oidc_callback=1';
        } );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'client123'; }
            if ( $key === 'oidc_client_secret' )     { return 'secret123'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            if ( $key === 'oidc_userinfo_endpoint' ) { return 'https://provider.example.com/userinfo'; }
            if ( $key === 'oidc_issuer' )            { return ''; }
            if ( $key === 'oidc_jwks_uri' )          { return ''; }
            return $default;
        } );
        Functions\when( 'get_transient' )->alias( function ( $key ) use ( $transient_val ) {
            if ( strpos( $key, 'oidc_state_' ) === 0 )        { return 1; }
            if ( strpos( $key, 'oidc_pkce_' ) === 0 )         { return ''; }
            if ( strpos( $key, 'oidc_nonce_' ) === 0 )        { return 1; }
            if ( strpos( $key, 'oidc_link_pending_' ) === 0 ) { return $transient_val; }
            return false;
        } );
        Functions\when( 'delete_transient' )->justReturn( true );
        Functions\when( 'wp_remote_post' )->justReturn( array() );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->alias( function () use ( $tokenBody, $callback_sub ) {
            static $call = 0;
            $call++;
            if ( $call === 1 ) { return $tokenBody; }
            return json_encode( array( 'sub' => $callback_sub, 'email' => 'linked@example.com' ) );
        } );
        Functions\when( 'wp_remote_get' )->justReturn( array() );
        Functions\when( 'is_user_logged_in' )->justReturn( true );
        Functions\when( 'get_current_user_id' )->justReturn( 7 );
        Functions\when( 'update_user_meta' )->justReturn( true );
        Functions\when( 'get_edit_profile_url' )->justReturn( 'https://example.com/wp-admin/profile.php' );
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'wp_safe_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );
    }

    public function test_handle_callback_link_subject_mismatch_calls_login_error() {
        $this->setUpLinkingCallbackMocks( 'different-sub-456', array( 'pending' => true, 'sub' => 'old-sub-123' ) );

        try {
            $this->auth->handle_callback();
        } catch ( OidcTestException $e ) {
            unset( $GLOBALS['wpdb'] );
            $this->assertStringContainsString( 'oidc_error', $e->getMessage() );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException for subject mismatch.' );
    }

    public function test_handle_callback_link_matching_sub_succeeds() {
        $this->setUpLinkingCallbackMocks( 'sub-link', array( 'pending' => true, 'sub' => 'sub-link' ) );

        try {
            $this->auth->handle_callback();
        } catch ( OidcTestException $e ) {
            unset( $GLOBALS['wpdb'] );
            $this->assertStringContainsString( 'profile', $e->getMessage() );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException for successful link.' );
    }

    public function test_handle_callback_link_empty_stored_sub_succeeds() {
        $this->setUpLinkingCallbackMocks( 'brand-new-sub', array( 'pending' => true, 'sub' => '' ) );

        try {
            $this->auth->handle_callback();
        } catch ( OidcTestException $e ) {
            unset( $GLOBALS['wpdb'] );
            $this->assertStringContainsString( 'profile', $e->getMessage() );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException for successful first-time link.' );
    }

    // -------------------------------------------------------------------------
    // Hooks – Filters
    // -------------------------------------------------------------------------

    public function test_oidc_scopes_filter_changes_scopes_in_auth_request() {
        $this->setUpInitiateLoginMocks( '' );
        Functions\when( 'apply_filters' )->alias( function ( $hook, $value ) {
            if ( 'oidc_scopes' === $hook ) {
                return 'openid email profile phone';
            }
            return $value;
        } );

        try {
            $this->auth->initiate_login();
        } catch ( OidcTestException $e ) {
            $this->assertStringContainsString( 'phone', $e->getMessage() );
            return;
        }
        $this->fail( 'Expected OidcTestException.' );
    }

    public function test_oidc_auth_params_filter_adds_custom_param() {
        $this->setUpInitiateLoginMocks( '' );
        Functions\when( 'apply_filters' )->alias( function ( $hook, $value ) {
            if ( 'oidc_auth_params' === $hook ) {
                $value['ui_locales'] = 'de';
            }
            return $value;
        } );

        try {
            $this->auth->initiate_login();
        } catch ( OidcTestException $e ) {
            $this->assertStringContainsString( 'ui_locales=de', $e->getMessage() );
            return;
        }
        $this->fail( 'Expected OidcTestException.' );
    }

    // -------------------------------------------------------------------------
    // Hooks – Actions
    // -------------------------------------------------------------------------

    public function test_oidc_account_linked_action_fires_after_linking() {
        $this->setUpLinkingCallbackMocks( 'new-sub-xyz', array( 'pending' => true, 'sub' => '' ) );

        $linkedUserId = null;
        $linkedSub    = null;
        Functions\when( 'do_action' )->alias( function ( $hook, ...$args ) use ( &$linkedUserId, &$linkedSub ) {
            if ( 'oidc_account_linked' === $hook ) {
                $linkedUserId = $args[0];
                $linkedSub    = $args[1];
            }
        } );

        try {
            $this->auth->handle_callback();
        } catch ( OidcTestException $e ) {
            unset( $GLOBALS['wpdb'] );
            $this->assertSame( 7, $linkedUserId );
            $this->assertSame( 'new-sub-xyz', $linkedSub );
            return;
        }
        unset( $GLOBALS['wpdb'] );
        $this->fail( 'Expected OidcTestException.' );
    }
}
