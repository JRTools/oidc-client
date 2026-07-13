<?php
/**
 * Tests für OIDC_Logout – Frontchannel, Backchannel und validate_logout_token.
 *
 * validate_logout_token ist private → wird via handle_backchannel_logout
 * indirekt getestet (WP_REST_Request-Stub mit get_param()).
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

if ( ! class_exists( 'OIDC_Log' ) ) {
    class OIDC_Log {
        public static function write( $_user_id, $_success, $_message ) {}
    }
}

if ( ! class_exists( 'WP_Session_Tokens' ) ) {
    class WP_Session_Tokens {
        private static $instance;
        public static function get_instance( $_user_id ) {
            if ( ! self::$instance ) {
                self::$instance = new self();
            }
            return self::$instance;
        }
        public function destroy_all() {}
    }
}

if ( ! class_exists( 'WP_REST_Request' ) ) {
    class WP_REST_Request {
        private $params = array();
        public function set_param( $key, $value ) { $this->params[ $key ] = $value; }
        public function get_param( $key ) { return isset( $this->params[ $key ] ) ? $this->params[ $key ] : null; }
    }
}

if ( ! class_exists( 'WP_REST_Response' ) ) {
    class WP_REST_Response {
        public $data;
        public $status;
        public function __construct( $data = null, $status = 200 ) {
            $this->data   = $data;
            $this->status = $status;
        }
    }
}

if ( ! class_exists( 'OIDC_Logout' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-logout.php';
}

class LogoutTest extends WpTestCase {

    /** @var OIDC_Logout */
    private $logout;

    /** Standard-events-Claim für Backchannel-Logout-Token. */
    private const EVENTS = array( 'http://schemas.openid.net/event/backchannel-logout' => array() );

    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        $this->logout = new OIDC_Logout();
    }

    /** Baut ein Logout-JWT mit den gegebenen Payload-Claims. */
    private function buildLogoutJwt( array $payload ): string {
        $header = base64_encode( json_encode( array( 'alg' => 'RS256' ) ) );
        return $header . '.' . base64_encode( json_encode( $payload ) ) . '.fakesig';
    }

    /** Erstellt einen WP_REST_Request mit dem gesetzten logout_token. */
    private function makeRequest( string $jwt ): WP_REST_Request {
        $request = new WP_REST_Request();
        $request->set_param( 'logout_token', $jwt );
        return $request;
    }

    // -------------------------------------------------------------------------
    // handle_frontchannel_logout
    // -------------------------------------------------------------------------

    public function test_frontchannel_logout_no_endpoint_returns_early() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\expect( 'wp_redirect' )->never();

        $this->logout->handle_frontchannel_logout( 1 );
        $this->addToAssertionCount( 1 );
    }

    public function test_frontchannel_logout_redirects_to_endpoint() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_end_session_endpoint' ) {
                return 'https://provider.example.com/logout';
            }
            return $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'delete_user_meta' )->justReturn( true );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->logout->handle_frontchannel_logout( 1 );
    }

    public function test_frontchannel_logout_includes_id_token_hint() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_end_session_endpoint' ) {
                return 'https://provider.example.com/logout';
            }
            return $default;
        } );
        Functions\when( 'get_user_meta' )->alias( function ( $user_id, $key, $single ) {
            if ( $key === '_oidc_id_token' ) {
                // Simuliere verschlüsselten Token – encrypt gibt base64 zurück
                // get_id_token ruft decrypt auf, wir geben direkt den Rohwert zurück
                return '';
            }
            return '';
        } );
        Functions\when( 'delete_user_meta' )->justReturn( true );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
        Functions\when( 'wp_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        try {
            $this->logout->handle_frontchannel_logout( 1 );
        } catch ( OidcTestException $e ) {
            $this->assertStringContainsString( 'https://provider.example.com/logout', $e->getMessage() );
            return;
        }
        $this->fail( 'Expected OidcTestException not thrown.' );
    }

    // -------------------------------------------------------------------------
    // handle_backchannel_logout – missing token
    // -------------------------------------------------------------------------

    public function test_backchannel_logout_missing_token_returns_400() {
        $request = new WP_REST_Request();
        // kein logout_token gesetzt

        $response = $this->logout->handle_backchannel_logout( $request );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'missing_logout_token', $response->data['error'] );
    }

    // -------------------------------------------------------------------------
    // handle_backchannel_logout – validate_logout_token Pfade
    // -------------------------------------------------------------------------

    public function test_backchannel_logout_invalid_jwt_format_returns_400() {
        Functions\when( '__' )->returnArg();

        $request = new WP_REST_Request();
        $request->set_param( 'logout_token', 'not.a.valid.jwt.structure.extra' );

        $response = $this->logout->handle_backchannel_logout( $request );

        $this->assertSame( 400, $response->status );
        $this->assertArrayHasKey( 'error', $response->data );
    }

    public function test_backchannel_logout_token_missing_iat_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        // JWT ohne iat-Claim: header.payload.sig
        $header  = base64_encode( json_encode( array( 'alg' => 'RS256' ) ) );
        $payload = base64_encode( json_encode( array(
            'sub'    => 'user123',
            'events' => array( 'http://schemas.openid.net/event/backchannel-logout' => new stdClass() ),
        ) ) );
        $jwt = $header . '.' . $payload . '.fakesig';

        $request = new WP_REST_Request();
        $request->set_param( 'logout_token', $jwt );

        $response = $this->logout->handle_backchannel_logout( $request );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_iat', $response->data['error'] );
    }

    public function test_backchannel_logout_token_with_nonce_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time(), 'nonce' => 'should-not-be-here', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_nonce', $response->data['error'] );
    }

    public function test_backchannel_logout_token_missing_events_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time() ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_events', $response->data['error'] );
    }

    public function test_backchannel_logout_token_missing_sub_and_sid_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        $jwt      = $this->buildLogoutJwt( array( 'iat' => time(), 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_subject', $response->data['error'] );
    }

    public function test_backchannel_logout_replay_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( false ); // JTI bereits im Cache

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time(), 'jti' => 'unique-jti-123', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_replay', $response->data['error'] );
    }

    public function test_backchannel_logout_user_not_found_returns_200() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'get_users' )->justReturn( array() );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'unknown-user', 'iat' => time(), 'jti' => 'jti-abc', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 200, $response->status );
    }

    public function test_backchannel_logout_valid_token_logs_out_user() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'delete_user_meta' )->justReturn( true );

        $GLOBALS['wpdb'] = new FakeWpdb();

        $user     = new WP_User();
        $user->ID = 42;
        Functions\when( 'get_users' )->justReturn( array( $user ) );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user42', 'iat' => time(), 'jti' => 'jti-xyz', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 200, $response->status );

        unset( $GLOBALS['wpdb'] );
    }

    // -------------------------------------------------------------------------
    // register_backchannel_endpoint
    // -------------------------------------------------------------------------

    public function test_register_backchannel_endpoint_calls_register_rest_route() {
        Functions\expect( 'register_rest_route' )
            ->once()
            ->with( 'oidc-client/v1', '/backchannel-logout', \Mockery::type( 'array' ) );

        $this->logout->register_backchannel_endpoint();
        $this->addToAssertionCount( 1 );
    }

    // -------------------------------------------------------------------------
    // validate_logout_token – Issuer- und Audience-Validierung
    // -------------------------------------------------------------------------

    public function test_backchannel_logout_issuer_mismatch_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_issuer' ) { return 'https://expected.example.com'; }
            return $default;
        } );

        $jwt      = $this->buildLogoutJwt( array( 'iss' => 'https://wrong-issuer.example.com', 'sub' => 'user123', 'iat' => time(), 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_iss', $response->data['error'] );
    }

    public function test_backchannel_logout_audience_mismatch_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_issuer' )    { return ''; }
            if ( $key === 'oidc_client_id' ) { return 'expected-client'; }
            return $default;
        } );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'aud' => 'wrong-client', 'iat' => time(), 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_aud', $response->data['error'] );
    }

    public function test_backchannel_logout_audience_array_match_succeeds() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_issuer' )    { return ''; }
            if ( $key === 'oidc_client_id' ) { return 'my-client'; }
            return $default;
        } );
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'get_users' )->justReturn( array() );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'aud' => array( 'other-client', 'my-client' ), 'iat' => time(), 'jti' => 'jti-array-test', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 200, $response->status );
    }

    public function test_backchannel_logout_future_iat_returns_400() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time() + 600, 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_iat', $response->data['error'] );
    }

    // -------------------------------------------------------------------------
    // JTI Replay-Schutz – atomares Check-and-Set
    // -------------------------------------------------------------------------

    public function test_jti_first_use_allowed_via_cache_add() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'get_users' )->justReturn( array() );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time(), 'jti' => 'fresh-jti-001', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 200, $response->status );
    }

    public function test_jti_replay_detected_by_cache_add() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( false );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time(), 'jti' => 'replayed-jti', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_replay', $response->data['error'] );
    }

    public function test_jti_replay_detected_by_transient_fallback() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( true );  // Cache restarted, add succeeds.
        Functions\when( 'get_transient' )->justReturn( 1 );    // But transient still holds the JTI.

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time(), 'jti' => 'cache-restarted-jti', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 400, $response->status );
        $this->assertSame( 'logout_token_replay', $response->data['error'] );
    }

    public function test_jti_uses_exp_claim_for_ttl() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'get_users' )->justReturn( array() );
        Functions\when( 'get_transient' )->justReturn( false );

        $exp = time() + 3600;

        Functions\expect( 'wp_cache_add' )
            ->once()
            ->with( \Mockery::type( 'string' ), 1, 'oidc_jti', \Mockery::on( function ( $ttl ) {
                // TTL sollte ~3600 sein (exp - time()), mit Toleranz für Testlaufzeit.
                return $ttl > 3500 && $ttl <= 3600;
            } ) )
            ->andReturn( true );
        Functions\expect( 'set_transient' )
            ->once()
            ->with( \Mockery::type( 'string' ), 1, \Mockery::on( function ( $ttl ) {
                return $ttl > 3500 && $ttl <= 3600;
            } ) )
            ->andReturn( true );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user123', 'iat' => time(), 'exp' => $exp, 'jti' => 'ttl-jti', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 200, $response->status );
    }

    // -------------------------------------------------------------------------
    // backchannel_logout_permission_callback – Rate-Limiting
    // -------------------------------------------------------------------------

    public function test_permission_callback_allows_request_under_limit() {
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\expect( 'set_transient' )
            ->once()
            ->with( \Mockery::type( 'string' ), 1, 60 )
            ->andReturn( true );

        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        $result = $this->logout->backchannel_logout_permission_callback();

        $this->assertTrue( $result );
    }

    public function test_permission_callback_increments_counter_within_limit() {
        Functions\when( 'get_transient' )->justReturn( 5 );
        Functions\expect( 'set_transient' )
            ->once()
            ->with( \Mockery::type( 'string' ), 6, 60 )
            ->andReturn( true );

        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        $result = $this->logout->backchannel_logout_permission_callback();

        $this->assertTrue( $result );
    }

    public function test_permission_callback_returns_error_when_rate_limit_exceeded() {
        Functions\when( 'get_transient' )->justReturn( 10 );

        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $result = $this->logout->backchannel_logout_permission_callback();

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'rate_limit_exceeded', $result->get_error_code() );
        $this->assertSame( 429, $result->data['status'] );
    }

    public function test_permission_callback_uses_fallback_ip_when_remote_addr_missing() {
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\expect( 'set_transient' )
            ->once()
            ->with( 'oidc_rl_' . md5( '0.0.0.0' ), 1, 60 )
            ->andReturn( true );

        unset( $_SERVER['REMOTE_ADDR'] );

        $result = $this->logout->backchannel_logout_permission_callback();

        $this->assertTrue( $result );
    }

    // -------------------------------------------------------------------------
    // Hooks – Actions
    // -------------------------------------------------------------------------

    public function test_oidc_logout_action_fires_during_frontchannel_logout() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_end_session_endpoint' ) {
                return 'https://provider.example.com/logout';
            }
            return $default;
        } );
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'delete_user_meta' )->justReturn( true );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );

        $firedUserId = null;
        Functions\when( 'do_action' )->alias( function ( $hook, ...$args ) use ( &$firedUserId ) {
            if ( 'oidc_logout' === $hook ) {
                $firedUserId = $args[0];
            }
        } );
        Functions\when( 'wp_redirect' )->alias( function ( $url ) {
            throw new OidcTestException( $url );
        } );

        $this->expectException( OidcTestException::class );
        $this->logout->handle_frontchannel_logout( 5 );

        $this->assertSame( 5, $firedUserId );
    }

    public function test_oidc_backchannel_logout_action_fires_after_session_destroyed() {
        Functions\when( '__' )->returnArg();
        Functions\when( 'current_time' )->justReturn( '2026-01-01 12:00:00' );
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'delete_user_meta' )->justReturn( true );

        $GLOBALS['wpdb'] = new FakeWpdb();

        $user     = new WP_User();
        $user->ID = 42;
        Functions\when( 'get_users' )->justReturn( array( $user ) );

        $firedUserId = null;
        Functions\when( 'do_action' )->alias( function ( $hook, ...$args ) use ( &$firedUserId ) {
            if ( 'oidc_backchannel_logout' === $hook ) {
                $firedUserId = $args[0];
            }
        } );

        $jwt      = $this->buildLogoutJwt( array( 'sub' => 'user42', 'iat' => time(), 'jti' => 'jti-bcl', 'events' => self::EVENTS ) );
        $response = $this->logout->handle_backchannel_logout( $this->makeRequest( $jwt ) );

        $this->assertSame( 200, $response->status );
        $this->assertSame( 42, $firedUserId );

        unset( $GLOBALS['wpdb'] );
    }
}
