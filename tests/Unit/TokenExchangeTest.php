<?php
/**
 * Tests für OIDC_Token_Exchange – Token Exchange und PKCE-Hilfsmethoden.
 *
 * Extrahiert aus AuthTest (SA-1 Refactoring).
 */

use Brain\Monkey\Functions;

require_once __DIR__ . '/WpTestCase.php';

if ( ! class_exists( 'OIDC_Token_Exchange' ) ) {
    require_once __DIR__ . '/../../includes/class-oidc-token-exchange.php';
}

class TokenExchangeTest extends WpTestCase {

    /** @var OIDC_Token_Exchange */
    private $exchange;

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'add_action' )->justReturn( null );
        Functions\when( 'add_filter' )->justReturn( null );
        Functions\when( 'get_option' )->justReturn( '' );

        $this->exchange = new OIDC_Token_Exchange();
    }

    // -------------------------------------------------------------------------
    // generate_random_string
    // -------------------------------------------------------------------------

    public function test_generate_random_string_is_hex() {
        $result = $this->exchange->generate_random_string();
        $this->assertMatchesRegularExpression( '/^[0-9a-f]+$/', $result );
    }

    public function test_generate_random_string_is_32_chars() {
        $result = $this->exchange->generate_random_string();
        $this->assertSame( 32, strlen( $result ) );
    }

    public function test_generate_random_string_is_unique() {
        $a = $this->exchange->generate_random_string();
        $b = $this->exchange->generate_random_string();
        $this->assertNotSame( $a, $b );
    }

    // -------------------------------------------------------------------------
    // generate_code_verifier
    // -------------------------------------------------------------------------

    public function test_generate_code_verifier_is_base64url() {
        $result = $this->exchange->generate_code_verifier();
        $this->assertMatchesRegularExpression( '/^[A-Za-z0-9\-_]+$/', $result );
    }

    public function test_generate_code_verifier_length_in_range() {
        $result = $this->exchange->generate_code_verifier();
        $len    = strlen( $result );
        $this->assertGreaterThanOrEqual( 43, $len );
        $this->assertLessThanOrEqual( 128, $len );
    }

    public function test_generate_code_verifier_no_padding() {
        $result = $this->exchange->generate_code_verifier();
        $this->assertStringNotContainsString( '=', $result );
    }

    // -------------------------------------------------------------------------
    // generate_code_challenge
    // -------------------------------------------------------------------------

    public function test_generate_code_challenge_is_base64url() {
        $verifier = $this->exchange->generate_code_verifier();
        $result   = $this->exchange->generate_code_challenge( $verifier );
        $this->assertMatchesRegularExpression( '/^[A-Za-z0-9\-_]+$/', $result );
    }

    public function test_generate_code_challenge_no_padding() {
        $verifier = 'testverifier';
        $result   = $this->exchange->generate_code_challenge( $verifier );
        $this->assertStringNotContainsString( '=', $result );
    }

    public function test_generate_code_challenge_s256_algorithm() {
        $verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $expected  = rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
        $result    = $this->exchange->generate_code_challenge( $verifier );
        $this->assertSame( $expected, $result );
    }

    public function test_generate_code_challenge_is_deterministic() {
        $verifier = $this->exchange->generate_code_verifier();
        $c1       = $this->exchange->generate_code_challenge( $verifier );
        $c2       = $this->exchange->generate_code_challenge( $verifier );
        $this->assertSame( $c1, $c2 );
    }

    // -------------------------------------------------------------------------
    // exchange_code_for_tokens
    // -------------------------------------------------------------------------

    public function test_exchange_code_no_token_endpoint_returns_wp_error() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( '__' )->returnArg();

        $result = $this->exchange->exchange_code_for_tokens( 'code', '' );

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

        $result = $this->exchange->exchange_code_for_tokens( 'mycode', '' );

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

        $result = $this->exchange->exchange_code_for_tokens( 'mycode', '' );

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

        $this->exchange->exchange_code_for_tokens( 'mycode', '' );

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

        $this->exchange->exchange_code_for_tokens( 'mycode', 'my-verifier' );

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

        $result = $this->exchange->exchange_code_for_tokens( 'mycode', '' );

        $this->assertIsArray( $result );
        $this->assertSame( 'tok123', $result['access_token'] );
    }

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

        $result = $this->exchange->exchange_code_for_tokens( 'mycode', '' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'token_error', $result->get_error_code() );
    }
}
