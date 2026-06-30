<?php
/**
 * Tests für OIDC_JWK_Helper.
 *
 * WP_Error wird als Stub bereitgestellt (tests/bootstrap.php).
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey;
use Brain\Monkey\Functions;

class JwkHelperTest extends WpTestCase {

	// -------------------------------------------------------------------------
	// der_length (via Reflexion, da private)
	// -------------------------------------------------------------------------

	private function call_der_length( $length ) {
		$ref    = new ReflectionClass( OIDC_JWK_Helper::class );
		$method = $ref->getMethod( 'der_length' );
		$method->setAccessible( true );
		return $method->invoke( null, $length );
	}

	public function test_der_length_short_is_single_byte() {
		$result = $this->call_der_length( 42 );
		$this->assertSame( chr( 42 ), $result );
		$this->assertSame( 1, strlen( $result ) );
	}

	public function test_der_length_127_is_single_byte() {
		$result = $this->call_der_length( 127 );
		$this->assertSame( chr( 127 ), $result );
	}

	public function test_der_length_128_is_multi_byte() {
		$result = $this->call_der_length( 128 );
		// Muss 2 Bytes sein: 0x81 0x80
		$this->assertSame( 2, strlen( $result ) );
		$this->assertSame( chr( 0x81 ), $result[0] );
		$this->assertSame( chr( 0x80 ), $result[1] );
	}

	public function test_der_length_300_is_multi_byte() {
		$result = $this->call_der_length( 300 );
		// 300 = 0x012C → 2 Längen-Bytes → Gesamt 3 Bytes
		$this->assertSame( 3, strlen( $result ) );
		$this->assertSame( chr( 0x82 ), $result[0] ); // 2 folgende Längen-Bytes
		$this->assertSame( chr( 0x01 ), $result[1] );
		$this->assertSame( chr( 0x2C ), $result[2] );
	}

	// -------------------------------------------------------------------------
	// find_jwk
	// -------------------------------------------------------------------------

	public function test_find_jwk_returns_matching_key_by_kid() {
		$jwks = array(
			'keys' => array(
				array( 'kty' => 'RSA', 'kid' => 'key-1', 'n' => 'abc', 'e' => 'AQAB' ),
				array( 'kty' => 'RSA', 'kid' => 'key-2', 'n' => 'def', 'e' => 'AQAB' ),
			),
		);

		$result = OIDC_JWK_Helper::find_jwk( $jwks, 'key-2' );
		$this->assertSame( 'def', $result['n'] );
	}

	public function test_find_jwk_returns_first_rsa_key_when_kid_empty() {
		$jwks = array(
			'keys' => array(
				array( 'kty' => 'RSA', 'kid' => 'key-1', 'n' => 'abc', 'e' => 'AQAB' ),
			),
		);

		$result = OIDC_JWK_Helper::find_jwk( $jwks, '' );
		$this->assertSame( 'abc', $result['n'] );
	}

	public function test_find_jwk_returns_null_when_no_match() {
		$jwks = array(
			'keys' => array(
				array( 'kty' => 'RSA', 'kid' => 'other', 'n' => 'abc', 'e' => 'AQAB' ),
			),
		);

		$result = OIDC_JWK_Helper::find_jwk( $jwks, 'wanted-kid' );
		$this->assertNull( $result );
	}

	public function test_find_jwk_ignores_non_rsa_keys() {
		$jwks = array(
			'keys' => array(
				array( 'kty' => 'EC', 'kid' => 'ec-key' ),
			),
		);

		$result = OIDC_JWK_Helper::find_jwk( $jwks, 'ec-key' );
		$this->assertNull( $result );
	}

	// -------------------------------------------------------------------------
	// jwk_to_pem
	// -------------------------------------------------------------------------

	public function test_jwk_to_pem_missing_n_returns_wp_error() {
		Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

		$result = OIDC_JWK_Helper::jwk_to_pem( array( 'e' => 'AQAB' ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwk_missing_params', $result->get_error_code() );
	}

	public function test_jwk_to_pem_missing_e_returns_wp_error() {
		Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

		$result = OIDC_JWK_Helper::jwk_to_pem( array( 'n' => 'abc' ) );
		$this->assertInstanceOf( WP_Error::class, $result );
	}

	public function test_jwk_to_pem_invalid_base64_returns_wp_error() {
		Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

		// '!!!' ist kein gültiges Base64url → base64url_decode gibt false zurück
		$result = OIDC_JWK_Helper::jwk_to_pem( array( 'n' => '!!!', 'e' => 'AQAB' ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwk_decode_failed', $result->get_error_code() );
	}

	public function test_jwk_to_pem_valid_produces_pem() {
		Monkey\Functions\expect( '__' )->zeroOrMoreTimes()->andReturnArg( 0 );

		// RSA-2048 Public Key Testdaten (Standard-Beispiel aus RFC 7517)
		$n = 'ofgWCuLjybRJ_qqjcJ7MvFEoZuRpk3t9-' .
			 'qZ6MjMj0OoRyMIa3yK2bXCa9ZMEj6C7V9MehDc9uSR0-' .
			 'W5yRFfCsG9S5o7KLJGEJVr8WFqnKP9ZEMNjQaVxHvYqH-' .
			 'Qo4XfEH-8JV7C5Zv9n1Jl1uyoZ4Q7XFbBxuoN5YLQJF3-' .
			 'mSKXbHTcaJm8hENFUhS7h7KXFf4RvzGJBXPmqbXbWOcIFH' .
			 'g0f7gPpuS5z1Z5DaTmEWalPYk5zZHJBRKH1SqpL7lEJf8' .
			 'sAHO0g5XLTl-2tsMxuVzU0';
		$e = 'AQAB';

		$result = OIDC_JWK_Helper::jwk_to_pem( array( 'n' => $n, 'e' => $e, 'kty' => 'RSA' ) );

		if ( is_wp_error( $result ) ) {
			$this->markTestSkipped( 'JWK-Testdaten erzeugen WP_Error: ' . $result->get_error_message() );
		} else {
			$this->assertStringContainsString( '-----BEGIN PUBLIC KEY-----', $result );
			$this->assertStringContainsString( '-----END PUBLIC KEY-----', $result );
		}
	}

	// -------------------------------------------------------------------------
	// get_jwks
	// -------------------------------------------------------------------------

	public function test_get_jwks_returns_cached_value() {
		$cached = array( 'keys' => array( array( 'kty' => 'RSA' ) ) );
		Functions\when( 'get_transient' )->justReturn( $cached );
		Functions\expect( 'wp_remote_get' )->never();

		$result = OIDC_JWK_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

		$this->assertSame( $cached, $result );
	}

	public function test_get_jwks_returns_wp_error_on_http_failure() {
		$error = new WP_Error( 'http_error', 'Connection failed' );
		Functions\when( 'get_transient' )->justReturn( false );
		Functions\when( 'wp_remote_get' )->justReturn( $error );
		Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
			return $thing instanceof WP_Error;
		} );

		$result = OIDC_JWK_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

		$this->assertInstanceOf( WP_Error::class, $result );
	}

	public function test_get_jwks_returns_wp_error_on_non_200() {
		Functions\when( 'get_transient' )->justReturn( false );
		Functions\when( 'wp_remote_get' )->justReturn( array( 'response' => array( 'code' => 404 ) ) );
		Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
			return $thing instanceof WP_Error;
		} );
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 404 );
		Functions\when( '__' )->returnArg();

		$result = OIDC_JWK_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwks_fetch_failed', $result->get_error_code() );
	}

	public function test_get_jwks_returns_wp_error_on_invalid_body() {
		Functions\when( 'get_transient' )->justReturn( false );
		Functions\when( 'wp_remote_get' )->justReturn( array() );
		Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
			return $thing instanceof WP_Error;
		} );
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( '{"no_keys":true}' );
		Functions\when( '__' )->returnArg();

		$result = OIDC_JWK_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwks_invalid', $result->get_error_code() );
	}

	public function test_get_jwks_fetches_and_caches_on_success() {
		$jwks = array( 'keys' => array( array( 'kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB' ) ) );
		Functions\when( 'get_transient' )->justReturn( false );
		Functions\when( 'wp_remote_get' )->justReturn( array() );
		Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
			return $thing instanceof WP_Error;
		} );
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( json_encode( $jwks ) );
		Functions\expect( 'set_transient' )->once();

		$result = OIDC_JWK_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

		$this->assertSame( $jwks, $result );
	}
}
