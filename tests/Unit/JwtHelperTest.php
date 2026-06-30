<?php
/**
 * Tests für OIDC_JWT_Helper.
 *
 * WP_Error wird als Stub bereitgestellt (tests/bootstrap.php).
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey;
use Brain\Monkey\Functions;

class JwtHelperTest extends WpTestCase {

	// -------------------------------------------------------------------------
	// base64url_decode
	// -------------------------------------------------------------------------

	public function test_base64url_decode_standard() {
		// "hello" base64url = "aGVsbG8"
		$result = OIDC_JWT_Helper::base64url_decode( 'aGVsbG8' );
		$this->assertSame( 'hello', $result );
	}

	public function test_base64url_decode_replaces_url_chars() {
		// base64 "+/" wird in url-safe zu "-_"
		$original = base64_encode( "\xfb\xff" ); // "+/" in standard base64
		$urlsafe  = strtr( $original, '+/', '-_' );
		$urlsafe  = rtrim( $urlsafe, '=' );
		$result   = OIDC_JWT_Helper::base64url_decode( $urlsafe );
		$this->assertSame( "\xfb\xff", $result );
	}

	public function test_base64url_decode_padding_added() {
		// Ohne Padding muss die Methode es ergänzen
		$input   = base64_encode( 'ab' ); // "YWI=" (1 Pad-Zeichen)
		$urlsafe = rtrim( strtr( $input, '+/', '-_' ), '=' );
		$result  = OIDC_JWT_Helper::base64url_decode( $urlsafe );
		$this->assertSame( 'ab', $result );
	}

	// -------------------------------------------------------------------------
	// parse_jwt
	// -------------------------------------------------------------------------

	public function test_parse_jwt_invalid_format_returns_wp_error() {
		Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

		$result = OIDC_JWT_Helper::parse_jwt( 'only.two' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'invalid_jwt_format', $result->get_error_code() );
	}

	public function test_parse_jwt_invalid_base64_returns_wp_error() {
		Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

		// Segment 1 ist valides Base64, Segment 2 aber kein valides JSON
		$bad_jwt = '!!!.!!!.!!!';
		$result  = OIDC_JWT_Helper::parse_jwt( $bad_jwt );
		$this->assertInstanceOf( WP_Error::class, $result );
	}

	public function test_parse_jwt_valid_returns_array() {
		Monkey\Functions\expect( '__' )->zeroOrMoreTimes()->andReturnArg( 0 );

		$header  = base64_encode( json_encode( array( 'alg' => 'RS256', 'typ' => 'JWT' ) ) );
		$payload = base64_encode( json_encode( array( 'sub' => '12345', 'iss' => 'https://example.com' ) ) );
		$sig     = 'fakesig';

		$jwt    = strtr( $header, '+/', '-_' ) . '.' . strtr( $payload, '+/', '-_' ) . '.' . $sig;
		$result = OIDC_JWT_Helper::parse_jwt( $jwt );

		$this->assertIsArray( $result );
		$this->assertCount( 3, $result );
		$this->assertSame( 'RS256', $result[0]['alg'] );
		$this->assertSame( '12345', $result[1]['sub'] );
	}

	// -------------------------------------------------------------------------
	// verify_signature
	// -------------------------------------------------------------------------

	public function test_verify_signature_unsupported_alg_returns_wp_error() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();

		$parts  = array( 'header', 'payload', 'sig' );
		$header = array( 'alg' => 'HS256' );

		$result = OIDC_JWT_Helper::verify_signature( $parts, $header, 'https://provider.example.com/jwks' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'unsupported_alg', $result->get_error_code() );
	}

	public function test_verify_signature_returns_wp_error_when_jwks_fails() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();
		Functions\when( 'get_transient' )->justReturn( false );
		$error = new WP_Error( 'http_error', 'Connection failed' );
		Functions\when( 'wp_remote_get' )->justReturn( $error );
		Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
			return $thing instanceof WP_Error;
		} );

		$parts  = array( 'header', 'payload', 'sig' );
		$header = array( 'alg' => 'RS256' );

		$result = OIDC_JWT_Helper::verify_signature( $parts, $header, 'https://provider.example.com/jwks' );

		$this->assertInstanceOf( WP_Error::class, $result );
	}

	/** Baut JWKS-Mocks auf, die immer false cachen und ein fixes JWKS zurückgeben. */
	private function mockJwks( array $jwks ): void {
		Functions\when( 'get_transient' )->justReturn( false );
		Functions\when( 'wp_remote_get' )->justReturn( array() );
		Functions\when( 'is_wp_error' )->alias( function ( $thing ) { return $thing instanceof WP_Error; } );
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( json_encode( $jwks ) );
		Functions\when( 'set_transient' )->justReturn( true );
		Functions\when( 'delete_transient' )->justReturn( true );
	}

	public function test_verify_signature_jwk_not_found_returns_wp_error() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();
		// JWKS mit anderem kid → find_jwk schlägt fehl (auch nach Retry)
		$this->mockJwks( array( 'keys' => array( array( 'kty' => 'RSA', 'kid' => 'other', 'n' => 'abc', 'e' => 'AQAB' ) ) ) );

		$result = OIDC_JWT_Helper::verify_signature(
			array( 'hdr', 'pay', 'sig' ),
			array( 'alg' => 'RS256', 'kid' => 'wanted-kid' ),
			'https://provider.example.com/jwks'
		);

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwk_not_found', $result->get_error_code() );
	}

	public function test_verify_signature_jwk_to_pem_error_returns_wp_error() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();
		// RSA-Key ohne n/e → jwk_to_pem gibt WP_Error zurück
		$this->mockJwks( array( 'keys' => array( array( 'kty' => 'RSA' ) ) ) );

		$result = OIDC_JWT_Helper::verify_signature(
			array( 'hdr', 'pay', 'sig' ),
			array( 'alg' => 'RS256' ),
			'https://provider.example.com/jwks'
		);

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwk_missing_params', $result->get_error_code() );
	}

	/** Erzeugt ein 512-Bit-RSA-Testschlüsselpaar und gibt [privat, JWK] zurück. */
	private function generateTestRsaJwk(): array {
		if ( ! function_exists( 'openssl_pkey_new' ) ) {
			$this->markTestSkipped( 'OpenSSL nicht verfügbar.' );
		}
		$private_key = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
		$details     = openssl_pkey_get_details( $private_key );
		$jwk = array(
			'kty' => 'RSA',
			'n'   => rtrim( strtr( base64_encode( $details['rsa']['n'] ), '+/', '-_' ), '=' ),
			'e'   => rtrim( strtr( base64_encode( $details['rsa']['e'] ), '+/', '-_' ), '=' ),
		);
		return array( $private_key, $jwk );
	}

	/** Signiert `$header.$payload` mit dem privaten Schlüssel und gibt die 3 JWT-Parts zurück. */
	private function signJwt( $private_key, string $header_b64, string $payload_b64 ): array {
		$signing_input = $header_b64 . '.' . $payload_b64;
		openssl_sign( $signing_input, $signature, $private_key, OPENSSL_ALGO_SHA256 );
		$sig_b64 = rtrim( strtr( base64_encode( $signature ), '+/', '-_' ), '=' );
		return array( $header_b64, $payload_b64, $sig_b64 );
	}

	public function test_verify_signature_sig_decode_failed_returns_wp_error() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();
		[, $jwk ] = $this->generateTestRsaJwk();
		$this->mockJwks( array( 'keys' => array( $jwk ) ) );

		// '!!!' ist kein gültiges Base64 → base64url_decode gibt false zurück
		$result = OIDC_JWT_Helper::verify_signature(
			array( 'hdr', 'pay', '!!!' ),
			array( 'alg' => 'RS256' ),
			'https://provider.example.com/jwks'
		);

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'sig_decode_failed', $result->get_error_code() );
	}

	public function test_verify_signature_invalid_sig_returns_wp_error() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();
		[, $jwk ] = $this->generateTestRsaJwk();
		$this->mockJwks( array( 'keys' => array( $jwk ) ) );

		$header_b64  = rtrim( strtr( base64_encode( json_encode( array( 'alg' => 'RS256' ) ) ), '+/', '-_' ), '=' );
		$payload_b64 = rtrim( strtr( base64_encode( json_encode( array( 'sub' => '123' ) ) ), '+/', '-_' ), '=' );
		// Falsche Signatur: andere Bytes
		$bad_sig = rtrim( strtr( base64_encode( str_repeat( 'x', 64 ) ), '+/', '-_' ), '=' );

		$result = OIDC_JWT_Helper::verify_signature(
			array( $header_b64, $payload_b64, $bad_sig ),
			array( 'alg' => 'RS256' ),
			'https://provider.example.com/jwks'
		);

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'sig_invalid', $result->get_error_code() );
	}

	public function test_verify_signature_valid_returns_true() {
		Functions\when( '__' )->returnArg();
		Functions\when( 'sanitize_text_field' )->returnArg();
		list( $private_key, $jwk ) = $this->generateTestRsaJwk();
		$this->mockJwks( array( 'keys' => array( $jwk ) ) );

		$header_b64  = rtrim( strtr( base64_encode( json_encode( array( 'alg' => 'RS256' ) ) ), '+/', '-_' ), '=' );
		$payload_b64 = rtrim( strtr( base64_encode( json_encode( array( 'sub' => '123' ) ) ), '+/', '-_' ), '=' );
		$parts       = $this->signJwt( $private_key, $header_b64, $payload_b64 );

		$result = OIDC_JWT_Helper::verify_signature(
			$parts,
			array( 'alg' => 'RS256' ),
			'https://provider.example.com/jwks'
		);

		$this->assertTrue( $result );
	}
}
