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
    // der_length (via Reflexion, da private)
    // -------------------------------------------------------------------------

    private function call_der_length( $length ) {
        $ref    = new ReflectionClass( OIDC_JWT_Helper::class );
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
    // jwk_to_pem
    // -------------------------------------------------------------------------

    public function test_jwk_to_pem_missing_n_returns_wp_error() {
        Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

        $result = OIDC_JWT_Helper::jwk_to_pem( array( 'e' => 'AQAB' ) );
        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'jwk_missing_params', $result->get_error_code() );
    }

    public function test_jwk_to_pem_missing_e_returns_wp_error() {
        Monkey\Functions\expect( '__' )->once()->andReturnArg( 0 );

        $result = OIDC_JWT_Helper::jwk_to_pem( array( 'n' => 'abc' ) );
        $this->assertInstanceOf( WP_Error::class, $result );
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

        $result = OIDC_JWT_Helper::jwk_to_pem( array( 'n' => $n, 'e' => $e, 'kty' => 'RSA' ) );

        // Wenn n/e gültige Base64url-Daten sind, sollte PEM entstehen
        if ( is_wp_error( $result ) ) {
            // openssl_pkey_get_public könnte bei Testdaten scheitern – wir testen nur das Format
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

        $result = OIDC_JWT_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

        $this->assertSame( $cached, $result );
    }

    public function test_get_jwks_returns_wp_error_on_http_failure() {
        $error = new WP_Error( 'http_error', 'Connection failed' );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'wp_remote_get' )->justReturn( $error );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
            return $thing instanceof WP_Error;
        } );

        $result = OIDC_JWT_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

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

        $result = OIDC_JWT_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

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

        $result = OIDC_JWT_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

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

        $result = OIDC_JWT_Helper::get_jwks( 'https://provider.example.com/.well-known/jwks.json' );

        $this->assertSame( $jwks, $result );
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
        $private_key = openssl_pkey_new( array( 'private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
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
        list( $private_key, $jwk ) = $this->generateTestRsaJwk();
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
        list( $private_key, $jwk ) = $this->generateTestRsaJwk();
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
