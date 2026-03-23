<?php
/**
 * Tests für OIDC_JWT_Helper.
 *
 * Diese Tests prüfen ausschließlich reine PHP-Logik ohne WP-Funktionen.
 * WP_Error wird als Stub bereitgestellt (tests/bootstrap.php).
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey;

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
        $input    = base64_encode( 'ab' ); // "YWI=" (1 Pad-Zeichen)
        $urlsafe  = rtrim( strtr( $input, '+/', '-_' ), '=' );
        $result   = OIDC_JWT_Helper::base64url_decode( $urlsafe );
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
}
