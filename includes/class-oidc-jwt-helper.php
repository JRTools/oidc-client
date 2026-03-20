<?php
/**
 * OIDC Client – Gemeinsame JWT-Hilfsmethoden (statisch)
 * Wird von OIDC_Auth und OIDC_Logout genutzt, um Code-Duplikation zu vermeiden.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_JWT_Helper {

    /**
     * Base64url-Dekodierung (RFC 4648 §5).
     *
     * @param string $input
     * @return string|false
     */
    public static function base64url_decode( $input ) {
        $b64 = strtr( $input, '-_', '+/' );
        $pad = strlen( $b64 ) % 4;
        if ( $pad ) {
            $b64 .= str_repeat( '=', 4 - $pad );
        }
        return base64_decode( $b64, true );
    }

    /**
     * JWT parsen: gibt [header_array, claims_array, parts_array] oder WP_Error zurück.
     *
     * @param string $jwt
     * @return array|WP_Error
     */
    public static function parse_jwt( $jwt ) {
        $parts = explode( '.', $jwt );
        if ( 3 !== count( $parts ) ) {
            return new WP_Error( 'invalid_jwt_format', __( 'Ungültiges JWT-Format.', 'oidc-client' ) );
        }

        $header_json  = self::base64url_decode( $parts[0] );
        $payload_json = self::base64url_decode( $parts[1] );

        if ( false === $header_json || false === $payload_json ) {
            return new WP_Error( 'jwt_decode_failed', __( 'JWT konnte nicht dekodiert werden.', 'oidc-client' ) );
        }

        $header = json_decode( $header_json, true );
        $claims = json_decode( $payload_json, true );

        if ( ! is_array( $header ) || ! is_array( $claims ) ) {
            return new WP_Error( 'jwt_parse_failed', __( 'JWT enthält kein gültiges JSON.', 'oidc-client' ) );
        }

        return array( $header, $claims, $parts );
    }

    /**
     * JWKS abrufen – gecacht für 1 Stunde via WordPress-Transient.
     *
     * @param string $jwks_uri
     * @return array|WP_Error
     */
    public static function get_jwks( $jwks_uri ) {
        $cache_key = 'oidc_jwks_' . md5( $jwks_uri );
        $cached    = get_transient( $cache_key );

        if ( is_array( $cached ) && isset( $cached['keys'] ) ) {
            return $cached;
        }

        $response = wp_remote_get( $jwks_uri, array(
            'timeout'   => 10,
            'sslverify' => true,
        ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( 200 !== (int) $code ) {
            return new WP_Error(
                'jwks_fetch_failed',
                /* translators: %d: HTTP-Statuscode beim JWKS-Abruf */
                sprintf( __( 'JWKS-Abruf fehlgeschlagen (HTTP %d).', 'oidc-client' ), $code )
            );
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! is_array( $data ) || empty( $data['keys'] ) ) {
            return new WP_Error( 'jwks_invalid', __( 'Ungültige JWKS-Antwort.', 'oidc-client' ) );
        }

        set_transient( $cache_key, $data, HOUR_IN_SECONDS );

        return $data;
    }

    /**
     * RS256-Signatur eines JWT prüfen.
     *
     * @param array  $parts    Array mit [header_b64, payload_b64, sig_b64].
     * @param array  $header   Dekodierter JWT-Header.
     * @param string $jwks_uri
     * @return true|WP_Error
     */
    public static function verify_signature( $parts, $header, $jwks_uri ) {
        if ( ! function_exists( 'openssl_verify' ) ) {
            return new WP_Error( 'openssl_missing', __( 'PHP OpenSSL-Extension ist nicht verfügbar.', 'oidc-client' ) );
        }

        $alg = isset( $header['alg'] ) ? $header['alg'] : '';
        if ( 'RS256' !== $alg ) {
            return new WP_Error(
                'unsupported_alg',
                /* translators: %s: Name des nicht unterstützten JWT-Signaturalgorithmus */
                sprintf( __( 'Nicht unterstützter Signaturalgorithmus: %s', 'oidc-client' ), sanitize_text_field( $alg ) )
            );
        }

        $kid  = isset( $header['kid'] ) ? $header['kid'] : '';
        $jwks = self::get_jwks( $jwks_uri );
        if ( is_wp_error( $jwks ) ) {
            return $jwks;
        }

        $jwk = self::find_jwk( $jwks, $kid );

        if ( null === $jwk ) {
            delete_transient( 'oidc_jwks_' . md5( $jwks_uri ) );
            $jwks = self::get_jwks( $jwks_uri );
            if ( is_wp_error( $jwks ) ) {
                return $jwks;
            }
            $jwk = self::find_jwk( $jwks, $kid );
        }

        if ( null === $jwk ) {
            return new WP_Error( 'jwk_not_found', __( 'Passender Public Key im JWKS nicht gefunden.', 'oidc-client' ) );
        }

        $pem = self::jwk_to_pem( $jwk );
        if ( is_wp_error( $pem ) ) {
            return $pem;
        }

        $signing_input = $parts[0] . '.' . $parts[1];
        $signature_raw = self::base64url_decode( $parts[2] );

        if ( false === $signature_raw ) {
            return new WP_Error( 'sig_decode_failed', __( 'JWT-Signatur konnte nicht dekodiert werden.', 'oidc-client' ) );
        }

        $public_key = openssl_pkey_get_public( $pem );
        if ( false === $public_key ) {
            return new WP_Error( 'pem_invalid', __( 'Public Key konnte nicht geladen werden.', 'oidc-client' ) );
        }

        $result = openssl_verify( $signing_input, $signature_raw, $public_key, OPENSSL_ALGO_SHA256 );

        if ( function_exists( 'openssl_free_key' ) ) {
            openssl_free_key( $public_key ); // phpcs:ignore
        }

        if ( 1 !== $result ) {
            return new WP_Error( 'sig_invalid', __( 'JWT-Signatur ist ungültig.', 'oidc-client' ) );
        }

        return true;
    }

    /**
     * Passenden JWK anhand kid (oder ersten RSA-Key) finden.
     */
    private static function find_jwk( $jwks, $kid ) {
        foreach ( $jwks['keys'] as $key ) {
            if ( isset( $key['kty'] ) && 'RSA' === $key['kty'] ) {
                if ( empty( $kid ) || ( isset( $key['kid'] ) && $key['kid'] === $kid ) ) {
                    return $key;
                }
            }
        }
        return null;
    }

    /**
     * JWK (RSA) zu PEM Public Key konvertieren.
     *
     * @param array $jwk
     * @return string|WP_Error PEM-String
     */
    public static function jwk_to_pem( $jwk ) {
        if ( ! isset( $jwk['n'] ) || ! isset( $jwk['e'] ) ) {
            return new WP_Error( 'jwk_missing_params', __( 'JWK fehlen n oder e Parameter.', 'oidc-client' ) );
        }

        $n = self::base64url_decode( $jwk['n'] );
        $e = self::base64url_decode( $jwk['e'] );

        if ( false === $n || false === $e ) {
            return new WP_Error( 'jwk_decode_failed', __( 'JWK-Parameter konnten nicht dekodiert werden.', 'oidc-client' ) );
        }

        $n_hex = bin2hex( $n );
        $e_hex = bin2hex( $e );

        if ( hexdec( substr( $n_hex, 0, 2 ) ) > 127 ) {
            $n_hex = '00' . $n_hex;
        }
        if ( hexdec( substr( $e_hex, 0, 2 ) ) > 127 ) {
            $e_hex = '00' . $e_hex;
        }

        $n_der  = hex2bin( $n_hex );
        $e_der  = hex2bin( $e_hex );
        $n_int  = "\x02" . self::der_length( strlen( $n_der ) ) . $n_der;
        $e_int  = "\x02" . self::der_length( strlen( $e_der ) ) . $e_der;
        $rsa_key   = "\x30" . self::der_length( strlen( $n_int ) + strlen( $e_int ) ) . $n_int . $e_int;
        $bit_string = "\x03" . self::der_length( strlen( $rsa_key ) + 1 ) . "\x00" . $rsa_key;
        $alg_id    = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $spki      = "\x30" . self::der_length( strlen( $alg_id ) + strlen( $bit_string ) ) . $alg_id . $bit_string;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split( base64_encode( $spki ), 64, "\n" )
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * ASN.1 DER Längen-Encoding.
     */
    private static function der_length( $length ) {
        if ( $length < 128 ) {
            return chr( $length );
        }
        $bytes = '';
        $tmp   = $length;
        while ( $tmp > 0 ) {
            $bytes = chr( $tmp & 0xff ) . $bytes;
            $tmp >>= 8;
        }
        return chr( 0x80 | strlen( $bytes ) ) . $bytes;
    }
}
