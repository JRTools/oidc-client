<?php
/**
 * OIDC Client – JWK-Hilfsmethoden (statisch)
 * Verantwortlich für JWKS-Abruf, JWK-Suche und JWK→PEM-Konvertierung.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OIDC_JWK_Helper {

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
	 * Passenden JWK anhand kid (oder ersten RSA-Key) finden.
	 *
	 * @param array  $jwks JWKS-Datenstruktur mit 'keys'-Array.
	 * @param string $kid  Key-ID aus dem JWT-Header.
	 * @return array|null JWK-Array oder null.
	 */
	public static function find_jwk( $jwks, $kid ) {
		foreach ( $jwks['keys'] as $key ) {
			if ( isset( $key['kty'] ) && 'RSA' === $key['kty'] && ( empty( $kid ) || ( isset( $key['kid'] ) && $key['kid'] === $kid ) ) ) {
				return $key;
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

		$n = OIDC_JWT_Helper::base64url_decode( $jwk['n'] );
		$e = OIDC_JWT_Helper::base64url_decode( $jwk['e'] );

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
	 *
	 * @param int $length
	 * @return string
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
