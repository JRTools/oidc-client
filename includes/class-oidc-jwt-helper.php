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
		$jwks = OIDC_JWK_Helper::get_jwks( $jwks_uri );
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}

		$jwk = OIDC_JWK_Helper::find_jwk( $jwks, $kid );

		if ( null === $jwk ) {
			delete_transient( 'oidc_jwks_' . md5( $jwks_uri ) ); // phpcs:ignore -- md5 used as cache key, not for security
			$jwks = OIDC_JWK_Helper::get_jwks( $jwks_uri );
			if ( is_wp_error( $jwks ) ) {
				return $jwks;
			}
			$jwk = OIDC_JWK_Helper::find_jwk( $jwks, $kid );
		}

		if ( null === $jwk ) {
			return new WP_Error( 'jwk_not_found', __( 'Passender Public Key im JWKS nicht gefunden.', 'oidc-client' ) );
		}

		$pem = OIDC_JWK_Helper::jwk_to_pem( $jwk );
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
}
