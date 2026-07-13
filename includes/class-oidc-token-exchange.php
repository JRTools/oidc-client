<?php
/**
 * OIDC Client – Token Exchange und PKCE-Hilfsmethoden
 *
 * Extrahiert aus OIDC_Auth (SA-1 Refactoring).
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Token_Exchange {

    // -------------------------------------------------------------------------
    // Token Exchange
    // -------------------------------------------------------------------------

    /**
     * Authorization Code gegen Tokens tauschen.
     *
     * @param string $code          Authorization Code.
     * @param string $code_verifier PKCE Code-Verifier (leer wenn PKCE deaktiviert).
     * @return array|WP_Error Token-Daten oder Fehler.
     */
    public function exchange_code_for_tokens( $code, $code_verifier ) {
        $token_ep      = get_option( 'jrtools_oidc_token_endpoint', '' );
        $client_id     = get_option( 'jrtools_oidc_client_id', '' );
        $client_secret = get_option( 'jrtools_oidc_client_secret', '' );
        $auth_method   = get_option( 'jrtools_oidc_token_auth_method', 'client_secret_post' );

        if ( empty( $token_ep ) ) {
            return new WP_Error( 'no_token_endpoint', __( 'Token-Endpoint nicht konfiguriert.', 'jrtools-openid-connect' ) );
        }

        $body = array(
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $this->get_redirect_uri(),
            'client_id'    => $client_id,
        );

        if ( ! empty( $code_verifier ) ) {
            $body['code_verifier'] = $code_verifier;
        }

        $headers = array( 'Content-Type' => 'application/x-www-form-urlencoded' );

        if ( 'client_secret_basic' === $auth_method ) {
            // Credentials per HTTP Basic Auth – client_secret bleibt aus dem Body
            $headers['Authorization'] = 'Basic ' . base64_encode( $client_id . ':' . $client_secret );
        } else {
            // client_secret_post – Credentials im POST-Body (Standard vieler Provider)
            $body['client_secret'] = $client_secret;
        }

        $response = wp_remote_post( $token_ep, array(
            'timeout'   => 15,
            'sslverify' => true,
            'headers'   => $headers,
            'body'      => $body,
        ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $raw_body      = wp_remote_retrieve_body( $response );
        $body_data     = json_decode( $raw_body, true );

        if ( isset( $body_data['error'] ) ) {
            $error_code = sanitize_text_field( $body_data['error'] );
            $error_desc = isset( $body_data['error_description'] )
                ? sanitize_text_field( $body_data['error_description'] )
                : '';

            $debug_sent = $body;
            $debug_sent['client_secret'] = isset( $debug_sent['client_secret'] ) ? '***' : '(not in body)';
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( '[OIDC Client] Token-Endpoint error.' // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                    . ' Code: ' . $error_code
                    . ' | URL: ' . $token_ep
                    . ' | Auth-Method: ' . $auth_method );
            }
            $msg = sprintf(
                /* translators: 1: Fehler-Code vom Token-Endpoint, 2: Fehlerbeschreibung oder leer */
                __( 'Fehler vom Provider (Token-Endpoint): %1$s%2$s', 'jrtools-openid-connect' ),
                $error_code,
                $error_desc ? ' – ' . $error_desc : ''
            );

            // Debug-Modus: nur sichere Metadaten (kein Response-Body mit Tokens)
            if ( get_option( 'jrtools_oidc_debug_mode', '' ) === '1' ) {
                $msg .= ' | Auth-Method: ' . $auth_method;
                $msg .= ' | HTTP: ' . $response_code;
            }

            return new WP_Error( 'token_error', $msg );
        }

        if ( 200 !== (int) $response_code || ! is_array( $body_data ) ) {
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( '[OIDC Client] Token-Endpoint unexpected response. HTTP ' . $response_code . ' | URL: ' . $token_ep ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            }
            return new WP_Error(
                'token_request_failed',
                /* translators: %d: HTTP-Statuscode des Token-Endpoints */
                sprintf( __( 'Token-Request fehlgeschlagen (HTTP %d).', 'jrtools-openid-connect' ), $response_code )
            );
        }

        return $body_data;
    }

    // -------------------------------------------------------------------------
    // Hilfsmethoden
    // -------------------------------------------------------------------------

    /**
     * Redirect-URI für den OAuth-Callback.
     *
     * @return string
     */
    public function get_redirect_uri() {
        return add_query_arg( 'oidc_callback', '1', wp_login_url() );
    }

    /**
     * Zufälligen Hex-String erzeugen (32 Zeichen).
     *
     * @return string
     */
    public function generate_random_string() {
        return bin2hex( random_bytes( 16 ) );
    }

    /**
     * PKCE Code-Verifier erzeugen (RFC 7636).
     *
     * @return string URL-safe Base64, 43–128 Zeichen.
     */
    public function generate_code_verifier() {
        // RFC 7636: URL-safe Base64, 43–128 Zeichen
        return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
    }

    /**
     * PKCE Code-Challenge aus Verifier erzeugen (S256).
     *
     * @param string $verifier Code-Verifier.
     * @return string BASE64URL(SHA256(ASCII(code_verifier))).
     */
    public function generate_code_challenge( $verifier ) {
        // S256: BASE64URL(SHA256(ASCII(code_verifier)))
        return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
    }
}
