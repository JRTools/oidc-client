<?php
/**
 * OIDC Client – Token-Speicherung und Token-Refresh
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Tokens {

    /**
     * Tokens nach erfolgreichem Login speichern.
     * ID-Token wird immer gespeichert (für Frontchannel-Logout).
     * Refresh/Access-Token nur wenn Token-Refresh aktiviert.
     *
     * @param int   $user_id
     * @param array $tokens  Token-Response-Array vom Provider
     */
    public function store_tokens( $user_id, $tokens ) {
        if ( ! empty( $tokens['id_token'] ) ) {
            update_user_meta( $user_id, '_oidc_id_token', $this->encrypt( $tokens['id_token'] ) );
        }

        if ( get_option( 'oidc_enable_refresh', '' ) !== '1' ) {
            return;
        }

        if ( ! empty( $tokens['access_token'] ) ) {
            update_user_meta( $user_id, '_oidc_access_token', $this->encrypt( $tokens['access_token'] ) );
        }

        $expires_in = isset( $tokens['expires_in'] ) ? (int) $tokens['expires_in'] : 3600;
        update_user_meta( $user_id, '_oidc_access_token_expires', time() + $expires_in );

        if ( ! empty( $tokens['refresh_token'] ) ) {
            update_user_meta( $user_id, '_oidc_refresh_token', $this->encrypt( $tokens['refresh_token'] ) );
        }

        /*
         * Action: oidc_tokens_stored
         *
         * Fires after tokens have been stored for a user.
         *
         * @param int $user_id WordPress user ID.
         */
        do_action( 'oidc_tokens_stored', $user_id );
    }

    /**
     * ID-Token lesen (entschlüsselt).
     *
     * @param int $user_id
     * @return string
     */
    public function get_id_token( $user_id ) {
        $raw = get_user_meta( $user_id, '_oidc_id_token', true );
        return $raw ? $this->decrypt( $raw ) : '';
    }

    /**
     * Gültiges Access-Token zurückgeben. Erneuert automatisch wenn abgelaufen.
     *
     * @param int $user_id
     * @return string|WP_Error
     */
    public function get_valid_access_token( $user_id ) {
        $token   = $this->decrypt( get_user_meta( $user_id, '_oidc_access_token', true ) );
        $expires = (int) get_user_meta( $user_id, '_oidc_access_token_expires', true );

        if ( $token && $expires > ( time() + 60 ) ) {
            return $token;
        }

        return $this->refresh_access_token( $user_id );
    }

    /**
     * Access-Token via Refresh-Token erneuern.
     *
     * @param int $user_id
     * @return string|WP_Error neuer Access-Token
     */
    private function refresh_access_token( $user_id ) {
        $lock_key = 'oidc_refresh_lock_' . $user_id;

        // Atomares Lock-Setzen: gibt false wenn Lock bereits existiert.
        if ( false === wp_cache_add( $lock_key, 1, 'oidc', 15 ) ) {
            // Anderer Request refresht gerade — kurz warten und neues Token laden.
            usleep( 500000 );
            $token   = $this->decrypt( get_user_meta( $user_id, '_oidc_access_token', true ) );
            $expires = (int) get_user_meta( $user_id, '_oidc_access_token_expires', true );
            if ( $token && $expires > time() ) {
                return $token;
            }
            return new WP_Error( 'refresh_locked', __( 'Token-Refresh durch anderen Request fehlgeschlagen.', 'oidc-client' ) );
        }

        try {
            $refresh_token = $this->decrypt( get_user_meta( $user_id, '_oidc_refresh_token', true ) );

            if ( empty( $refresh_token ) ) {
                return new WP_Error( 'no_refresh_token', __( 'Kein Refresh-Token vorhanden.', 'oidc-client' ) );
            }

            $token_ep      = get_option( 'oidc_token_endpoint', '' );
            $client_id     = get_option( 'oidc_client_id', '' );
            $client_secret = get_option( 'oidc_client_secret', '' );
            $auth_method   = get_option( 'oidc_token_auth_method', 'client_secret_post' );

            $body = array(
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refresh_token,
                'client_id'     => $client_id,
            );

            $headers = array( 'Content-Type' => 'application/x-www-form-urlencoded' );

            if ( 'client_secret_basic' === $auth_method ) {
                $headers['Authorization'] = 'Basic ' . base64_encode( $client_id . ':' . $client_secret );
            } else {
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

            $data = json_decode( wp_remote_retrieve_body( $response ), true );

            if ( isset( $data['error'] ) ) {
                return new WP_Error( 'refresh_error', sanitize_text_field( $data['error_description'] ?? $data['error'] ) );
            }

            if ( empty( $data['access_token'] ) ) {
                return new WP_Error( 'refresh_failed', __( 'Token-Refresh fehlgeschlagen.', 'oidc-client' ) );
            }

            $this->store_tokens( $user_id, $data );

            /*
             * Action: oidc_tokens_refreshed
             *
             * Fires after a successful token refresh.
             *
             * @param int $user_id WordPress user ID.
             */
            do_action( 'oidc_tokens_refreshed', $user_id );

            return $data['access_token'];
        } finally {
            wp_cache_delete( $lock_key, 'oidc' );
        }
    }

    /**
     * Access- und Refresh-Token löschen (bei Logout).
     * ID-Token bleibt erhalten bis Frontchannel-Logout abgeschlossen ist.
     *
     * @param int $user_id
     */
    public function clear_tokens( $user_id ) {
        delete_user_meta( $user_id, '_oidc_access_token' );
        delete_user_meta( $user_id, '_oidc_access_token_expires' );
        delete_user_meta( $user_id, '_oidc_refresh_token' );
    }

    /**
     * Alle Token-Metas löschen (inkl. ID-Token, nach Logout).
     *
     * @param int $user_id
     */
    public function clear_all_tokens( $user_id ) {
        $this->clear_tokens( $user_id );
        delete_user_meta( $user_id, '_oidc_id_token' );
    }

    // -------------------------------------------------------------------------
    // Verschlüsselung (AES-256-CBC via OpenSSL)
    // -------------------------------------------------------------------------

    /**
     * Token verschlüsseln. Gibt Klartext zurück wenn Verschlüsselung deaktiviert
     * oder OpenSSL nicht verfügbar.
     *
     * @param string $plaintext
     * @return string
     */
    private function encrypt( $plaintext ) {
        if ( get_option( 'oidc_token_encryption', '1' ) !== '1' ) {
            return $plaintext;
        }
        if ( ! function_exists( 'openssl_encrypt' ) || empty( $plaintext ) ) {
            return $plaintext;
        }

        $key = substr( hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY, true ), 0, 32 );
        $iv  = random_bytes( 16 );
        $enc = openssl_encrypt( $plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );

        if ( false === $enc ) {
            return $plaintext; // Fallback bei Fehler
        }

        return 'enc:' . base64_encode( $iv . $enc );
    }

    /**
     * Token entschlüsseln. Gibt Klartext zurück wenn nicht verschlüsselt (Legacy).
     *
     * @param string $value
     * @return string
     */
    private function decrypt( $value ) {
        if ( empty( $value ) ) {
            return '';
        }
        // Nicht verschlüsselt (Legacy oder Verschlüsselung deaktiviert)
        if ( strpos( $value, 'enc:' ) !== 0 ) {
            return $value;
        }
        if ( ! function_exists( 'openssl_decrypt' ) ) {
            return '';
        }

        $key  = substr( hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY, true ), 0, 32 );
        $data = base64_decode( substr( $value, 4 ) );

        if ( strlen( $data ) <= 16 ) {
            return '';
        }

        $iv  = substr( $data, 0, 16 );
        $enc = substr( $data, 16 );

        $result = openssl_decrypt( $enc, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );

        return ( false === $result ) ? '' : $result;
    }
}
