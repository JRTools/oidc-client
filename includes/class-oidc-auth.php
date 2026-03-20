<?php
/**
 * OIDC Client – Authorization Code Flow mit PKCE
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Auth {

    public function __construct() {
        add_action( 'login_init',          array( $this, 'handle_callback' ) );
        add_action( 'oidc_initiate_login', array( $this, 'initiate_login' ) );
        add_action( 'init',                array( $this, 'check_session_validity' ) );

        // F6: Avatar-Filter nur laden wenn aktiviert
        if ( get_option( 'oidc_sync_avatar', '' ) === '1' ) {
            add_filter( 'get_avatar_url', array( $this, 'filter_avatar_url' ), 10, 3 );
        }
    }

    // -------------------------------------------------------------------------
    // F4: Session-Gültigkeit prüfen (Token-Refresh oder Logout)
    // -------------------------------------------------------------------------

    public function check_session_validity() {
        if ( get_option( 'oidc_session_management', '' ) !== '1' ) {
            return;
        }
        if ( get_option( 'oidc_enable_refresh', '' ) !== '1' ) {
            return;
        }
        if ( ! is_user_logged_in() ) {
            return;
        }

        $user_id = get_current_user_id();
        if ( empty( get_user_meta( $user_id, '_oidc_subject', true ) ) ) {
            return; // Kein OIDC-Nutzer
        }

        $result = ( new OIDC_Tokens() )->get_valid_access_token( $user_id );

        if ( is_wp_error( $result ) ) {
            OIDC_Log::write( $user_id, false, 'Session beendet: ' . $result->get_error_message() );
            wp_logout();
            wp_safe_redirect( add_query_arg(
                'oidc_error',
                rawurlencode( __( 'Sitzung abgelaufen. Bitte erneut anmelden.', 'oidc-client' ) ),
                wp_login_url()
            ) );
            exit;
        }
    }

    // -------------------------------------------------------------------------
    // Redirect zum Provider
    // -------------------------------------------------------------------------

    public function initiate_login( $extra_params = array() ) {
        $client_id = get_option( 'oidc_client_id', '' );
        $auth_ep   = get_option( 'oidc_authorization_endpoint', '' );
        $scopes    = get_option( 'oidc_scopes', 'openid email profile' );

        if ( empty( $client_id ) || empty( $auth_ep ) ) {
            wp_die( esc_html__( 'OIDC ist nicht vollständig konfiguriert. Bitte prüfe die Einstellungen.', 'oidc-client' ) );
        }

        // State – CSRF-Schutz
        $state = $this->generate_random_string();
        set_transient( 'oidc_state_' . $state, 1, 5 * MINUTE_IN_SECONDS );

        // Nonce – Replay-Schutz im ID-Token
        $nonce = $this->generate_random_string();
        set_transient( 'oidc_nonce_' . $nonce, 1, 5 * MINUTE_IN_SECONDS );

        // PKCE – nur wenn Provider S256 unterstützt
        $code_verifier  = '';
        $code_challenge = '';
        if ( get_option( 'oidc_pkce_supported', '1' ) === '1' ) {
            $code_verifier  = $this->generate_code_verifier();
            $code_challenge = $this->generate_code_challenge( $code_verifier );
            set_transient( 'oidc_pkce_' . $state, $code_verifier, 5 * MINUTE_IN_SECONDS );
        }

        $params = array(
            'response_type' => 'code',
            'client_id'     => $client_id,
            'redirect_uri'  => $this->get_redirect_uri(),
            'scope'         => $scopes,
            'state'         => $state,
            'nonce'         => $nonce,
        );

        if ( ! empty( $code_challenge ) ) {
            $params['code_challenge']        = $code_challenge;
            $params['code_challenge_method'] = 'S256';
        }

        // F11: Extra-Parameter für Account-Linking (z.B. prompt=login)
        if ( ! empty( $extra_params['prompt'] ) ) {
            $params['prompt'] = sanitize_text_field( $extra_params['prompt'] );
        }

        wp_safe_redirect( $auth_ep . '?' . http_build_query( $params ) );
        exit;
    }

    // -------------------------------------------------------------------------
    // Callback verarbeiten
    // -------------------------------------------------------------------------

    public function handle_callback() {
        if ( ! isset( $_GET['oidc_callback'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- OAuth-Callback, Nonce-Prüfung erfolgt über State-Parameter (CSRF-Schutz).
            return;
        }

        if ( isset( $_GET['error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $error_code = sanitize_text_field( wp_unslash( $_GET['error'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $error_desc = isset( $_GET['error_description'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                ? sanitize_text_field( wp_unslash( $_GET['error_description'] ) ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                : '';
            $msg = sprintf(
                /* translators: 1: Fehler-Code, 2: Beschreibung oder leer */
                __( 'Fehler vom Provider (Authorization): %1$s%2$s', 'oidc-client' ),
                $error_code,
                $error_desc ? ' – ' . $error_desc : ''
            );
            $this->login_error( $msg );
            return;
        }

        $code  = isset( $_GET['code'] )  ? sanitize_text_field( wp_unslash( $_GET['code'] ) )  : '';  // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        if ( empty( $code ) || empty( $state ) ) {
            $this->login_error( __( 'Fehlende Parameter im Callback.', 'oidc-client' ) );
            return;
        }

        // State validieren (CSRF-Schutz)
        $state_transient = get_transient( 'oidc_state_' . $state );
        delete_transient( 'oidc_state_' . $state );

        if ( false === $state_transient ) {
            $this->login_error( __( 'Ungültiger oder abgelaufener State-Parameter.', 'oidc-client' ) );
            return;
        }

        // PKCE code_verifier laden und direkt löschen
        $code_verifier = get_transient( 'oidc_pkce_' . $state );
        delete_transient( 'oidc_pkce_' . $state );

        // Token Exchange
        $tokens = $this->exchange_code_for_tokens( $code, $code_verifier ? $code_verifier : '' );
        if ( is_wp_error( $tokens ) ) {
            $this->login_error( $tokens->get_error_message() );
            return;
        }

        // ID-Token validieren
        $id_token = isset( $tokens['id_token'] ) ? $tokens['id_token'] : '';
        $claims   = $this->validate_id_token( $id_token );
        if ( is_wp_error( $claims ) ) {
            $this->login_error( $claims->get_error_message() );
            return;
        }

        // Nonce validieren
        $token_nonce     = isset( $claims['nonce'] ) ? $claims['nonce'] : '';
        $nonce_transient = get_transient( 'oidc_nonce_' . $token_nonce );
        delete_transient( 'oidc_nonce_' . $token_nonce );

        if ( empty( $token_nonce ) || false === $nonce_transient ) {
            $this->login_error( __( 'Ungültige oder fehlende Nonce im ID-Token.', 'oidc-client' ) );
            return;
        }

        // Userinfo abrufen
        $access_token = isset( $tokens['access_token'] ) ? $tokens['access_token'] : '';
        $userinfo     = $this->fetch_userinfo( $access_token );
        if ( is_wp_error( $userinfo ) ) {
            $this->login_error( $userinfo->get_error_message() );
            return;
        }

        // F11: Account-Linking prüfen (eingeloggter User verknüpft OIDC-Konto)
        if ( is_user_logged_in() ) {
            $current_user_id = get_current_user_id();
            $link_pending    = get_transient( 'oidc_link_pending_' . $current_user_id );
            if ( $link_pending ) {
                delete_transient( 'oidc_link_pending_' . $current_user_id );
                $sub = sanitize_text_field( isset( $userinfo['sub'] ) ? $userinfo['sub'] : '' );
                if ( $sub ) {
                    update_user_meta( $current_user_id, '_oidc_subject', $sub );
                }
                wp_safe_redirect( get_edit_profile_url( $current_user_id ) . '#oidc-linked' );
                exit;
            }
        }

        // Benutzer einloggen oder anlegen
        $this->authenticate_user( $userinfo, $tokens );
    }

    // -------------------------------------------------------------------------
    // Token Exchange
    // -------------------------------------------------------------------------

    private function exchange_code_for_tokens( $code, $code_verifier ) {
        $token_ep      = get_option( 'oidc_token_endpoint', '' );
        $client_id     = get_option( 'oidc_client_id', '' );
        $client_secret = get_option( 'oidc_client_secret', '' );
        $auth_method   = get_option( 'oidc_token_auth_method', 'client_secret_post' );

        if ( empty( $token_ep ) ) {
            return new WP_Error( 'no_token_endpoint', __( 'Token-Endpoint nicht konfiguriert.', 'oidc-client' ) );
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
                    . ' URL: ' . $token_ep
                    . ' | Auth-Method: ' . $auth_method
                    . ' | Sent: ' . wp_json_encode( $debug_sent )
                    . ' | Response: ' . $raw_body );
            }
            /* translators: 1: Fehler-Code vom Token-Endpoint, 2: Fehlerbeschreibung oder leer */
            $msg = sprintf(
                __( 'Fehler vom Provider (Token-Endpoint): %1$s%2$s', 'oidc-client' ),
                $error_code,
                $error_desc ? ' – ' . $error_desc : ''
            );

            // Debug-Modus: volle Antwort in der Fehlermeldung (nur wenn aktiviert)
            if ( get_option( 'oidc_debug_mode', '' ) === '1' ) {
                $msg .= ' | Raw: ' . $raw_body;
                $msg .= ' | Sent (no secret): ' . wp_json_encode( $debug_sent );
                $msg .= ' | Auth-Method: ' . $auth_method;
            }

            return new WP_Error( 'token_error', $msg );
        }

        if ( 200 !== (int) $response_code || ! is_array( $body_data ) ) {
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( '[OIDC Client] Token-Endpoint unexpected response. HTTP ' . $response_code . ' | Body: ' . $raw_body ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            }
            return new WP_Error(
                'token_request_failed',
                /* translators: %d: HTTP-Statuscode des Token-Endpoints */
                sprintf( __( 'Token-Request fehlgeschlagen (HTTP %d).', 'oidc-client' ), $response_code )
            );
        }

        return $body_data;
    }

    // -------------------------------------------------------------------------
    // ID-Token validieren (Claims + RS256-Signaturprüfung via openssl)
    // -------------------------------------------------------------------------

    private function validate_id_token( $id_token ) {
        if ( empty( $id_token ) ) {
            return new WP_Error( 'no_id_token', __( 'Kein ID-Token empfangen.', 'oidc-client' ) );
        }

        $parsed = OIDC_JWT_Helper::parse_jwt( $id_token );
        if ( is_wp_error( $parsed ) ) {
            return $parsed;
        }

        list( $header, $claims, $parts ) = $parsed;

        $now = time();

        // exp – Ablaufzeit
        if ( ! isset( $claims['exp'] ) || (int) $claims['exp'] < ( $now - 60 ) ) {
            return new WP_Error( 'token_expired', __( 'ID-Token ist abgelaufen.', 'oidc-client' ) );
        }

        // iat – nicht in der Zukunft (5 Minuten Toleranz für Clock-Skew)
        if ( ! isset( $claims['iat'] ) || (int) $claims['iat'] > ( $now + 5 * MINUTE_IN_SECONDS ) ) {
            return new WP_Error( 'token_iat_invalid', __( 'ID-Token iat ist ungültig.', 'oidc-client' ) );
        }

        // iss – Issuer prüfen
        $expected_issuer = get_option( 'oidc_issuer', '' );
        if ( ! empty( $expected_issuer ) ) {
            $token_iss = isset( $claims['iss'] ) ? $claims['iss'] : '';
            if ( $token_iss !== $expected_issuer ) {
                return new WP_Error( 'token_iss_mismatch', __( 'ID-Token Issuer stimmt nicht überein.', 'oidc-client' ) );
            }
        }

        // aud – Audience prüfen
        $client_id = get_option( 'oidc_client_id', '' );
        if ( ! empty( $client_id ) ) {
            $aud      = isset( $claims['aud'] ) ? $claims['aud'] : array();
            $aud_list = is_array( $aud ) ? $aud : array( $aud );
            if ( ! in_array( $client_id, $aud_list, true ) ) {
                return new WP_Error( 'token_aud_mismatch', __( 'ID-Token Audience stimmt nicht überein.', 'oidc-client' ) );
            }
        }

        // RS256-Signaturprüfung
        $jwks_uri = get_option( 'oidc_jwks_uri', '' );
        if ( ! empty( $jwks_uri ) ) {
            $sig_result = OIDC_JWT_Helper::verify_signature( $parts, $header, $jwks_uri );
            if ( is_wp_error( $sig_result ) ) {
                return $sig_result;
            }
        }

        return $claims;
    }

    // -------------------------------------------------------------------------
    // Userinfo abrufen
    // -------------------------------------------------------------------------

    private function fetch_userinfo( $access_token ) {
        $userinfo_ep = get_option( 'oidc_userinfo_endpoint', '' );

        if ( empty( $userinfo_ep ) ) {
            return new WP_Error( 'no_userinfo_endpoint', __( 'Userinfo-Endpoint nicht konfiguriert.', 'oidc-client' ) );
        }

        $response = wp_remote_get( $userinfo_ep, array(
            'timeout'   => 10,
            'sslverify' => true,
            'headers'   => array(
                'Authorization' => 'Bearer ' . $access_token,
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! is_array( $data ) || empty( $data['email'] ) ) {
            return new WP_Error(
                'userinfo_no_email',
                __( 'Der Provider hat keine E-Mail-Adresse zurückgegeben. Bitte prüfe die konfigurierten Scopes.', 'oidc-client' )
            );
        }

        return $data;
    }

    // -------------------------------------------------------------------------
    // Benutzer einloggen oder anlegen
    // -------------------------------------------------------------------------

    private function authenticate_user( $userinfo, $tokens = array() ) {
        // F5: Active-Claim prüfen (Konto deaktiviert?)
        $active_claim = get_option( 'oidc_active_claim', '' );
        if ( ! empty( $active_claim ) && isset( $userinfo[ $active_claim ] ) ) {
            $v = $userinfo[ $active_claim ];
            if ( false === $v || 0 === $v || 'false' === $v || '0' === $v ) {
                OIDC_Log::write( 0, false, __( 'Konto deaktiviert (Active-Claim).', 'oidc-client' ) );
                $this->login_error( __( 'Dein Konto ist deaktiviert. Bitte wende dich an den Administrator.', 'oidc-client' ) );
                return;
            }
        }

        $email = sanitize_email( isset( $userinfo['email'] ) ? $userinfo['email'] : '' );

        if ( ! is_email( $email ) ) {
            $this->login_error( __( 'Ungültige E-Mail-Adresse vom Provider.', 'oidc-client' ) );
            return;
        }

        // F11: Benutzer zuerst via Subject-Claim suchen
        $sub  = sanitize_text_field( isset( $userinfo['sub'] ) ? $userinfo['sub'] : '' );
        $user = false;

        if ( ! empty( $sub ) ) {
            $users = get_users( array(
                'meta_key'   => '_oidc_subject', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
                'meta_value' => $sub,            // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
                'number'     => 1,
            ) );
            if ( ! empty( $users ) ) {
                $user = $users[0];
            }
        }

        // Fallback: Suche per E-Mail
        if ( ! $user ) {
            $user = get_user_by( 'email', $email );
            // Subject nachträglich speichern
            if ( $user && ! empty( $sub ) ) {
                update_user_meta( $user->ID, '_oidc_subject', $sub );
            }
        }

        if ( ! $user ) {
            if ( ! get_option( 'oidc_create_user', false ) ) {
                $this->login_error( __( 'Kein lokales Konto für diese E-Mail-Adresse vorhanden. Bitte wende dich an den Administrator.', 'oidc-client' ) );
                return;
            }

            // Benutzernamen aus preferred_username oder E-Mail ableiten
            $raw_username = isset( $userinfo['preferred_username'] )
                ? $userinfo['preferred_username']
                : strstr( $email, '@', true );
            $username = sanitize_user( $raw_username, true );

            // Eindeutigkeit sicherstellen
            if ( username_exists( $username ) ) {
                $username = $username . '_' . wp_generate_password( 5, false );
            }

            $user_id = wp_insert_user( array(
                'user_login' => $username,
                'user_email' => $email,
                'user_pass'  => wp_generate_password( 32, true, true ),
                'first_name' => isset( $userinfo['given_name'] )  ? sanitize_text_field( $userinfo['given_name'] )  : '',
                'last_name'  => isset( $userinfo['family_name'] ) ? sanitize_text_field( $userinfo['family_name'] ) : '',
                'role'       => get_option( 'oidc_default_role', 'subscriber' ),
            ) );

            if ( is_wp_error( $user_id ) ) {
                $this->login_error( $user_id->get_error_message() );
                return;
            }

            $user = get_user_by( 'id', $user_id );

            // F11: Subject beim neuen User speichern
            if ( ! empty( $sub ) ) {
                update_user_meta( $user->ID, '_oidc_subject', $sub );
            }
        } else {
            // Bestehenden Benutzer mit aktuellen Daten vom Provider aktualisieren
            $update_data = array( 'ID' => $user->ID );

            if ( isset( $userinfo['given_name'] ) ) {
                $update_data['first_name'] = sanitize_text_field( $userinfo['given_name'] );
            }
            if ( isset( $userinfo['family_name'] ) ) {
                $update_data['last_name'] = sanitize_text_field( $userinfo['family_name'] );
            }
            if ( isset( $userinfo['name'] ) ) {
                $update_data['display_name'] = sanitize_text_field( $userinfo['name'] );
            }
            if ( isset( $userinfo['website'] ) ) {
                $update_data['user_url'] = esc_url_raw( $userinfo['website'] );
            }

            if ( count( $update_data ) > 1 ) {
                wp_update_user( $update_data );
            }
        }

        // F6: Avatar-URL speichern
        if ( get_option( 'oidc_sync_avatar', '' ) === '1' && ! empty( $userinfo['picture'] ) ) {
            update_user_meta( $user->ID, '_oidc_avatar_url', esc_url_raw( $userinfo['picture'] ) );
        }

        // F4: Rollen-Mapping anwenden
        ( new OIDC_Roles() )->apply_role_mapping( $user->ID, $userinfo );

        // F2: Tokens speichern (id_token immer, access/refresh nur wenn Refresh aktiv)
        ( new OIDC_Tokens() )->store_tokens( $user->ID, $tokens );

        // Einloggen
        $remember = get_option( 'oidc_remember_me', 'never' ) === 'always';
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, $remember );
        do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core-Hook.

        // F7: Erfolgreichen Login loggen
        OIDC_Log::write( $user->ID, true, __( 'OIDC Login erfolgreich.', 'oidc-client' ) );

        $redirect_to = apply_filters( 'login_redirect', admin_url(), '', $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core-Filter.
        wp_safe_redirect( $redirect_to );
        exit;
    }

    // -------------------------------------------------------------------------
    // F6: Avatar-URL-Filter
    // -------------------------------------------------------------------------

    public function filter_avatar_url( $url, $id_or_email, $args ) {
        $user = false;

        if ( is_numeric( $id_or_email ) ) {
            $user = get_user_by( 'id', (int) $id_or_email );
        } elseif ( is_string( $id_or_email ) ) {
            $user = get_user_by( 'email', $id_or_email );
        } elseif ( $id_or_email instanceof WP_User ) {
            $user = $id_or_email;
        } elseif ( $id_or_email instanceof WP_Post ) {
            $user = get_user_by( 'id', (int) $id_or_email->post_author );
        } elseif ( $id_or_email instanceof WP_Comment ) {
            $user = get_user_by( 'email', $id_or_email->comment_author_email );
        }

        if ( $user ) {
            $avatar_url = get_user_meta( $user->ID, '_oidc_avatar_url', true );
            if ( ! empty( $avatar_url ) ) {
                return esc_url( $avatar_url );
            }
        }

        return $url;
    }

    // -------------------------------------------------------------------------
    // Hilfsmethoden
    // -------------------------------------------------------------------------

    private function get_redirect_uri() {
        return add_query_arg( 'oidc_callback', '1', wp_login_url() );
    }

    private function generate_random_string() {
        return bin2hex( random_bytes( 16 ) );
    }

    private function generate_code_verifier() {
        // RFC 7636: URL-safe Base64, 43–128 Zeichen
        return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
    }

    private function generate_code_challenge( $verifier ) {
        // S256: BASE64URL(SHA256(ASCII(code_verifier)))
        return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
    }

    private function login_error( $message, $user_id = 0 ) {
        OIDC_Log::write( $user_id, false, $message );
        wp_safe_redirect( add_query_arg(
            'oidc_error',
            rawurlencode( $message ),
            wp_login_url()
        ) );
        exit;
    }
}
