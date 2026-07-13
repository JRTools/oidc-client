<?php
/**
 * OIDC Client – Authorization Code Flow mit PKCE
 *
 * Orchestrator: Delegiert Token Exchange an OIDC_Token_Exchange
 * und Benutzerverwaltung an OIDC_User_Manager.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Auth {

    /** @var OIDC_Token_Exchange */
    private $token_exchange;

    /** @var OIDC_User_Manager */
    private $user_manager;

    public function __construct() {
        $this->token_exchange = new OIDC_Token_Exchange();
        $this->user_manager   = new OIDC_User_Manager();

        add_action( 'login_init',                array( $this, 'handle_callback' ) );
        add_action( 'jrtools_oidc_initiate_login', array( $this, 'initiate_login' ) );
        add_action( 'init',                      array( $this, 'check_session_validity' ) );
    }

    // -------------------------------------------------------------------------
    // F4: Session-Gültigkeit prüfen (Token-Refresh oder Logout)
    // -------------------------------------------------------------------------

    public function check_session_validity() {
        if ( get_option( 'jrtools_oidc_session_management', '' ) !== '1' ) {
            return;
        }
        if ( get_option( 'jrtools_oidc_enable_refresh', '' ) !== '1' ) {
            return;
        }
        if ( ! is_user_logged_in() ) {
            return;
        }

        $user_id = get_current_user_id();
        if ( empty( get_user_meta( $user_id, '_jrtools_oidc_subject', true ) ) ) {
            return; // Kein OIDC-Nutzer
        }

        $result = ( new OIDC_Tokens() )->get_valid_access_token( $user_id );

        if ( is_wp_error( $result ) ) {
            OIDC_Log::write( $user_id, false, 'Session beendet: ' . $result->get_error_message() );
            wp_logout();
            wp_safe_redirect( add_query_arg(
                'oidc_error',
                rawurlencode( __( 'Sitzung abgelaufen. Bitte erneut anmelden.', 'jrtools-openid-connect' ) ),
                wp_login_url()
            ) );
            exit;
        }
    }

    // -------------------------------------------------------------------------
    // Redirect zum Provider
    // -------------------------------------------------------------------------

    public function initiate_login( $extra_params = array() ) {
        $client_id = get_option( 'jrtools_oidc_client_id', '' );
        $auth_ep   = get_option( 'jrtools_oidc_authorization_endpoint', '' );
        $scopes    = get_option( 'jrtools_oidc_scopes', 'openid email profile' );

        if ( empty( $client_id ) || empty( $auth_ep ) ) {
            wp_die( esc_html__( 'OIDC ist nicht vollständig konfiguriert. Bitte prüfe die Einstellungen.', 'jrtools-openid-connect' ) );
        }

        /*
         * Filter: jrtools_oidc_scopes
         *
         * Allows modifying the OAuth scopes requested from the OIDC provider.
         *
         * @param string $scopes Space-separated list of scopes (e.g. "openid email profile").
         */
        $scopes = apply_filters( 'jrtools_oidc_scopes', $scopes );

        // State – CSRF-Schutz
        $state = $this->token_exchange->generate_random_string();
        set_transient( 'jrtools_oidc_state_' . $state, 1, 5 * MINUTE_IN_SECONDS );

        // Nonce – Replay-Schutz im ID-Token
        $nonce = $this->token_exchange->generate_random_string();
        set_transient( 'jrtools_oidc_nonce_' . $nonce, 1, 5 * MINUTE_IN_SECONDS );

        // PKCE – nur wenn Provider S256 unterstützt
        $code_verifier  = '';
        $code_challenge = '';
        if ( get_option( 'jrtools_oidc_pkce_supported', '1' ) === '1' ) {
            $code_verifier  = $this->token_exchange->generate_code_verifier();
            $code_challenge = $this->token_exchange->generate_code_challenge( $code_verifier );
            set_transient( 'jrtools_oidc_pkce_' . $state, $code_verifier, 5 * MINUTE_IN_SECONDS );
        }

        $params = array(
            'response_type' => 'code',
            'client_id'     => $client_id,
            'redirect_uri'  => $this->token_exchange->get_redirect_uri(),
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

        /*
         * Filter: jrtools_oidc_auth_params
         *
         * Allows adding or modifying parameters sent to the OIDC authorization endpoint.
         * Use this to add custom parameters such as ui_locales, acr_values, or login_hint.
         *
         * @param array $params Query parameters for the authorization request.
         */
        $params = apply_filters( 'jrtools_oidc_auth_params', $params );

        wp_redirect( $auth_ep . '?' . http_build_query( $params ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Externes Redirect zum OIDC Authorization Endpoint (gespeicherte Admin-Option, kein User-Input).
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
                __( 'Fehler vom Provider (Authorization): %1$s%2$s', 'jrtools-openid-connect' ),
                $error_code,
                $error_desc ? ' – ' . $error_desc : ''
            );
            $this->user_manager->login_error( $msg );
            return;
        }

        $code  = isset( $_GET['code'] )  ? sanitize_text_field( wp_unslash( $_GET['code'] ) )  : '';  // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        if ( empty( $code ) || empty( $state ) ) {
            $this->user_manager->login_error( __( 'Fehlende Parameter im Callback.', 'jrtools-openid-connect' ) );
            return;
        }

        // State validieren (CSRF-Schutz)
        $state_transient = get_transient( 'jrtools_oidc_state_' . $state );
        delete_transient( 'jrtools_oidc_state_' . $state );

        if ( false === $state_transient ) {
            $this->user_manager->login_error( __( 'Ungültiger oder abgelaufener State-Parameter.', 'jrtools-openid-connect' ) );
            return;
        }

        // PKCE code_verifier laden und direkt löschen
        $code_verifier = get_transient( 'jrtools_oidc_pkce_' . $state );
        delete_transient( 'jrtools_oidc_pkce_' . $state );

        // Token Exchange
        $tokens = $this->token_exchange->exchange_code_for_tokens( $code, $code_verifier ? $code_verifier : '' );
        if ( is_wp_error( $tokens ) ) {
            $this->user_manager->login_error( $tokens->get_error_message() );
            return;
        }

        // ID-Token validieren
        $id_token = isset( $tokens['id_token'] ) ? $tokens['id_token'] : '';
        $claims   = $this->validate_id_token( $id_token );
        if ( is_wp_error( $claims ) ) {
            $this->user_manager->login_error( $claims->get_error_message() );
            return;
        }

        // Nonce validieren
        $token_nonce     = isset( $claims['nonce'] ) ? $claims['nonce'] : '';
        $nonce_transient = get_transient( 'jrtools_oidc_nonce_' . $token_nonce );
        delete_transient( 'jrtools_oidc_nonce_' . $token_nonce );

        if ( empty( $token_nonce ) || false === $nonce_transient ) {
            $this->user_manager->login_error( __( 'Ungültige oder fehlende Nonce im ID-Token.', 'jrtools-openid-connect' ) );
            return;
        }

        // Userinfo abrufen
        $access_token = isset( $tokens['access_token'] ) ? $tokens['access_token'] : '';
        $userinfo     = $this->fetch_userinfo( $access_token );
        if ( is_wp_error( $userinfo ) ) {
            $this->user_manager->login_error( $userinfo->get_error_message() );
            return;
        }

        // F11: Account-Linking prüfen (eingeloggter User verknüpft OIDC-Konto)
        if ( is_user_logged_in() ) {
            $current_user_id = get_current_user_id();
            $link_pending    = get_transient( 'jrtools_oidc_link_pending_' . $current_user_id );
            if ( $link_pending ) {
                delete_transient( 'jrtools_oidc_link_pending_' . $current_user_id );
                $sub = sanitize_text_field( isset( $userinfo['sub'] ) ? $userinfo['sub'] : '' );

                // SE-1: Subject-Overwrite verhindern – gespeicherten sub mit neuem vergleichen.
                $stored_sub = '';
                if ( is_array( $link_pending ) && ! empty( $link_pending['sub'] ) ) {
                    $stored_sub = $link_pending['sub'];
                }
                if ( ! empty( $stored_sub ) && $stored_sub !== $sub ) {
                    $this->user_manager->login_error( __( 'Subject-Mismatch: Der OIDC-Anbieter hat ein anderes Konto zurückgegeben.', 'jrtools-openid-connect' ) );
                    return;
                }

                if ( $sub ) {
                    update_user_meta( $current_user_id, '_jrtools_oidc_subject', $sub );
                }

                /*
                 * Action: jrtools_oidc_account_linked
                 *
                 * Fires after an existing WordPress account has been linked to an OIDC provider.
                 *
                 * @param int    $user_id WordPress user ID.
                 * @param string $sub     The OIDC subject identifier.
                 */
                do_action( 'jrtools_oidc_account_linked', $current_user_id, $sub );

                wp_safe_redirect( get_edit_profile_url( $current_user_id ) . '#oidc-linked' );
                exit;
            }
        }

        // Benutzer einloggen oder anlegen
        $this->user_manager->authenticate_user( $userinfo, $tokens );
    }

    // -------------------------------------------------------------------------
    // ID-Token validieren (Claims + RS256-Signaturprüfung via openssl)
    // -------------------------------------------------------------------------

    private function validate_id_token( $id_token ) {
        if ( empty( $id_token ) ) {
            return new WP_Error( 'no_id_token', __( 'Kein ID-Token empfangen.', 'jrtools-openid-connect' ) );
        }

        $parsed = OIDC_JWT_Helper::parse_jwt( $id_token );
        if ( is_wp_error( $parsed ) ) {
            return $parsed;
        }

        list( $header, $claims, $parts ) = $parsed;

        $now = time();

        // exp – Ablaufzeit
        if ( ! isset( $claims['exp'] ) || (int) $claims['exp'] < ( $now - 60 ) ) {
            return new WP_Error( 'token_expired', __( 'ID-Token ist abgelaufen.', 'jrtools-openid-connect' ) );
        }

        // iat – nicht in der Zukunft (5 Minuten Toleranz für Clock-Skew)
        if ( ! isset( $claims['iat'] ) || (int) $claims['iat'] > ( $now + 5 * MINUTE_IN_SECONDS ) ) {
            return new WP_Error( 'token_iat_invalid', __( 'ID-Token iat ist ungültig.', 'jrtools-openid-connect' ) );
        }

        // iss – Issuer prüfen
        $expected_issuer = get_option( 'jrtools_oidc_issuer', '' );
        if ( ! empty( $expected_issuer ) ) {
            $token_iss = isset( $claims['iss'] ) ? $claims['iss'] : '';
            if ( $token_iss !== $expected_issuer ) {
                return new WP_Error( 'token_iss_mismatch', __( 'ID-Token Issuer stimmt nicht überein.', 'jrtools-openid-connect' ) );
            }
        }

        // aud – Audience prüfen
        $client_id = get_option( 'jrtools_oidc_client_id', '' );
        if ( ! empty( $client_id ) ) {
            $aud      = isset( $claims['aud'] ) ? $claims['aud'] : array();
            $aud_list = is_array( $aud ) ? $aud : array( $aud );
            if ( ! in_array( $client_id, $aud_list, true ) ) {
                return new WP_Error( 'token_aud_mismatch', __( 'ID-Token Audience stimmt nicht überein.', 'jrtools-openid-connect' ) );
            }
        }

        // RS256-Signaturprüfung
        $jwks_uri = get_option( 'jrtools_oidc_jwks_uri', '' );
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
        $userinfo_ep = get_option( 'jrtools_oidc_userinfo_endpoint', '' );

        if ( empty( $userinfo_ep ) ) {
            return new WP_Error( 'no_userinfo_endpoint', __( 'Userinfo-Endpoint nicht konfiguriert.', 'jrtools-openid-connect' ) );
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

        $response_code = wp_remote_retrieve_response_code( $response );
        if ( 200 !== (int) $response_code ) {
            return new WP_Error(
                'userinfo_request_failed',
                /* translators: %d: HTTP-Statuscode des Userinfo-Endpoints */
                sprintf( __( 'Userinfo endpoint returned HTTP %d.', 'jrtools-openid-connect' ), $response_code )
            );
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! is_array( $data ) || empty( $data['email'] ) ) {
            return new WP_Error(
                'userinfo_no_email',
                __( 'Der Provider hat keine E-Mail-Adresse zurückgegeben. Bitte prüfe die konfigurierten Scopes.', 'jrtools-openid-connect' )
            );
        }

        return $data;
    }
}
