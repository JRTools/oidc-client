<?php
/**
 * OIDC Client – Frontchannel- und Backchannel-Logout
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Logout {

    public function __construct() {
        add_action( 'wp_logout',      array( $this, 'handle_frontchannel_logout' ) );
        add_action( 'rest_api_init',  array( $this, 'register_backchannel_endpoint' ) );
    }

    // -------------------------------------------------------------------------
    // F1: Frontchannel-Logout – Weiterleitung zum End-Session-Endpoint
    // -------------------------------------------------------------------------

    public function handle_frontchannel_logout( $user_id ) {
        $end_session_ep = get_option( 'oidc_end_session_endpoint', '' );

        if ( empty( $end_session_ep ) ) {
            return;
        }

        $id_token = ( new OIDC_Tokens() )->get_id_token( $user_id );

        // Tokens nach Logout löschen
        ( new OIDC_Tokens() )->clear_all_tokens( $user_id );

        $params = array(
            'post_logout_redirect_uri' => wp_login_url(),
        );

        if ( ! empty( $id_token ) ) {
            $params['id_token_hint'] = $id_token;
        }

        wp_safe_redirect( $end_session_ep . '?' . http_build_query( $params ) );
        exit;
    }

    // -------------------------------------------------------------------------
    // F3: Backchannel-Logout – REST-Endpoint registrieren
    // -------------------------------------------------------------------------

    public function register_backchannel_endpoint() {
        register_rest_route( 'oidc-client/v1', '/backchannel-logout', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_backchannel_logout' ),
            'permission_callback' => '__return_true',
        ) );
    }

    /**
     * Backchannel-Logout-Request verarbeiten.
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function handle_backchannel_logout( WP_REST_Request $request ) {
        $logout_token = $request->get_param( 'logout_token' );

        if ( empty( $logout_token ) ) {
            return new WP_REST_Response( array( 'error' => 'missing_logout_token' ), 400 );
        }

        $claims = $this->validate_logout_token( $logout_token );

        if ( is_wp_error( $claims ) ) {
            return new WP_REST_Response( array(
			'error' => $claims->get_error_code(),
			'error_description' => $claims->get_error_message(),
			), 400 );
        }

        // Benutzer über sub-Claim suchen
        $sub  = isset( $claims['sub'] ) ? sanitize_text_field( $claims['sub'] ) : '';
        $sid  = isset( $claims['sid'] ) ? sanitize_text_field( $claims['sid'] ) : '';
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

        if ( ! $user ) {
            // Kein Benutzer gefunden – trotzdem 200 zurückgeben (idempotent)
            return new WP_REST_Response( null, 200 );
        }

        // Alle Sessions dieses Benutzers beenden
        WP_Session_Tokens::get_instance( $user->ID )->destroy_all();

        // Tokens löschen
        ( new OIDC_Tokens() )->clear_all_tokens( $user->ID );

        OIDC_Log::write( $user->ID, true, 'Backchannel-Logout durchgeführt' . ( $sid ? ' (sid: ' . $sid . ')' : '' ) );

        return new WP_REST_Response( null, 200 );
    }

    // -------------------------------------------------------------------------
    // Logout-Token validieren
    // -------------------------------------------------------------------------

    /**
     * @param string $jwt
     * @return array|WP_Error Claims-Array bei Erfolg
     */
    private function validate_logout_token( $jwt ) {
        $parsed = OIDC_JWT_Helper::parse_jwt( $jwt );
        if ( is_wp_error( $parsed ) ) {
            return $parsed;
        }

        list( $header, $claims, $parts ) = $parsed;

        // Signatur prüfen
        $jwks_uri = get_option( 'oidc_jwks_uri', '' );
        if ( ! empty( $jwks_uri ) ) {
            $sig_result = OIDC_JWT_Helper::verify_signature( $parts, $header, $jwks_uri );
            if ( is_wp_error( $sig_result ) ) {
                return $sig_result;
            }
        }

        $now = time();

        // iss prüfen
        $expected_issuer = get_option( 'oidc_issuer', '' );
        if ( ! empty( $expected_issuer ) ) {
            if ( ! isset( $claims['iss'] ) || $claims['iss'] !== $expected_issuer ) {
                return new WP_Error( 'logout_token_iss', 'Logout-Token Issuer ungültig.' );
            }
        }

        // aud prüfen
        $client_id = get_option( 'oidc_client_id', '' );
        if ( ! empty( $client_id ) ) {
            $aud      = isset( $claims['aud'] ) ? $claims['aud'] : array();
            $aud_list = is_array( $aud ) ? $aud : array( $aud );
            if ( ! in_array( $client_id, $aud_list, true ) ) {
                return new WP_Error( 'logout_token_aud', 'Logout-Token Audience ungültig.' );
            }
        }

        // iat prüfen (nicht zu alt, nicht in der Zukunft)
        if ( ! isset( $claims['iat'] ) || (int) $claims['iat'] > ( $now + 5 * MINUTE_IN_SECONDS ) ) {
            return new WP_Error( 'logout_token_iat', 'Logout-Token iat ungültig.' );
        }

        // nonce darf NICHT vorhanden sein (verhindert ID-Token-Wiederverwendung)
        if ( isset( $claims['nonce'] ) ) {
            return new WP_Error( 'logout_token_nonce', 'Logout-Token enthält unerlaubtes nonce-Claim.' );
        }

        // events-Claim prüfen (muss Backchannel-Logout-Event enthalten)
        if ( ! isset( $claims['events'] ) || ! is_array( $claims['events'] )
            || ! array_key_exists( 'http://schemas.openid.net/event/backchannel-logout', $claims['events'] ) ) {
            return new WP_Error( 'logout_token_events', 'Logout-Token events-Claim ungültig.' );
        }

        // sub oder sid muss vorhanden sein
        if ( empty( $claims['sub'] ) && empty( $claims['sid'] ) ) {
            return new WP_Error( 'logout_token_subject', 'Logout-Token enthält weder sub noch sid.' );
        }

        // JTI Replay-Schutz
        if ( isset( $claims['jti'] ) ) {
            $jti     = sanitize_text_field( $claims['jti'] );
            $jti_key = 'oidc_jti_' . md5( $jti );
            if ( false !== get_transient( $jti_key ) ) {
                return new WP_Error( 'logout_token_replay', 'Logout-Token wurde bereits verwendet (Replay).' );
            }
            set_transient( $jti_key, 1, DAY_IN_SECONDS );
        }

        return $claims;
    }
}
