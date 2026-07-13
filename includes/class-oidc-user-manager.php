<?php
/**
 * OIDC Client – Benutzerverwaltung (Login/Erstellung)
 *
 * Extrahiert aus OIDC_Auth (SA-1 Refactoring).
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_User_Manager {

    // -------------------------------------------------------------------------
    // Benutzer einloggen oder anlegen
    // -------------------------------------------------------------------------

    /**
     * Benutzer anhand der Userinfo-Daten einloggen oder neu anlegen.
     *
     * @param array $userinfo Userinfo-Daten vom Provider.
     * @param array $tokens   Token-Daten (id_token, access_token, refresh_token).
     */
    public function authenticate_user( $userinfo, $tokens = array() ) {
        // F5: Active-Claim prüfen (Konto deaktiviert?)
        $active_claim = get_option( 'jrtools_oidc_active_claim', '' );
        if ( ! empty( $active_claim ) && isset( $userinfo[ $active_claim ] ) ) {
            $v = $userinfo[ $active_claim ];
            if ( false === $v || 0 === $v || 'false' === $v || '0' === $v ) {
                OIDC_Log::write( 0, false, __( 'Konto deaktiviert (Active-Claim).', 'jrtools-openid-connect' ) );
                $this->login_error( __( 'Dein Konto ist deaktiviert. Bitte wende dich an den Administrator.', 'jrtools-openid-connect' ) );
                return;
            }
        }

        $email = sanitize_email( isset( $userinfo['email'] ) ? $userinfo['email'] : '' );

        if ( ! is_email( $email ) ) {
            $this->login_error( __( 'Ungültige E-Mail-Adresse vom Provider.', 'jrtools-openid-connect' ) );
            return;
        }

        // SE-2: sub-Claim ist mandatory – kein Email-Fallback (Account-Takeover-Schutz).
        $sub = sanitize_text_field( isset( $userinfo['sub'] ) ? $userinfo['sub'] : '' );

        if ( empty( $sub ) ) {
            $this->login_error( __( 'Fehlender sub-Claim im Token. Authentifizierung nicht möglich.', 'jrtools-openid-connect' ) );
            return;
        }

        /*
         * Filter: oidc_userinfo
         *
         * Allows modification of the userinfo data returned by the provider
         * before it is used to create or update the WordPress user.
         *
         * @param array $userinfo Userinfo claims from the provider.
         */
        $userinfo = apply_filters( 'jrtools_oidc_userinfo', $userinfo );

        // Benutzer ausschließlich via Subject-Claim suchen.
        $users = get_users( array(
            'meta_key'   => '_jrtools_oidc_subject', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
            'meta_value' => $sub,            // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
            'number'     => 1,
        ) );
        $user = ! empty( $users ) ? $users[0] : false;

        if ( ! $user ) {
            if ( ! get_option( 'jrtools_oidc_create_user', false ) ) {
                $this->login_error( __( 'Kein lokales Konto für diese E-Mail-Adresse vorhanden. Bitte wende dich an den Administrator.', 'jrtools-openid-connect' ) );
                return;
            }

            // Benutzernamen aus preferred_username, nickname oder E-Mail ableiten
            if ( isset( $userinfo['preferred_username'] ) ) {
                $raw_username = $userinfo['preferred_username'];
            } elseif ( isset( $userinfo['nickname'] ) ) {
                $raw_username = $userinfo['nickname'];
            } else {
                $raw_username = strstr( $email, '@', true );
            }
            $username = sanitize_user( $raw_username, true );

            // Eindeutigkeit sicherstellen
            if ( username_exists( $username ) ) {
                $username = $username . '_' . wp_generate_password( 5, false );
            }

            $new_user_data = array(
                'user_login'    => $username,
                'user_email'    => $email,
                'user_pass'     => wp_generate_password( 32, true, true ),
                'first_name'    => isset( $userinfo['given_name'] )  ? sanitize_text_field( $userinfo['given_name'] )  : '',
                'last_name'     => isset( $userinfo['family_name'] ) ? sanitize_text_field( $userinfo['family_name'] ) : '',
                'display_name'  => isset( $userinfo['name'] )        ? sanitize_text_field( $userinfo['name'] )        : '',
                'user_url'      => isset( $userinfo['website'] )     ? esc_url_raw( $userinfo['website'] )             : '',
                'user_nicename' => isset( $userinfo['nickname'] )    ? sanitize_user( $userinfo['nickname'] )          : '',
                'role'          => get_option( 'jrtools_oidc_default_role', 'subscriber' ),
            );

            /*
             * Filter: oidc_new_user_data
             *
             * Allows modification of the user data array before a new WordPress
             * user is created via wp_insert_user().
             *
             * @param array $new_user_data User data passed to wp_insert_user().
             * @param array $userinfo      Userinfo claims from the provider.
             */
            $new_user_data = apply_filters( 'jrtools_oidc_new_user_data', $new_user_data, $userinfo );

            /*
             * Filter: oidc_user_role
             *
             * Allows overriding the role assigned to a newly created user.
             * Runs after oidc_new_user_data, so it takes precedence over the
             * role set in that filter.
             *
             * @param string $role     The WordPress role slug.
             * @param array  $userinfo Userinfo claims from the provider.
             */
            $new_user_data['role'] = apply_filters( 'jrtools_oidc_user_role', $new_user_data['role'], $userinfo );

            $user_id = wp_insert_user( $new_user_data );

            if ( is_wp_error( $user_id ) ) {
                $this->login_error( $user_id->get_error_message() );
                return;
            }

            $user = get_user_by( 'id', $user_id );

            // Subject beim neuen User speichern (sub ist hier garantiert vorhanden).
            update_user_meta( $user->ID, '_jrtools_oidc_subject', $sub );

            /*
             * Action: oidc_user_created
             *
             * Fires after a new WordPress user has been created via OIDC login.
             *
             * @param int   $user_id  ID of the newly created user.
             * @param array $userinfo Userinfo claims from the provider.
             */
            do_action( 'jrtools_oidc_user_created', $user->ID, $userinfo );
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
            if ( isset( $userinfo['nickname'] ) ) {
                $update_data['user_nicename'] = sanitize_user( $userinfo['nickname'] );
            }

            if ( count( $update_data ) > 1 ) {
                wp_update_user( $update_data );

                /*
                 * Action: oidc_user_updated
                 *
                 * Fires after an existing WordPress user has been updated with
                 * current data from the OIDC provider.
                 *
                 * @param int   $user_id  ID of the updated user.
                 * @param array $userinfo Userinfo claims from the provider.
                 */
                do_action( 'jrtools_oidc_user_updated', $user->ID, $userinfo );
            }
        }

        // Standard-Claims in wp_usermeta synchronisieren (nur wenn im Token vorhanden)
        $this->sync_user_meta( $user->ID, $userinfo );

        // F6: Avatar-URL speichern
        if ( get_option( 'jrtools_oidc_sync_avatar', '' ) === '1' && ! empty( $userinfo['picture'] ) ) {
            update_user_meta( $user->ID, '_jrtools_oidc_avatar_url', esc_url_raw( $userinfo['picture'] ) );
        }

        // F4: Rollen-Mapping anwenden
        ( new OIDC_Roles() )->apply_role_mapping( $user->ID, $userinfo );

        // F2: Tokens speichern (id_token immer, access/refresh nur wenn Refresh aktiv)
        ( new OIDC_Tokens() )->store_tokens( $user->ID, $tokens );

        // Einloggen
        $remember = get_option( 'jrtools_oidc_remember_me', 'never' ) === 'always';
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, $remember );
        do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core-Hook.

        // F7: Erfolgreichen Login loggen
        OIDC_Log::write( $user->ID, true, __( 'OIDC Login erfolgreich.', 'jrtools-openid-connect' ) );

        /*
         * Action: oidc_login_success
         *
         * Fires after a successful OIDC login, before the redirect.
         *
         * @param int   $user_id  ID of the logged-in user.
         * @param array $userinfo Userinfo claims from the provider.
         */
        do_action( 'jrtools_oidc_login_success', $user->ID, $userinfo );

        /*
         * Filter: oidc_login_redirect
         *
         * Allows changing the URL the user is redirected to after a successful login.
         *
         * @param string  $redirect_to Default redirect URL (result of login_redirect filter).
         * @param WP_User $user        The logged-in user object.
         */
        $redirect_to = apply_filters( 'login_redirect', admin_url(), '', $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core-Filter. NOSONAR -- apply_filters() accepts variadic args; extra args are passed to filter callbacks.
        $redirect_to = apply_filters( 'jrtools_oidc_login_redirect', $redirect_to, $user );
        wp_safe_redirect( $redirect_to );
        exit;
    }

    /**
     * Synchronisiert OIDC Standard-Claims (§5.1) in wp_usermeta.
     * Nur Claims die im Token vorhanden sind werden geschrieben.
     *
     * @param int   $user_id  WordPress User-ID.
     * @param array $userinfo Userinfo-Daten vom Provider.
     */
    private function sync_user_meta( $user_id, $userinfo ) {
        // Native WordPress usermeta-Keys (WP kennt diese nativ)
        $wp_meta_claims = array(
            'nickname' => 'sanitize_text_field',
            'locale'   => 'sanitize_text_field',
        );

        foreach ( $wp_meta_claims as $claim => $sanitizer ) {
            if ( isset( $userinfo[ $claim ] ) ) {
                update_user_meta( $user_id, $claim, $sanitizer( $userinfo[ $claim ] ) );
            }
        }

        // OIDC-spezifische usermeta-Keys (Präfix _oidc_)
        $oidc_meta_claims = array(
            'middle_name'            => 'sanitize_text_field',
            'profile'                => 'esc_url_raw',
            'gender'                 => 'sanitize_text_field',
            'birthdate'              => 'sanitize_text_field',
            'zoneinfo'               => 'sanitize_text_field',
            'phone_number'           => 'sanitize_text_field',
            'phone_number_verified'  => null, // Boolean
            'email_verified'         => null, // Boolean
            'updated_at'             => null, // Integer (Unix timestamp)
        );

        foreach ( $oidc_meta_claims as $claim => $sanitizer ) {
            if ( ! isset( $userinfo[ $claim ] ) ) {
                continue;
            }
            $value = $userinfo[ $claim ];
            if ( null !== $sanitizer ) {
                if ( ! is_string( $value ) ) {
                    continue;
                }
                $value = $sanitizer( $value );
            } elseif ( is_bool( $value ) || in_array( $value, array( 'true', 'false', '0', '1', 0, 1 ), true ) ) {
                $value = (bool) filter_var( $value, FILTER_VALIDATE_BOOLEAN );
            } else {
                $value = (int) $value;
            }
            update_user_meta( $user_id, '_jrtools_oidc_' . $claim, $value );
        }

        // address ist ein JSON-Objekt (§5.1.1) – als JSON-String speichern
        if ( isset( $userinfo['address'] ) && is_array( $userinfo['address'] ) ) {
            update_user_meta( $user_id, '_jrtools_oidc_address', wp_json_encode( $userinfo['address'] ) );
        }
    }

    // -------------------------------------------------------------------------
    // Login-Fehler behandeln
    // -------------------------------------------------------------------------

    /**
     * Login-Fehler loggen und zur Login-Seite weiterleiten.
     *
     * @param string $message Fehlermeldung.
     * @param int    $user_id Benutzer-ID (0 wenn unbekannt).
     */
    public function login_error( $message, $user_id = 0 ) {
        OIDC_Log::write( $user_id, false, $message );

        /*
         * Action: oidc_login_failed
         *
         * Fires when an OIDC login attempt fails, before the redirect.
         *
         * @param string $message Error message.
         * @param int    $user_id WordPress user ID (0 if unknown).
         */
        do_action( 'jrtools_oidc_login_failed', $message, $user_id );

        wp_safe_redirect( add_query_arg(
            'oidc_error',
            rawurlencode( $message ),
            wp_login_url()
        ) );
        exit;
    }
}
