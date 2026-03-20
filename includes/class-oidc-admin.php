<?php
/**
 * OIDC Client – Admin-Einstellungsseite und Discovery-AJAX
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Admin {

    public function __construct() {
        add_action( 'admin_menu',            array( $this, 'add_settings_page' ) );
        add_action( 'admin_init',            array( $this, 'register_settings' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
        add_action( 'wp_ajax_oidc_fetch_discovery', array( $this, 'ajax_fetch_discovery' ) );
        add_action( 'wp_ajax_oidc_clear_cache',     array( $this, 'ajax_clear_cache' ) );
    }

    // -------------------------------------------------------------------------
    // Admin-Menü
    // -------------------------------------------------------------------------

    public function add_settings_page() {
        add_options_page(
            __( 'OIDC Client', 'oidc-client' ),
            __( 'OIDC Client', 'oidc-client' ),
            'manage_options',
            'oidc-client',
            array( $this, 'render_settings_page' )
        );
    }

    // -------------------------------------------------------------------------
    // Settings API registrieren
    // -------------------------------------------------------------------------

    public function register_settings() {
        $options = array(
            'oidc_discovery_url'          => 'esc_url_raw',
            'oidc_provider_name'          => 'sanitize_text_field',
            'oidc_issuer'                 => 'sanitize_text_field',
            'oidc_authorization_endpoint' => 'esc_url_raw',
            'oidc_token_endpoint'         => 'esc_url_raw',
            'oidc_userinfo_endpoint'      => 'esc_url_raw',
            'oidc_jwks_uri'               => 'esc_url_raw',
            'oidc_end_session_endpoint'   => 'esc_url_raw',
            'oidc_pkce_supported'         => array( $this, 'sanitize_checkbox' ),
            'oidc_client_id'              => 'sanitize_text_field',
            'oidc_client_secret'          => array( $this, 'sanitize_secret' ),
            'oidc_scopes'                 => 'sanitize_text_field',
            'oidc_token_auth_method'      => 'sanitize_text_field',
            'oidc_debug_mode'             => array( $this, 'sanitize_checkbox' ),
            'oidc_create_user'            => array( $this, 'sanitize_checkbox' ),
            'oidc_default_role'           => 'sanitize_text_field',
            // Erweiterte Optionen
            'oidc_enable_refresh'         => array( $this, 'sanitize_checkbox' ),
            'oidc_active_claim'           => 'sanitize_text_field',
            'oidc_sync_avatar'            => array( $this, 'sanitize_checkbox' ),
            'oidc_hide_wp_login'          => array( $this, 'sanitize_checkbox' ),
            'oidc_auto_login'             => array( $this, 'sanitize_checkbox' ),
            'oidc_button_icon_url'        => 'esc_url_raw',
            'oidc_token_encryption'       => array( $this, 'sanitize_checkbox' ),
            'oidc_lock_email'             => array( $this, 'sanitize_checkbox' ),
            'oidc_lock_password'          => array( $this, 'sanitize_checkbox' ),
            'oidc_session_management'     => array( $this, 'sanitize_checkbox' ),
            'oidc_remember_me'            => 'sanitize_text_field',
            // Rollen-Mapping
            'oidc_role_claim'             => 'sanitize_text_field',
            'oidc_role_mapping'           => array( $this, 'sanitize_role_mapping' ),
        );

        foreach ( $options as $option_name => $sanitize_callback ) {
            register_setting(
                'oidc_client_settings',
                $option_name,
                array( 'sanitize_callback' => $sanitize_callback )
            );
        }

        // ----- Abschnitt 1: Provider -----
        add_settings_section(
            'oidc_section_provider',
            __( 'Provider', 'oidc-client' ),
            array( $this, 'section_provider_description' ),
            'oidc-client'
        );

        add_settings_field(
            'oidc_discovery_url',
            __( 'Discovery URL', 'oidc-client' ),
            array( $this, 'field_discovery_url' ),
            'oidc-client',
            'oidc_section_provider'
        );
        add_settings_field(
            'oidc_provider_name',
            __( 'Provider-Name', 'oidc-client' ),
            array( $this, 'field_text' ),
            'oidc-client',
            'oidc_section_provider',
            array(
                'option'      => 'oidc_provider_name',
                'description' => __( 'Wird im Login-Button angezeigt: „Login mit …"', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_issuer',
            __( 'Issuer', 'oidc-client' ),
            array( $this, 'field_text' ),
            'oidc-client',
            'oidc_section_provider',
            array(
                'option'      => 'oidc_issuer',
                'description' => __( 'Wird automatisch aus der Discovery-URL befüllt.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_authorization_endpoint',
            __( 'Authorization Endpoint', 'oidc-client' ),
            array( $this, 'field_url' ),
            'oidc-client',
            'oidc_section_provider',
            array( 'option' => 'oidc_authorization_endpoint' )
        );
        add_settings_field(
            'oidc_token_endpoint',
            __( 'Token Endpoint', 'oidc-client' ),
            array( $this, 'field_url' ),
            'oidc-client',
            'oidc_section_provider',
            array( 'option' => 'oidc_token_endpoint' )
        );
        add_settings_field(
            'oidc_userinfo_endpoint',
            __( 'Userinfo Endpoint', 'oidc-client' ),
            array( $this, 'field_url' ),
            'oidc-client',
            'oidc_section_provider',
            array( 'option' => 'oidc_userinfo_endpoint' )
        );
        add_settings_field(
            'oidc_jwks_uri',
            __( 'JWKS URI', 'oidc-client' ),
            array( $this, 'field_url' ),
            'oidc-client',
            'oidc_section_provider',
            array( 'option' => 'oidc_jwks_uri' )
        );
        add_settings_field(
            'oidc_pkce_supported',
            __( 'PKCE (S256)', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_provider',
            array(
                'option'      => 'oidc_pkce_supported',
                'description' => __( 'PKCE verwenden (empfohlen). Deaktivieren wenn der Provider kein PKCE unterstützt und „invalid_client"-Fehler auftreten.', 'oidc-client' ),
            )
        );

        // ----- Abschnitt 2: Client -----
        add_settings_section(
            'oidc_section_client',
            __( 'Client', 'oidc-client' ),
            null,
            'oidc-client'
        );

        add_settings_field(
            'oidc_client_id',
            __( 'Client ID', 'oidc-client' ),
            array( $this, 'field_text' ),
            'oidc-client',
            'oidc_section_client',
            array( 'option' => 'oidc_client_id' )
        );
        add_settings_field(
            'oidc_client_secret',
            __( 'Client Secret', 'oidc-client' ),
            array( $this, 'field_password' ),
            'oidc-client',
            'oidc_section_client',
            array( 'option' => 'oidc_client_secret' )
        );
        add_settings_field(
            'oidc_scopes',
            __( 'Scopes', 'oidc-client' ),
            array( $this, 'field_text' ),
            'oidc-client',
            'oidc_section_client',
            array(
                'option'      => 'oidc_scopes',
                'default'     => 'openid email profile',
                'description' => __( 'Leerzeichen-getrennte Liste, z. B. „openid email profile"', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_redirect_uri',
            __( 'Redirect URI', 'oidc-client' ),
            array( $this, 'field_redirect_uri' ),
            'oidc-client',
            'oidc_section_client'
        );
        add_settings_field(
            'oidc_token_auth_method',
            __( 'Token-Endpoint Authentifizierung', 'oidc-client' ),
            array( $this, 'field_token_auth_method' ),
            'oidc-client',
            'oidc_section_client'
        );

        // ----- Abschnitt 3: Benutzerverwaltung -----
        add_settings_section(
            'oidc_section_users',
            __( 'Benutzerverwaltung', 'oidc-client' ),
            null,
            'oidc-client'
        );

        add_settings_field(
            'oidc_create_user',
            __( 'Benutzer automatisch anlegen', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_users',
            array(
                'option'      => 'oidc_create_user',
                'description' => __( 'Falls kein lokales Konto existiert, wird automatisch eines erstellt.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_default_role',
            __( 'Standard-Rolle für neue Benutzer', 'oidc-client' ),
            array( $this, 'field_roles_dropdown' ),
            'oidc-client',
            'oidc_section_users'
        );
        add_settings_field(
            'oidc_debug_mode',
            __( 'Debug-Modus', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_users',
            array(
                'option'      => 'oidc_debug_mode',
                'description' => __( 'Zeigt bei Fehlern die vollständige Provider-Antwort und gesendete Parameter an. Nur zur Fehlersuche aktivieren, danach wieder deaktivieren.', 'oidc-client' ),
            )
        );

        // ----- Abschnitt 4: Erweiterte Optionen -----
        add_settings_section(
            'oidc_section_advanced',
            __( 'Erweiterte Optionen', 'oidc-client' ),
            null,
            'oidc-client'
        );

        add_settings_field(
            'oidc_end_session_endpoint',
            __( 'End-Session Endpoint', 'oidc-client' ),
            array( $this, 'field_url' ),
            'oidc-client',
            'oidc_section_advanced',
            array( 'option' => 'oidc_end_session_endpoint' )
        );
        add_settings_field(
            'oidc_enable_refresh',
            __( 'Token-Refresh', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_enable_refresh',
                'description' => __( 'Refresh-Token und Access-Token nach Login speichern und automatisch erneuern.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_active_claim',
            __( 'Active-Claim', 'oidc-client' ),
            array( $this, 'field_text' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_active_claim',
                'description' => __( 'Claim-Name der Aktivierung (z. B. „active" oder „email_verified"). Login wird verweigert wenn false/0.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_sync_avatar',
            __( 'Profilbild synchronisieren', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_sync_avatar',
                'description' => __( 'Profilbild (picture-Claim) vom Provider übernehmen und als WordPress-Avatar anzeigen.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_hide_wp_login',
            __( 'WP-Login-Formular ausblenden', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_hide_wp_login',
                'description' => __( 'Standard-WordPress-Loginformular ausblenden. Mit ?showlogin=1 weiterhin erreichbar.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_auto_login',
            __( 'Auto-Login', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_auto_login',
                'description' => __( 'Automatisch zum OIDC-Provider weiterleiten wenn die Login-Seite aufgerufen wird.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_button_icon_url',
            __( 'Button-Icon URL', 'oidc-client' ),
            array( $this, 'field_url' ),
            'oidc-client',
            'oidc_section_advanced',
            array( 'option' => 'oidc_button_icon_url' )
        );
        add_settings_field(
            'oidc_token_encryption',
            __( 'Token-Verschlüsselung', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_token_encryption',
                'description' => __( 'Access-, Refresh- und ID-Token verschlüsselt in der Datenbank speichern (AES-256-CBC). Erfordert PHP OpenSSL.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_lock_email',
            __( 'E-Mail sperren', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_lock_email',
                'description' => __( 'OIDC-Nutzer können ihre E-Mail-Adresse nicht selbst ändern.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_lock_password',
            __( 'Passwort sperren', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_lock_password',
                'description' => __( 'OIDC-Nutzer können ihr Passwort nicht selbst ändern.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_session_management',
            __( 'Session-Management', 'oidc-client' ),
            array( $this, 'field_checkbox' ),
            'oidc-client',
            'oidc_section_advanced',
            array(
                'option'      => 'oidc_session_management',
                'description' => __( 'Session an Token-Ablauf binden: Bei jedem Request Token prüfen, Refresh versuchen, sonst ausloggen. Erfordert Token-Refresh.', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_remember_me',
            __( 'Angemeldet bleiben', 'oidc-client' ),
            array( $this, 'field_remember_me' ),
            'oidc-client',
            'oidc_section_advanced'
        );

        // ----- Abschnitt 5: Rollen-Mapping -----
        add_settings_section(
            'oidc_section_roles',
            __( 'Rollen-Mapping', 'oidc-client' ),
            array( $this, 'section_roles_description' ),
            'oidc-client'
        );

        add_settings_field(
            'oidc_role_claim',
            __( 'Rollen-Claim', 'oidc-client' ),
            array( $this, 'field_text' ),
            'oidc-client',
            'oidc_section_roles',
            array(
                'option'      => 'oidc_role_claim',
                'description' => __( 'Name des Claims der Rollen enthält, z. B. „roles" oder „groups".', 'oidc-client' ),
            )
        );
        add_settings_field(
            'oidc_role_mapping',
            __( 'Rollen-Mapping', 'oidc-client' ),
            array( $this, 'field_role_mapping' ),
            'oidc-client',
            'oidc_section_roles'
        );
    }

    // -------------------------------------------------------------------------
    // Seite rendern
    // -------------------------------------------------------------------------

    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Keine Berechtigung.', 'oidc-client' ) );
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'OIDC Client Einstellungen', 'oidc-client' ); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields( 'oidc_client_settings' );
                do_settings_sections( 'oidc-client' );
                submit_button();
                ?>
            </form>
            <p style="margin-top:0.5em;">
                <button id="oidc-clear-cache" class="button button-secondary">
                    <?php esc_html_e( 'JWKS-Cache leeren', 'oidc-client' ); ?>
                </button>
                <span id="oidc-cache-status" style="margin-left:8px;"></span>
            </p>
            <?php $this->render_provider_config_box(); ?>
        </div>
        <?php
    }

    private function render_provider_config_box() {
        $home_url       = home_url();
        $login_url      = wp_login_url();
        $redirect_uri   = add_query_arg( 'oidc_callback', '1', $login_url );
        $logout_uri     = add_query_arg( 'loggedout', 'true', $login_url );
        $backchannel_uri = rest_url( 'oidc-client/v1/backchannel-logout' );

        $params = array(
            __( 'Redirect URI (Callback URL)', 'oidc-client' )       => $redirect_uri,
            __( 'Post-logout Redirect URI', 'oidc-client' )          => $logout_uri,
            __( 'Backchannel Logout URI', 'oidc-client' )            => $backchannel_uri,
            __( 'Allowed Origin / CORS Origin', 'oidc-client' )      => $home_url,
            __( 'Allowed Web Origin', 'oidc-client' )                => $home_url,
            __( 'Initiate Login URI', 'oidc-client' )                => add_query_arg( 'oidc_login', '1', $login_url ),
        );
        ?>
        <div class="oidc-provider-config-box">
            <h2><?php esc_html_e( 'Konfiguration auf OIDC-Provider-Seite', 'oidc-client' ); ?></h2>
            <p class="description">
                <?php esc_html_e( 'Diese Werte musst du in der Client-Konfiguration deines OIDC-Providers (z. B. Keycloak, Entra ID, Google, easyVerein) hinterlegen.', 'oidc-client' ); ?>
            </p>
            <table class="oidc-provider-config-table widefat">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Parameter', 'oidc-client' ); ?></th>
                        <th><?php esc_html_e( 'Wert', 'oidc-client' ); ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $params as $label => $value ) : ?>
                    <tr>
                        <td><strong><?php echo esc_html( $label ); ?></strong></td>
                        <td>
                            <code class="oidc-config-value" id="oidc-val-<?php echo esc_attr( sanitize_title( $label ) ); ?>">
                                <?php echo esc_html( $value ); ?>
                            </code>
                        </td>
                        <td>
                            <button type="button"
                                    class="button button-small oidc-copy-btn"
                                    data-target="oidc-val-<?php echo esc_attr( sanitize_title( $label ) ); ?>"
                                    data-value="<?php echo esc_attr( $value ); ?>">
                                <?php esc_html_e( 'Kopieren', 'oidc-client' ); ?>
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <style>
            .oidc-provider-config-box {
                margin-top: 2em;
                padding: 16px 20px;
                background: #fff;
                border: 1px solid #c3c4c7;
                border-left: 4px solid #2271b1;
                box-shadow: 0 1px 1px rgba(0,0,0,.04);
            }
            .oidc-provider-config-box h2 {
                margin-top: 0;
            }
            .oidc-provider-config-table {
                margin-top: 12px;
                border-collapse: collapse;
            }
            .oidc-provider-config-table th,
            .oidc-provider-config-table td {
                padding: 8px 12px;
                vertical-align: middle;
            }
            .oidc-provider-config-table thead th {
                background: #f6f7f7;
                font-weight: 600;
            }
            .oidc-provider-config-table tbody tr:nth-child(even) {
                background: #f9f9f9;
            }
            .oidc-config-value {
                display: inline-block;
                word-break: break-all;
                font-size: 13px;
                background: transparent;
                padding: 0;
            }
            .oidc-copy-btn.copied {
                color: #00a32a;
            }
        </style>
        <script>
        (function () {
            document.querySelectorAll('.oidc-copy-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var value = this.getAttribute('data-value');
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(value);
                    } else {
                        var ta = document.createElement('textarea');
                        ta.value = value;
                        ta.style.position = 'fixed';
                        ta.style.opacity  = '0';
                        document.body.appendChild(ta);
                        ta.select();
                        document.execCommand('copy');
                        document.body.removeChild(ta);
                    }
                    this.textContent = '✓ Kopiert';
                    this.classList.add('copied');
                    var self = this;
                    setTimeout(function () {
                        self.textContent = '<?php echo esc_js( __( 'Kopieren', 'oidc-client' ) ); ?>';
                        self.classList.remove('copied');
                    }, 2000);
                });
            });
        }());
        </script>
        <?php
    }

    // -------------------------------------------------------------------------
    // Cache-Button + AJAX
    // -------------------------------------------------------------------------

    public function ajax_clear_cache() {
        check_ajax_referer( 'oidc_clear_cache', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( null, 403 );
        }

        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Transients direkt löschen ist hier bewusst und notwendig; delete_transient() kennt keine Wildcard.
        $wpdb->query(
            "DELETE FROM {$wpdb->options}
             WHERE option_name LIKE '_transient_oidc_jwks_%'
                OR option_name LIKE '_transient_timeout_oidc_jwks_%'"
        );

        wp_send_json_success();
    }

    // -------------------------------------------------------------------------
    // Felder
    // -------------------------------------------------------------------------

    public function section_provider_description() {
        echo '<p>' . esc_html__( 'Gib die Discovery-URL deines OIDC-Providers ein und klicke auf „Abrufen", um die Endpunkte automatisch zu befüllen.', 'oidc-client' ) . '</p>';
    }

    public function field_discovery_url() {
        $value = esc_attr( get_option( 'oidc_discovery_url', '' ) );
        ?>
        <input type="url" id="oidc_discovery_url" name="oidc_discovery_url"
               value="<?php echo esc_attr( get_option( 'oidc_discovery_url', '' ) ); ?>" class="regular-text"
               placeholder="https://provider.example.com/.well-known/openid-configuration" />
        <button type="button" id="oidc-fetch-discovery" class="button button-secondary">
            <?php esc_html_e( 'Abrufen', 'oidc-client' ); ?>
        </button>
        <span id="oidc-discovery-status" style="margin-left:8px;"></span>
        <?php
    }

    public function field_text( $args ) {
        $option  = $args['option'];
        $default = isset( $args['default'] ) ? $args['default'] : '';
        $value   = esc_attr( get_option( $option, $default ) );
        $desc    = isset( $args['description'] ) ? $args['description'] : '';
        printf(
            '<input type="text" id="%1$s" name="%1$s" value="%2$s" class="regular-text" />',
            esc_attr( $option ),
            esc_attr( get_option( $option, $default ) )
        );
        if ( $desc ) {
            printf( '<p class="description">%s</p>', esc_html( $desc ) );
        }
    }

    public function field_url( $args ) {
        $option = $args['option'];
        $value  = esc_attr( get_option( $option, '' ) );
        printf(
            '<input type="url" id="%1$s" name="%1$s" value="%2$s" class="regular-text" />',
            esc_attr( $option ),
            esc_attr( get_option( $option, '' ) )
        );
    }

    public function field_password( $args ) {
        $option = $args['option'];
        $value  = esc_attr( get_option( $option, '' ) );
        printf(
            '<input type="password" id="%1$s" name="%1$s" value="%2$s" class="regular-text" autocomplete="new-password" />',
            esc_attr( $option ),
            esc_attr( get_option( $option, '' ) )
        );
    }

    public function field_redirect_uri() {
        $redirect_uri = add_query_arg( 'oidc_callback', '1', wp_login_url() );
        ?>
        <input type="url" value="<?php echo esc_attr( $redirect_uri ); ?>"
               class="regular-text" readonly="readonly" />
        <p class="description">
            <?php esc_html_e( 'Diese URI muss beim OIDC-Provider als erlaubte Redirect URI eingetragen werden.', 'oidc-client' ); ?>
        </p>
        <?php
    }

    public function field_token_auth_method() {
        $current = get_option( 'oidc_token_auth_method', 'client_secret_post' );
        $methods = array(
            'client_secret_post'  => __( 'client_secret_post – Credentials im POST-Body (Standard, z. B. easyVerein, Keycloak)', 'oidc-client' ),
            'client_secret_basic' => __( 'client_secret_basic – HTTP Basic Auth (z. B. Azure AD, Okta)', 'oidc-client' ),
        );
        echo '<select name="oidc_token_auth_method" id="oidc_token_auth_method">';
        foreach ( $methods as $value => $label ) {
            printf(
                '<option value="%s"%s>%s</option>',
                esc_attr( $value ),
                selected( $current, $value, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
        echo '<p class="description">' . esc_html__( 'Wie sich dieses Plugin beim Token-Endpoint authentifiziert. Bei „invalid_client"-Fehlern die andere Methode probieren.', 'oidc-client' ) . '</p>';
    }

    public function field_checkbox( $args ) {
        $option = $args['option'];
        $value  = get_option( $option, false );
        $desc   = isset( $args['description'] ) ? $args['description'] : '';
        printf(
            '<label><input type="checkbox" id="%1$s" name="%1$s" value="1" %2$s /> %3$s</label>',
            esc_attr( $option ),
            checked( $value, '1', false ),
            esc_html( $desc )
        );
    }

    public function field_roles_dropdown() {
        $current = get_option( 'oidc_default_role', 'subscriber' );
        $roles   = wp_roles()->roles;
        echo '<select name="oidc_default_role" id="oidc_default_role">';
        foreach ( $roles as $role_key => $role_data ) {
            printf(
                '<option value="%s"%s>%s</option>',
                esc_attr( $role_key ),
                selected( $current, $role_key, false ),
                esc_html( translate_user_role( $role_data['name'] ) )
            );
        }
        echo '</select>';
    }

    public function field_remember_me() {
        $current = get_option( 'oidc_remember_me', 'never' );
        $options = array(
            'never'  => __( 'Nie – Sitzung endet beim Schließen des Browsers', 'oidc-client' ),
            'always' => __( 'Immer – Dauerhaftes Auth-Cookie (14 Tage)', 'oidc-client' ),
        );
        echo '<select name="oidc_remember_me" id="oidc_remember_me">';
        foreach ( $options as $value => $label ) {
            printf(
                '<option value="%s"%s>%s</option>',
                esc_attr( $value ),
                selected( $current, $value, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
    }

    // -------------------------------------------------------------------------
    // Sanitize-Callbacks
    // -------------------------------------------------------------------------

    public function sanitize_checkbox( $value ) {
        return ( '1' === $value || true === $value ) ? '1' : '';
    }

    public function sanitize_secret( $value ) {
        // Nur Null-Bytes und Whitespace am Rand entfernen – keine HTML-Stripping
        $value = wp_unslash( $value );
        $value = preg_replace( '/[\x00]/', '', $value ); // Null-Bytes
        return trim( $value );
    }

    public function sanitize_role_mapping( $value ) {
        if ( empty( $value ) ) {
            return '';
        }
        $decoded = json_decode( wp_unslash( $value ), true );
        if ( ! is_array( $decoded ) ) {
            return '';
        }
        $sanitized = array();
        foreach ( $decoded as $k => $v ) {
            $sanitized[ sanitize_text_field( $k ) ] = sanitize_text_field( $v );
        }
        return wp_json_encode( $sanitized );
    }

    public function section_roles_description() {
        echo '<p>' . esc_html__( 'Ordne Werte aus dem Rollen-Claim WordPress-Rollen zu. Wird kein Mapping gefunden, bleibt die bestehende Rolle erhalten.', 'oidc-client' ) . '</p>';
    }

    public function field_role_mapping() {
        $mapping_json = get_option( 'oidc_role_mapping', '' );
        $mapping      = ! empty( $mapping_json ) ? json_decode( $mapping_json, true ) : array();
        if ( ! is_array( $mapping ) ) {
            $mapping = array();
        }
        $wp_roles = wp_roles()->roles;
        ?>
        <input type="hidden" id="oidc_role_mapping" name="oidc_role_mapping"
               value="<?php echo esc_attr( $mapping_json ); ?>" />

        <table id="oidc-role-mapping-table" class="widefat" style="width:auto;margin-bottom:8px;">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Claim-Wert', 'oidc-client' ); ?></th>
                    <th><?php esc_html_e( 'WordPress-Rolle', 'oidc-client' ); ?></th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $mapping as $claim_value => $wp_role ) : ?>
                <tr>
                    <td>
                        <input type="text" class="rm-claim regular-text"
                               value="<?php echo esc_attr( $claim_value ); ?>" />
                    </td>
                    <td>
                        <select class="rm-role">
                            <?php foreach ( $wp_roles as $role_key => $role_data ) : ?>
                            <option value="<?php echo esc_attr( $role_key ); ?>"
                                <?php selected( $wp_role, $role_key ); ?>>
                                <?php echo esc_html( translate_user_role( $role_data['name'] ) ); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </td>
                    <td>
                        <button type="button" class="button button-small rm-remove">
                            <?php esc_html_e( 'Entfernen', 'oidc-client' ); ?>
                        </button>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <button type="button" id="oidc-rm-add" class="button button-secondary">
            <?php esc_html_e( '+ Zeile hinzufügen', 'oidc-client' ); ?>
        </button>
        <p class="description">
            <?php esc_html_e( 'Einem Claim-Wert können mehrere Zeilen zugewiesen werden. Es wird die erste passende Zeile verwendet.', 'oidc-client' ); ?>
        </p>
        <script>
        (function () {
            var rolesHtml = 
            <?php
                $opts = '';
			foreach ( $wp_roles as $role_key => $role_data ) {
				$opts .= '<option value="' . esc_attr( $role_key ) . '">' . esc_html( translate_user_role( $role_data['name'] ) ) . '</option>';
			}
                echo wp_json_encode( $opts );
            ?>
            ;

            function serialize() {
                var result = {};
                document.querySelectorAll('#oidc-role-mapping-table tbody tr').forEach(function (row) {
                    var claim = row.querySelector('.rm-claim').value.trim();
                    var role  = row.querySelector('.rm-role').value;
                    if (claim) result[claim] = role;
                });
                document.getElementById('oidc_role_mapping').value = JSON.stringify(result);
            }

            document.getElementById('oidc-rm-add').addEventListener('click', function () {
                var tbody = document.querySelector('#oidc-role-mapping-table tbody');
                var tr = document.createElement('tr');
                tr.innerHTML = '<td><input type="text" class="rm-claim regular-text" value="" /></td>'
                    + '<td><select class="rm-role">' + rolesHtml + '</select></td>'
                    + '<td><button type="button" class="button button-small rm-remove"><?php echo esc_js( __( 'Entfernen', 'oidc-client' ) ); ?></button></td>';
                tbody.appendChild(tr);
            });

            document.querySelector('#oidc-role-mapping-table').addEventListener('click', function (e) {
                if (e.target.classList.contains('rm-remove')) {
                    e.target.closest('tr').remove();
                    serialize();
                }
            });

            var form = document.querySelector('form');
            if (form) {
                form.addEventListener('submit', serialize);
            }
        }());
        </script>
        <?php
    }

    // -------------------------------------------------------------------------
    // Scripts / AJAX
    // -------------------------------------------------------------------------

    public function enqueue_scripts( $hook ) {
        if ( 'settings_page_oidc-client' !== $hook ) {
            return;
        }

        wp_enqueue_style(
            'oidc-admin',
            OIDC_CLIENT_URL . 'assets/css/admin.css',
            array(),
            OIDC_CLIENT_VERSION
        );

        wp_enqueue_script(
            'oidc-admin',
            OIDC_CLIENT_URL . 'assets/js/admin.js',
            array( 'jquery' ),
            OIDC_CLIENT_VERSION,
            true
        );

        wp_localize_script( 'oidc-admin', 'oidcAdmin', array(
            'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
            'nonce'      => wp_create_nonce( 'oidc_fetch_discovery' ),
            'cacheNonce' => wp_create_nonce( 'oidc_clear_cache' ),
            'i18n'       => array(
                'fetching'      => __( 'Wird abgerufen…', 'oidc-client' ),
                'error'         => __( 'Fehler beim Abrufen.', 'oidc-client' ),
                'success'       => __( 'Erfolgreich abgerufen.', 'oidc-client' ),
                'cacheCleared'  => __( 'Cache geleert.', 'oidc-client' ),
                'cacheError'    => __( 'Fehler beim Leeren.', 'oidc-client' ),
            ),
        ) );
    }

    public function ajax_fetch_discovery() {
        check_ajax_referer( 'oidc_fetch_discovery', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Keine Berechtigung.', 'oidc-client' ) ), 403 );
        }

        $url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

        if ( empty( $url ) || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
            wp_send_json_error( array( 'message' => __( 'Ungültige URL.', 'oidc-client' ) ), 400 );
        }

        $response = wp_remote_get( $url, array(
            'timeout'   => 10,
            'sslverify' => true,
        ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( array( 'message' => $response->get_error_message() ), 500 );
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( 200 !== (int) $code ) {
            wp_send_json_error(
                /* translators: %d: HTTP-Statuscode der Discovery-URL-Anfrage */
                array( 'message' => sprintf( __( 'HTTP-Fehler %d', 'oidc-client' ), $code ) ),
                500
            );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( ! is_array( $data ) ) {
            wp_send_json_error( array( 'message' => __( 'Ungültige JSON-Antwort.', 'oidc-client' ) ), 500 );
        }

        wp_send_json_success( array(
            'authorization_endpoint'  => isset( $data['authorization_endpoint'] ) ? esc_url_raw( $data['authorization_endpoint'] ) : '',
            'token_endpoint'          => isset( $data['token_endpoint'] ) ? esc_url_raw( $data['token_endpoint'] ) : '',
            'userinfo_endpoint'       => isset( $data['userinfo_endpoint'] ) ? esc_url_raw( $data['userinfo_endpoint'] ) : '',
            'jwks_uri'                => isset( $data['jwks_uri'] ) ? esc_url_raw( $data['jwks_uri'] ) : '',
            'issuer'                  => isset( $data['issuer'] ) ? sanitize_text_field( $data['issuer'] ) : '',
            'end_session_endpoint'    => isset( $data['end_session_endpoint'] ) ? esc_url_raw( $data['end_session_endpoint'] ) : '',
            'pkce_supported'          => ! empty( $data['code_challenge_methods_supported'] )
                                         && in_array( 'S256', (array) $data['code_challenge_methods_supported'], true ),
        ) );
    }
}
