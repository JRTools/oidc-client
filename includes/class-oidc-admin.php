<?php
/**
 * OIDC Client – Admin-Einstellungsseite und Discovery-AJAX
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OIDC_Admin {

	/** @var OIDC_Admin_Fields */
	public $fields;

	/** @var OIDC_Admin_Sanitize */
	public $sanitize;

	public function __construct() {
		$this->fields   = new OIDC_Admin_Fields();
		$this->sanitize = new OIDC_Admin_Sanitize();
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
			__( 'OIDC Client', 'jrtools-openid-connect' ),
			__( 'OIDC Client', 'jrtools-openid-connect' ),
			'manage_options',
			'oidc-client',
			array( $this, 'render_settings_page' )
		);
	}

	// -------------------------------------------------------------------------
	// Settings API registrieren
	// -------------------------------------------------------------------------

	/**
	 * Wrapper um add_settings_field() mit festem Page-Parameter 'oidc-client'.
	 *
	 * @param string       $id       Feld-ID / Option-Name.
	 * @param string       $label    Angezeigter Feldname.
	 * @param callable     $callback Render-Callback.
	 * @param string       $section  Settings-Abschnitts-ID.
	 * @param array<mixed> $args     Optionale Argumente für den Callback.
	 */
	private function add_field( $id, $label, $callback, $section, $args = array() ) {
		add_settings_field( $id, $label, $callback, 'jrtools-openid-connect', $section, $args );
	}

	public function register_settings() {
		$options = array(
			'jrtools_oidc_discovery_url'          => 'esc_url_raw',
			'jrtools_oidc_provider_name'          => 'sanitize_text_field',
			'jrtools_oidc_issuer'                 => 'sanitize_text_field',
			'jrtools_oidc_authorization_endpoint' => 'esc_url_raw',
			'jrtools_oidc_token_endpoint'         => 'esc_url_raw',
			'jrtools_oidc_userinfo_endpoint'      => 'esc_url_raw',
			'jrtools_oidc_jwks_uri'               => 'esc_url_raw',
			'jrtools_oidc_end_session_endpoint'   => 'esc_url_raw',
			'jrtools_oidc_pkce_supported'         => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_client_id'              => 'sanitize_text_field',
			'jrtools_oidc_client_secret'          => array( $this->sanitize, 'sanitize_secret' ),
			'jrtools_oidc_scopes'                 => 'sanitize_text_field',
			'jrtools_oidc_token_auth_method'      => 'sanitize_text_field',
			'jrtools_oidc_debug_mode'             => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_create_user'            => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_default_role'           => 'sanitize_text_field',
			'jrtools_oidc_enable_refresh'         => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_active_claim'           => 'sanitize_text_field',
			'jrtools_oidc_sync_avatar'            => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_hide_wp_login'          => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_auto_login'             => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_button_icon_url'        => 'esc_url_raw',
			'jrtools_oidc_token_encryption'       => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_lock_email'             => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_lock_password'          => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_session_management'     => array( $this->sanitize, 'sanitize_checkbox' ),
			'jrtools_oidc_remember_me'            => 'sanitize_text_field',
			'jrtools_oidc_role_claim'             => 'sanitize_text_field',
			'jrtools_oidc_role_mapping'           => array( $this->sanitize, 'sanitize_role_mapping' ),
		);

		foreach ( $options as $option_name => $sanitize_callback ) {
			register_setting(
				'oidc_client_settings',
				$option_name,
				array( 'sanitize_callback' => $sanitize_callback )
			);
		}

		$this->register_provider_section();
		$this->register_client_section();
		$this->register_users_advanced_roles_sections();
	}

	/**
	 * Registriert Abschnitt 1: Provider-Felder.
	 */
	private function register_provider_section() {
		// ----- Abschnitt 1: Provider -----
		add_settings_section(
			'oidc_section_provider',
			__( 'Provider',   'jrtools-openid-connect' ),
			array( $this->fields, 'section_provider_description' ),
			'jrtools-openid-connect'
		);

		$this->add_field( 'jrtools_oidc_discovery_url', __( 'Discovery URL',   'jrtools-openid-connect' ), array( $this->fields, 'field_discovery_url' ), 'oidc_section_provider' );
		$this->add_field(
			'jrtools_oidc_provider_name',
			__( 'Provider-Name',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_text' ),
			'oidc_section_provider',
			array(
				'option'      => 'jrtools_oidc_provider_name',
				'description' => __( 'Wird im Login-Button angezeigt: „Login mit …"',   'jrtools-openid-connect' ),
			)
		);
		$this->add_field(
			'jrtools_oidc_issuer',
			__( 'Issuer',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_text' ),
			'oidc_section_provider',
			array(
				'option'      => 'jrtools_oidc_issuer',
				'description' => __( 'Wird automatisch aus der Discovery-URL befüllt.',   'jrtools-openid-connect' ),
			)
		);
		$this->add_field( 'jrtools_oidc_authorization_endpoint', __( 'Authorization Endpoint',   'jrtools-openid-connect' ), array( $this->fields, 'field_url' ), 'oidc_section_provider', array( 'option' => 'jrtools_oidc_authorization_endpoint' ) );
		$this->add_field( 'jrtools_oidc_token_endpoint', __( 'Token Endpoint',   'jrtools-openid-connect' ), array( $this->fields, 'field_url' ), 'oidc_section_provider', array( 'option' => 'jrtools_oidc_token_endpoint' ) );
		$this->add_field( 'jrtools_oidc_userinfo_endpoint', __( 'Userinfo Endpoint',   'jrtools-openid-connect' ), array( $this->fields, 'field_url' ), 'oidc_section_provider', array( 'option' => 'jrtools_oidc_userinfo_endpoint' ) );
		$this->add_field( 'jrtools_oidc_jwks_uri', __( 'JWKS URI',   'jrtools-openid-connect' ), array( $this->fields, 'field_url' ), 'oidc_section_provider', array( 'option' => 'jrtools_oidc_jwks_uri' ) );
		$this->add_field(
			'jrtools_oidc_pkce_supported',
			__( 'PKCE (S256)',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_checkbox' ),
			'oidc_section_provider',
			array(
				'option'      => 'jrtools_oidc_pkce_supported',
				'description' => __( 'PKCE verwenden (empfohlen). Deaktivieren wenn der Provider kein PKCE unterstützt und „invalid_client"-Fehler auftreten.',   'jrtools-openid-connect' ),
			)
		);
	}

	/**
	 * Registriert Abschnitt 2: Client-Felder.
	 */
	private function register_client_section() {
		// ----- Abschnitt 2: Client -----
		add_settings_section( 'oidc_section_client', __( 'Client',   'jrtools-openid-connect' ), null,   'jrtools-openid-connect' );

		$this->add_field( 'jrtools_oidc_client_id', __( 'Client ID',   'jrtools-openid-connect' ), array( $this->fields, 'field_text' ), 'oidc_section_client', array( 'option' => 'jrtools_oidc_client_id' ) );
		$this->add_field( 'jrtools_oidc_client_secret', __( 'Client Secret',   'jrtools-openid-connect' ), array( $this->fields, 'field_password' ), 'oidc_section_client', array( 'option' => 'jrtools_oidc_client_secret' ) );
		$this->add_field(
			'jrtools_oidc_scopes',
			__( 'Scopes',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_text' ),
			'oidc_section_client',
			array(
				'option'      => 'jrtools_oidc_scopes',
				'default'     => 'openid email profile',
				'description' => __( 'Leerzeichen-getrennte Liste, z. B. „openid email profile"',   'jrtools-openid-connect' ),
			)
		);
		$this->add_field( 'oidc_redirect_uri', __( 'Redirect URI',   'jrtools-openid-connect' ), array( $this->fields, 'field_redirect_uri' ), 'oidc_section_client' );
		$this->add_field( 'jrtools_oidc_token_auth_method', __( 'Token-Endpoint Authentifizierung',   'jrtools-openid-connect' ), array( $this->fields, 'field_token_auth_method' ), 'oidc_section_client' );
	}

	/**
	 * Registriert Abschnitt 3 (Benutzerverwaltung), 4 (Erweiterte Optionen) und 5 (Rollen-Mapping).
	 */
	private function register_users_advanced_roles_sections() {
		// ----- Abschnitt 3: Benutzerverwaltung -----
		add_settings_section( 'oidc_section_users', __( 'Benutzerverwaltung',   'jrtools-openid-connect' ), null,   'jrtools-openid-connect' );

		$this->add_field(
			'jrtools_oidc_create_user',
			__( 'Benutzer automatisch anlegen',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_checkbox' ),
			'oidc_section_users',
			array(
				'option'      => 'jrtools_oidc_create_user',
				'description' => __( 'Falls kein lokales Konto existiert, wird automatisch eines erstellt.',   'jrtools-openid-connect' ),
			)
		);
		$this->add_field( 'jrtools_oidc_default_role', __( 'Standard-Rolle für neue Benutzer',   'jrtools-openid-connect' ), array( $this->fields, 'field_roles_dropdown' ), 'oidc_section_users' );
		$this->add_field(
			'jrtools_oidc_debug_mode',
			__( 'Debug-Modus',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_checkbox' ),
			'oidc_section_users',
			array(
				'option'      => 'jrtools_oidc_debug_mode',
				'description' => __( 'Zeigt bei Fehlern die vollständige Provider-Antwort und gesendete Parameter an. Nur zur Fehlersuche aktivieren, danach wieder deaktivieren.',   'jrtools-openid-connect' ),
			)
		);

		// ----- Abschnitt 4: Erweiterte Optionen -----
		add_settings_section( 'oidc_section_advanced', __( 'Erweiterte Optionen',   'jrtools-openid-connect' ), null,   'jrtools-openid-connect' );

		$this->add_field( 'jrtools_oidc_end_session_endpoint', __( 'End-Session Endpoint',   'jrtools-openid-connect' ), array( $this->fields, 'field_url' ), 'oidc_section_advanced', array( 'option' => 'jrtools_oidc_end_session_endpoint' ) );

		foreach ( array(
			array( 'jrtools_oidc_enable_refresh', __( 'Token-Refresh', 'jrtools-openid-connect' ), __( 'Refresh-Token und Access-Token nach Login speichern und automatisch erneuern.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_sync_avatar', __( 'Profilbild synchronisieren', 'jrtools-openid-connect' ), __( 'Profilbild (picture-Claim) vom Provider übernehmen und als WordPress-Avatar anzeigen.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_hide_wp_login', __( 'WP-Login-Formular ausblenden', 'jrtools-openid-connect' ), __( 'Standard-WordPress-Loginformular ausblenden. Mit ?showlogin=1 weiterhin erreichbar.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_auto_login', __( 'Auto-Login', 'jrtools-openid-connect' ), __( 'Automatisch zum OIDC-Provider weiterleiten wenn die Login-Seite aufgerufen wird.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_token_encryption', __( 'Token-Verschlüsselung', 'jrtools-openid-connect' ), __( 'Access-, Refresh- und ID-Token verschlüsselt in der Datenbank speichern (AES-256-CBC). Erfordert PHP OpenSSL.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_lock_email', __( 'E-Mail sperren', 'jrtools-openid-connect' ), __( 'OIDC-Nutzer können ihre E-Mail-Adresse nicht selbst ändern.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_lock_password', __( 'Passwort sperren', 'jrtools-openid-connect' ), __( 'OIDC-Nutzer können ihr Passwort nicht selbst ändern.',   'jrtools-openid-connect' ) ),
			array( 'jrtools_oidc_session_management', __( 'Session-Management', 'jrtools-openid-connect' ), __( 'Session an Token-Ablauf binden: Bei jedem Request Token prüfen, Refresh versuchen, sonst ausloggen. Erfordert Token-Refresh.',   'jrtools-openid-connect' ) ),
		) as list( $option, $label, $desc ) ) {
			$this->add_field( $option, $label, array( $this->fields, 'field_checkbox' ), 'oidc_section_advanced', array(
				'option'      => $option,
				'description' => $desc,
			) );
		}

		$this->add_field( 'jrtools_oidc_active_claim', __( 'Active-Claim',   'jrtools-openid-connect' ), array( $this->fields, 'field_text' ), 'oidc_section_advanced', array(
			'option'      => 'jrtools_oidc_active_claim',
			'description' => __( 'Claim-Name der Aktivierung (z. B. „active" oder „email_verified"). Login wird verweigert wenn false/0.',   'jrtools-openid-connect' ),
		) );
		$this->add_field( 'jrtools_oidc_button_icon_url', __( 'Button-Icon URL',   'jrtools-openid-connect' ), array( $this->fields, 'field_url' ), 'oidc_section_advanced', array( 'option' => 'jrtools_oidc_button_icon_url' ) );
		$this->add_field( 'jrtools_oidc_remember_me', __( 'Angemeldet bleiben',   'jrtools-openid-connect' ), array( $this->fields, 'field_remember_me' ), 'oidc_section_advanced' );

		// ----- Abschnitt 5: Rollen-Mapping -----
		add_settings_section(
			'oidc_section_roles',
			__( 'Rollen-Mapping',   'jrtools-openid-connect' ),
			array( $this->fields, 'section_roles_description' ),
			'jrtools-openid-connect'
		);

		$this->add_field(
			'jrtools_oidc_role_claim',
			__( 'Rollen-Claim',   'jrtools-openid-connect' ),
			array( $this->fields, 'field_text' ),
			'oidc_section_roles',
			array(
				'option'      => 'jrtools_oidc_role_claim',
				'description' => __( 'Name des Claims der Rollen enthält, z. B. „roles" oder „groups".',   'jrtools-openid-connect' ),
			)
		);
		$this->add_field( 'jrtools_oidc_role_mapping', __( 'Rollen-Mapping',   'jrtools-openid-connect' ), array( $this->fields, 'field_role_mapping' ), 'oidc_section_roles' );
	}

	// -------------------------------------------------------------------------
	// Seite rendern
	// -------------------------------------------------------------------------

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Keine Berechtigung.',   'jrtools-openid-connect' ) );
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'OIDC Client Einstellungen',   'jrtools-openid-connect' ); ?></h1>
			<form method="post" action="options.php">
				<?php
				settings_fields( 'oidc_client_settings' );
				do_settings_sections(   'jrtools-openid-connect' );
				submit_button();
				?>
			</form>
			<p style="margin-top:0.5em;">
				<button id="oidc-clear-cache" class="button button-secondary">
					<?php esc_html_e( 'JWKS-Cache leeren',   'jrtools-openid-connect' ); ?>
				</button>
				<span id="oidc-cache-status" style="margin-left:8px;"></span>
			</p>
			<?php $this->render_provider_config_box(); ?>
		</div>
		<?php
	}

	private function render_provider_config_box() {
		$home_url        = home_url();
		$login_url       = wp_login_url();
		$redirect_uri    = add_query_arg( 'oidc_callback', '1', $login_url );
		$logout_uri      = add_query_arg( 'loggedout', 'true', $login_url );
		$backchannel_uri = rest_url( 'jrtools-oidc/v1/backchannel-logout' );

		$params = array(
			__( 'Redirect URI (Callback URL)',   'jrtools-openid-connect' )       => $redirect_uri,
			__( 'Post-logout Redirect URI',   'jrtools-openid-connect' )          => $logout_uri,
			__( 'Backchannel Logout URI',   'jrtools-openid-connect' )            => $backchannel_uri,
			__( 'Allowed Origin / CORS Origin',   'jrtools-openid-connect' )      => $home_url,
			__( 'Allowed Web Origin',   'jrtools-openid-connect' )                => $home_url,
			__( 'Initiate Login URI',   'jrtools-openid-connect' )                => add_query_arg( 'oidc_login', '1', $login_url ),
		);
		?>
		<div class="oidc-provider-config-box">
			<h2><?php esc_html_e( 'Konfiguration auf OIDC-Provider-Seite',   'jrtools-openid-connect' ); ?></h2>
			<p class="description">
				<?php esc_html_e( 'Diese Werte musst du in der Client-Konfiguration deines OIDC-Providers (z. B. Keycloak, Entra ID, Google, easyVerein) hinterlegen.',   'jrtools-openid-connect' ); ?>
			</p>
			<table class="oidc-provider-config-table widefat">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Parameter',   'jrtools-openid-connect' ); ?></th>
						<th><?php esc_html_e( 'Wert',   'jrtools-openid-connect' ); ?></th>
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
								<?php esc_html_e( 'Kopieren',   'jrtools-openid-connect' ); ?>
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
						self.textContent = '<?php echo esc_js( __( 'Kopieren',   'jrtools-openid-connect' ) ); ?>';
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Transients direkt löschen ist bewusst; delete_transient() kennt keine Wildcard.
		$wpdb->query(
			"DELETE FROM {$wpdb->options}
			 WHERE option_name LIKE '_transient_jrtools_oidc_jwks_%'
				OR option_name LIKE '_transient_timeout_jrtools_oidc_jwks_%'"
		);

		wp_send_json_success();
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
			JRTOOLS_OIDC_URL . 'assets/css/admin.css',
			array(),
			JRTOOLS_OIDC_VERSION
		);

		wp_enqueue_script(
			'oidc-admin',
			JRTOOLS_OIDC_URL . 'assets/js/admin.js',
			array( 'jquery' ),
			JRTOOLS_OIDC_VERSION,
			true
		);

		wp_localize_script( 'oidc-admin', 'oidcAdmin', array(
			'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
			'nonce'      => wp_create_nonce( 'oidc_fetch_discovery' ),
			'cacheNonce' => wp_create_nonce( 'oidc_clear_cache' ),
			'i18n'       => array(
				'fetching'      => __( 'Wird abgerufen…',   'jrtools-openid-connect' ),
				'error'         => __( 'Fehler beim Abrufen.',   'jrtools-openid-connect' ),
				'success'       => __( 'Erfolgreich abgerufen.',   'jrtools-openid-connect' ),
				'cacheCleared'  => __( 'Cache geleert.',   'jrtools-openid-connect' ),
				'cacheError'    => __( 'Fehler beim Leeren.',   'jrtools-openid-connect' ),
			),
		) );
	}

	public function ajax_fetch_discovery() {
		check_ajax_referer( 'oidc_fetch_discovery', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Keine Berechtigung.',   'jrtools-openid-connect' ) ), 403 );
		}

		$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

		if ( empty( $url ) || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			wp_send_json_error( array( 'message' => __( 'Ungültige URL.',   'jrtools-openid-connect' ) ), 400 );
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
				array( 'message' => sprintf( __( 'HTTP-Fehler %d',   'jrtools-openid-connect' ), $code ) ),
				500
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			wp_send_json_error( array( 'message' => __( 'Ungültige JSON-Antwort.',   'jrtools-openid-connect' ) ), 500 );
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
