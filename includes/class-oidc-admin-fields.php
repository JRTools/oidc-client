<?php
/**
 * OIDC Client – Render-Callbacks für Admin-Felder und -Abschnitte.
 */

defined( 'ABSPATH' ) || exit;

/**
 * Stellt Render-Callbacks für die Admin-Einstellungsfelder bereit.
 */
class OIDC_Admin_Fields {

	/**
	 * Rendert ein <select>-Element mit <option>-Einträgen.
	 *
	 * @param string               $name    Name- und ID-Attribut des Selects.
	 * @param array<string,string> $options Assoziatives Array value => label.
	 * @param string               $current Aktuell gespeicherter Wert.
	 */
	private function render_select( $name, array $options, $current ) {
		printf( '<select name="%1$s" id="%1$s">', esc_attr( $name ) );
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

	/** Beschreibungstext für den Provider-Abschnitt. */
	public function section_provider_description() {
		echo '<p>' . esc_html__( 'Gib die Discovery-URL deines OIDC-Providers ein und klicke auf „Abrufen", um die Endpunkte automatisch zu befüllen.', 'jrtools-openid-connect' ) . '</p>';
	}

	/** Beschreibungstext für den Rollen-Mapping-Abschnitt. */
	public function section_roles_description() {
		echo '<p>' . esc_html__( 'Ordne Werte aus dem Rollen-Claim WordPress-Rollen zu. Wird kein Mapping gefunden, bleibt die bestehende Rolle erhalten.', 'jrtools-openid-connect' ) . '</p>';
	}

	/** Rendert das Feld für die Discovery-URL. */
	public function field_discovery_url() {
		?>
		<input type="url" id="jrtools_oidc_discovery_url" name="jrtools_oidc_discovery_url"
			   value="<?php echo esc_attr( get_option( 'jrtools_oidc_discovery_url', '' ) ); ?>" class="regular-text"
			   placeholder="https://provider.example.com/.well-known/openid-configuration" />
		<button type="button" id="oidc-fetch-discovery" class="button button-secondary">
			<?php esc_html_e( 'Abrufen', 'jrtools-openid-connect' ); ?>
		</button>
		<span id="oidc-discovery-status" style="margin-left:8px;"></span>
		<?php
	}

	/**
	 * Rendert ein Text-Eingabefeld.
	 *
	 * @param array<string,string> $args Argumente: option, default, description.
	 */
	public function field_text( $args ) {
		$option  = $args['option'];
		$default = isset( $args['default'] ) ? $args['default'] : '';
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

	/**
	 * Rendert ein URL-Eingabefeld.
	 *
	 * @param array<string,string> $args Argumente: option.
	 */
	public function field_url( $args ) {
		$option = $args['option'];
		printf(
			'<input type="url" id="%1$s" name="%1$s" value="%2$s" class="regular-text" />',
			esc_attr( $option ),
			esc_attr( get_option( $option, '' ) )
		);
	}

	/**
	 * Rendert ein Passwort-Eingabefeld.
	 *
	 * @param array<string,string> $args Argumente: option.
	 */
	public function field_password( $args ) {
		$option = $args['option'];
		printf(
			'<input type="password" id="%1$s" name="%1$s" value="%2$s" class="regular-text" autocomplete="new-password" />',
			esc_attr( $option ),
			esc_attr( get_option( $option, '' ) )
		);
	}

	/** Rendert das schreibgeschützte Redirect-URI-Feld. */
	public function field_redirect_uri() {
		$redirect_uri = add_query_arg( 'oidc_callback', '1', wp_login_url() );
		?>
		<input type="url" value="<?php echo esc_attr( $redirect_uri ); ?>"
			   class="regular-text" readonly="readonly" />
		<p class="description">
			<?php esc_html_e( 'Diese URI muss beim OIDC-Provider als erlaubte Redirect URI eingetragen werden.', 'jrtools-openid-connect' ); ?>
		</p>
		<?php
	}

	/** Rendert das Auswahlfeld für die Token-Endpoint-Authentifizierungsmethode. */
	public function field_token_auth_method() {
		$current = get_option( 'jrtools_oidc_token_auth_method', 'client_secret_post' );
		$methods = array(
			'client_secret_post'  => __( 'client_secret_post – Credentials im POST-Body (Standard, z. B. easyVerein, Keycloak)', 'jrtools-openid-connect' ),
			'client_secret_basic' => __( 'client_secret_basic – HTTP Basic Auth (z. B. Azure AD, Okta)', 'jrtools-openid-connect' ),
		);
		$this->render_select( 'jrtools_oidc_token_auth_method', $methods, $current );
		echo '<p class="description">' . esc_html__( 'Wie sich dieses Plugin beim Token-Endpoint authentifiziert. Bei „invalid_client"-Fehlern die andere Methode probieren.', 'jrtools-openid-connect' ) . '</p>';
	}

	/**
	 * Rendert eine Checkbox.
	 *
	 * @param array<string,string> $args Argumente: option, description.
	 */
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

	/** Rendert das Dropdown für die Standard-WordPress-Rolle. */
	public function field_roles_dropdown() {
		$current = get_option( 'jrtools_oidc_default_role', 'subscriber' );
		$roles   = wp_roles()->roles;
		$options = array();
		foreach ( $roles as $role_key => $role_data ) {
			$options[ $role_key ] = translate_user_role( $role_data['name'] );
		}
		$this->render_select( 'jrtools_oidc_default_role', $options, $current );
	}

	/** Rendert das Auswahlfeld für „Angemeldet bleiben". */
	public function field_remember_me() {
		$current = get_option( 'jrtools_oidc_remember_me', 'never' );
		$options = array(
			'never'  => __( 'Nie – Sitzung endet beim Schließen des Browsers', 'jrtools-openid-connect' ),
			'always' => __( 'Immer – Dauerhaftes Auth-Cookie (14 Tage)', 'jrtools-openid-connect' ),
		);
		$this->render_select( 'jrtools_oidc_remember_me', $options, $current );
	}

	/** Rendert die Tabelle für das Rollen-Mapping. */
	public function field_role_mapping() {
		$mapping_json = get_option( 'jrtools_oidc_role_mapping', '' );
		$mapping      = ! empty( $mapping_json ) ? json_decode( $mapping_json, true ) : array();
		if ( ! is_array( $mapping ) ) {
			$mapping = array();
		}
		$wp_roles = wp_roles()->roles;
		?>
		<input type="hidden" id="jrtools_oidc_role_mapping" name="jrtools_oidc_role_mapping"
			   value="<?php echo esc_attr( $mapping_json ); ?>" />

		<table id="oidc-role-mapping-table" class="widefat" style="width:auto;margin-bottom:8px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Claim-Wert', 'jrtools-openid-connect' ); ?></th>
					<th><?php esc_html_e( 'WordPress-Rolle', 'jrtools-openid-connect' ); ?></th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				<?php
				foreach ( $mapping as $claim_value => $wp_role ) :
					$row_id = 'rm-row-' . sanitize_key( $claim_value );
					?>
				<tr>
					<td>
						<label for="<?php echo esc_attr( $row_id . '-claim' ); ?>" class="screen-reader-text"><?php esc_html_e( 'Claim-Wert', 'jrtools-openid-connect' ); ?></label>
						<input type="text" id="<?php echo esc_attr( $row_id . '-claim' ); ?>" class="rm-claim regular-text"
							   value="<?php echo esc_attr( $claim_value ); ?>" />
					</td>
					<td>
						<label for="<?php echo esc_attr( $row_id . '-role' ); ?>" class="screen-reader-text"><?php esc_html_e( 'WordPress-Rolle', 'jrtools-openid-connect' ); ?></label>
						<select id="<?php echo esc_attr( $row_id . '-role' ); ?>" class="rm-role">
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
							<?php esc_html_e( 'Entfernen', 'jrtools-openid-connect' ); ?>
						</button>
					</td>
				</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<button type="button" id="oidc-rm-add" class="button button-secondary">
			<?php esc_html_e( '+ Zeile hinzufügen', 'jrtools-openid-connect' ); ?>
		</button>
		<p class="description">
			<?php esc_html_e( 'Einem Claim-Wert können mehrere Zeilen zugewiesen werden. Es wird die erste passende Zeile verwendet.', 'jrtools-openid-connect' ); ?>
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
				document.getElementById('jrtools_oidc_role_mapping').value = JSON.stringify(result);
			}

			document.getElementById('oidc-rm-add').addEventListener('click', function () {
				var tbody = document.querySelector('#oidc-role-mapping-table tbody');
				var tr = document.createElement('tr');
				tr.innerHTML = '<td><input type="text" class="rm-claim regular-text" value="" /></td>'
					+ '<td><select class="rm-role">' + rolesHtml + '</select></td>'
					+ '<td><button type="button" class="button button-small rm-remove"><?php echo esc_js( __( 'Entfernen', 'jrtools-openid-connect' ) ); ?></button></td>';
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
}
