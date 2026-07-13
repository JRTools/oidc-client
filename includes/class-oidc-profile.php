<?php
/**
 * OIDC Client – Account-Linking (Benutzerprofil)
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Profile {

    public function __construct() {
        add_action( 'show_user_profile',          array( $this, 'render_profile_section' ) );
        add_action( 'edit_user_profile',          array( $this, 'render_profile_section' ) );
        add_action( 'show_user_profile',          array( $this, 'lock_profile_fields_ui' ) );
        add_action( 'edit_user_profile',          array( $this, 'lock_profile_fields_ui' ) );
        add_action( 'login_init',                 array( $this, 'initiate_link_login' ) );
        add_action( 'admin_post_jrtools_oidc_unlink',     array( $this, 'handle_unlink' ) );
        add_action( 'user_profile_update_errors', array( $this, 'maybe_lock_email' ),    10, 3 );
        add_action( 'user_profile_update_errors', array( $this, 'maybe_lock_password' ), 10, 3 );

        // F6: Avatar-Filter nur laden wenn aktiviert
        if ( get_option( 'jrtools_oidc_sync_avatar', '' ) === '1' ) {
            add_filter( 'get_avatar_url', array( $this, 'filter_avatar_url' ), 10, 3 );
        }
    }

    // -------------------------------------------------------------------------
    // F2: E-Mail-Änderung sperren
    // -------------------------------------------------------------------------

    public function maybe_lock_email( WP_Error $errors, $update, $user ) {
        if ( get_option( 'jrtools_oidc_lock_email', '' ) !== '1' ) {
            return;
        }
        if ( ! $update ) {
            return;
        }
        if ( empty( get_user_meta( $user->ID, '_jrtools_oidc_subject', true ) ) ) {
            return;
        }

        $existing = get_user_by( 'id', $user->ID );
        if ( $existing && $existing->user_email !== $user->user_email ) {
            $errors->add(
                'jrtools_oidc_email_locked',
                __( 'Die E-Mail-Adresse kann nicht geändert werden, da dieses Konto mit einem OIDC-Anbieter verknüpft ist.', 'jrtools-openid-connect' )
            );
            $user->user_email = $existing->user_email;
        }
    }

    // -------------------------------------------------------------------------
    // F3: Passwort-Änderung sperren
    // -------------------------------------------------------------------------

    public function maybe_lock_password( WP_Error $errors, $_update, $user ) {
        if ( get_option( 'jrtools_oidc_lock_password', '' ) !== '1' ) {
            return;
        }
        if ( empty( get_user_meta( $user->ID, '_jrtools_oidc_subject', true ) ) ) {
            return;
        }

        if ( ! empty( $_POST['pass1'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce wird vom WP-Core in wp-admin/user-edit.php geprüft.
            $errors->add(
                'jrtools_oidc_password_locked',
                __( 'Das Passwort kann nicht geändert werden, da dieses Konto mit einem OIDC-Anbieter verknüpft ist.', 'jrtools-openid-connect' )
            );
        }
    }

    // -------------------------------------------------------------------------
    // UI-Hinweise für gesperrte Felder
    // -------------------------------------------------------------------------

    public function lock_profile_fields_ui( WP_User $user ) {
        $subject = get_user_meta( $user->ID, '_jrtools_oidc_subject', true );
        if ( empty( $subject ) ) {
            return;
        }

        $lock_email    = get_option( 'jrtools_oidc_lock_email', '' ) === '1';
        $lock_password = get_option( 'jrtools_oidc_lock_password', '' ) === '1';

        if ( ! $lock_email && ! $lock_password ) {
            return;
        }
        ?>
        <?php if ( $lock_email ) : ?>
        <style>#email { pointer-events: none; opacity: 0.6; }</style>
        <script>
        document.addEventListener('DOMContentLoaded', function () {
            var emailField = document.getElementById('email');
            if (emailField) {
                emailField.setAttribute('readonly', 'readonly');
                var hint = document.createElement('p');
                hint.className = 'description';
                hint.textContent = <?php echo wp_json_encode( __( 'E-Mail-Adresse wird vom OIDC-Anbieter verwaltet und kann hier nicht geändert werden.', 'jrtools-openid-connect' ) ); ?>;
                emailField.parentNode.appendChild(hint);
            }
        });
        </script>
        <?php endif; ?>
        <?php if ( $lock_password ) : ?>
        <style>
            #password-reset-wrap,
            #pass-strength-result,
            .user-pass1-wrap,
            .user-pass2-wrap,
            .pw-weak,
            #application-passwords-section { display: none !important; }
        </style>
        <script>
        document.addEventListener('DOMContentLoaded', function () {
            var pwSection = document.querySelector('.user-pass1-wrap') || document.getElementById('pass1-text');
            if (pwSection) {
                var hint = document.createElement('p');
                hint.className = 'description';
                hint.textContent = <?php echo wp_json_encode( __( 'Passwort wird vom OIDC-Anbieter verwaltet und kann hier nicht geändert werden.', 'jrtools-openid-connect' ) ); ?>;
                var pwRow = pwSection.closest('tr') || pwSection.parentNode;
                if (pwRow) pwRow.parentNode.insertBefore(hint, pwRow);
            }
        });
        </script>
        <?php endif; ?>
        <?php
    }

    // -------------------------------------------------------------------------
    // Profil-Sektion rendern
    // -------------------------------------------------------------------------

    public function render_profile_section( WP_User $user ) {
        $subject = get_user_meta( $user->ID, '_jrtools_oidc_subject', true );
        ?>
        <h2><?php esc_html_e( 'OpenID Connect', 'jrtools-openid-connect' ); ?></h2>
        <table class="form-table">
            <tr>
                <th><?php esc_html_e( 'OIDC-Verknüpfung', 'jrtools-openid-connect' ); ?></th>
                <td>
                    <?php if ( ! empty( $subject ) ) : ?>
                        <p>
                            <span class="dashicons dashicons-yes-alt" style="color:#46b450;"></span>
                            <?php esc_html_e( 'Dieses Konto ist mit einem OIDC-Anbieter verknüpft.', 'jrtools-openid-connect' ); ?>
                        </p>
                        <?php if ( get_current_user_id() === $user->ID ) : ?>
                        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                            <input type="hidden" name="action" value="jrtools_oidc_unlink">
                            <?php wp_nonce_field( 'jrtools_oidc_unlink_' . $user->ID, 'jrtools_oidc_unlink_nonce' ); ?>
                            <button type="submit" class="button button-secondary" onclick="return confirm('<?php esc_attr_e( 'OIDC-Verknüpfung wirklich aufheben?', 'jrtools-openid-connect' ); ?>')">
                                <?php esc_html_e( 'Verknüpfung aufheben', 'jrtools-openid-connect' ); ?>
                            </button>
                        </form>
                        <?php endif; ?>
                    <?php else : ?>
                        <p>
                            <span class="dashicons dashicons-no-alt" style="color:#dc3232;"></span>
                            <?php esc_html_e( 'Dieses Konto ist nicht mit einem OIDC-Anbieter verknüpft.', 'jrtools-openid-connect' ); ?>
                        </p>
                        <?php if ( get_current_user_id() === $user->ID ) : ?>
                        <a href="
							<?php
							echo esc_url( add_query_arg( array(
							'jrtools_oidc_link' => '1',
							'jrtools_oidc_link_nonce' => wp_create_nonce( 'jrtools_oidc_link' ),
							), wp_login_url() ) );
							?>
                                    "
                           class="button button-primary">
                            <?php esc_html_e( 'Mit OIDC-Anbieter verknüpfen', 'jrtools-openid-connect' ); ?>
                        </a>
                        <?php endif; ?>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php
    }

    // -------------------------------------------------------------------------
    // Account-Linking initiieren
    // -------------------------------------------------------------------------

    public function initiate_link_login() {
        if ( ! isset( $_GET['jrtools_oidc_link'] ) || '1' !== $_GET['jrtools_oidc_link'] ) {
            return;
        }

        if ( ! is_user_logged_in() ) {
            return;
        }

        $nonce = isset( $_GET['jrtools_oidc_link_nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['jrtools_oidc_link_nonce'] ) ) : '';
        if ( ! wp_verify_nonce( $nonce, 'jrtools_oidc_link' ) ) {
            wp_die( esc_html__( 'Sicherheitstoken ungültig.', 'jrtools-openid-connect' ) );
        }

        $user_id         = get_current_user_id();
        $existing_subject = get_user_meta( $user_id, '_jrtools_oidc_subject', true );
        set_transient( 'jrtools_oidc_link_pending_' . $user_id, array(
            'pending' => true,
            'sub'     => $existing_subject ? $existing_subject : '',
        ), 5 * MINUTE_IN_SECONDS );

        do_action( 'jrtools_oidc_initiate_login', array( 'prompt' => 'login' ) );
    }

    // -------------------------------------------------------------------------
    // Verknüpfung aufheben
    // -------------------------------------------------------------------------

    public function handle_unlink() {
        if ( ! is_user_logged_in() ) {
            wp_die( esc_html__( 'Keine Berechtigung.', 'jrtools-openid-connect' ) );
        }

        $user_id = get_current_user_id();
        $nonce   = isset( $_POST['jrtools_oidc_unlink_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['jrtools_oidc_unlink_nonce'] ) ) : '';

        if ( ! wp_verify_nonce( $nonce, 'jrtools_oidc_unlink_' . $user_id ) ) {
            wp_die( esc_html__( 'Sicherheitstoken ungültig.', 'jrtools-openid-connect' ) );
        }

        delete_user_meta( $user_id, '_jrtools_oidc_subject' );

        wp_safe_redirect( get_edit_profile_url( $user_id ) . '#oidc-unlinked' );
        exit;
    }

    // -------------------------------------------------------------------------
    // F6: Avatar-URL-Filter
    // -------------------------------------------------------------------------

    /**
     * OIDC-Avatar-URL für Benutzer zurückgeben, falls gespeichert.
     *
     * @param string $url         Aktuelle Avatar-URL.
     * @param mixed  $id_or_email User-ID, E-Mail, WP_User, WP_Post oder WP_Comment.
     * @param array  $_args       Zusätzliche Argumente (nicht verwendet).
     * @return string Avatar-URL.
     */
    public function filter_avatar_url( $url, $id_or_email, $_args ) {
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
            $avatar_url = get_user_meta( $user->ID, '_jrtools_oidc_avatar_url', true );
            if ( ! empty( $avatar_url ) ) {
                return esc_url( $avatar_url );
            }
        }

        return $url;
    }
}
