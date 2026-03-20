<?php
/**
 * OIDC Client – Login-Button, Fehleranzeige und Login-Trigger
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Login {

    public function __construct() {
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_styles' ) );
        add_action( 'login_form',            array( $this, 'render_login_button' ) );
        add_action( 'login_form',            array( $this, 'render_error_message' ) );
        add_action( 'login_init',            array( $this, 'handle_login_action' ) );
        add_action( 'login_enqueue_scripts', array( $this, 'maybe_hide_wp_login_form' ) );
        add_action( 'login_init',            array( $this, 'maybe_auto_login' ) );
    }

    public function enqueue_styles() {
        if ( empty( get_option( 'oidc_client_id' ) ) ) {
            return;
        }
        wp_enqueue_style(
            'oidc-login',
            OIDC_CLIENT_URL . 'assets/css/login.css',
            array(),
            OIDC_CLIENT_VERSION
        );
    }

    public function render_login_button() {
        $client_id     = get_option( 'oidc_client_id', '' );
        $provider_name = get_option( 'oidc_provider_name', 'OIDC Provider' );

        if ( empty( $client_id ) ) {
            return;
        }

        $login_url = add_query_arg( 'oidc_login', '1', wp_login_url() );
        $nonce_url = wp_nonce_url( $login_url, 'oidc_login' );
        $icon_url  = get_option( 'oidc_button_icon_url', '' );
        ?>
        <div class="oidc-login-wrapper">
            <div class="oidc-divider">
                <span><?php esc_html_e( 'oder', 'oidc-client' ); ?></span>
            </div>
            <a href="<?php echo esc_url( $nonce_url ); ?>" class="oidc-login-button">
                <?php if ( ! empty( $icon_url ) ) : ?>
                    <img src="<?php echo esc_url( $icon_url ); ?>"
                         alt="" class="oidc-button-icon" width="20" height="20" />
                <?php endif; ?>
                <?php
                echo esc_html( sprintf(
                    /* translators: %s: Name des OIDC-Providers */
                    __( 'Login mit %s', 'oidc-client' ),
                    $provider_name
                ) );
                ?>
            </a>
        </div>
        <?php
    }

    // F8: WordPress-Loginformular ausblenden
    public function maybe_hide_wp_login_form() {
        if ( get_option( 'oidc_hide_wp_login', '' ) !== '1' ) {
            return;
        }
        if ( isset( $_GET['showlogin'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Einfacher Passthrough-Parameter ohne sicherheitsrelevante Funktion.
            return;
        }
        ?>
        <style>
            #loginform, .wp-pwd, #nav { display: none !important; }
        </style>
        <?php
    }

    // F9: Auto-Login
    public function maybe_auto_login() {
        if ( get_option( 'oidc_auto_login', '' ) !== '1' ) {
            return;
        }
        if ( is_user_logged_in() ) {
            return;
        }

        // Ausnahmen: Passthrough-Parameter
        $skip_params = array( 'showlogin', 'loggedout', 'oidc_error', 'oidc_callback', 'oidc_link' );
        foreach ( $skip_params as $param ) {
            if ( isset( $_GET[ $param ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Passthrough-Parameter für Auto-Login-Ausnahmen.
                return;
            }
        }

        $action = isset( $_GET['action'] ) ? sanitize_text_field( wp_unslash( $_GET['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $skip_actions = array( 'logout', 'lostpassword', 'rp', 'resetpass' );
        if ( in_array( $action, $skip_actions, true ) ) {
            return;
        }

        do_action( 'oidc_initiate_login' );
    }

    public function render_error_message() {
        if ( ! isset( $_GET['oidc_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Fehleranzeige aus OIDC-Callback, kein sensitives Formular.
            return;
        }
        $error = sanitize_text_field( urldecode( wp_unslash( $_GET['oidc_error'] ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Recommended
        if ( ! empty( $error ) ) {
            printf(
                '<div class="oidc-error"><p>%s</p></div>',
                esc_html( $error )
            );
        }
    }

    public function handle_login_action() {
        if ( ! isset( $_GET['oidc_login'] ) ) {
            return;
        }

        $nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';

        if ( ! wp_verify_nonce( $nonce, 'oidc_login' ) ) {
            wp_die( esc_html__( 'Sicherheitscheck fehlgeschlagen.', 'oidc-client' ) );
        }

        do_action( 'oidc_initiate_login' );
    }
}
