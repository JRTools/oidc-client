<?php
/**
 * OIDC Client – Login-Log (Datenbank-Tabelle + Admin-Seite)
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Log {

    public function __construct() {
        add_action( 'admin_menu', array( $this, 'add_log_page' ) );
    }

    // -------------------------------------------------------------------------
    // Tabelle anlegen (Activation Hook)
    // -------------------------------------------------------------------------

    public static function install() {
        global $wpdb;

        $table           = $wpdb->prefix . 'oidc_login_log';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id         BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id    BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            timestamp  DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip         VARCHAR(45)         NOT NULL DEFAULT '',
            success    TINYINT(1)          NOT NULL DEFAULT 0,
            message    VARCHAR(500)        NOT NULL DEFAULT '',
            PRIMARY KEY (id),
            KEY user_id  (user_id),
            KEY timestamp (timestamp)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    // -------------------------------------------------------------------------
    // Log-Eintrag schreiben
    // -------------------------------------------------------------------------

    public static function write( $user_id, $success, $message ) {
        global $wpdb;

        $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Log-Tabelle, bewusst kein Caching.
            $wpdb->prefix . 'oidc_login_log',
            array(
                'user_id'   => (int) $user_id,
                'timestamp' => current_time( 'mysql' ),
                'ip'        => self::get_client_ip(),
                'success'   => $success ? 1 : 0,
                'message'   => mb_substr( (string) $message, 0, 500 ),
            ),
            array( '%d', '%s', '%s', '%d', '%s' )
        );
    }

    private static function get_client_ip() {
        // X-Forwarded-For nur als Hinweis, REMOTE_ADDR ist verlässlich
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
        if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return $ip;
        }
        return '';
    }

    // -------------------------------------------------------------------------
    // Admin-Menü
    // -------------------------------------------------------------------------

    public function add_log_page() {
        add_management_page(
            __( 'OIDC Login-Log', 'oidc-client' ),
            __( 'OIDC Login-Log', 'oidc-client' ),
            'manage_options',
            'oidc-login-log',
            array( $this, 'render_log_page' )
        );
    }

    public function render_log_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Keine Berechtigung.', 'oidc-client' ) );
        }

        global $wpdb;

        $per_page = 25;
        $page     = max( 1, (int) ( isset( $_GET['paged'] ) ? sanitize_text_field( wp_unslash( $_GET['paged'] ) ) : 1 ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $offset   = ( $page - 1 ) * $per_page;
        $table    = $wpdb->prefix . 'oidc_login_log';

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table ist intern generiert, kein User-Input. Log-Daten werden bewusst nicht gecacht.
        $items = $wpdb->get_results( $wpdb->prepare(
            "SELECT l.*, u.user_login
             FROM {$table} l
             LEFT JOIN {$wpdb->users} u ON l.user_id = u.ID
             ORDER BY l.timestamp DESC
             LIMIT %d OFFSET %d",
            $per_page,
            $offset
        ) );
        // phpcs:enable

        $total       = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total_pages = max( 1, (int) ceil( $total / $per_page ) );

        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'OIDC Login-Log', 'oidc-client' ); ?></h1>
            <p class="description">
                <?php
                /* translators: %d: Anzahl der Log-Einträge */
                printf(
                    esc_html__( '%d Einträge gesamt', 'oidc-client' ),
                    (int) $total // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- int-cast, kein User-Input.
                );
                ?>
            </p>

            <?php if ( empty( $items ) ) : ?>
                <p><?php esc_html_e( 'Noch keine Einträge vorhanden.', 'oidc-client' ); ?></p>
            <?php else : ?>

            <table class="widefat striped oidc-log-table">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Zeitstempel', 'oidc-client' ); ?></th>
                        <th><?php esc_html_e( 'Benutzer', 'oidc-client' ); ?></th>
                        <th><?php esc_html_e( 'IP-Adresse', 'oidc-client' ); ?></th>
                        <th><?php esc_html_e( 'Status', 'oidc-client' ); ?></th>
                        <th><?php esc_html_e( 'Meldung', 'oidc-client' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $items as $item ) : ?>
                    <tr>
                        <td><?php echo esc_html( $item->timestamp ); ?></td>
                        <td>
                            <?php if ( $item->user_id && $item->user_login ) : ?>
                                <a href="<?php echo esc_url( get_edit_user_link( $item->user_id ) ); ?>">
                                    <?php echo esc_html( $item->user_login ); ?>
                                </a>
                            <?php else : ?>
                                <em><?php esc_html_e( 'unbekannt', 'oidc-client' ); ?></em>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html( $item->ip ); ?></td>
                        <td>
                            <?php if ( $item->success ) : ?>
                                <span class="oidc-log-success">&#10003; <?php esc_html_e( 'Erfolg', 'oidc-client' ); ?></span>
                            <?php else : ?>
                                <span class="oidc-log-failure">&#10007; <?php esc_html_e( 'Fehler', 'oidc-client' ); ?></span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html( $item->message ); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <div class="tablenav bottom">
                <div class="tablenav-pages">
                    <?php
                    echo wp_kses_post( paginate_links( array( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links() gibt intern escaped HTML zurück.
                        'base'      => add_query_arg( 'paged', '%#%' ),
                        'format'    => '',
                        'prev_text' => '&laquo;',
                        'next_text' => '&raquo;',
                        'total'     => $total_pages,
                        'current'   => $page,
                    ) ) );
                    ?>
                </div>
            </div>

            <?php endif; ?>
        </div>
        <?php
    }
}
