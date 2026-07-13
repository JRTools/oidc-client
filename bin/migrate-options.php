<?php
/**
 * WP-CLI-Migrationsskript: oidc_* Options und _oidc_* User-Meta nach jrtools_oidc_* kopieren.
 *
 * Verwendung:
 *   wp eval-file bin/migrate-options.php
 *
 * Was dieses Script tut:
 *   1. Alle oidc_* WordPress-Options in jrtools_oidc_* kopieren (alte Werte bleiben erhalten).
 *   2. Alle _oidc_* User-Meta-Keys für alle Benutzer in _jrtools_oidc_* kopieren (alte Werte bleiben).
 *   3. Zusammenfassung ausgeben.
 */

if ( ! defined( 'ABSPATH' ) ) {
    echo "Dieses Script muss über WP-CLI ausgeführt werden: wp eval-file bin/migrate-options.php\n";
    exit( 1 );
}

$options_migrated = 0;
$options_skipped  = 0;
$meta_migrated    = 0;
$meta_skipped     = 0;

// -------------------------------------------------------------------------
// 1. WordPress Options migrieren
// -------------------------------------------------------------------------

$old_options = array(
    'oidc_discovery_url',
    'oidc_provider_name',
    'oidc_issuer',
    'oidc_authorization_endpoint',
    'oidc_token_endpoint',
    'oidc_userinfo_endpoint',
    'oidc_jwks_uri',
    'oidc_end_session_endpoint',
    'oidc_pkce_supported',
    'oidc_client_id',
    'oidc_client_secret',
    'oidc_scopes',
    'oidc_token_auth_method',
    'oidc_debug_mode',
    'oidc_create_user',
    'oidc_default_role',
    'oidc_enable_refresh',
    'oidc_active_claim',
    'oidc_sync_avatar',
    'oidc_hide_wp_login',
    'oidc_auto_login',
    'oidc_button_icon_url',
    'oidc_token_encryption',
    'oidc_lock_email',
    'oidc_lock_password',
    'oidc_session_management',
    'oidc_remember_me',
    'oidc_role_claim',
    'oidc_role_mapping',
);

echo "=== Migriere WordPress Options ===\n";

foreach ( $old_options as $old_key ) {
    $new_key = 'jrtools_' . $old_key;
    $value   = get_option( $old_key );

    if ( false === $value ) {
        // Option existiert nicht – überspringen
        $options_skipped++;
        continue;
    }

    $existing_new = get_option( $new_key );
    if ( false !== $existing_new ) {
        echo "  ÜBERSPRUNGEN (neu existiert bereits): {$old_key} → {$new_key}\n";
        $options_skipped++;
        continue;
    }

    $result = add_option( $new_key, $value );
    if ( $result ) {
        echo "  OK: {$old_key} → {$new_key}\n";
        $options_migrated++;
    } else {
        echo "  FEHLER: {$old_key} → {$new_key}\n";
    }
}

// -------------------------------------------------------------------------
// 2. User Meta migrieren
// -------------------------------------------------------------------------

$old_meta_keys = array(
    '_oidc_subject',
    '_oidc_id_token',
    '_oidc_access_token',
    '_oidc_access_token_expires',
    '_oidc_refresh_token',
    '_oidc_avatar_url',
    '_oidc_address',
    '_oidc_middle_name',
    '_oidc_profile',
    '_oidc_gender',
    '_oidc_birthdate',
    '_oidc_zoneinfo',
    '_oidc_phone_number',
    '_oidc_phone_number_verified',
    '_oidc_email_verified',
    '_oidc_updated_at',
);

echo "\n=== Migriere User Meta ===\n";

// Alle User-IDs abrufen die mindestens einen der alten Meta-Keys haben
$user_ids = get_users( array(
    'fields'     => 'ID',
    'meta_query' => array(
        'relation' => 'OR',
        array( 'key' => '_oidc_subject', 'compare' => 'EXISTS' ),
    ),
) );

if ( empty( $user_ids ) ) {
    echo "  Keine Benutzer mit _oidc_*-Meta gefunden.\n";
} else {
    echo "  Gefunden: " . count( $user_ids ) . " Benutzer mit OIDC-Meta.\n";

    foreach ( $user_ids as $user_id ) {
        echo "\n  Benutzer ID {$user_id}:\n";
        foreach ( $old_meta_keys as $old_key ) {
            $value = get_user_meta( $user_id, $old_key, true );
            if ( '' === $value || false === $value ) {
                continue;
            }

            $new_key      = '_jrtools' . $old_key; // _oidc_subject → _jrtools_oidc_subject
            $existing_new = get_user_meta( $user_id, $new_key, true );

            if ( '' !== $existing_new && false !== $existing_new ) {
                echo "    ÜBERSPRUNGEN (neu existiert bereits): {$old_key} → {$new_key}\n";
                $meta_skipped++;
                continue;
            }

            $result = update_user_meta( $user_id, $new_key, $value );
            if ( false !== $result ) {
                echo "    OK: {$old_key} → {$new_key}\n";
                $meta_migrated++;
            } else {
                echo "    FEHLER: {$old_key} → {$new_key}\n";
            }
        }
    }
}

// -------------------------------------------------------------------------
// 3. Zusammenfassung
// -------------------------------------------------------------------------

echo "\n=== Zusammenfassung ===\n";
echo "Options migriert:  {$options_migrated}\n";
echo "Options übersprungen: {$options_skipped}\n";
echo "User-Meta migriert:   {$meta_migrated}\n";
echo "User-Meta übersprungen: {$meta_skipped}\n";
echo "\nHinweis: Alte oidc_* Options und _oidc_* Meta-Keys wurden NICHT gelöscht.\n";
echo "Nach erfolgreicher Prüfung können sie manuell entfernt werden.\n";
