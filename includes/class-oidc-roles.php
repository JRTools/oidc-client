<?php
/**
 * OIDC Client – Rollen-Mapping
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class OIDC_Roles {

    /**
     * Rollen des Benutzers anhand eines Claims aus dem Userinfo-Response setzen.
     *
     * @param int   $user_id
     * @param array $userinfo
     */
    public function apply_role_mapping( $user_id, $userinfo ) {
        $role_claim = get_option( 'jrtools_oidc_role_claim', '' );

        if ( empty( $role_claim ) ) {
            return;
        }

        if ( ! isset( $userinfo[ $role_claim ] ) ) {
            return;
        }

        $mapping_json = get_option( 'jrtools_oidc_role_mapping', '' );
        if ( empty( $mapping_json ) ) {
            return;
        }

        $mapping = json_decode( $mapping_json, true );
        if ( ! is_array( $mapping ) ) {
            return;
        }

        // Claim-Wert normalisieren: immer als Array behandeln
        $claim_values = $userinfo[ $role_claim ];
        if ( ! is_array( $claim_values ) ) {
            $claim_values = array( $claim_values );
        }

        $user = get_user_by( 'id', $user_id );
        if ( ! $user ) {
            return;
        }

        // Alle WordPress-Rollen ermitteln, die via Mapping erreichbar sind
        $mapped_roles = array();
        foreach ( $claim_values as $value ) {
            $value = (string) $value;
            if ( isset( $mapping[ $value ] ) && ! empty( $mapping[ $value ] ) ) {
                $wp_role = sanitize_text_field( $mapping[ $value ] );
                if ( ! empty( $wp_role ) && wp_roles()->is_role( $wp_role ) ) {
                    $mapped_roles[] = $wp_role;
                }
            }
        }

        if ( empty( $mapped_roles ) ) {
            return;
        }

        // Erste gemappte Rolle als primäre Rolle setzen, weitere hinzufügen
        $user->set_role( $mapped_roles[0] );
        for ( $i = 1; $i < count( $mapped_roles ); $i++ ) {
            $user->add_role( $mapped_roles[ $i ] );
        }
    }
}
