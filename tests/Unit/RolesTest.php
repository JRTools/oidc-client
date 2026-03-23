<?php
/**
 * Tests für OIDC_Roles – Rollen-Mapping-Logik.
 *
 * Brain\Monkey mockt get_option, get_user_by und wp_roles.
 * Für get_option werden when()-Stubs verwendet, da die Funktion
 * mehrfach mit unterschiedlichen Argumenten aufgerufen wird.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

class RolesTest extends WpTestCase {

    /** Hilfsmethode: get_option-Stub mit Map registrieren. */
    private function stub_get_option( array $map ) {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) use ( $map ) {
            return array_key_exists( $key, $map ) ? $map[ $key ] : $default;
        } );
    }

    public function test_no_role_claim_option_does_nothing() {
        $this->stub_get_option( array( 'oidc_role_claim' => '' ) );
        Functions\expect( 'get_user_by' )->never();

        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 1, array( 'roles' => array( 'admin' ) ) );
        $this->assertTrue( true );
    }

    public function test_no_claim_in_userinfo_does_nothing() {
        $this->stub_get_option( array( 'oidc_role_claim' => 'roles' ) );
        Functions\expect( 'get_user_by' )->never();

        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 1, array() ); // kein 'roles'-Key
        $this->assertTrue( true );
    }

    public function test_empty_mapping_json_does_nothing() {
        $this->stub_get_option( array(
            'oidc_role_claim'   => 'roles',
            'oidc_role_mapping' => '',
        ) );
        Functions\expect( 'get_user_by' )->never();

        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 1, array( 'roles' => 'editor' ) );
        $this->assertTrue( true );
    }

    public function test_no_matching_mapping_does_not_change_role() {
        $this->stub_get_option( array(
            'oidc_role_claim'   => 'roles',
            'oidc_role_mapping' => json_encode( array( 'admin-group' => 'administrator' ) ),
        ) );

        $user_stub = new WP_User();
        Functions\when( 'get_user_by' )->justReturn( $user_stub );

        // 'other-group' ist nicht im Mapping → sanitize_text_field + wp_roles nie aufgerufen
        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 1, array( 'roles' => 'other-group' ) );

        $this->assertEmpty( $user_stub->get_set_role_calls() );
    }

    public function test_single_match_calls_set_role() {
        $this->stub_get_option( array(
            'oidc_role_claim'   => 'groups',
            'oidc_role_mapping' => json_encode( array( 'editors' => 'editor' ) ),
        ) );

        $user_stub     = new WP_User();
        $user_stub->ID = 5;

        Functions\when( 'get_user_by' )->justReturn( $user_stub );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_roles' )->justReturn( new class {
            public function is_role( $role ) {
                return 'editor' === $role;
            }
        } );

        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 5, array( 'groups' => 'editors' ) );

        $this->assertSame( array( 'editor' ), $user_stub->get_set_role_calls() );
        $this->assertEmpty( $user_stub->get_add_role_calls() );
    }

    public function test_claim_as_array_maps_multiple_roles() {
        $this->stub_get_option( array(
            'oidc_role_claim'   => 'groups',
            'oidc_role_mapping' => json_encode( array(
                'editors' => 'editor',
                'authors' => 'author',
            ) ),
        ) );

        $user_stub     = new WP_User();
        $user_stub->ID = 7;

        Functions\when( 'get_user_by' )->justReturn( $user_stub );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_roles' )->justReturn( new class {
            public function is_role( $role ) {
                return in_array( $role, array( 'editor', 'author' ), true );
            }
        } );

        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 7, array( 'groups' => array( 'editors', 'authors' ) ) );

        $this->assertSame( array( 'editor' ), $user_stub->get_set_role_calls() );
        $this->assertSame( array( 'author' ), $user_stub->get_add_role_calls() );
    }

    public function test_unknown_wp_role_is_skipped() {
        $this->stub_get_option( array(
            'oidc_role_claim'   => 'roles',
            'oidc_role_mapping' => json_encode( array( 'superuser' => 'nonexistent_role' ) ),
        ) );

        $user_stub = new WP_User();
        Functions\when( 'get_user_by' )->justReturn( $user_stub );
        Functions\when( 'sanitize_text_field' )->returnArg();
        Functions\when( 'wp_roles' )->justReturn( new class {
            public function is_role( $role ) {
                return false; // Rolle existiert nicht in WordPress
            }
        } );

        $roles = new OIDC_Roles();
        $roles->apply_role_mapping( 1, array( 'roles' => 'superuser' ) );

        $this->assertEmpty( $user_stub->get_set_role_calls() );
    }
}
