<?php
/**
 * Tests für OIDC_Tokens – Fokus auf encrypt/decrypt-Logik.
 *
 * Private Methoden werden über Reflexion getestet.
 * Brain\Monkey mockt get_option, get_user_meta, update_user_meta.
 */

require_once __DIR__ . '/WpTestCase.php';

use Brain\Monkey\Functions;

class TokensTest extends WpTestCase {

    // Hilfsmethode: private Methode via Reflexion aufrufen
    private function call_private( $object, $method, ...$args ) {
        $ref = new ReflectionObject( $object );
        $m   = $ref->getMethod( $method );
        $m->setAccessible( true );
        return $m->invoke( $object, ...$args );
    }

    // -------------------------------------------------------------------------
    // decrypt
    // -------------------------------------------------------------------------

    public function test_decrypt_empty_string_returns_empty() {
        $tokens = new OIDC_Tokens();
        $result = $this->call_private( $tokens, 'decrypt', '' );
        $this->assertSame( '', $result );
    }

    public function test_decrypt_plaintext_without_prefix_passthrough() {
        $tokens = new OIDC_Tokens();
        $result = $this->call_private( $tokens, 'decrypt', 'plain.access.token' );
        $this->assertSame( 'plain.access.token', $result );
    }

    public function test_decrypt_short_enc_data_returns_empty() {
        $tokens = new OIDC_Tokens();
        // "enc:" + zu kurze Base64-Daten (weniger als 16 Byte nach Dekodierung)
        $short  = 'enc:' . base64_encode( 'tooshort' );
        $result = $this->call_private( $tokens, 'decrypt', $short );
        $this->assertSame( '', $result );
    }

    // -------------------------------------------------------------------------
    // encrypt
    // -------------------------------------------------------------------------

    public function test_encrypt_disabled_returns_plaintext() {
        Functions\when( 'get_option' )->justReturn( '' );

        $tokens = new OIDC_Tokens();
        $result = $this->call_private( $tokens, 'encrypt', 'my-token' );
        $this->assertSame( 'my-token', $result );
    }

    public function test_encrypt_empty_string_returns_empty() {
        Functions\when( 'get_option' )->justReturn( '1' );

        $tokens = new OIDC_Tokens();
        $result = $this->call_private( $tokens, 'encrypt', '' );
        $this->assertSame( '', $result );
    }

    public function test_encrypt_adds_enc_prefix() {
        Functions\when( 'get_option' )->justReturn( '1' );

        $tokens = new OIDC_Tokens();
        $result = $this->call_private( $tokens, 'encrypt', 'test-token-value' );
        $this->assertStringStartsWith( 'enc:', $result );
    }

    public function test_encrypt_decrypt_roundtrip() {
        Functions\when( 'get_option' )->justReturn( '1' );

        $tokens    = new OIDC_Tokens();
        $plaintext = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig';

        $encrypted = $this->call_private( $tokens, 'encrypt', $plaintext );
        $this->assertStringStartsWith( 'enc:', $encrypted );
        $this->assertNotSame( $plaintext, $encrypted );

        $decrypted = $this->call_private( $tokens, 'decrypt', $encrypted );
        $this->assertSame( $plaintext, $decrypted );
    }

    public function test_encrypt_produces_different_ciphertext_each_time() {
        Functions\when( 'get_option' )->justReturn( '1' );

        $tokens = new OIDC_Tokens();
        $enc1   = $this->call_private( $tokens, 'encrypt', 'same-token' );
        $enc2   = $this->call_private( $tokens, 'encrypt', 'same-token' );

        // IV ist zufällig → Ciphertext muss sich unterscheiden
        $this->assertNotSame( $enc1, $enc2 );

        // Aber beide müssen korrekt entschlüsseln
        $this->assertSame( 'same-token', $this->call_private( $tokens, 'decrypt', $enc1 ) );
        $this->assertSame( 'same-token', $this->call_private( $tokens, 'decrypt', $enc2 ) );
    }

    // -------------------------------------------------------------------------
    // get_id_token
    // -------------------------------------------------------------------------

    public function test_get_id_token_returns_empty_when_no_meta() {
        Functions\expect( 'get_user_meta' )
            ->once()
            ->with( 1, '_oidc_id_token', true )
            ->andReturn( '' );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_id_token( 1 );
        $this->assertSame( '', $result );
    }

    public function test_get_id_token_decrypts_stored_value() {
        Functions\when( 'get_option' )->justReturn( '1' );

        $tokens      = new OIDC_Tokens();
        $plaintext   = 'the-id-token';
        $encrypted   = $this->call_private( $tokens, 'encrypt', $plaintext );

        Functions\expect( 'get_user_meta' )
            ->once()
            ->with( 42, '_oidc_id_token', true )
            ->andReturn( $encrypted );

        $result = $tokens->get_id_token( 42 );
        $this->assertSame( $plaintext, $result );
    }

    // -------------------------------------------------------------------------
    // store_tokens
    // -------------------------------------------------------------------------

    public function test_store_tokens_only_saves_id_token_when_refresh_disabled() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_enable_refresh' ) {
                return '';
            }
            if ( $key === 'oidc_token_encryption' ) {
                return '';
            }
            return $default;
        } );

        Functions\expect( 'update_user_meta' )
            ->once()
            ->with( 1, '_oidc_id_token', 'my-id-token' );

        $tokens = new OIDC_Tokens();
        $tokens->store_tokens( 1, array(
            'id_token'     => 'my-id-token',
            'access_token' => 'my-access-token',
            'refresh_token' => 'my-refresh-token',
        ) );
        $this->addToAssertionCount( 1 );
    }

    public function test_store_tokens_saves_all_tokens_when_refresh_enabled() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_enable_refresh' ) {
                return '1';
            }
            if ( $key === 'oidc_token_encryption' ) {
                return '';
            }
            return $default;
        } );

        $update_calls = array();
        Functions\when( 'update_user_meta' )->alias( function ( $_user_id, $meta_key, $_value ) use ( &$update_calls ) {
            $update_calls[] = $meta_key;
        } );

        $tokens = new OIDC_Tokens();
        $tokens->store_tokens( 1, array(
            'id_token'     => 'id-t',
            'access_token' => 'acc-t',
            'refresh_token' => 'ref-t',
            'expires_in'   => 3600,
        ) );

        $this->assertContains( '_oidc_id_token', $update_calls );
        $this->assertContains( '_oidc_access_token', $update_calls );
        $this->assertContains( '_oidc_refresh_token', $update_calls );
        $this->assertContains( '_oidc_access_token_expires', $update_calls );
    }

    public function test_store_tokens_skips_missing_id_token() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_enable_refresh' ) {
                return '';
            }
            return $default;
        } );

        Functions\expect( 'update_user_meta' )->never();

        $tokens = new OIDC_Tokens();
        $tokens->store_tokens( 1, array() );
        $this->addToAssertionCount( 1 );
    }

    public function test_store_tokens_default_expires_in_when_missing() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_enable_refresh' ) {
                return '1';
            }
            if ( $key === 'oidc_token_encryption' ) {
                return '';
            }
            return $default;
        } );

        $expires_value = null;
        Functions\when( 'update_user_meta' )->alias( function ( $_user_id, $meta_key, $value ) use ( &$expires_value ) {
            if ( $meta_key === '_oidc_access_token_expires' ) {
                $expires_value = $value;
            }
        } );

        $tokens = new OIDC_Tokens();
        $tokens->store_tokens( 1, array( 'access_token' => 'acc' ) );

        $this->assertNotNull( $expires_value );
        $this->assertGreaterThan( time() + 3500, (int) $expires_value );
    }

    // -------------------------------------------------------------------------
    // clear_tokens / clear_all_tokens
    // -------------------------------------------------------------------------

    public function test_clear_tokens_deletes_access_and_refresh_meta() {
        $deleted = array();
        Functions\when( 'delete_user_meta' )->alias( function ( $_user_id, $meta_key ) use ( &$deleted ) {
            $deleted[] = $meta_key;
        } );

        $tokens = new OIDC_Tokens();
        $tokens->clear_tokens( 99 );

        $this->assertContains( '_oidc_access_token', $deleted );
        $this->assertContains( '_oidc_access_token_expires', $deleted );
        $this->assertContains( '_oidc_refresh_token', $deleted );
        $this->assertNotContains( '_oidc_id_token', $deleted );
    }

    public function test_clear_all_tokens_also_deletes_id_token() {
        $deleted = array();
        Functions\when( 'delete_user_meta' )->alias( function ( $_user_id, $meta_key ) use ( &$deleted ) {
            $deleted[] = $meta_key;
        } );

        $tokens = new OIDC_Tokens();
        $tokens->clear_all_tokens( 99 );

        $this->assertContains( '_oidc_access_token', $deleted );
        $this->assertContains( '_oidc_refresh_token', $deleted );
        $this->assertContains( '_oidc_id_token', $deleted );
    }

    // -------------------------------------------------------------------------
    // get_valid_access_token
    // -------------------------------------------------------------------------

    public function test_get_valid_access_token_returns_token_when_valid() {
        Functions\when( 'get_option' )->justReturn( '' );

        Functions\when( 'get_user_meta' )->alias( function ( $_user_id, $meta_key, $_single ) {
            if ( $meta_key === '_oidc_access_token' ) {
                return 'valid-access-token';
            }
            if ( $meta_key === '_oidc_access_token_expires' ) {
                return (string) ( time() + 3600 );
            }
            return '';
        } );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertSame( 'valid-access-token', $result );
    }

    public function test_get_valid_access_token_returns_error_when_no_refresh_token() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            return $default; // oidc_token_encryption = ''
        } );

        Functions\when( 'get_user_meta' )->alias( function ( $_user_id, $meta_key, $_single ) {
            if ( $meta_key === '_oidc_access_token' ) {
                return ''; // kein Token
            }
            if ( $meta_key === '_oidc_access_token_expires' ) {
                return '0';
            }
            if ( $meta_key === '_oidc_refresh_token' ) {
                return ''; // kein Refresh-Token
            }
            return '';
        } );

        Functions\when( '__' )->returnArg();

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'no_refresh_token', $result->get_error_code() );
    }

    /** Hilfsmethode: get_user_meta-Alias mit abgelaufenem Access-Token und vorhandenem Refresh-Token. */
    private function expiredTokenMeta( string $refresh_token ): callable {
        return function ( $_user_id, $meta_key, $_single ) use ( $refresh_token ) {
            if ( $meta_key === '_oidc_access_token' ) { return ''; }
            if ( $meta_key === '_oidc_access_token_expires' ) { return '0'; }
            if ( $meta_key === '_oidc_refresh_token' ) { return $refresh_token; }
            return '';
        };
    }

    public function test_get_valid_access_token_returns_wp_error_on_http_failure() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'get_user_meta' )->alias( $this->expiredTokenMeta( 'my-refresh-token' ) );
        Functions\when( '__' )->returnArg();

        $http_error = new WP_Error( 'http_request_failed', 'Connection refused' );
        Functions\when( 'wp_remote_post' )->justReturn( $http_error );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) {
            return $thing instanceof WP_Error;
        } );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'http_request_failed', $result->get_error_code() );
    }

    public function test_get_valid_access_token_returns_error_on_provider_error_response() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'get_user_meta' )->alias( $this->expiredTokenMeta( 'my-refresh-token' ) );
        Functions\when( '__' )->returnArg();
        Functions\when( 'sanitize_text_field' )->returnArg();

        Functions\when( 'wp_remote_post' )->justReturn( array( 'response' => array( 'code' => 400 ) ) );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) { return $thing instanceof WP_Error; } );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'error' => 'invalid_grant', 'error_description' => 'Token expired' ) )
        );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'refresh_error', $result->get_error_code() );
    }

    public function test_get_valid_access_token_returns_error_when_access_token_missing_in_response() {
        Functions\when( 'get_option' )->justReturn( '' );
        Functions\when( 'get_user_meta' )->alias( $this->expiredTokenMeta( 'my-refresh-token' ) );
        Functions\when( '__' )->returnArg();

        Functions\when( 'wp_remote_post' )->justReturn( array( 'response' => array( 'code' => 200 ) ) );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) { return $thing instanceof WP_Error; } );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( json_encode( array( 'token_type' => 'Bearer' ) ) );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertSame( 'refresh_failed', $result->get_error_code() );
    }

    public function test_get_valid_access_token_refreshes_with_client_secret_post() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'my-client'; }
            if ( $key === 'oidc_client_secret' )     { return 'my-secret'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_post'; }
            return $default;
        } );
        Functions\when( 'get_user_meta' )->alias( $this->expiredTokenMeta( 'my-refresh-token' ) );
        Functions\when( 'update_user_meta' )->justReturn( true );

        Functions\when( 'wp_remote_post' )->justReturn( array( 'response' => array( 'code' => 200 ) ) );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) { return $thing instanceof WP_Error; } );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'access_token' => 'new-access-token', 'expires_in' => 3600 ) )
        );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertSame( 'new-access-token', $result );
    }

    public function test_get_valid_access_token_refreshes_with_client_secret_basic() {
        Functions\when( 'get_option' )->alias( function ( $key, $default = '' ) {
            if ( $key === 'oidc_token_endpoint' )    { return 'https://provider.example.com/token'; }
            if ( $key === 'oidc_client_id' )         { return 'my-client'; }
            if ( $key === 'oidc_client_secret' )     { return 'my-secret'; }
            if ( $key === 'oidc_token_auth_method' ) { return 'client_secret_basic'; }
            return $default;
        } );
        Functions\when( 'get_user_meta' )->alias( $this->expiredTokenMeta( 'my-refresh-token' ) );
        Functions\when( 'update_user_meta' )->justReturn( true );

        $captured_args = null;
        Functions\when( 'wp_remote_post' )->alias( function ( $url, $args ) use ( &$captured_args ) {
            $captured_args = $args;
            return array( 'response' => array( 'code' => 200 ) );
        } );
        Functions\when( 'is_wp_error' )->alias( function ( $thing ) { return $thing instanceof WP_Error; } );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn(
            json_encode( array( 'access_token' => 'new-access-token', 'expires_in' => 3600 ) )
        );

        $tokens = new OIDC_Tokens();
        $result = $tokens->get_valid_access_token( 1 );

        $this->assertSame( 'new-access-token', $result );
        $this->assertArrayHasKey( 'Authorization', $captured_args['headers'] );
        $this->assertStringStartsWith( 'Basic ', $captured_args['headers']['Authorization'] );
        $this->assertArrayNotHasKey( 'client_secret', $captured_args['body'] );
    }
}
