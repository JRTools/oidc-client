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
        $this->assertGreaterThan( time() + 3500, $expires_value );
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
}
