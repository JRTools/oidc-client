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

    protected function setUp(): void {
        parent::setUp();
    }

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
}
