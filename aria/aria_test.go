package aria

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestNewAriaInvalid checks that NewAria returns an error for unsupported key sizes
func TestNewAriaInvalid(t *testing.T) {
	invalidKeys := [][]byte{
		[]byte{},
		[]byte("short"),
		make([]byte, 10),
		make([]byte, 17),
		make([]byte, 31),
		make([]byte, 33),
	}
	for _, key := range invalidKeys {
		_, err := NewAria(key)
		if err == nil {
			t.Errorf("Expected error for key length %d, got nil", len(key))
		}
	}
}

// TestEncryptDecryptRoundtrip tests that encrypting and then decrypting returns the original plaintext
func TestEncryptDecryptRoundtrip(t *testing.T) {
	// test for different key sizes
	keySizes := []int{16, 24, 32}
	// sample plaintext block (16 bytes)
	plaintext := []byte("ABCDEFGHIJKLMNOP")

	for _, k := range keySizes {
		// generate random key of length k
		key := make([]byte, k)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}
		a, err := NewAria(key)
		if err != nil {
			t.Fatalf("NewAria returned error for key size %d: %v", k, err)
		}
		ciphertext := make([]byte, 16)
		a.Encrypt(ciphertext, plaintext)

		decrypted := make([]byte, 16)
		a.Decrypt(decrypted, ciphertext)

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Roundtrip failed for key size %d: got %x, want %x", k, decrypted, plaintext)
		}
	}
}

// TestMultipleBlocks tests that sequential blocks can be encrypted and decrypted independently
func TestMultipleBlocks(t *testing.T) {
	key := []byte("0123456789abcdef") // 16-byte key
	a, err := NewAria(key)
	if err != nil {
		t.Fatalf("NewAria returned error: %v", err)
	}
	// two plaintext blocks
	blocks := [][16]byte{
		{'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '0', '1', '2'},
		{'G', 'o', 'L', 'a', 'n', 'g', 'T', 'e', 's', 't', 'B', 'l', 'o', 'c', 'k', '2'},
	}
	for _, blk := range blocks {
		pt := blk[:]
		ct := make([]byte, 16)
		a.Encrypt(ct, pt)
		dt := make([]byte, 16)
		a.Decrypt(dt, ct)
		if !bytes.Equal(dt, pt) {
			t.Errorf("Block roundtrip failed: got %q, want %q", dt, pt)
		}
	}
}

// TestEncryptPanicsOnShortBuffers ensures that providing buffers shorter than 16 bytes to Encrypt or Decrypt panics as expected.
func TestEncryptPanicsOnShortBuffers(t *testing.T) {
	a, err := NewAria(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	short := make([]byte, 8)
	dst := make([]byte, 16)
	// short src
	if !assertPanic(func() { a.Encrypt(dst, short) }) {
		t.Error("Encrypt did not panic on short src")
	}
	// short dst
	if !assertPanic(func() { a.Encrypt(short, make([]byte, 16)) }) {
		t.Error("Encrypt did not panic on short dst")
	}
	// same tests for Decrypt
	if !assertPanic(func() { a.Decrypt(dst, short) }) {
		t.Error("Decrypt did not panic on short src")
	}
	if !assertPanic(func() { a.Decrypt(short, make([]byte, 16)) }) {
		t.Error("Decrypt did not panic on short dst")
	}
}

// TestDeterministicEncryption ensures Encrypt always produces same ciphertext for same inputs.
func TestDeterministicEncryption(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	a, err := NewAria(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("0123456789ABCDEF")
	ct1 := make([]byte, 16)
	ct2 := make([]byte, 16)
	a.Encrypt(ct1, plaintext)
	a.Encrypt(ct2, plaintext)
	if !bytes.Equal(ct1, ct2) {
		t.Errorf("Deterministic encryption failed: %x vs %x", ct1, ct2)
	}
}

// assertPanic returns true if f() panics.
func assertPanic(f func()) (didPanic bool) {
	defer func() {
		if r := recover(); r != nil {
			didPanic = true
		}
	}()
	f()
	return
}
