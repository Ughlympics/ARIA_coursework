package aria_test

import (
	"reflect"
	"sym_crypt_course_work/aria"
	"testing"
)

func TestAriaEncryptDecrypt(t *testing.T) {
	plaintext := [4]uint32{
		0x00112233,
		0x44556677,
		0x8899aabb,
		0xccddeeff,
	}

	tests := []struct {
		name       string
		key        []uint32
		cipherText [4]uint32
	}{
		{
			name: "128-bit key",
			key: []uint32{
				0x00010203,
				0x04050607,
				0x08090a0b,
				0x0c0d0e0f,
			},
			cipherText: [4]uint32{
				0xd718fbd6,
				0xab644c73,
				0x9da95f3b,
				0xe6451778,
			},
		},
		{
			name: "192-bit key",
			key: []uint32{
				0x00010203,
				0x04050607,
				0x08090a0b,
				0x0c0d0e0f,
				0x10111213,
				0x14151617,
			},
			cipherText: [4]uint32{
				0x26449c18,
				0x05dbe7aa,
				0x25a468ce,
				0x263a9e79,
			},
		},
		{
			name: "256-bit key",
			key: []uint32{
				0x00010203,
				0x04050607,
				0x08090a0b,
				0x0c0d0e0f,
				0x10111213,
				0x14151617,
				0x18191a1b,
				0x1c1d1e1f,
			},
			cipherText: [4]uint32{
				0xf92bd7c7,
				0x9fb72e2f,
				0x2b8f80c1,
				0x972d24fc,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ariaInstance := aria.NewAria(tt.key)

			// Перевірка шифрування
			encrypted := ariaInstance.Encrypt(ariaInstance, plaintext)
			if !reflect.DeepEqual(encrypted, tt.cipherText) {
				t.Errorf("Encrypt() = %08x, want %08x", encrypted, tt.cipherText)
			}

			// Перевірка розшифрування
			decrypted := ariaInstance.Decrypt(tt.cipherText)
			if !reflect.DeepEqual(decrypted, plaintext) {
				t.Errorf("Decrypt() = %08x, want %08x", decrypted, plaintext)
			}
		})
	}
}

func TestInvalidKeyLength(t *testing.T) {
	invalidKeys := [][]uint32{
		{},                                  // пустий
		{0x00000000},                        // 1 блок
		{0x1, 0x2, 0x3},                     // 96-біт
		{0x1, 0x2, 0x3, 0x4, 0x5},           // не 128/192/256
		{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // 224-біт
	}

	for _, key := range invalidKeys {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic or error for invalid key: %x", key)
			}
		}()
		aria.NewAria(key)
	}
}
