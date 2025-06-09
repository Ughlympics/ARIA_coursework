package main

import (
	"fmt"
	"sym_crypt_course_work/aria"
)

func main() {
	//000102030405060708090a0b0c0d0e0f
	key1 := []uint32{
		0x00010203,
		0x04050607,
		0x08090a0b,
		0x0c0d0e0f,
	}

	//00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617
	key2 := []uint32{
		0x00010203,
		0x04050607,
		0x08090a0b,
		0x0c0d0e0f,
		0x10111213,
		0x14151617,
	}

	//00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f
	key3 := []uint32{
		0x00010203,
		0x04050607,
		0x08090a0b,
		0x0c0d0e0f,
		0x10111213,
		0x14151617,
		0x18191a1b,
		0x1c1d1e1f,
	}

	//00112233 44556677 8899aabb ccddeeff
	plaintext := [4]uint32{
		0x00112233,
		0x44556677,
		0x8899aabb,
		0xccddeeff,
	}

	//d718fbd6 ab644c73 9da95f3b e6451778
	cyphertext1 := [4]uint32{
		0xd718fbd6,
		0xab644c73,
		0x9da95f3b,
		0xe6451778,
	}

	//26449c18 05dbe7aa 25a468ce 263a9e79
	cyphertext2 := [4]uint32{
		0x26449c18,
		0x05dbe7aa,
		0x25a468ce,
		0x263a9e79,
	}

	//f92bd7c7 9fb72e2f 2b8f80c1 972d24fc
	cyphertext3 := [4]uint32{
		0xf92bd7c7,
		0x9fb72e2f,
		0x2b8f80c1,
		0x972d24fc,
	}

	aria1 := aria.NewAria(key1)
	aria2 := aria.NewAria(key2)
	aria3 := aria.NewAria(key3)

	cipherText1 := aria1.Encrypt(aria1, plaintext)
	p1 := aria1.Decrypt(cyphertext1)

	cipherText2 := aria2.Encrypt(aria2, plaintext)
	p2 := aria2.Decrypt(cyphertext2)

	cipherText3 := aria3.Encrypt(aria3, plaintext)
	p3 := aria3.Decrypt(cyphertext3)

	fmt.Println("Шифротекст для 128bit ключа:")
	fmt.Printf("%08x %08x %08x %08x\n", cipherText1[0], cipherText1[1], cipherText1[2], cipherText1[3])
	fmt.Println("Розшифрований текст для 128 ключа:")
	fmt.Printf("%08x %08x %08x %08x\n", p1[0], p1[1], p1[2], p1[3])

	fmt.Println("Шифротекст для 192bit ключа:")
	fmt.Printf("%08x %08x %08x %08x\n", cipherText2[0], cipherText2[1], cipherText2[2], cipherText2[3])
	fmt.Println("Розшифрований текст для 192bit ключа:")
	fmt.Printf("%08x %08x %08x %08x\n", p2[0], p2[1], p2[2], p2[3])

	fmt.Println("Шифротекст для 256bit ключа:")
	fmt.Printf("%08x %08x %08x %08x\n", cipherText3[0], cipherText3[1], cipherText3[2], cipherText3[3])
	fmt.Println("Розшифрований текст для 256bit ключа:")
	fmt.Printf("%08x %08x %08x %08x\n", p3[0], p3[1], p3[2], p3[3])

}
