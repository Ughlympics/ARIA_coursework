package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sym_crypt_course_work/aria"
)

func main() {
	showMenu()

	for {
		fmt.Print("\nОберіть опцію: ")
		var input string
		fmt.Scanln(&input)

		switch input {
		case "1":
			listTextFiles()
		case "2":
			encryptFlow()
		case "3":
			decryptFlow()
		case "4":
			showMenu()
		case "0":
			fmt.Println("До побачення!")
			return
		default:
			fmt.Println("Невідома команда. Спробуйте ще раз.")
		}
	}
}

func showMenu() {
	fmt.Println("=== ARIA Шифрувальник ===")
	fmt.Println("1 - Показати всі .txt файли в поточній директорії")
	fmt.Println("2 - Зашифрувати файл (вибір plaintext, ключа, вихідного файлу)")
	fmt.Println("3 - Розшифрувати файл (вибір ciphertext, ключа, вихідного файлу)")
	fmt.Println("4 - Показати це меню ще раз")
	fmt.Println("0 - Вийти")
}

func listTextFiles() {
	files, err := filepath.Glob("*.txt")
	if err != nil || len(files) == 0 {
		fmt.Println("Файли *.txt не знайдено.")
		return
	}
	for i, f := range files {
		fmt.Printf("%d: %s\n", i, f)
	}
}

func selectFile(prompt string) string {
	files, _ := filepath.Glob("*.txt")
	if len(files) == 0 {
		fmt.Println("Файли *.txt не знайдено.")
		return ""
	}

	fmt.Println(prompt)
	for i, f := range files {
		fmt.Printf("%d: %s\n", i, f)
	}

	var index int
	fmt.Print("Введіть номер файлу: ")
	fmt.Scanln(&index)

	if index < 0 || index >= len(files) {
		fmt.Println("Неправильний вибір.")
		return ""
	}

	return files[index]
}

func readFileAsUint32Blocks(filename string) ([][4]uint32, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	blocks := [][4]uint32{}
	for i := 0; i+16 <= len(data); i += 16 {
		block := [4]uint32{}
		for j := 0; j < 4; j++ {
			block[j] = uint32(data[i+4*j])<<24 |
				uint32(data[i+4*j+1])<<16 |
				uint32(data[i+4*j+2])<<8 |
				uint32(data[i+4*j+3])
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

func writeBlocksToFile(blocks [][4]uint32, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, b := range blocks {
		for _, word := range b {
			f.Write([]byte{
				byte(word >> 24),
				byte(word >> 16),
				byte(word >> 8),
				byte(word),
			})
		}
	}
	return nil
}

func readKeyFromFile(filename string) ([]uint32, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	keyString := strings.TrimSpace(string(data))
	key, err := parseKeyStringToUint32Slice(keyString)
	if err != nil {
		return nil, err
	}
	if len(key) != 4 && len(key) != 6 && len(key) != 8 {
		return nil, fmt.Errorf("ключ має бути 128, 192 або 256 біт (4, 6 або 8 слів)")
	}
	return key, nil
}

func encryptFlow() {
	plaintextFile := selectFile("Виберіть файл з plaintext:")
	keyFile := selectFile("Виберіть файл з ключем:")
	outputFile := selectOutput("Введіть назву вихідного файлу:")

	if plaintextFile == "" || keyFile == "" || outputFile == "" {
		return
	}

	plaintextBlocks, err := readFileAsUint32Blocks(plaintextFile)
	if err != nil {
		fmt.Println("Помилка читання:", err)
		return
	}

	key, err := readKeyFromFile(keyFile)
	if err != nil {
		fmt.Println("Помилка читання ключа:", err)
		return
	}
	a := aria.NewAria(key)

	var result [][4]uint32
	for _, block := range plaintextBlocks {
		result = append(result, a.Encrypt(a, block))
	}

	writeBlocksToFile(result, outputFile)
	fmt.Println("Файл зашифровано в", outputFile)
}

func decryptFlow() {
	ciphertextFile := selectFile("Виберіть файл з ciphertext:")
	keyFile := selectFile("Виберіть файл з ключем:")
	outputFile := selectOutput("Введіть назву вихідного файлу:")

	if ciphertextFile == "" || keyFile == "" || outputFile == "" {
		return
	}

	ciphertextBlocks, err := readFileAsUint32Blocks(ciphertextFile)
	if err != nil {
		fmt.Println("Помилка читання:", err)
		return
	}

	key, err := readKeyFromFile(keyFile)
	if err != nil {
		fmt.Println("Помилка читання ключа:", err)
		return
	}
	a := aria.NewAria(key)

	var result [][4]uint32
	for _, block := range ciphertextBlocks {
		result = append(result, a.Decrypt(block))
	}

	writeBlocksToFile(result, outputFile)
	fmt.Println("Файл розшифровано в", outputFile)
}

func selectOutput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	name, _ := reader.ReadString('\n')
	return strings.TrimSpace(name)
}

func parseKeyStringToUint32Slice(s string) ([]uint32, error) {
	if len(s)%8 != 0 {
		return nil, fmt.Errorf("рядок має бути кратний 8 символам (32 бітам)")
	}

	var result []uint32
	for i := 0; i < len(s); i += 8 {
		part := s[i : i+8]
		val, err := strconv.ParseUint(part, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("неможливо конвертувати '%s': %v", part, err)
		}
		result = append(result, uint32(val))
	}
	return result, nil
}

// func main() {
// 	//000102030405060708090a0b0c0d0e0f
// 	key1 := []uint32{
// 		0x00010203,
// 		0x04050607,
// 		0x08090a0b,
// 		0x0c0d0e0f,
// 	}

// 	//00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617
// 	key2 := []uint32{
// 		0x00010203,
// 		0x04050607,
// 		0x08090a0b,
// 		0x0c0d0e0f,
// 		0x10111213,
// 		0x14151617,
// 	}

// 	//00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f
// 	key3 := []uint32{
// 		0x00010203,
// 		0x04050607,
// 		0x08090a0b,
// 		0x0c0d0e0f,
// 		0x10111213,
// 		0x14151617,
// 		0x18191a1b,
// 		0x1c1d1e1f,
// 	}

// 	//00112233 44556677 8899aabb ccddeeff
// 	plaintext := [4]uint32{
// 		0x00112233,
// 		0x44556677,
// 		0x8899aabb,
// 		0xccddeeff,
// 	}

// 	//d718fbd6 ab644c73 9da95f3b e6451778
// 	cyphertext1 := [4]uint32{
// 		0xd718fbd6,
// 		0xab644c73,
// 		0x9da95f3b,
// 		0xe6451778,
// 	}

// 	//26449c18 05dbe7aa 25a468ce 263a9e79
// 	cyphertext2 := [4]uint32{
// 		0x26449c18,
// 		0x05dbe7aa,
// 		0x25a468ce,
// 		0x263a9e79,
// 	}

// 	//f92bd7c7 9fb72e2f 2b8f80c1 972d24fc
// 	cyphertext3 := [4]uint32{
// 		0xf92bd7c7,
// 		0x9fb72e2f,
// 		0x2b8f80c1,
// 		0x972d24fc,
// 	}

// 	aria1 := aria.NewAria(key1)
// 	aria2 := aria.NewAria(key2)
// 	aria3 := aria.NewAria(key3)

// 	cipherText1 := aria1.Encrypt(aria1, plaintext)
// 	p1 := aria1.Decrypt(cyphertext1)

// 	cipherText2 := aria2.Encrypt(aria2, plaintext)
// 	p2 := aria2.Decrypt(cyphertext2)

// 	cipherText3 := aria3.Encrypt(aria3, plaintext)
// 	p3 := aria3.Decrypt(cyphertext3)

// 	fmt.Println("Шифротекст для 128bit ключа:")
// 	fmt.Printf("%08x %08x %08x %08x\n", cipherText1[0], cipherText1[1], cipherText1[2], cipherText1[3])
// 	fmt.Println("Розшифрований текст для 128 ключа:")
// 	fmt.Printf("%08x %08x %08x %08x\n", p1[0], p1[1], p1[2], p1[3])

// 	fmt.Println("Шифротекст для 192bit ключа:")
// 	fmt.Printf("%08x %08x %08x %08x\n", cipherText2[0], cipherText2[1], cipherText2[2], cipherText2[3])
// 	fmt.Println("Розшифрований текст для 192bit ключа:")
// 	fmt.Printf("%08x %08x %08x %08x\n", p2[0], p2[1], p2[2], p2[3])

// 	fmt.Println("Шифротекст для 256bit ключа:")
// 	fmt.Printf("%08x %08x %08x %08x\n", cipherText3[0], cipherText3[1], cipherText3[2], cipherText3[3])
// 	fmt.Println("Розшифрований текст для 256bit ключа:")
// 	fmt.Printf("%08x %08x %08x %08x\n", p3[0], p3[1], p3[2], p3[3])

// }
