package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sym_crypt_course_work/aria"
)

// func main() {

// 	reader := bufio.NewReader(os.Stdin)

// 	fmt.Println("Hi! Welcome into ARIA cypher utility.")
// 	fmt.Println("Choose option:")
// 	printMenu()

// 	for {
// 		input, _ := reader.ReadString('\n')
// 		input = strings.TrimSpace(input)

// 		switch input {
// 		case "1":
// 			describeProgram()
// 		case "2":
// 			showDirectoryFiles()
// 		case "3":
// 			encryptFile()
// 		case "4":
// 			decryptFile()
// 		case "5":
// 			printMenu()
// 		case "0":
// 			fmt.Println("Bye bye.")
// 			return
// 		default:
// 			fmt.Println("Choose something else or exit.")
// 		}

// 		fmt.Println()
// 	}
// }

// func printMenu() {
// 	fmt.Println("1 - Description of the program")
// 	fmt.Println("2 - Show directory files")
// 	fmt.Println("3 - Encrypt .txt file")
// 	fmt.Println("4 - Decrypt .txt file")
// 	fmt.Println("5 - Help")
// 	fmt.Println("0 - Exit")
// }

// func describeProgram() {
// 	fmt.Println("ARIA — is a block cipher developed in South Korea.")
// 	fmt.Println("Supports 128, 192 and 256 bit keys. Used to protect data.")
// 	fmt.Println("The program allows you to encrypt and decrypt .txt files using the ARIA algorithm.")
// 	fmt.Println()
// 	fmt.Println("Operating Principle:")
// 	fmt.Println("  In the same directory as the executable, you must have three .txt files:")
// 	fmt.Println("    • plaintext.txt   – contains the data to encrypt (16‑byte blocks separated by spaces)")
// 	fmt.Println("    • keys.txt        – either a single key for all blocks,")
// 	fmt.Println("                        or one key per block (matching the number of plaintext blocks)")
// 	fmt.Println("    • ciphertext.txt  – will receive the encrypted output")
// 	fmt.Println()
// 	fmt.Println("File Requirements:")
// 	fmt.Println("  • Plaintext is split into 16‑byte blocks, each block separated by a single space.")
// 	fmt.Println("  • Keys file may contain:")
// 	fmt.Println("      – One key, applied to all blocks,")
// 	fmt.Println("      – Or N keys for N blocks, so each block is encrypted independently.")
// 	fmt.Println()
// 	fmt.Println("Press 5 to get menu")

// }

// func showDirectoryFiles() {
// 	files, err := os.ReadDir(".")
// 	if err != nil {
// 		fmt.Println("Ups, you should read desription :)", err)
// 		return
// 	}

// 	fmt.Println(" .txt files in main directory:")
// 	found := false
// 	for _, file := range files {
// 		if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
// 			fmt.Println(" -", file.Name())
// 			found = true
// 		}
// 	}

// 	if !found {
// 		fmt.Println("No .txt files.")
// 	}
// }

func main() {
	keyHex := "000102030405060708090a0b0c0d0e0f"
	plaintextHex := "00112233445566778899aabbccddeeff"
	expectedCipherHex := "d718fbd6ab644c739da95f3be6451778"

	// Конвертация hex-строк в []byte
	key, _ := hex.DecodeString(keyHex)
	plaintext, _ := hex.DecodeString(plaintextHex)
	expectedCipher, _ := hex.DecodeString(expectedCipherHex)

	// Создание блока ARIA
	block, err := aria.NewAria(key)
	if err != nil {
		panic(err)
	}

	// Шифрование
	ciphertext := make([]byte, 16)
	block.Encrypt(ciphertext, plaintext)

	// Расшифровка
	decrypted := make([]byte, 16)
	block.Decrypt(decrypted, ciphertext)

	// Вывод результатов
	fmt.Printf("Key         : %x\n", key)
	fmt.Printf("Plaintext   : %x\n", plaintext)
	fmt.Printf("Ciphertext  : %x\n", ciphertext)
	fmt.Printf("Expected    : %x\n", expectedCipher)
	fmt.Printf("Decrypted   : %x\n", decrypted)

	// Проверка совпадений
	if hex.EncodeToString(ciphertext) == expectedCipherHex {
		fmt.Println("Encryption successful: matches expected.")
	} else {
		fmt.Println("Encryption failed: doesn't match expected.")
	}

	if string(decrypted) == string(plaintext) {
		fmt.Println("Decryption successful.")
	} else {
		fmt.Println("Decryption failed.")
	}
}

// --- CORE FUNCTIONS BELOW -----------------------

func encryptFile() {
	txts, err := listTxtFiles(".")
	if err != nil {
		fmt.Println("Scan error:", err)
		return
	}
	if len(txts) < 3 {
		fmt.Println("Need at least three .txt files (plaintext, keys, output).")
		return
	}

	// pick plaintext, keys, output by number
	pi, err := pickFile("Select plaintext file #:", txts)
	if err != nil {
		fmt.Println(err)
		return
	}
	ki, err := pickFile("Select keys file #:", txts)
	if err != nil {
		fmt.Println(err)
		return
	}
	oi, err := pickFile("Select output file #:", txts)
	if err != nil {
		fmt.Println(err)
		return
	}

	// read plaintext blocks
	plainBlocks, err := read16ByteBlocks(txts[pi])
	if err != nil {
		fmt.Println("Plaintext error:", err)
		return
	}

	// read key blocks
	keyBlocks, err := read16ByteBlocks(txts[ki])
	if err != nil {
		fmt.Println("Keys file error:", err)
		return
	}

	// build cipher(s)
	var engines []*aria.Aria
	switch {
	case len(keyBlocks) == 1:
		// one key for all blocks
		a, err := aria.NewAria(keyBlocks[0][:])
		if err != nil {
			fmt.Println("Invalid key:", err)
			return
		}
		for range plainBlocks {
			engines = append(engines, a)
		}
	case len(keyBlocks) == len(plainBlocks):
		// one key per block
		for _, kb := range keyBlocks {
			a, err := aria.NewAria(kb[:])
			if err != nil {
				fmt.Println("Invalid key:", err)
				return
			}
			engines = append(engines, a)
		}
	default:
		fmt.Printf("Keys file must have either 1 key or %d keys\n", len(plainBlocks))
		return
	}

	// open output and write
	outF, err := os.Create(txts[oi])
	if err != nil {
		fmt.Println("Failed to open output:", err)
		return
	}
	defer outF.Close()
	w := bufio.NewWriter(outF)

	// for i, blk := range plainBlocks {
	// 	dst := make([]byte, 16)
	// 	engines[i].Encrypt(dst, blk[:])
	// 	w.WriteString(fmt.Sprintf("% x", dst))
	// 	if i < len(plainBlocks)-1 {
	// 		w.WriteByte(' ')
	// 	}
	// }

	var rawTokens []string
	for i, blk := range plainBlocks {
		dst := make([]byte, 16)
		engines[i].Encrypt(dst, blk[:])
		rawTokens = append(rawTokens, fmt.Sprintf("% x", dst))
	}
	full := strings.Join(rawTokens, " ")
	formatted := formatTo32CharBlocks(full)
	w.WriteString(formatted)

	w.Flush()
	fmt.Println("Encryption complete →", txts[oi])
}

func decryptFile() {
	txts, err := listTxtFiles(".")
	if err != nil {
		fmt.Println("Scan error:", err)
		return
	}
	if len(txts) < 3 {
		fmt.Println("Need at least three .txt files (ciphertext, keys, output).")
		return
	}

	pi, err := pickFile("Select ciphertext file #:", txts)
	if err != nil {
		fmt.Println(err)
		return
	}
	ki, err := pickFile("Select keys file #:", txts)
	if err != nil {
		fmt.Println(err)
		return
	}
	oi, err := pickFile("Select output file #:", txts)
	if err != nil {
		fmt.Println(err)
		return
	}

	cipherBlocks, err := readHex16ByteBlocks(txts[pi])
	if err != nil {
		fmt.Println("Ciphertext error:", err)
		return
	}

	keyBlocks, err := read16ByteBlocks(txts[ki])
	if err != nil {
		fmt.Println("Keys file error:", err)
		return
	}

	var engines []*aria.Aria
	switch {
	case len(keyBlocks) == 1:
		a, err := aria.NewAria(keyBlocks[0][:])
		if err != nil {
			fmt.Println("Invalid key:", err)
			return
		}
		for range cipherBlocks {
			engines = append(engines, a)
		}
	case len(keyBlocks) == len(cipherBlocks):
		for _, kb := range keyBlocks {
			a, err := aria.NewAria(kb[:])
			if err != nil {
				fmt.Println("Invalid key:", err)
				return
			}
			engines = append(engines, a)
		}
	default:
		fmt.Printf("Keys file must have either 1 key or %d keys\n", len(cipherBlocks))
		return
	}

	// outF, err := os.Create(txts[oi])
	// if err != nil {
	// 	fmt.Println("Failed to open output:", err)
	// 	return
	// }
	// defer outF.Close()
	// w := bufio.NewWriter(outF)

	// for i, blk := range cipherBlocks {
	// 	dst := make([]byte, 16)
	// 	engines[i].Decrypt(dst, blk[:])
	// 	w.Write(dst)
	// 	if i < len(cipherBlocks)-1 {
	// 		w.WriteByte(' ')
	// 	}
	// }
	// w.Flush()
	// fmt.Println("Decryption complete →", txts[oi])

	// 1) decrypt into a temp raw file
	rawName := "__raw_plain.txt"
	rawF, err := os.Create(rawName)
	if err != nil {
		fmt.Println("Failed to open temp file:", err)
		return
	}
	w := bufio.NewWriter(rawF)
	for i, blk := range cipherBlocks {
		dst := make([]byte, 16)
		engines[i].Decrypt(dst, blk[:])
		w.Write(dst)
		if i < len(cipherBlocks)-1 {
			w.WriteByte(' ') // keep spaces so formatTo16CharBlocks will strip them
		}
	}
	w.Flush()
	rawF.Close()

	// 2) reformat into 16‑char blocks into the final output
	if err := reformatFile16(rawName, txts[oi]); err != nil {
		fmt.Println("Failed to reformat plaintext:", err)
		return
	}

	// 3) cleanup
	os.Remove(rawName)

	fmt.Println("Decryption complete →", txts[oi])
}

// ---- helpers ----

func listTxtFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".txt") {
			out = append(out, d.Name())
		}
		return nil
	})
	return out, err
}

func pickFile(prompt string, opts []string) (int, error) {
	fmt.Println(prompt)
	for i, name := range opts {
		fmt.Printf("  %2d) %s\n", i+1, name)
	}
	fmt.Print("Enter number: ")
	var idx int
	if _, err := fmt.Scan(&idx); err != nil {
		return 0, err
	}
	if idx < 1 || idx > len(opts) {
		return 0, errors.New("selection out of range")
	}
	return idx - 1, nil
}

// read16ByteBlocks reads raw 16‑byte tokens separated by spaces.
func read16ByteBlocks(fname string) ([][16]byte, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(string(data))
	var out [][16]byte
	for i, tk := range parts {
		b := []byte(tk)
		if len(b) != 16 {
			return nil, fmt.Errorf("token %d in %s has length %d, want 16", i+1, fname, len(b))
		}
		var blk [16]byte
		copy(blk[:], b)
		out = append(out, blk)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no 16‑byte blocks in %s", fname)
	}
	return out, nil
}

// readHex16ByteBlocks reads 16‑byte values written as "aa bb cc ..." in hex.
func readHex16ByteBlocks(fname string) ([][16]byte, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(string(data))
	var out [][16]byte
	for i, tk := range parts {
		raw := make([]byte, 16)
		n, err := fmt.Sscanf(tk,
			"%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
			&raw[0], &raw[1], &raw[2], &raw[3],
			&raw[4], &raw[5], &raw[6], &raw[7],
			&raw[8], &raw[9], &raw[10], &raw[11],
			&raw[12], &raw[13], &raw[14], &raw[15],
		)
		if err != nil || n != 16 {
			return nil, fmt.Errorf("token %d in %s is not a 16‑byte hex string", i+1, fname)
		}
		var blk [16]byte
		copy(blk[:], raw)
		out = append(out, blk)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no hex blocks in %s", fname)
	}
	return out, nil
}

// formatTo16CharBlocks takes an input string, removes all whitespace,
// then splits it into 16‑char chunks separated by spaces.
func formatTo16CharBlocks(s string) string {
	// remove all whitespace
	cleaned := strings.Join(strings.Fields(s), "")

	var parts []string
	for i := 0; i < len(cleaned); i += 16 {
		end := i + 16
		if end > len(cleaned) {
			end = len(cleaned)
		}
		parts = append(parts, cleaned[i:end])
	}
	return strings.Join(parts, " ")
}

// reformatFile16 reads the file at inPath, reformats its contents into
// 16‑char blocks, and writes the result to outPath.
func reformatFile16(inPath, outPath string) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	formatted := formatTo16CharBlocks(string(data))
	return os.WriteFile(outPath, []byte(formatted), 0644)
}

// formatTo32CharBlocks takes a hex‑byte string like "93 52 1e f2 …"
// strips all spaces, then emits substrings of length 32 (16 bytes * 2 hex digits),
// joined by single spaces.
func formatTo32CharBlocks(s string) string {
	// remove all whitespace
	cleaned := strings.Join(strings.Fields(s), "")
	var parts []string
	for i := 0; i < len(cleaned); i += 32 {
		end := i + 32
		if end > len(cleaned) {
			end = len(cleaned)
		}
		parts = append(parts, cleaned[i:end])
	}
	return strings.Join(parts, " ")
}
