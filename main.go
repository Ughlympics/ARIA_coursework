package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Hi! Welcome into ARIA cypher utility.")
	fmt.Println("Choose option:")
	printMenu()

	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			describeProgram()
		case "2":
			showDirectoryFiles()
		case "3":
			encryptFile()
		case "4":
			decryptFile()
		case "5":
			printMenu()
		case "0":
			fmt.Println("Bye bye.")
			return
		default:
			fmt.Println("Wrong option, try again.")
		}

		fmt.Println()
	}
}

func printMenu() {
	fmt.Println("1 - Description of the program")
	fmt.Println("2 - Show directory files")
	fmt.Println("3 - Encrypt .txt file")
	fmt.Println("4 - Decrypt .txt file")
	fmt.Println("5 - Help")
	fmt.Println("0 - Exit")
}

func describeProgram() {
	fmt.Println("ARIA — is a block cipher developed in South Korea.")
	fmt.Println("Supports 128, 192 and 256 bit keys. Used to protect data.")
	fmt.Println("The program allows you to encrypt and decrypt .txt files using the ARIA algorithm.")
	fmt.Println()
	fmt.Println("Operating Principle:")
	fmt.Println("  In the same directory as the executable, you must have three .txt files:")
	fmt.Println("    • plaintext.txt   – contains the data to encrypt (16‑byte blocks separated by spaces)")
	fmt.Println("    • keys.txt        – either a single key for all blocks,")
	fmt.Println("                        or one key per block (matching the number of plaintext blocks)")
	fmt.Println("    • ciphertext.txt  – will receive the encrypted output")
	fmt.Println()
	fmt.Println("File Requirements:")
	fmt.Println("  • Plaintext is split into 16‑byte blocks, each block separated by a single space.")
	fmt.Println("  • Keys file may contain:")
	fmt.Println("      – One key, applied to all blocks,")
	fmt.Println("      – Or N keys for N blocks, so each block is encrypted independently.")
	fmt.Println()
	fmt.Println("Press 5 to get menu")

}

func showDirectoryFiles() {
	files, err := os.ReadDir(".")
	if err != nil {
		fmt.Println("Ups, you should read desription :)", err)
		return
	}

	fmt.Println(" .txt files in main directory:")
	found := false
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
			fmt.Println(" -", file.Name())
			found = true
		}
	}

	if !found {
		fmt.Println("No .txt files.")
	}
}

func encryptFile() {
	fmt.Println("")
}

func decryptFile() {
	fmt.Println("")
}
