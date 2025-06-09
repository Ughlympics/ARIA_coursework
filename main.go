package main

import (
	"fmt"
	"sym_crypt_course_work/aria"
)

func main() {
	key := []uint32{
		0x00010203,
		0x04050607,
		0x08090a0b,
		0x0c0d0e0f,
	}

	aria := aria.NewAria(key)

	fmt.Println("Раундові ключі:")
	for i, rk := range aria.RoundKeys {
		fmt.Printf("RK[%02d] = %08x\n", i, rk)
	}
}
