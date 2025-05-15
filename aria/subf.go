package aria

func (c *Aria) Encrypt(dst, src []byte) {
	if len(src) < 16 {
		panic("aria: input not full block")
	}
	if len(dst) < 16 {
		panic("aria: output not full block")
	}
	if inexactOverlap(dst[:16], src[:16]) {
		panic("aria: invalid buffer overlap")
	}

	n := c.rounds()
	var p [16]byte
	copy(p[:], src[:16])

	for i := 1; i <= n-1; i++ {
		xk := toBytes(c.encKeys[(i-1)*4 : i*4])
		if i&1 == 1 {
			p = fo(p, xk)
		} else {
			p = fe(p, xk)
		}
	}

	last := toBytes(c.encKeys[(n-1)*4 : n*4])
	out := toBytes(c.encKeys[n*4 : (n+1)*4])
	p = xor(substitution2(xor(p, last)), out)

	copy(dst[:16], p[:])
}

func (c *Aria) Decrypt(dst, src []byte) {
	if len(src) < 16 {
		panic("aria: input not full block")
	}
	if len(dst) < 16 {
		panic("aria: output not full block")
	}
	if inexactOverlap(dst[:16], src[:16]) {
		panic("aria: invalid buffer overlap")
	}

	// same as encKeysrypt, but with decKeys
	n := c.rounds()
	var p [16]byte
	copy(p[:], src[:16])

	for i := 1; i <= n-1; i++ {
		xk := toBytes(c.decKeys[(i-1)*4 : i*4])
		if i&1 == 1 {
			p = fo(p, xk)
		} else {
			p = fe(p, xk)
		}
	}

	last := toBytes(c.decKeys[(n-1)*4 : n*4])
	out := toBytes(c.decKeys[n*4 : (n+1)*4])
	p = xor(substitution2(xor(p, last)), out)

	copy(dst[:16], p[:])
}
