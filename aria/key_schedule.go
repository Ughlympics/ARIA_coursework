package aria

import "encoding/binary"

//SL1
func substitution1(x [16]byte) (y [16]byte) {
	y[0] = sb1[x[0]]
	y[1] = sb2[x[1]]
	y[2] = sb3[x[2]]
	y[3] = sb4[x[3]]
	y[4] = sb1[x[4]]
	y[5] = sb2[x[5]]
	y[6] = sb3[x[6]]
	y[7] = sb4[x[7]]
	y[8] = sb1[x[8]]
	y[9] = sb2[x[9]]
	y[10] = sb3[x[10]]
	y[11] = sb4[x[11]]
	y[12] = sb1[x[12]]
	y[13] = sb2[x[13]]
	y[14] = sb3[x[14]]
	y[15] = sb4[x[15]]
	return
}

//SL2
func substitution2(x [16]byte) (y [16]byte) {
	y[0] = sb3[x[0]]
	y[1] = sb4[x[1]]
	y[2] = sb1[x[2]]
	y[3] = sb2[x[3]]
	y[4] = sb3[x[4]]
	y[5] = sb4[x[5]]
	y[6] = sb1[x[6]]
	y[7] = sb2[x[7]]
	y[8] = sb3[x[8]]
	y[9] = sb4[x[9]]
	y[10] = sb1[x[10]]
	y[11] = sb2[x[11]]
	y[12] = sb3[x[12]]
	y[13] = sb4[x[13]]
	y[14] = sb1[x[14]]
	y[15] = sb2[x[15]]
	return
}

//DL
func diffusion(x [16]byte) (y [16]byte) {
	y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14]
	y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15]
	y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15]
	y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14]
	y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15]
	y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15]
	y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13]
	y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13]
	y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15]
	y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14]
	y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15]
	y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14]
	y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12]
	y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13]
	y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14]
	y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15]
	return
}

func xor(x, y [16]byte) (z [16]byte) {
	for i := 0; i < 16; i++ {
		z[i] = x[i] ^ y[i]
	}
	return
}

func fo(d, rk [16]byte) [16]byte {
	return diffusion(substitution1(xor(d, rk)))
}

func fe(d, rk [16]byte) [16]byte {
	return diffusion(substitution2(xor(d, rk)))
}

func lrotate(x [16]byte, n int) (y [16]byte) {
	q, r := n/8, n%8
	s := 8 - r
	for i := 0; i < 16; i++ {
		a := x[(int(q)+i)%16]
		b := x[(int(q)+i+1)%16]
		y[i] = a<<r | b>>s
	}
	return
}

func rrotate(x [16]byte, n uint) (y [16]byte) {
	q, r := int(n/8)%16, n%8
	s := 8 - r
	for i := 0; i < 16; i++ {
		a := x[(i-q+16)%16]
		b := x[(i-q-1+16)%16]
		y[i] = a>>r | b<<s
	}
	return
}

func copyBytes(xk []uint32, x [16]byte) {
	for i := 0; i < 4; i++ {
		xk[i] = binary.BigEndian.Uint32(x[i*4 : (i+1)*4])
	}
}

func toBytes(u []uint32) (r [16]byte) {
	binary.BigEndian.PutUint32(r[0:4], u[0])
	binary.BigEndian.PutUint32(r[4:8], u[1])
	binary.BigEndian.PutUint32(r[8:12], u[2])
	binary.BigEndian.PutUint32(r[12:16], u[3])
	return
}

func (c *Aria) expandKey(key []byte) error {
	n := c.rounds()

	var kl, kr [16]byte

	copy(kl[:], key[:min(c.size, 16)])
	if c.size > 16 {
		copy(kr[:], key[16:c.size])
	}

	var ck1, ck2, ck3 [16]byte

	if c.size == 16 { // 128
		ck1 = c1
		ck2 = c2
		ck3 = c3
	} else if c.size == 24 { // 192
		ck1 = c2
		ck2 = c3
		ck3 = c1
	} else if c.size == 32 { // 256
		ck1 = c3
		ck2 = c1
		ck3 = c2
	} else {
		panic("aria: unsupported key size")
	}

	var w0, w1, w2, w3 [16]byte

	w0 = kl
	w1 = xor(fo(w0, ck1), kr)
	w2 = xor(fe(w1, ck2), w0)
	w3 = xor(fo(w2, ck3), w1)

	copyBytes(c.encKeys, xor(w0, rrotate(w1, 19)))
	copyBytes(c.encKeys[4:], xor(w1, rrotate(w2, 19)))
	copyBytes(c.encKeys[8:], xor(w2, rrotate(w3, 19)))
	copyBytes(c.encKeys[12:], xor(w3, rrotate(w0, 19)))
	copyBytes(c.encKeys[16:], xor(w0, rrotate(w1, 31)))
	copyBytes(c.encKeys[20:], xor(w1, rrotate(w2, 31)))
	copyBytes(c.encKeys[24:], xor(w2, rrotate(w3, 31)))
	copyBytes(c.encKeys[28:], xor(w3, rrotate(w0, 31)))
	copyBytes(c.encKeys[32:], xor(w0, lrotate(w1, 61)))
	copyBytes(c.encKeys[36:], xor(w1, lrotate(w2, 61)))
	copyBytes(c.encKeys[40:], xor(w2, lrotate(w3, 61)))
	copyBytes(c.encKeys[44:], xor(w3, lrotate(w0, 61)))
	copyBytes(c.encKeys[48:], xor(w0, lrotate(w1, 31)))
	if n > 12 {
		copyBytes(c.encKeys[52:], xor(w1, lrotate(w2, 31)))
		copyBytes(c.encKeys[56:], xor(w2, lrotate(w3, 31)))
	}
	if n > 14 {
		copyBytes(c.encKeys[60:], xor(w3, lrotate(w0, 31)))
		copyBytes(c.encKeys[64:], xor(w0, lrotate(w1, 19)))
	}

	copy(c.decKeys, c.encKeys[n*4:(n+1)*4])

	for i := 1; i <= n-1; i++ {
		t := diffusion(toBytes(c.encKeys[(n-i)*4 : (n-i+1)*4]))
		copyBytes(c.decKeys[i*4:], t)
	}

	copy(c.decKeys[n*4:], c.encKeys[:4])
	return nil
}
