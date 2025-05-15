package aria

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
