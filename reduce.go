package zanolib

func load3(in []byte) int64 {
	return int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16)
}

func load4(in []byte) int64 {
	return int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16) | (int64(in[3]) << 24)
}

// ScReduce32 reduces a 32-byte scalar modulo the group order for Ed25519
// and modifies the input slice in place.
func ScReduce32(s []byte) {
	if len(s) != 32 {
		panic("ScReduce32: input must be 32 bytes")
	}

	s0 := (load3(s[0:3])) & 2097151
	s1 := (load4(s[2:6]) >> 5) & 2097151
	s2 := (load3(s[5:8]) >> 2) & 2097151
	s3 := (load4(s[7:11]) >> 7) & 2097151
	s4 := (load4(s[10:14]) >> 4) & 2097151
	s5 := (load3(s[13:16]) >> 1) & 2097151
	s6 := (load4(s[15:19]) >> 6) & 2097151
	s7 := (load3(s[18:21]) >> 3) & 2097151
	s8 := (load3(s[21:24])) & 2097151
	s9 := (load4(s[23:27]) >> 5) & 2097151
	s10 := (load3(s[26:29]) >> 2) & 2097151
	s11 := (load4(s[28:32]) >> 7)
	s12 := int64(0)

	var carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9, carry10, carry11 int64

	// First pass of carries
	carry0 = (s0 + (1 << 20)) >> 21
	s1 += carry0
	s0 -= carry0 << 21

	carry2 = (s2 + (1 << 20)) >> 21
	s3 += carry2
	s2 -= carry2 << 21

	carry4 = (s4 + (1 << 20)) >> 21
	s5 += carry4
	s4 -= carry4 << 21

	carry6 = (s6 + (1 << 20)) >> 21
	s7 += carry6
	s6 -= carry6 << 21

	carry8 = (s8 + (1 << 20)) >> 21
	s9 += carry8
	s8 -= carry8 << 21

	carry10 = (s10 + (1 << 20)) >> 21
	s11 += carry10
	s10 -= carry10 << 21

	carry1 = (s1 + (1 << 20)) >> 21
	s2 += carry1
	s1 -= carry1 << 21

	carry3 = (s3 + (1 << 20)) >> 21
	s4 += carry3
	s3 -= carry3 << 21

	carry5 = (s5 + (1 << 20)) >> 21
	s6 += carry5
	s5 -= carry5 << 21

	carry7 = (s7 + (1 << 20)) >> 21
	s8 += carry7
	s7 -= carry7 << 21

	carry9 = (s9 + (1 << 20)) >> 21
	s10 += carry9
	s9 -= carry9 << 21

	carry11 = (s11 + (1 << 20)) >> 21
	s12 += carry11
	s11 -= carry11 << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	// Second pass of carries
	carry0 = s0 >> 21
	s1 += carry0
	s0 -= carry0 << 21

	carry1 = s1 >> 21
	s2 += carry1
	s1 -= carry1 << 21

	carry2 = s2 >> 21
	s3 += carry2
	s2 -= carry2 << 21

	carry3 = s3 >> 21
	s4 += carry3
	s3 -= carry3 << 21

	carry4 = s4 >> 21
	s5 += carry4
	s4 -= carry4 << 21

	carry5 = s5 >> 21
	s6 += carry5
	s5 -= carry5 << 21

	carry6 = s6 >> 21
	s7 += carry6
	s6 -= carry6 << 21

	carry7 = s7 >> 21
	s8 += carry7
	s7 -= carry7 << 21

	carry8 = s8 >> 21
	s9 += carry8
	s8 -= carry8 << 21

	carry9 = s9 >> 21
	s10 += carry9
	s9 -= carry9 << 21

	carry10 = s10 >> 21
	s11 += carry10
	s10 -= carry10 << 21

	carry11 = s11 >> 21
	s12 += carry11
	s11 -= carry11 << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901

	// Third pass of carries
	carry0 = s0 >> 21
	s1 += carry0
	s0 -= carry0 << 21

	carry1 = s1 >> 21
	s2 += carry1
	s1 -= carry1 << 21

	carry2 = s2 >> 21
	s3 += carry2
	s2 -= carry2 << 21

	carry3 = s3 >> 21
	s4 += carry3
	s3 -= carry3 << 21

	carry4 = s4 >> 21
	s5 += carry4
	s4 -= carry4 << 21

	carry5 = s5 >> 21
	s6 += carry5
	s5 -= carry5 << 21

	carry6 = s6 >> 21
	s7 += carry6
	s6 -= carry6 << 21

	carry7 = s7 >> 21
	s8 += carry7
	s7 -= carry7 << 21

	carry8 = s8 >> 21
	s9 += carry8
	s8 -= carry8 << 21

	carry9 = s9 >> 21
	s10 += carry9
	s9 -= carry9 << 21

	carry10 = s10 >> 21
	s11 += carry10
	s10 -= carry10 << 21

	// Now store back into s (each s[i] is one byte)
	s[0] = byte(s0 >> 0)
	s[1] = byte(s0 >> 8)
	s[2] = byte((s0 >> 16) | (s1 << 5))
	s[3] = byte(s1 >> 3)
	s[4] = byte(s1 >> 11)
	s[5] = byte((s1 >> 19) | (s2 << 2))
	s[6] = byte(s2 >> 6)
	s[7] = byte((s2 >> 14) | (s3 << 7))
	s[8] = byte(s3 >> 1)
	s[9] = byte(s3 >> 9)
	s[10] = byte((s3 >> 17) | (s4 << 4))
	s[11] = byte(s4 >> 4)
	s[12] = byte(s4 >> 12)
	s[13] = byte((s4 >> 20) | (s5 << 1))
	s[14] = byte(s5 >> 7)
	s[15] = byte((s5 >> 15) | (s6 << 6))
	s[16] = byte(s6 >> 2)
	s[17] = byte(s6 >> 10)
	s[18] = byte((s6 >> 18) | (s7 << 3))
	s[19] = byte(s7 >> 5)
	s[20] = byte(s7 >> 13)
	s[21] = byte(s8 >> 0)
	s[22] = byte(s8 >> 8)
	s[23] = byte((s8 >> 16) | (s9 << 5))
	s[24] = byte(s9 >> 3)
	s[25] = byte(s9 >> 11)
	s[26] = byte((s9 >> 19) | (s10 << 2))
	s[27] = byte(s10 >> 6)
	s[28] = byte((s10 >> 14) | (s11 << 7))
	s[29] = byte(s11 >> 1)
	s[30] = byte(s11 >> 9)
	s[31] = byte(s11 >> 17)
}
