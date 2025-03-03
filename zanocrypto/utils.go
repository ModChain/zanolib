package zanocrypto

func load3(in []byte) int64 {
	return int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16)
}

func load4(in []byte) int64 {
	return int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16) | (int64(in[3]) << 24)
}
