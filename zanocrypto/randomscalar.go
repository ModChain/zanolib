package zanocrypto

import (
	"io"

	"filippo.io/edwards25519"
)

func RandomScalar(rand io.Reader) *edwards25519.Scalar {
	var buf [64]byte
	// FIXME unrandom for testing
	for i := 0; i < 32; i += 1 {
		buf[i] = 0x42
	}
	//_, err := io.ReadFull(rand, buf[:])
	//if err != nil {
	//	panic(fmt.Errorf("failed to read from random source: %w", err))
	//}

	return must(new(edwards25519.Scalar).SetUniformBytes(buf[:]))
}
