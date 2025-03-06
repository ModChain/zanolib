package zanocrypto

import (
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

func RandomScalar(rand io.Reader) *edwards25519.Scalar {
	var buf [64]byte
	_, err := io.ReadFull(rand, buf[:])
	if err != nil {
		panic(fmt.Errorf("failed to read from random source: %w", err))
	}

	return must(new(edwards25519.Scalar).SetUniformBytes(buf[:]))
}
