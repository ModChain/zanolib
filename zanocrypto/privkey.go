package zanocrypto

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"filippo.io/edwards25519"
)

func GenerateKeyScalar() *edwards25519.Scalar {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		panic(err)
	}

	h := sha512.New()
	h.Write(seed)
	digest := h.Sum(nil)

	res, err := new(edwards25519.Scalar).SetBytesWithClamping(digest[:32])
	if err != nil {
		panic(err)
	}
	return res
}

func PubFromPriv(priv *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).ScalarBaseMult(priv)
}
