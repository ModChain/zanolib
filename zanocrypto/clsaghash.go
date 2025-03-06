package zanocrypto

import (
	"hash"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

type clsagHash struct {
	h hash.Hash
}

func newClsagHash() *clsagHash {
	return &clsagHash{h: sha3.NewLegacyKeccak256()}
}

func (c *clsagHash) addBytes(b []byte) {
	c.h.Write(b)
}

func (c *clsagHash) addPointBytes(p *edwards25519.Point) {
	c.h.Write(p.Bytes())
}

func (c *clsagHash) addScalarBytes(s *edwards25519.Scalar) {
	c.h.Write(s.Bytes())
}

func (c *clsagHash) calcHash() *edwards25519.Scalar {
	res := c.h.Sum(nil)
	c.h.Reset()
	var buf64 [64]byte
	copy(buf64[:], res)
	pt, _ := new(edwards25519.Scalar).SetUniformBytes(buf64[:])
	return pt
}
